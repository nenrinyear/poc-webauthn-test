import { test, expect } from '@playwright/test';

test('browser WebAuthn registration, discoverable login, extra passkey and development rejection experiments', async ({ page, context }) => {
  const consoleErrors: string[] = [];
  page.on('pageerror', error => consoleErrors.push(error.message));
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
    protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true,
    isUserVerified: true, automaticPresenceSimulation: true,
  } });
  await page.goto('/register');
  await page.getByLabel('ユーザー名', { exact: true }).fill('browser_researcher');
  await page.getByRole('button', { name: 'パスキーを登録して作成' }).click();
  await expect(page.getByRole('status')).toContainText('アカウントを作成し、ログインしました');
  await page.getByRole('link', { name: 'ユーザー情報へ →' }).click();
  await expect(page.getByRole('heading', { name: 'browser_researcher', exact: true })).toBeVisible();
  await expect(page.locator('.key')).toHaveCount(1);
  const cookies = await context.cookies();
  expect(cookies.find(c => c.name === 'lab_session')).toMatchObject({ httpOnly: true, sameSite: 'Strict', secure: false });
  expect(await page.evaluate(() => document.cookie)).not.toContain('lab_session');
  await page.getByRole('button', { name: 'ログアウト', exact: true }).click();
  await expect(page.getByRole('status')).toContainText('ログアウトしました');
  await page.getByRole('link', { name: 'ログイン', exact: true }).click();
  await page.getByRole('button', { name: 'パスキーを選んでログイン' }).click();
  await expect(page.getByRole('status')).toContainText('パスキー認証に成功');
  await page.getByRole('link', { name: '開発・検証', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'WebAuthn フローを観察する' })).toBeVisible();
  await expect(page.locator('.events')).toContainText('SimpleWebAuthnによる検証');
  await page.getByRole('button', { name: '応答を再送' }).click();
  await expect(page.getByRole('status')).toContainText('拒否を確認しました');
  for (const [name, reason] of [
    ['challengeを改変', 'challenge'], ['Originを改変', 'origin'], ['rpIdHashを改変', 'RP ID'],
  ] as const) {
    await page.getByRole('button', { name }).click();
    await expect(page.getByRole('status')).toContainText('拒否を確認しました');
    await expect(page.locator('.event.server').last().locator('pre')).toContainText(reason, { ignoreCase: true });
  }
  await page.getByRole('link', { name: 'ユーザー情報', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'browser_researcher', exact: true })).toBeVisible();
  // A second virtual authenticator models an additional physical device.
  await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
    protocol: 'ctap2', transport: 'usb', hasResidentKey: true, hasUserVerification: true,
    isUserVerified: true, automaticPresenceSimulation: true,
  } });
  await page.getByRole('button', { name: 'パスキーを追加', exact: true }).click();
  await expect(page.getByRole('status')).toContainText('パスキーを追加しました');
  await expect(page.locator('.key')).toHaveCount(2);
  await page.getByRole('link', { name: '開発・検証', exact: true }).click();
  await page.getByRole('button', { name: '正常な認証', exact: true }).click();
  await expect(page.getByRole('status')).toContainText('パスキー認証に成功');
  await page.getByRole('button', { name: '記録を消去', exact: true }).click();
  await expect(page.locator('.event')).toHaveCount(0);
  expect(consoleErrors).toEqual([]);
});
