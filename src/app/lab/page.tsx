import { notFound } from 'next/navigation';
import { Workbench } from '@/components/workbench';

export default function Page() {
  // ナビゲーションの非表示だけでなく、直接アクセスした場合も開発時に限定する。
  if (process.env.NODE_ENV !== 'development') notFound();

  return <Workbench mode="lab" />;
}
