import { notFound } from 'next/navigation';
import { Workbench } from '@/components/workbench';
export default function Page() {
  if (process.env.NODE_ENV !== 'development') notFound();
  return <Workbench mode="lab" />;
}
