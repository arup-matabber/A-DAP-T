import { gateClass, severityClass } from '@/lib/score';

export function StatusPill({ label, tone }: { label: string; tone?: string }) {
  const cls = tone ? tone : severityClass(label);
  return <span className={`pill ${cls}`}>{label}</span>;
}

export function GatePill({ decision }: { decision?: string }) {
  return <span className={`pill ${gateClass(decision)}`}>{decision || 'UNKNOWN'}</span>;
}
