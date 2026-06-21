import type { Severity } from '@/types/scan';

export function severityLabel(value?: Severity): string {
  if (!value) return 'Info';
  const normalized = String(value).toLowerCase();
  return normalized.charAt(0).toUpperCase() + normalized.slice(1);
}

export function severityClass(value?: Severity): string {
  const normalized = String(value || '').toLowerCase();
  if (normalized.includes('critical')) return 'danger';
  if (normalized.includes('high')) return 'danger';
  if (normalized.includes('medium')) return 'warning';
  if (normalized.includes('low')) return 'safe';
  return 'neutral';
}

export function gateClass(decision?: string): string {
  const normalized = String(decision || '').toUpperCase();
  if (normalized === 'BLOCK') return 'danger';
  if (normalized === 'REVIEW') return 'warning';
  if (normalized === 'ALLOW') return 'safe';
  return 'neutral';
}

export function categoryName(key: string): string {
  return key
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (match) => match.toUpperCase());
}
