'use client';

import type { ScanReport } from '@/types/scan';

const CURRENT_REPORT_KEY = 'adpt_result';

export function saveCurrentReport(report: ScanReport): void {
  const raw = JSON.stringify(report);
  sessionStorage.setItem(CURRENT_REPORT_KEY, raw);
  localStorage.setItem(CURRENT_REPORT_KEY, raw);
}

export function loadCurrentReport(): ScanReport | null {
  const raw = sessionStorage.getItem(CURRENT_REPORT_KEY) || localStorage.getItem(CURRENT_REPORT_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as ScanReport;
  } catch {
    return null;
  }
}
