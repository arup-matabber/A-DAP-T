'use client';

import { clearAuthState, getValidAuthToken } from '@/lib/auth';

export const API_BASE = process.env.NEXT_PUBLIC_ADAPT_API_BASE || 'https://adapt-3s27.onrender.com';

type ApiOptions = RequestInit & { auth?: boolean; retryOnRefresh?: boolean };

function shouldTreatAsAuthFailure(status: number, body: unknown): boolean {
  if (status === 401 || status === 403) return true;
  const text = typeof body === 'string' ? body : JSON.stringify(body || {});
  return /invalid|expired|authentication|required|unauthorized/i.test(text);
}

export function formatApiError(error: unknown, fallback = 'Something went wrong. Please try again.'): string {
  const message = error instanceof Error ? error.message : String(error || '');
  const lower = message.toLowerCase();

  if (/quota|limit|rate|429|resource exhausted/.test(lower)) {
    return 'The AI service or backend hit a usage limit. Wait a short while and try again, or run a demo scan without AI-heavy actions.';
  }
  if (/failed to fetch|network|load failed|connection|cors/.test(lower)) {
    return 'A-DAP-T could not reach the backend. The Render service may be waking up or your network blocked the request.';
  }
  if (/expired|invalid token|unauthorized|authentication|required/.test(lower)) {
    return 'Your session expired. Please sign in again so A-DAP-T can refresh protected scan access.';
  }
  if (/github|repository|repo|branch/.test(lower)) {
    return `GitHub scan failed: ${message}`;
  }
  if (/zip|file|upload/.test(lower)) {
    return `Project upload failed: ${message}`;
  }
  return message || fallback;
}

export async function apiFetch<T = unknown>(path: string, options: ApiOptions = {}): Promise<T> {
  const headers = new Headers(options.headers || {});

  if (options.auth !== false) {
    const token = await getValidAuthToken(API_BASE);
    if (token) headers.set('Authorization', `Bearer ${token}`);
  }

  const response = await fetch(`${API_BASE}${path}`, { ...options, headers });
  const text = await response.text();
  const data = text ? tryJson(text) : null;

  if (!response.ok) {
    if (shouldTreatAsAuthFailure(response.status, data)) clearAuthState();
    const detail = typeof data === 'object' && data && 'detail' in data ? String((data as any).detail) : text;
    throw new Error(detail || `Request failed with status ${response.status}`);
  }

  return data as T;
}

function tryJson(text: string): unknown {
  try { return JSON.parse(text); } catch { return text; }
}

export function downloadText(filename: string, content: string, type = 'text/plain'): void {
  const blob = new Blob([content || ''], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export async function copyText(text: string): Promise<void> {
  await navigator.clipboard.writeText(text || '');
}
