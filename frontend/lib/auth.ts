'use client';

import type { AuthState } from '@/types/auth';

const AUTH_KEY = 'adpt_auth';
const TOKEN_REFRESH_MARGIN_MS = 5 * 60 * 1000;

function normalizeAuthState(auth: unknown): AuthState | null {
  if (!auth) return null;

  if (typeof auth === 'string') {
    return auth ? { idToken: auth } : null;
  }

  if (typeof auth !== 'object') return null;

  const raw = auth as Record<string, any>;
  const seconds = Number(raw.expiresIn ?? raw.expires_in ?? 3600);
  const expiresAt = raw.expiresAt ?? (Number.isFinite(seconds) ? Date.now() + seconds * 1000 : undefined);
  const idToken = raw.idToken ?? raw.id_token ?? raw.token ?? raw.accessToken;

  if (!idToken) return null;

  return {
    ...raw,
    idToken,
    refreshToken: raw.refreshToken ?? raw.refresh_token,
    uid: raw.uid ?? raw.localId ?? raw.user_id,
    expiresAt,
  } as AuthState;
}

export function getAuthState(): AuthState | null {
  if (typeof window === 'undefined') return null;
  const raw = window.localStorage.getItem(AUTH_KEY);
  if (!raw) return null;

  try {
    return normalizeAuthState(JSON.parse(raw));
  } catch {
    return normalizeAuthState(raw);
  }
}

export function saveAuthState(auth: unknown): void {
  if (typeof window === 'undefined') return;
  const normalized = normalizeAuthState(auth);
  if (!normalized) return;
  window.localStorage.setItem(AUTH_KEY, JSON.stringify(normalized));
}

export function clearAuthState(): void {
  if (typeof window === 'undefined') return;
  window.localStorage.removeItem(AUTH_KEY);
}

export function isLoggedIn(): boolean {
  return !!getAuthState()?.idToken;
}

function tokenNeedsRefresh(auth: AuthState | null): boolean {
  if (!auth?.idToken) return true;
  if (!auth.expiresAt) return false;
  return Date.now() >= Number(auth.expiresAt) - TOKEN_REFRESH_MARGIN_MS;
}

export async function getValidAuthToken(apiBase: string): Promise<string | null> {
  const auth = getAuthState();
  if (!auth?.idToken) return null;
  if (!tokenNeedsRefresh(auth)) return auth.idToken;
  if (!auth.refreshToken) return auth.idToken;

  const response = await fetch(`${apiBase}/auth/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refreshToken: auth.refreshToken }),
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    clearAuthState();
    throw new Error(data.detail || 'Session expired. Please sign in again.');
  }

  const nextAuth = normalizeAuthState({
    ...auth,
    ...data,
    email: auth.email ?? data.email,
    displayName: auth.displayName ?? data.displayName,
    uid: auth.uid ?? data.localId ?? data.user_id,
  });

  if (!nextAuth) {
    clearAuthState();
    throw new Error('Session expired. Please sign in again.');
  }

  saveAuthState(nextAuth);
  return nextAuth.idToken;
}
