'use client';

import Link from 'next/link';
import { FormEvent, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { apiFetch, formatApiError } from '@/lib/api';
import { saveAuthState } from '@/lib/auth';
import { BrandWord } from '@/components/ui/BrandWord';

type LoginResponse = { idToken?: string; refreshToken?: string; expiresIn?: string; localId?: string; email?: string; displayName?: string };

export default function SignInPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');

  useEffect(() => {
    setMessage(new URLSearchParams(window.location.search).get('message') || '');
  }, []);

  function getNextPath() {
    if (typeof window === 'undefined') return '/scanner';
    const next = new URLSearchParams(window.location.search).get('next');
    return next && next.startsWith('/') && !next.startsWith('//') ? next : '/scanner';
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError('');
    setLoading(true);

    try {
      const data = await apiFetch<LoginResponse>('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
        auth: false,
      });

      saveAuthState({
        idToken: data.idToken,
        refreshToken: data.refreshToken,
        expiresIn: data.expiresIn,
        uid: data.localId,
        email: data.email || email,
        displayName: data.displayName || 'A-DAP-T User',
      });

      pendo.identify({
        visitor: {
          id: data.localId || '',
          email: data.email || email,
          full_name: data.displayName || 'A-DAP-T User',
        },
      });

      router.push(getNextPath());
      const redirectPath = getNextPath();
      const nextParam = new URLSearchParams(window.location.search).get('next');
      if (typeof pendo !== 'undefined') {
        pendo.track('user_signed_in', {
          has_next_redirect: Boolean(nextParam),
          redirect_path: redirectPath,
        });
      }

      router.push(redirectPath);
    } catch (err) {
      setError(formatApiError(err, 'Sign in failed. Please check your credentials and try again.'));
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="auth-wrap">
      <section className="auth-grid">
        <div className="glass-card auth-card shimmer">
          <div className="tech-label"><span className="pulse-dot" /> SECURE SESSION</div>
          <h1>Log in.</h1>
          <p className="muted">Access scanner, saved reports, DAP, and deployment gate outputs.</p>
          <form className="form-stack" onSubmit={submit} style={{ marginTop: 22 }}>
            {error && <div className="form-error">{error}</div>}
            {message && <div className="form-success">{message}</div>}
            <label className="form-row">
              <span className="form-label">Email</span>
              <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
            </label>
            <label className="form-row">
              <span className="form-label">Password</span>
              <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
            </label>
            <button className="btn btn-primary" type="submit" disabled={loading}>{loading ? 'Signing in...' : 'Sign in'}</button>
          </form>
          <p className="muted" style={{ marginTop: 16 }}>No account? <Link href="/signup" style={{ color: 'var(--text)' }}>Create one</Link></p>
        </div>

        <aside className="glass-card auth-info">
          <div>
            <div className="tech-label"><span className="pulse-dot" /> SESSION CONTEXT</div>
            <h2 className="panel-title" style={{ marginTop: 12 }}>Return to your risk workspace.</h2>
            <p className="muted">After sign in, <BrandWord /> can refresh your Firebase token before protected calls and keep scans, DAP, and report history available during longer review sessions.</p>
            <div className="auth-info-list">
              <div className="auth-info-item"><span className="auth-info-icon">✓</span><div><strong>Saved reports</strong><p className="faint" style={{ margin: '3px 0 0' }}>Open previous scans and continue review.</p></div></div>
              <div className="auth-info-item"><span className="auth-info-icon">✓</span><div><strong>Report-aware DAP</strong><p className="faint" style={{ margin: '3px 0 0' }}>Ask what to fix first using the current report.</p></div></div>
              <div className="auth-info-item"><span className="auth-info-icon">✓</span><div><strong>Deployment gate</strong><p className="faint" style={{ margin: '3px 0 0' }}>Copy workflow and policy outputs after scan.</p></div></div>
            </div>
          </div>
          <p className="faint" style={{ marginTop: 22 }}>If your session expires, the frontend refreshes the token before API calls instead of logging you out unnecessarily.</p>
        </aside>
      </section>
    </main>
  );
}
