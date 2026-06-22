'use client';

import Link from 'next/link';
import { FormEvent, useState } from 'react';
import { useRouter } from 'next/navigation';
import { apiFetch, formatApiError } from '@/lib/api';
import { saveAuthState } from '@/lib/auth';
import { BrandWord } from '@/components/ui/BrandWord';

type LoginResponse = { idToken?: string; refreshToken?: string; expiresIn?: string; localId?: string; email?: string; displayName?: string };

const accessReasons = [
  ['Run scans', 'Use protected demo, GitHub, and ZIP scan endpoints.'],
  ['Save history', 'Reopen previous reports and continue review later.'],
  ['Ask DAP', 'Use the current report context for fix-first guidance.'],
  ['Gate deploys', 'Generate workflow and policy artifacts for CI/CD.'],
];

export default function SignUpPage() {
  const router = useRouter();
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  function getNextPath() {
    if (typeof window === 'undefined') return '/scanner';
    const next = new URLSearchParams(window.location.search).get('next');
    return next && next.startsWith('/') && !next.startsWith('//') ? next : '/scanner';
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError('');

    if (password !== confirm) {
      setError('Passwords do not match.');
      return;
    }

    setLoading(true);
    try {
      await apiFetch('/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ display_name: displayName, email, password }),
        auth: false,
      });

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
        displayName: data.displayName || displayName,
      });

      pendo.identify({
        visitor: {
          id: data.localId || '',
          email: data.email || email,
          full_name: data.displayName || displayName,
        },
      });

      router.push(getNextPath());
      const redirectPath = getNextPath();
      if (typeof pendo !== 'undefined') {
        pendo.track('account_created', {
          display_name: displayName,
          signup_method: 'email',
          redirect_path: redirectPath,
        });
      }

      router.push(redirectPath);
    } catch (err) {
      setError(formatApiError(err, 'Sign up failed. Please check the details and try again.'));
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="auth-wrap">
      <section className="auth-grid">
        <div className="glass-card auth-card shimmer">
          <div className="tech-label"><span className="pulse-dot" /> CREATE ACCESS</div>
          <h1>Start scanning.</h1>
          <p className="muted">Create an account to run protected scans, save reports, and use DAP with report context.</p>
          <form className="form-stack" onSubmit={submit} style={{ marginTop: 22 }}>
            {error && <div className="form-error">{error}</div>}
            <label className="form-row">
              <span className="form-label">Name</span>
              <input className="input" value={displayName} onChange={(e) => setDisplayName(e.target.value)} required />
            </label>
            <label className="form-row">
              <span className="form-label">Email</span>
              <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
            </label>
            <div className="grid grid-2">
              <label className="form-row">
                <span className="form-label">Password</span>
                <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
              </label>
              <label className="form-row">
                <span className="form-label">Confirm</span>
                <input className="input" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required />
              </label>
            </div>
            <button className="btn btn-primary" type="submit" disabled={loading}>{loading ? 'Creating...' : 'Create account'}</button>
          </form>
          <p className="muted" style={{ marginTop: 16 }}>Already have an account? <Link href="/signin" style={{ color: 'var(--text)' }}>Sign in</Link></p>
        </div>

        <aside className="glass-card auth-info">
          <div>
            <div className="tech-label"><span className="pulse-dot" /> WHY ACCOUNT ACCESS</div>
            <h2 className="panel-title" style={{ marginTop: 12 }}><BrandWord /> is not just a landing page.</h2>
            <p className="muted">The app stores report history and protects scan resources, so authenticated access keeps the workflow reliable during demos and real scans.</p>
            <div className="auth-info-list">
              {accessReasons.map(([title, body], index) => (
                <div className="auth-info-item" key={title}>
                  <span className="auth-info-icon">{index + 1}</span>
                  <div><strong>{title}</strong><p className="faint" style={{ margin: '3px 0 0' }}>{body}</p></div>
                </div>
              ))}
            </div>
          </div>
          <p className="faint" style={{ marginTop: 22 }}>Safety note: project files are read as text only. Uploaded code is not executed by the scanner.</p>
        </aside>
      </section>
    </main>
  );
}
