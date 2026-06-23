'use client';

import { ReactNode, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { getAuthState } from '@/lib/auth';

export function AuthGate({ children, nextPath, label = 'Checking secure session...' }: { children: ReactNode; nextPath: string; label?: string }) {
  const router = useRouter();
  const [allowed, setAllowed] = useState(false);

  useEffect(() => {
    const auth = getAuthState();
    if (!auth) {
      router.replace(`/signin?next=${encodeURIComponent(nextPath)}`);
      return;
    }
    setAllowed(true);
  }, [router, nextPath]);

  if (!allowed) {
    return (
      <main className="page-shell auth-check-shell">
        <div className="container">
          <section className="solid-card panel auth-check-card">
            <div className="tech-label"><span className="pulse-dot" /> SECURE ROUTE</div>
            <h1 className="panel-title">Preparing workspace.</h1>
            <p className="muted">{label}</p>
          </section>
        </div>
      </main>
    );
  }

  return <>{children}</>;
}
