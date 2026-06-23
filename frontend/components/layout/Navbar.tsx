'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { usePathname } from 'next/navigation';
import { clearAuthState, getAuthState } from '@/lib/auth';
import { BrandWord } from '@/components/ui/BrandWord';

function ShieldMark() {
  const [imageFailed, setImageFailed] = useState(false);
  if (!imageFailed) {
    return <img className="brand-logo-img" src="/adapt-logo.svg" alt="" onError={() => setImageFailed(true)} />;
  }
  return (
    <svg className="brand-shield" viewBox="0 0 24 26" fill="none" aria-hidden="true">
      <path d="M12 2.2 20.5 5.4v6.3c0 5.5-3.3 9.4-8.5 12.1-5.2-2.7-8.5-6.6-8.5-12.1V5.4L12 2.2Z" stroke="currentColor" strokeWidth="1.8" />
      <path d="M8.2 13.2h7.6M12 9.4v7.6" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
    </svg>
  );
}

export function Navbar() {
  const pathname = usePathname();
  const [isAuthed, setIsAuthed] = useState(false);

  const checkAuth = () => {
    setIsAuthed(!!getAuthState());
  };

  useEffect(() => {
    checkAuth();
    window.addEventListener('storage', checkAuth);
    return () => window.removeEventListener('storage', checkAuth);
  }, [pathname]);

  function logout() {
    clearAuthState();
    pendo.clearSession();
    setIsAuthed(false);
    window.location.href = '/';
  }

  const navLinks = [
    { name: 'Scanner', href: '/scanner' },
    { name: 'Report', href: '/report/current' },
    { name: 'Compare', href: '/compare' },
    { name: 'Methodology', href: '/methodology' },
    { name: 'About', href: '/about' },
  ];

  return (
    <header className="navbar">
      <div className="container nav-inner">
        <Link href="/" className="brand" aria-label="A-DAP-T home">
          <span className="brand-mark"><ShieldMark /></span>
          <span className="brand-name"><BrandWord /></span>
        </Link>

        <nav className="nav-links" aria-label="Primary navigation">
          {navLinks.map((link) => (
            <Link
              key={link.href}
              className={`nav-link ${pathname === link.href ? 'active' : ''}`}
              href={link.href}
              style={pathname === link.href ? { color: 'var(--emerald)' } : {}}
            >
              {link.name}
            </Link>
          ))}
        </nav>

        <div className="nav-actions">
          {isAuthed ? (
            <>
              <Link className="btn btn-secondary btn-small" href="/profile">Profile</Link>
              <button className="btn btn-secondary btn-small" type="button" onClick={logout}>Log out</button>
            </>
          ) : (
            <>
              <Link className="btn btn-secondary btn-small" href="/signin">Log in</Link>
              <Link className="btn btn-primary btn-small" href="/signup">Get access</Link>
            </>
          )}
        </div>
      </div>
      <style jsx>{`
        .nav-link.active::after { width: 100%; }
      `}</style>
    </header>
  );
}
