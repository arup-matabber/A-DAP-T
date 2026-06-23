import Link from 'next/link';
import { BrandWord } from '@/components/ui/BrandWord';

export function Footer() {
  return (
    <footer className="footer">
      <div className="container">
        <div className="footer-grid">
          <div>
            <h2 className="footer-brand"><BrandWord /></h2>
            <p className="muted" style={{ maxWidth: 420 }}>
              Deployment safety gate for AI agents. Scan risky behavior, prove attack paths, generate fix previews, and block unsafe releases.
            </p>
          </div>
          <div>
            <div className="footer-title">Product</div>
            <Link className="footer-link" href="/scanner">Scanner</Link>
            <Link className="footer-link" href="/report/current">Report workspace</Link>
            <Link className="footer-link" href="/compare">Compare</Link>
            <Link className="footer-link" href="/methodology">Methodology</Link>
            <Link className="footer-link" href="/about">About</Link>
          </div>
          <div>
            <div className="footer-title">System</div>
            <a className="footer-link" href="https://adapt-3s27.onrender.com/docs" target="_blank" rel="noreferrer">API docs</a>
            <a className="footer-link" href="https://github.com/Dhruvg334/a-dap-t" target="_blank" rel="noreferrer">GitHub repo</a>
            <Link className="footer-link" href="/profile">Saved reports</Link>
          </div>
        </div>
        <div className="footer-bottom">
          <span>Scan → Prove → Patch → Gate</span>
          <span>Rule-based verdict. AI explains only.</span>
        </div>
      </div>
    </footer>
  );
}
