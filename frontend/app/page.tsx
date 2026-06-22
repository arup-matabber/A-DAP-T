import Link from 'next/link';
import { BrandWord } from '@/components/ui/BrandWord';

const features = [
  {
    label: '01_PROVE',
    title: 'Prove risky paths',
    body: 'Static simulations show what can go wrong, the preconditions, the trigger, and the guardrail needed to stop it.'
  },
  {
    label: '02_PATCH',
    title: 'Generate fix previews',
    body: 'Patch cards include diffs, risk reduction, effort, and validation steps. Developers stay in control.'
  },
  {
    label: '03_GATE',
    title: 'Block unsafe releases',
    body: 'Deployment gate output gives BLOCK, REVIEW, or ALLOW with CI workflow and policy JSON artifacts.'
  }
];

function MiniRisk({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <div className="mock-risk">
      <span>{label}</span>
      <div className="risk-bar"><div className="risk-fill" style={{ width: `${value}%`, background: tone }} /></div>
      <strong>{value}</strong>
    </div>
  );
}

export default function HomePage() {
  return (
    <main>
      <section className="hero">
        <video className="hero-video" autoPlay muted loop playsInline preload="auto" poster="/gradient.png" aria-hidden="true">
          <source src="/hero-bg.mp4" type="video/mp4" />
        </video>
        <div className="container hero-grid">
          <div className="hero-copy">
            <div className="tech-label"><span className="pulse-dot" /> AGENT DEPLOYMENT GATE</div>
            <h1 className="display-title">Scan AI agents<br />before they <em>ship.</em></h1>
            <p>
              <BrandWord /> checks agent code, tools, secrets, approval gates, and audit trails — then proves risky paths, generates patch previews, and blocks unsafe deployments before release.
            </p>
            <div className="hero-actions">
              <Link className="btn btn-primary" href="/scanner">Start Scanning</Link>
              <Link className="btn btn-secondary" href="/methodology">View Methodology</Link>
            </div>
            <div className="hero-meta">
              <span className="meta-item">Rule-based verdict</span>
              <span className="meta-item">Gemini explains only</span>
              <span className="meta-item">No code execution</span>
            </div>
          </div>

          <div className="glass-card shimmer mockup">
            <div className="mock-window">
              <div className="window-dots"><span className="dot-red" /><span className="dot-yellow" /><span className="dot-green" /></div>
              <div className="tech-label">LIVE SCAN OUTPUT</div>
              <div className="mock-dashboard">
                <div className="mock-main">
                  <div>
                    <div className="mock-score">32</div>
                    <p className="mock-score-caption">Safety score</p>
                  </div>
                  <div>
                    <strong>Vulnerable support agent</strong>
                    <p className="faint" style={{ margin: '4px 0 0' }}>13 findings · 8 proof paths · 8 patches</p>
                  </div>
                  <span className="mock-badge block">Blocked</span>
                </div>

                <div className="mock-metrics">
                  <div className="mock-metric"><span className="panel-label">Prove</span><strong>8</strong><span className="faint">paths</span></div>
                  <div className="mock-metric"><span className="panel-label">Patch</span><strong>8</strong><span className="faint">fixes</span></div>
                  <div className="mock-metric"><span className="panel-label">Gate</span><strong>BLOCK</strong><span className="faint">CI</span></div>
                </div>

                <div className="mock-risk-list">
                  <MiniRisk label="Secret exposure" value={65} tone="linear-gradient(90deg, #10b981, #f59e0b)" />
                  <MiniRisk label="Tool permission" value={45} tone="linear-gradient(90deg, #10b981, #f59e0b)" />
                  <MiniRisk label="Data exposure" value={65} tone="linear-gradient(90deg, #10b981, #f59e0b)" />
                </div>
                <div className="hero-terminal">
                  <div><span>&gt; adapt scan support-agent</span><strong>completed</strong></div>
                  <div><span>&gt; prove risky paths</span><strong>8 paths</strong></div>
                  <div><span>&gt; generate patches</span><strong>8 previews</strong></div>
                  <div><span>&gt; gate --min-score 75</span><strong className="terminal-danger">blocked</strong></div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="container" style={{ padding: '66px 22px' }}>
        <div className="page-head centered">
          <div>
            <div className="tech-label"><span className="pulse-dot" /> PRODUCT LOOP</div>
            <h2 className="section-title" style={{ marginTop: 14 }}>Scan. Prove. Patch. Gate.</h2>
          </div>
          <p className="page-desc"><BrandWord /> V2 moves from a report into a deployment workflow for AI agents that can act.</p>
        </div>
        <div className="grid grid-3">
          {features.map((feature) => (
            <article className="glass-card panel shimmer" key={feature.label}>
              <div className="panel-label">{feature.label}</div>
              <h3 className="panel-title">{feature.title}</h3>
              <p className="muted">{feature.body}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="container" style={{ padding: '22px 22px 82px' }}>
        <div className="glass-card panel centered" style={{ padding: '40px 22px' }}>
          <div className="tech-label"><span className="pulse-dot" /> READY FOR V2</div>
          <h2 className="section-title" style={{ margin: '14px auto 18px', maxWidth: 820 }}>A deployment gate built for agents that take action.</h2>
          <p className="page-desc" style={{ margin: '0 auto 26px' }}>Run the vulnerable demo, inspect Prove Mode, review patch previews, and copy the generated CI gate workflow.</p>
          <Link className="btn btn-primary" href="/scanner">Run Demo Scan</Link>
        </div>
      </section>
    </main>
  );
}
