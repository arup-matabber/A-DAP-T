'use client';

import { BrandWord } from '@/components/ui/BrandWord';
import { Users, Target, Zap, PlayCircle, ShieldCheck } from 'lucide-react';

const people = [
  {
    name: 'Dhruv Gupta',
    role: 'Product direction · backend integration · AI safety workflow',
    body: 'Led A-DAP-T’s product direction, V2 backend upgrades, report artifacts, DAP behavior, deployment gate flow, and final integration quality.'
  },
  {
    name: 'Pavit Agrawal',
    role: 'Score delta · report comparison · project engineering',
    body: 'Owns the report comparison and re-scan improvement flow so users can measure how safety changes after fixes.'
  },
  {
    name: 'Akshhaya Isa',
    role: 'Frontend development · UI implementation support',
    body: 'Supports the frontend migration and page implementation work for the upgraded A-DAP-T experience.'
  }
];

export default function AboutPage() {
  // Hardcoded YouTube ID for the A-DAP-T Website Demo as per user instruction
  const videoId = "1r-QIjQmbbo";

  return (
    <main className="page-shell">
      <div className="container">
        <div className="page-head centered">
          <div>
            <div className="tech-label page-kicker"><span className="pulse-dot" /> ABOUT</div>
            <h1 className="page-title">Built for agents that can act.</h1>
          </div>
          <p className="page-desc"><BrandWord /> started as an AI-agent risk scanner and is now moving toward a deployment safety gate: scan, prove, patch, re-scan, and gate unsafe releases before they ship.</p>
        </div>

        {/* Hardcoded YouTube Video Section - Platform Guide */}
        <section className="glass-card panel shimmer" style={{ marginBottom: 48, padding: '40px' }}>
          <div className="panel-head" style={{ marginBottom: 24 }}>
            <div>
              <div className="panel-label">PLATFORM GUIDE</div>
              <h2 className="panel-title">A-DAP-T Website Demo</h2>
            </div>
            <div className="pill safe" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <PlayCircle size={12} /> VIDEO GUIDE
            </div>
          </div>

          <div style={{ maxWidth: '960px', margin: '0 auto' }}>
            <div style={{
              background: '#000',
              borderRadius: 24,
              overflow: 'hidden',
              aspectRatio: '16/9',
              border: '1px solid var(--border)',
              boxShadow: '0 25px 60px rgba(0,0,0,0.6)',
              position: 'relative'
            }}>
              <iframe
                width="100%"
                height="100%"
                src={`https://www.youtube.com/embed/${videoId}?rel=0&modestbranding=1`}
                title="A-DAP-T Website Demo"
                frameBorder="0"
                allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share"
                allowFullScreen
              ></iframe>
            </div>
            <div style={{ marginTop: 28, display: 'flex', justifyContent: 'center' }}>
               <div className="notice" style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '12px 20px', borderRadius: '99px' }}>
                 <ShieldCheck size={16} className="text-emerald" />
                 <span style={{ fontSize: '13px' }}>Watch this guide to master the pre-deployment security workflow.</span>
               </div>
            </div>
          </div>
        </section>

        <section className="grid grid-3" style={{ marginBottom: 32 }}>
          <article className="glass-card panel">
            <div className="panel-label"><Target size={12} style={{marginRight: 6}} /> Mission</div>
            <h2 className="panel-title">Make agent risk visible.</h2>
            <p className="muted">AI agents now call tools, touch records, and trigger workflow actions. <BrandWord /> helps teams see risky paths before deployment.</p>
          </article>
          <article className="glass-card panel">
            <div className="panel-label"><Zap size={12} style={{marginRight: 6}} /> Approach</div>
            <h2 className="panel-title">Deterministic first.</h2>
            <p className="muted">The scanner owns findings, scoring, patches, and gate decisions. AI only explains the report and helps users understand what to fix.</p>
          </article>
          <article className="glass-card panel">
            <div className="panel-label"><Users size={12} style={{marginRight: 6}} /> Scalability</div>
            <h2 className="panel-title">Enterprise Ready.</h2>
            <p className="muted">Built to handle complex monorepos, multiple project directories, and integrated CI/CD workflows for automated safety gating.</p>
          </article>
        </section>

        <section className="glass-card panel" style={{ marginBottom: 32 }}>
          <div className="panel-head">
            <div>
              <div className="panel-label">Developer introductions</div>
              <h2 className="panel-title">Team behind the build.</h2>
            </div>
            <span className="pill neutral"><BrandWord /> V2</span>
          </div>
          <div className="grid grid-3">
            {people.map((person) => (
              <article className="solid-card panel" key={person.name}>
                <div className="profile-avatar" style={{ marginBottom: 14 }}>{person.name.split(' ').map((part) => part[0]).join('')}</div>
                <h3 className="panel-title">{person.name}</h3>
                <p className="faint" style={{ margin: '8px 0 12px', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{person.role}</p>
                <p className="muted" style={{ fontSize: '13px' }}>{person.body}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="glass-card panel centered" style={{ padding: '48px 22px' }}>
          <div className="tech-label"><span className="pulse-dot" /> PRODUCT LOOP</div>
          <h2 className="section-title" style={{ margin: '14px auto 16px' }}>Scan. Prove. Patch. Gate.</h2>
          <p className="page-desc" style={{ margin: '0 auto', maxWidth: '700px' }}>The goal is not to replace security audits. The goal is to catch common AI-agent deployment risks earlier and make the first review sharper.</p>
        </section>
      </div>

      <style jsx>{`
        h3 { font-family: Newsreader, serif; }
        .text-emerald { color: var(--emerald); }
      `}</style>
    </main>
  );
}
