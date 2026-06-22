'use client';

import { FormEvent, ReactNode, useState } from 'react';
import { useRouter } from 'next/navigation';
import type { ScanReport } from '@/types/scan';
import { apiFetch, formatApiError } from '@/lib/api';
import { AuthGate } from '@/components/auth/AuthGate';
import { BrandWord } from '@/components/ui/BrandWord';
import { saveCurrentReport } from '@/lib/report-storage';

type ScanMode = 'vulnerable' | 'secured' | 'github' | 'zip';

function Icon({ type }: { type: ScanMode }) {
  const common = { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 1.8, strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const };
  if (type === 'vulnerable') return <svg {...common}><path d="M12 3 2.8 20h18.4L12 3Z" /><path d="M12 9v5" /><path d="M12 17.2h.01" /></svg>;
  if (type === 'secured') return <svg {...common}><path d="M12 3.4 19.5 6v5.6c0 4.8-2.9 8.2-7.5 10-4.6-1.8-7.5-5.2-7.5-10V6L12 3.4Z" /><path d="m8.8 12.3 2.1 2.1 4.4-4.7" /></svg>;
  if (type === 'github') return <svg {...common}><path d="M9 19c-4 1.2-4-2-5.6-2.4" /><path d="M15 22v-3.6a3.2 3.2 0 0 0-.9-2.5c3-.3 6.1-1.5 6.1-6.6a5.1 5.1 0 0 0-1.4-3.6 4.8 4.8 0 0 0-.1-3.5s-1.1-.3-3.6 1.4a12.4 12.4 0 0 0-6.6 0C6 1.9 4.9 2.2 4.9 2.2a4.8 4.8 0 0 0-.1 3.5 5.1 5.1 0 0 0-1.4 3.6c0 5.1 3.1 6.3 6.1 6.6a3.2 3.2 0 0 0-.9 2.5V22" /></svg>;
  return <svg {...common}><path d="M12 3v12" /><path d="m7 8 5-5 5 5" /><path d="M5 15v4a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-4" /></svg>;
}

const scanOptions: Array<{ id: ScanMode; label: string; title: string; body: string; meta: string }> = [
  { id: 'vulnerable', label: 'Intentionally vulnerable', title: 'Vulnerable demo agent', body: 'Fastest V2 walkthrough: unsafe tools, proof paths, generated fixes, and blocked deployment.', meta: 'Best starting point' },
  { id: 'secured', label: 'Hardened demo', title: 'Secured demo agent', body: 'Run the safer baseline and compare how guardrails change the deployment verdict.', meta: 'Safer baseline' },
  { id: 'github', label: 'Public repository', title: 'GitHub repo scan', body: 'Paste a public GitHub repository URL. Code is downloaded as ZIP and read as text only.', meta: 'No code execution' },
  { id: 'zip', label: 'Upload project', title: 'ZIP upload', body: 'Upload a project ZIP with safe extraction limits for local or private demos.', meta: '20 MB / 300 files' },
];

export default function ScannerPage() {
  const router = useRouter();
  const [mode, setMode] = useState<ScanMode>('vulnerable');
  const [repoUrl, setRepoUrl] = useState('https://github.com/Dhruvg334/closira-smb-support-agent');
  const [branch, setBranch] = useState('main');
  const [zipFile, setZipFile] = useState<File | null>(null);
  const [saveReport, setSaveReport] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [progressText, setProgressText] = useState('');

  async function runScan(event?: FormEvent) {
    event?.preventDefault();
    setError('');
    setLoading(true);
    setProgressText('Preparing scan request...');

    try {
      let report: ScanReport;
      if (mode === 'vulnerable') {
        setProgressText('Running vulnerable demo scan...');
        report = await apiFetch<ScanReport>(`/scan/demo/vulnerable?save_report=${saveReport}`);
      } else if (mode === 'secured') {
        setProgressText('Running secured demo scan...');
        report = await apiFetch<ScanReport>(`/scan/demo/secured?save_report=${saveReport}`);
      } else if (mode === 'github') {
        setProgressText('Downloading and scanning GitHub repository...');
        report = await apiFetch<ScanReport>('/scan/github', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ repo_url: repoUrl, branch, save_report: saveReport }),
        });
      } else {
        if (!zipFile) throw new Error('Select a ZIP file first.');
        const formData = new FormData();
        formData.append('file', zipFile);
        formData.append('save_report', String(saveReport));
        setProgressText('Uploading and scanning ZIP project...');
        report = await apiFetch<ScanReport>('/scan/upload', { method: 'POST', body: formData });
      }
      setProgressText('Building V2 report workspace...');
      saveCurrentReport(report);

      if (typeof pendo !== 'undefined') {
        pendo.track('scan_completed', {
          scan_mode: mode,
          project_name: report.project_name || report.repo_name || '',
          safety_score: Number(report.safety_score ?? 0),
          gate_decision: report.deployment_gate?.decision || '',
          findings_count: report.findings?.length || 0,
          critical_count: report.summary?.critical || 0,
          high_count: report.summary?.high || 0,
          attack_simulations_count: report.attack_simulations?.length || 0,
          patches_count: report.patches?.length || 0,
          blockers_count: report.deployment_gate?.blockers?.length || 0,
          save_report_enabled: saveReport,
          scan_type: report.scan_type || mode,
          repo_url: mode === 'github' ? repoUrl : '',
          repo_branch: mode === 'github' ? branch : '',
        });
      }

      router.push('/report/current');
    } catch (err) {
      if (typeof pendo !== 'undefined') {
        pendo.track('scan_failed', {
          scan_mode: mode,
          error_message: String(err instanceof Error ? err.message : err).substring(0, 200),
          error_type: err instanceof Error ? err.name : 'unknown',
        });
      }
      setError(formatApiError(err, 'Scan failed. Check the scan target and try again.'));
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthGate nextPath="/scanner" label="Checking access before opening the scan launcher...">
      <main className="page-shell">
      <div className="container">
        <div className="page-head centered">
          <div>
            <div className="tech-label page-kicker"><span className="pulse-dot" /> SCAN LAUNCHER</div>
            <h1 className="page-title">Choose your scan target.</h1>
          </div>
          <p className="page-desc">Run built-in demo agents, scan a public GitHub repository, or upload a project ZIP. <BrandWord /> reads source files as text and does not execute project code.</p>
          <button className="btn btn-primary" onClick={() => runScan()} disabled={loading}>{loading ? 'Scanning...' : 'Run Scan'}</button>
        </div>

        {error && <div className="form-error" style={{ marginBottom: 18 }}>{error}</div>}
        {loading && <div className="form-success" style={{ marginBottom: 18 }}>{progressText || 'Scanning...'}</div>}

        <section className="scan-grid">
          {scanOptions.map((option) => (
            <button key={option.id} className={`glass-card scan-card ${mode === option.id ? 'active shimmer' : ''}`} type="button" onClick={() => setMode(option.id)}>
              <div>
                <div className="scan-icon"><Icon type={option.id} /></div>
                <h3>{option.title}</h3>
                <p>{option.body}</p>
              </div>
              <div className="scan-footer">
                <span className="pill neutral">{option.label}</span>
                <span className="faint">{option.meta}</span>
              </div>
            </button>
          ))}
        </section>

        <form className="glass-card panel" style={{ marginTop: 18 }} onSubmit={runScan}>
          <div className="panel-head">
            <div>
              <div className="panel-label">Scan configuration</div>
              <h2 className="panel-title">{scanOptions.find((option) => option.id === mode)?.title}</h2>
            </div>
            <label className="pill neutral" style={{ cursor: 'pointer' }}>
              <input type="checkbox" checked={saveReport} onChange={(e) => setSaveReport(e.target.checked)} style={{ marginRight: 8 }} /> Save report
            </label>
          </div>

          {mode === 'github' && (
            <div className="grid grid-2">
              <label className="form-row"><span className="form-label">Repository URL</span><input className="input" value={repoUrl} onChange={(e) => setRepoUrl(e.target.value)} placeholder="https://github.com/user/repo" /></label>
              <label className="form-row"><span className="form-label">Branch</span><input className="input" value={branch} onChange={(e) => setBranch(e.target.value)} placeholder="main" /></label>
            </div>
          )}

          {mode === 'zip' && (
            <label className="form-row"><span className="form-label">Project ZIP</span><input className="input" type="file" accept=".zip" onChange={(e) => setZipFile(e.target.files?.[0] || null)} /><span className="faint">ZIP limits are enforced by the backend. Uploaded code is never executed.</span></label>
          )}

          {(mode === 'vulnerable' || mode === 'secured') && (
            <p className="muted">This built-in sample verifies the full V2 loop: score, findings, Prove Mode, patch previews, deployment gate, and DAP.</p>
          )}

          <div style={{ marginTop: 20, display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <button className="btn btn-primary" type="submit" disabled={loading}>{loading ? 'Running scan...' : 'Run Selected Scan'}</button>
            <span className="pill neutral">Scan → Prove → Patch → Gate</span>
          </div>
        </form>
      </div>
      </main>
    </AuthGate>
  );
}
