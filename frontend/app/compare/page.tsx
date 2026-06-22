'use client';

import Link from 'next/link';
import { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, CheckCircle, GitCompareArrows, TrendingUp } from 'lucide-react';
import { AuthGate } from '@/components/auth/AuthGate';
import { apiFetch, formatApiError } from '@/lib/api';
import type { Finding, ScanReport } from '@/types/scan';

const CAT_LABELS: Record<string, string> = {
  prompt_injection: 'Prompt Injection',
  secret_exposure: 'Secret Exposure',
  tool_permission: 'Tool Permission',
  human_approval: 'Human Approval',
  data_exposure: 'Data Exposure',
  auditability: 'Auditability',
};

type ReportSummary = ScanReport & { id?: string; created_at?: string; timestamp?: string };

function reportId(report: ReportSummary) {
  return report.report_id || report.id || '';
}

function reportLabel(report: ReportSummary) {
  const dateValue = report.created_at || report.timestamp;
  const date = dateValue ? new Date(dateValue) : null;
  const labelDate = date && !Number.isNaN(date.getTime()) ? date.toLocaleDateString() : 'saved report';
  return `${report.project_name || 'A-DAP-T scan'} · ${labelDate} · score ${report.safety_score ?? '—'}`;
}

function findingKey(finding: Finding) {
  return [finding.id, finding.category, finding.title, finding.file, finding.line].filter(Boolean).join('::') || finding.title;
}

function severityCount(findings: Finding[], severity: string) {
  return findings.filter((f) => String(f.severity || '').toLowerCase() === severity).length;
}

function deltaClass(value: number) {
  if (value > 0) return 'safe';
  if (value < 0) return 'danger';
  return 'neutral';
}

const trackedComparisonPairs = new Set<string>();

function CompareContent() {
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [beforeId, setBeforeId] = useState('');
  const [afterId, setAfterId] = useState('');
  const [beforeReport, setBeforeReport] = useState<ScanReport | null>(null);
  const [afterReport, setAfterReport] = useState<ScanReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    apiFetch<ReportSummary[]>('/reports')
      .then((data) => setReports(Array.isArray(data) ? data : []))
      .catch((err) => setError(formatApiError(err, 'Could not load saved reports.')));
  }, []);

  useEffect(() => {
    if (!beforeId || !afterId || beforeId === afterId) {
      setBeforeReport(null);
      setAfterReport(null);
      return;
    }

    let cancelled = false;
    setLoading(true);
    setError('');

    Promise.all([
      apiFetch<ScanReport>(`/reports/${encodeURIComponent(beforeId)}`),
      apiFetch<ScanReport>(`/reports/${encodeURIComponent(afterId)}`),
    ])
      .then(([before, after]) => {
        if (cancelled) return;
        setBeforeReport(before);
        setAfterReport(after);

        const pairKey = `${beforeId}::${afterId}`;
        if (typeof pendo !== 'undefined' && !trackedComparisonPairs.has(pairKey)) {
          trackedComparisonPairs.add(pairKey);
          const beforeScore = Number(before.safety_score || 0);
          const afterScore = Number(after.safety_score || 0);
          const scoreDelta = afterScore - beforeScore;
          const beforeFindings = before.findings || [];
          const afterFindings = after.findings || [];
          const afterKeys = new Set(afterFindings.map((f) => findingKey(f)));
          const beforeKeys = new Set(beforeFindings.map((f) => findingKey(f)));
          const fixed = beforeFindings.filter((f) => !afterKeys.has(findingKey(f)));
          const added = afterFindings.filter((f) => !beforeKeys.has(findingKey(f)));

          let verdict = 'No material score change';
          if (scoreDelta > 0) verdict = 'Security posture improved';
          if (scoreDelta < 0) verdict = 'Security posture regressed';

          const catDeltas = Object.keys(CAT_LABELS).map((key) => ({
            key,
            reduction: Number(before.category_scores?.[key] || 0) - Number(after.category_scores?.[key] || 0),
          }));
          const strongest = catDeltas.sort((a, b) => b.reduction - a.reduction)[0];

          pendo.track('report_comparison_completed', {
            before_report_id: beforeId,
            after_report_id: afterId,
            before_score: beforeScore,
            after_score: afterScore,
            score_delta: scoreDelta,
            verdict,
            fixed_findings_count: fixed.length,
            new_findings_count: added.length,
            critical_fixed: severityCount(fixed, 'critical'),
            high_fixed: severityCount(fixed, 'high'),
            critical_added: severityCount(added, 'critical'),
            high_added: severityCount(added, 'high'),
            strongest_reduction_category: strongest?.key || '',
          });
        }
      })
      .catch((err) => {
        if (cancelled) return;
        setError(formatApiError(err, 'Could not compare these reports.'));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => { cancelled = true; };
  }, [beforeId, afterId]);

  const comparison = useMemo(() => {
    if (!beforeReport || !afterReport) return null;

    const beforeScore = Number(beforeReport.safety_score || 0);
    const afterScore = Number(afterReport.safety_score || 0);
    const scoreDelta = afterScore - beforeScore;
    const beforeFindings = beforeReport.findings || [];
    const afterFindings = afterReport.findings || [];
    const afterMap = new Map(afterFindings.map((f) => [findingKey(f), f]));
    const beforeMap = new Map(beforeFindings.map((f) => [findingKey(f), f]));
    const fixed = beforeFindings.filter((f) => !afterMap.has(findingKey(f)));
    const added = afterFindings.filter((f) => !beforeMap.has(findingKey(f)));

    const categoryDeltas = Object.keys(CAT_LABELS).map((key) => {
      const beforeRisk = Number(beforeReport.category_scores?.[key] || 0);
      const afterRisk = Number(afterReport.category_scores?.[key] || 0);
      return {
        key,
        label: CAT_LABELS[key],
        beforeRisk,
        afterRisk,
        riskReduction: beforeRisk - afterRisk,
      };
    });

    const strongestReduction = [...categoryDeltas].sort((a, b) => b.riskReduction - a.riskReduction)[0];
    const criticalFixed = severityCount(fixed, 'critical');
    const highFixed = severityCount(fixed, 'high');
    const criticalAdded = severityCount(added, 'critical');
    const highAdded = severityCount(added, 'high');

    let verdict = 'No material score change';
    if (scoreDelta > 0) verdict = 'Security posture improved';
    if (scoreDelta < 0) verdict = 'Security posture regressed';

    return {
      beforeScore,
      afterScore,
      scoreDelta,
      fixed,
      added,
      criticalFixed,
      highFixed,
      criticalAdded,
      highAdded,
      categoryDeltas,
      strongestReduction,
      verdict,
    };
  }, [beforeReport, afterReport]);

  const hasEnoughReports = reports.length >= 2;
  const sameReportSelected = beforeId && afterId && beforeId === afterId;

  return (
    <main className="page-shell compare-page">
      <div className="container">
        <div className="page-head centered narrow-head">
          <div className="tech-label page-kicker"><span className="pulse-dot" /> RE-SCAN / SCORE DELTA</div>
          <h1 className="page-title">Compare Reports</h1>
          <p className="page-desc">Measure how much safer an agent became after fixes. A higher safety score is better; a lower category risk score is better.</p>
        </div>

        {!hasEnoughReports && (
          <section className="solid-card panel empty-history-card">
            <GitCompareArrows size={34} className="text-emerald" />
            <h2 className="panel-title">Run at least two scans first.</h2>
            <p className="muted">Compare needs a baseline report and a later report. Run the vulnerable and secured demo scans for the cleanest walkthrough.</p>
            <Link className="btn btn-primary" href="/scanner">Run Scans</Link>
          </section>
        )}

        {hasEnoughReports && (
          <section className="solid-card panel compare-selector-card">
            <div className="compare-selector-head">
              <div>
                <div className="panel-label">Report Pair</div>
                <h2 className="panel-title">Choose a baseline and a target.</h2>
              </div>
              <div className="compare-help">Tip: baseline = before fixes, target = after fixes.</div>
            </div>

            <div className="grid grid-2">
              <label className="form-row">
                <span className="form-label">Before Report</span>
                <select className="input" value={beforeId} onChange={(e) => setBeforeId(e.target.value)}>
                  <option value="">Select baseline...</option>
                  {reports.map((report) => {
                    const id = reportId(report);
                    return <option key={id} value={id} disabled={id === afterId}>{reportLabel(report)}</option>;
                  })}
                </select>
              </label>

              <label className="form-row">
                <span className="form-label">After Report</span>
                <select className="input" value={afterId} onChange={(e) => setAfterId(e.target.value)}>
                  <option value="">Select target...</option>
                  {reports.map((report) => {
                    const id = reportId(report);
                    return <option key={id} value={id} disabled={id === beforeId}>{reportLabel(report)}</option>;
                  })}
                </select>
              </label>
            </div>
          </section>
        )}

        {sameReportSelected && <div className="form-error">Select two different reports to compare score movement.</div>}
        {loading && <div className="form-success">Loading full reports for comparison...</div>}
        {error && <div className="form-error">{error}</div>}

        {comparison && beforeReport && afterReport && (
          <div className="compare-results animate-in">
            <section className={`solid-card panel compare-verdict ${deltaClass(comparison.scoreDelta)}`}>
              <div>
                <div className="panel-label">Verdict</div>
                <h2 className="panel-title">{comparison.verdict}</h2>
                <p className="muted">
                  {comparison.scoreDelta > 0 && `Safety score improved by ${comparison.scoreDelta} points. ${comparison.fixed.length} previous findings are no longer present.`}
                  {comparison.scoreDelta < 0 && `Safety score dropped by ${Math.abs(comparison.scoreDelta)} points. Review the newly introduced findings before deploying.`}
                  {comparison.scoreDelta === 0 && 'The safety score did not move. Check fixed and new findings to see what changed under the same score.'}
                </p>
              </div>
              <div className="delta-orb">
                <span>{comparison.scoreDelta >= 0 ? '+' : ''}{comparison.scoreDelta}</span>
                <small>score delta</small>
              </div>
            </section>

            <section className="compare-score-grid">
              <div className="solid-card stat">
                <div className="stat-label">Baseline Score</div>
                <div className="stat-value">{comparison.beforeScore}</div>
              </div>
              <div className="solid-card stat">
                <div className="stat-label">Target Score</div>
                <div className="stat-value">{comparison.afterScore}</div>
              </div>
              <div className="solid-card stat">
                <div className="stat-label">Critical Fixed</div>
                <div className="stat-value text-emerald">{comparison.criticalFixed}</div>
              </div>
              <div className="solid-card stat">
                <div className="stat-label">High Fixed</div>
                <div className="stat-value text-emerald">{comparison.highFixed}</div>
              </div>
            </section>

            {comparison.strongestReduction?.riskReduction > 0 && (
              <section className="solid-card panel compare-highlight">
                <TrendingUp size={20} className="text-emerald" />
                <div>
                  <div className="panel-label">Largest Risk Reduction</div>
                  <strong>{comparison.strongestReduction.label}</strong>
                  <p className="muted">Risk decreased by {comparison.strongestReduction.riskReduction} points in this category.</p>
                </div>
              </section>
            )}

            <section className="solid-card panel compare-category-panel">
              <div className="panel-head">
                <div>
                  <div className="panel-label">Category Movement</div>
                  <h2 className="panel-title">Risk score deltas</h2>
                </div>
                <p className="muted">Positive reduction is good because category scores measure risk.</p>
              </div>
              <div className="compare-category-list">
                {comparison.categoryDeltas.map((item) => (
                  <div className="compare-category-row" key={item.key}>
                    <div>
                      <strong>{item.label}</strong>
                      <span>{item.beforeRisk} → {item.afterRisk}</span>
                    </div>
                    <div className="compare-risk-track" aria-hidden="true">
                      <span style={{ width: `${Math.min(100, Math.max(0, item.beforeRisk))}%` }} />
                      <em style={{ width: `${Math.min(100, Math.max(0, item.afterRisk))}%` }} />
                    </div>
                    <div className={`pill ${item.riskReduction >= 0 ? 'safe' : 'danger'}`}>{item.riskReduction >= 0 ? '-' : '+'}{Math.abs(item.riskReduction)} risk</div>
                  </div>
                ))}
              </div>
            </section>

            <section className="grid grid-2 compare-findings-grid">
              <div className="solid-card panel">
                <div className="panel-head compact">
                  <div>
                    <div className="panel-label">Resolved</div>
                    <h2 className="panel-title">Fixed findings</h2>
                  </div>
                  <CheckCircle size={20} className="text-emerald" />
                </div>
                <FindingList findings={comparison.fixed} empty="No previous findings disappeared between these reports." />
              </div>
              <div className="solid-card panel">
                <div className="panel-head compact">
                  <div>
                    <div className="panel-label">Introduced</div>
                    <h2 className="panel-title">New findings</h2>
                  </div>
                  <AlertTriangle size={20} className="text-red" />
                </div>
                <FindingList findings={comparison.added} empty="No new findings were introduced in the target report." />
              </div>
            </section>
          </div>
        )}
      </div>
    </main>
  );
}

function FindingList({ findings, empty }: { findings: Finding[]; empty: string }) {
  if (!findings.length) return <p className="muted empty-list-copy">{empty}</p>;
  return (
    <div className="compare-finding-list">
      {findings.slice(0, 8).map((finding, index) => (
        <div className="compare-finding-card" key={`${findingKey(finding)}-${index}`}>
          <div>
            <strong>{finding.title || 'Untitled finding'}</strong>
            <span>{finding.category || 'Uncategorized'}</span>
          </div>
          <div className="pill neutral">{String(finding.severity || 'info').toUpperCase()}</div>
        </div>
      ))}
      {findings.length > 8 && <p className="muted">+{findings.length - 8} more findings not shown here.</p>}
    </div>
  );
}

export default function ComparePage() {
  return (
    <AuthGate nextPath="/compare" label="Checking access before comparing reports...">
      <CompareContent />
    </AuthGate>
  );
}
