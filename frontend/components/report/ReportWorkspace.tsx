'use client';

import { useState } from 'react';
import type { AttackSimulation, PatchPreview, ScanReport } from '@/types/scan';
import { categoryName, gateClass, severityClass, severityLabel } from '@/lib/score';
import { copyText, downloadText } from '@/lib/api';
import { DapPanel } from '@/components/dap/DapPanel';

function riskFillStyle(value: number): string {
  const score = Math.max(0, Math.min(100, Number(value) || 0));
  if (score <= 39) return 'linear-gradient(90deg, #10b981 0%, #34d399 100%)';
  if (score <= 69) return 'linear-gradient(90deg, #10b981 0%, #f59e0b 100%)';
  return 'linear-gradient(90deg, #10b981 0%, #f59e0b 58%, #ef4444 100%)';
}

function gateLabel(decision?: string): string {
  const clean = String(decision || 'REVIEW').toUpperCase();
  if (clean === 'BLOCK') return 'BLOCKED';
  if (clean === 'ALLOW') return 'ALLOWED';
  return 'REVIEW';
}

function blockerCount(report: ScanReport): number {
  return report.deployment_gate?.blockers?.length || 0;
}

export function ReportWorkspace({ report }: { report: ScanReport }) {
  const gate = report.deployment_gate || null;
  const summary = report.summary || {};
  const findings = report.findings || [];
  const attacks = report.attack_simulations || [];
  const patches = report.patches || [];
  const categories = report.category_scores || {};

  const projectName = report.project_name || report.repo_name || 'Current scan';
  const score = Number(report.safety_score ?? 0);
  const gateDecision = gate?.decision || (score >= 80 ? 'ALLOW' : score >= 60 ? 'REVIEW' : 'BLOCK');
  const blockers = blockerCount(report);

  return (
    <main className="page-shell report-page-shell">
      <div className="container report-container">
        <div className="page-head centered report-hero-head">
          <div>
            <div className="tech-label page-kicker"><span className="pulse-dot" /> V2 REPORT WORKSPACE</div>
            <h1 className="page-title">Deployment<br />verdict.</h1>
            <p className="page-desc">Review score, policy blockers, findings, static proof paths, generated patch previews, and deployment gate output in one report workspace.</p>
          </div>
          <div className="report-export-actions">
            <button className="btn btn-secondary" onClick={() => {
              if (typeof pendo !== 'undefined') {
                pendo.track('report_json_downloaded', {
                  project_name: projectName,
                  safety_score: score,
                  gate_decision: gateDecision,
                  findings_count: findings.length,
                  file_format: 'json',
                });
              }
              downloadText(`${projectName}-report.json`, JSON.stringify(report, null, 2), 'application/json');
            }}>Download JSON</button>
            <button className="btn btn-primary" onClick={() => {
              if (typeof pendo !== 'undefined') {
                pendo.track('report_pdf_exported', {
                  project_name: projectName,
                  safety_score: score,
                  gate_decision: gateDecision,
                  findings_count: findings.length,
                });
              }
              window.print();
            }}>Export PDF</button>
          </div>
        </div>

        <section className="stat-grid report-stat-grid">
          <div className="glass-card stat shimmer">
            <div className="stat-value">{score}</div>
            <div className="stat-label">Safety Score</div>
          </div>
          <div className="glass-card stat">
            <div className="stat-value text">{gateLabel(gateDecision)}</div>
            <div className="stat-label">Deployment Gate</div>
          </div>
          <div className="glass-card stat">
            <div className="stat-value">{summary.critical ?? 0}</div>
            <div className="stat-label">Critical</div>
          </div>
          <div className="glass-card stat">
            <div className="stat-value">{blockers}</div>
            <div className="stat-label">Policy Blockers</div>
          </div>
        </section>

        <div className="report-stack">
          <ExecutiveVerdict report={report} />
          <CategoryPanel categories={categories} />
          <FindingsPanel findings={findings} />
          <AttackPanel attacks={attacks} />
          <PatchPanel patches={patches} />
          <DeploymentGatePanel gate={gate} score={score} />
        </div>

        <DapPanel report={report} />
      </div>
    </main>
  );
}

function ExecutiveVerdict({ report }: { report: ScanReport }) {
  const gate = report.deployment_gate;
  const decision = gate?.decision || 'REVIEW';
  const minimum = gate?.minimum_safety_score ?? 75;
  const score = Number(report.safety_score ?? gate?.gate_score ?? 0);
  const blockers = gate?.blockers || [];
  const scorePasses = score >= minimum;
  const isBlocked = String(decision).toUpperCase() === 'BLOCK';

  let verdictText = gate?.summary || report.ai_report_summary || report.ai_summary || 'A-DAP-T generated a deterministic risk report for this agent.';
  if (isBlocked && scorePasses && blockers.length) {
    verdictText = `Score gate passed (${score}/${minimum}), but deployment is blocked because ${blockers.length} mandatory policy blocker${blockers.length === 1 ? '' : 's'} failed.`;
  }

  return (
    <section className="glass-card panel shimmer executive-verdict-card">
      <div className="panel-head report-panel-head">
        <div>
          <div className="panel-label">Executive verdict</div>
          <h2 className="panel-title">Can this agent ship?</h2>
        </div>
        <span className={`pill ${gateClass(decision)}`}>{gate?.decision_badge || gateLabel(decision)}</span>
      </div>
      <p className="muted verdict-copy">{verdictText}</p>
      {isBlocked && scorePasses && blockers.length ? <p className="faint">This is expected gate behavior: a high score does not override required approval, audit, or tool-safety controls.</p> : null}
      {!isBlocked && gate?.decision_reason ? <p className="faint">{gate.decision_reason}</p> : null}
      {gate?.required_action && <p><strong>Required action:</strong> <span className="muted">{gate.required_action}</span></p>}
    </section>
  );
}

function CategoryPanel({ categories }: { categories: Record<string, number> }) {
  const entries = Object.entries(categories);
  if (!entries.length) return null;

  return (
    <section className="glass-card panel report-panel-card">
      <div className="panel-head report-panel-head">
        <div>
          <div className="panel-label">Category risk scoring</div>
          <h2 className="panel-title">Where the risk is concentrated.</h2>
        </div>
        <span className="pill neutral">Higher is worse</span>
      </div>
      {entries.map(([key, value]) => (
        <div className="category-row" key={key}>
          <div className="category-name">{categoryName(key)}</div>
          <div className="risk-bar"><div className="risk-fill" style={{ width: `${Math.min(100, Math.max(0, Number(value)))}%`, background: riskFillStyle(Number(value)) }} /></div>
          <div className="faint">{value}</div>
        </div>
      ))}
    </section>
  );
}

function FindingsPanel({ findings }: { findings: ScanReport['findings'] }) {
  if (!findings?.length) return null;

  return (
    <section className="report-section">
      <div className="panel-head report-section-head">
        <div>
          <div className="panel-label">Findings</div>
          <h2 className="section-title">What needs attention.</h2>
        </div>
      </div>
      <div className="grid report-finding-grid">
        {findings.map((finding, index) => (
          <article className="glass-card finding-card report-finding-card" key={finding.id || `${finding.title}-${index}`}>
            <div className="finding-title-row report-card-heading">
              <div className="report-card-copy">
                <div className="report-pill-row">
                  <span className={`pill ${severityClass(finding.severity)}`}>{severityLabel(finding.severity)}</span>
                  {finding.category && <span className="pill neutral">{finding.category}</span>}
                  {finding.id && <span className="pill neutral">{finding.id}</span>}
                </div>
                <h3 className="finding-title">{finding.title || 'Untitled finding'}</h3>
                <p className="muted">{finding.description || finding.why_it_matters}</p>
              </div>
              <span className="faint path-label">{finding.file}{finding.line ? `:${finding.line}` : ''}</span>
            </div>
            {finding.evidence && <pre className="code-block">{finding.evidence}</pre>}
            {finding.suggested_fix && <p><strong>Suggested fix:</strong> <span className="muted">{finding.suggested_fix}</span></p>}
          </article>
        ))}
      </div>
    </section>
  );
}

function AttackPanel({ attacks }: { attacks: AttackSimulation[] }) {
  if (!attacks.length) return null;
  return (
    <section className="report-section">
      <div className="panel-head report-section-head">
        <div>
          <div className="panel-label">Prove Mode</div>
          <h2 className="section-title">Static attack paths.</h2>
        </div>
        <span className="pill warning">No live exploit</span>
      </div>
      <div className="report-attack-grid">
        {attacks.slice(0, 8).map((attack, index) => <AttackCard key={`${attack.finding_id}-${index}`} attack={attack} />)}
      </div>
    </section>
  );
}

function AttackCard({ attack }: { attack: AttackSimulation }) {
  const path = attack.location || attack.file || 'Project path unavailable';
  return (
    <article className="glass-card artifact-card attack-path-card">
      <div className="attack-card-head">
        <div className="report-card-copy">
          <div className="report-pill-row">
            <span className="pill danger">{attack.simulation_type || attack.risk_level || 'attack path'}</span>
            {attack.priority_score ? <span className="pill neutral">priority {attack.priority_score}</span> : null}
          </div>
          <h3>{attack.title || 'Static attack simulation'}</h3>
        </div>
        <span className="path-label">{path}</span>
      </div>
      <p className="muted"><strong>Goal:</strong> {attack.attack_goal || 'Demonstrate a plausible risky path without executing the target project.'}</p>
      {attack.malicious_input && <pre className="code-block attack-input">{attack.malicious_input}</pre>}
      {attack.attack_steps?.length ? <ol className="list-clean attack-steps">{attack.attack_steps.map((step, i) => <li key={i}>{step}</li>)}</ol> : null}
      {attack.detection_signal && <p className="faint"><strong>Detection signal:</strong> {attack.detection_signal}</p>}
      {attack.guardrail && <p><strong>Guardrail:</strong> <span className="muted">{attack.guardrail}</span></p>}
    </article>
  );
}

function PatchPanel({ patches }: { patches: PatchPreview[] }) {
  const [openId, setOpenId] = useState<string | null>(null);
  if (!patches.length) return null;

  return (
    <section className="report-section">
      <div className="panel-head report-section-head">
        <div>
          <div className="panel-label">Generated fixes</div>
          <h2 className="section-title">Patch previews.</h2>
        </div>
        <span className="pill neutral">Preview only</span>
      </div>
      <div className="grid report-patch-grid">
        {patches.slice(0, 8).map((patch, index) => {
          const id = patch.finding_id || `${patch.title}-${index}`;
          const isOpen = openId === id;
          return (
            <article className="glass-card artifact-card report-patch-card" key={id}>
              <div className="finding-title-row report-card-heading">
                <div className="report-card-copy">
                  <div className="report-pill-row">
                    <span className="pill safe">{patch.patch_type || 'patch'}</span>
                    {patch.estimated_effort && <span className="pill neutral">{patch.estimated_effort} effort</span>}
                  </div>
                  <h3 className="finding-title">{patch.title || 'Generated patch preview'}</h3>
                  <p className="muted">{patch.risk_reduction || patch.explanation}</p>
                </div>
                <div className="patch-action-row">
                  <button className="btn btn-secondary btn-small" onClick={() => setOpenId(isOpen ? null : id)}>{isOpen ? 'Hide diff' : 'View diff'}</button>
                  <button className="btn btn-secondary btn-small" onClick={() => {
                    if (typeof pendo !== 'undefined') {
                      pendo.track('patch_diff_copied', {
                        finding_id: patch.finding_id || '',
                        patch_type: patch.patch_type || '',
                        patch_title: (patch.title || '').substring(0, 100),
                        estimated_effort: patch.estimated_effort || '',
                        risk_reduction: patch.risk_reduction || '',
                        confidence: patch.confidence || '',
                      });
                    }
                    copyText(patch.diff || '');
                  }}>Copy</button>
                  <button className="btn btn-primary btn-small" onClick={() => {
                    if (typeof pendo !== 'undefined') {
                      pendo.track('patch_downloaded', {
                        finding_id: patch.finding_id || '',
                        patch_filename: patch.patch_filename || 'adapt.patch',
                        patch_type: patch.patch_type || '',
                        patch_title: (patch.title || '').substring(0, 100),
                        estimated_effort: patch.estimated_effort || '',
                        risk_reduction: patch.risk_reduction || '',
                        confidence: patch.confidence || '',
                      });
                    }
                    downloadText(patch.patch_filename || 'adapt.patch', patch.diff || '');
                  }}>Download</button>
                </div>
              </div>
              {isOpen && <pre className="code-block">{patch.diff || 'No diff provided.'}</pre>}
              {patch.validation_steps?.length ? <ul className="list-clean">{patch.validation_steps.map((step, i) => <li key={i}>{step}</li>)}</ul> : null}
            </article>
          );
        })}
      </div>
    </section>
  );
}

function DeploymentGatePanel({ gate, score }: { gate: ScanReport['deployment_gate']; score: number }) {
  if (!gate) return null;
  const workflow = gate.github_actions_yaml || '';
  const policy = gate.policy_json || JSON.stringify(gate.recommended_policy || {}, null, 2);
  const minimum = gate.minimum_safety_score ?? 75;
  const scorePasses = score >= minimum;
  return (
    <section className="glass-card panel shimmer deployment-gate-panel">
      <div className="panel-head report-panel-head">
        <div>
          <div className="panel-label">Deployment gate</div>
          <h2 className="panel-title">Block unsafe releases.</h2>
        </div>
        <span className={`pill ${gateClass(gate.decision)}`}>{gate.decision_badge || gateLabel(gate.decision)}</span>
      </div>
      <div className="gate-summary-strip">
        <div><span>Score gate</span><strong className={scorePasses ? 'text-emerald' : 'text-red'}>{scorePasses ? 'Passed' : 'Failed'}</strong></div>
        <div><span>Gate score</span><strong>{gate.gate_score ?? score}</strong></div>
        <div><span>Minimum</span><strong>{minimum}</strong></div>
        <div><span>Policy blockers</span><strong>{gate.blockers?.length || 0}</strong></div>
      </div>
      <div className="grid grid-2 gate-detail-grid">
        <div>
          {gate.blockers?.length ? <ul className="list-clean">{gate.blockers.map((b, i) => <li key={i}>{b}</li>)}</ul> : <p className="muted">No hard policy blockers were returned by the gate.</p>}
        </div>
        <div>
          {gate.next_actions?.length ? <ul className="list-clean">{gate.next_actions.map((a, i) => <li key={i}>{a}</li>)}</ul> : null}
          <div className="gate-action-row">
            <button className="btn btn-secondary btn-small" onClick={() => {
              if (typeof pendo !== 'undefined') {
                pendo.track('gate_workflow_copied', {
                  gate_decision: gate.decision || '',
                  safety_score: score,
                  minimum_safety_score: minimum,
                  blockers_count: gate.blockers?.length || 0,
                });
              }
              copyText(workflow);
            }}>Copy workflow</button>
            <button className="btn btn-secondary btn-small" onClick={() => {
              if (typeof pendo !== 'undefined') {
                pendo.track('gate_workflow_downloaded', {
                  gate_decision: gate.decision || '',
                  safety_score: score,
                  minimum_safety_score: minimum,
                  blockers_count: gate.blockers?.length || 0,
                  workflow_filename: gate.workflow_filename || 'adapt-safety-gate.yml',
                });
              }
              downloadText(gate.workflow_filename || 'adapt-safety-gate.yml', workflow, 'text/yaml');
            }}>Download workflow</button>
            <button className="btn btn-primary btn-small" onClick={() => {
              if (typeof pendo !== 'undefined') {
                pendo.track('gate_policy_downloaded', {
                  gate_decision: gate.decision || '',
                  safety_score: score,
                  minimum_safety_score: minimum,
                  blockers_count: gate.blockers?.length || 0,
                  policy_filename: gate.policy_filename || 'adapt-policy.json',
                });
              }
              downloadText(gate.policy_filename || 'adapt-policy.json', policy, 'application/json');
            }}>Download policy</button>
          </div>
        </div>
      </div>
    </section>
  );
}
