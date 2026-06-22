'use client';

import Link from 'next/link';
import { useEffect, useMemo, useState } from 'react';
import dynamic from 'next/dynamic';
import { useRouter } from 'next/navigation';
import { Edit2, FolderPlus, Trash2 } from 'lucide-react';
import { AuthGate } from '@/components/auth/AuthGate';
import { apiFetch, formatApiError } from '@/lib/api';
import { getAuthState } from '@/lib/auth';
import { saveCurrentReport } from '@/lib/report-storage';
import type { ScanReport } from '@/types/scan';


const TrendsChart = dynamic(
  () => import('@/components/profile/TrendsChart').then((module) => module.TrendsChart),
  {
    ssr: false,
    loading: () => <div className="chart-loading">Loading score movement...</div>,
  }
);

type ReportSummary = ScanReport & {
  id?: string;
  created_at?: string;
  timestamp?: string;
  upload_name?: string;
};

type ReportGroup = {
  id: string;
  name: string;
  reportIds: string[];
};

function formatDate(value?: string | null) {
  if (!value) return 'Recently saved';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Recently saved';
  return date.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function getReportId(report: ReportSummary) {
  return report.report_id || report.id || null;
}

function decisionClass(decision?: string) {
  const value = String(decision || '').toUpperCase();
  if (value === 'BLOCK') return 'danger';
  if (value === 'REVIEW') return 'warning';
  if (value === 'ALLOW') return 'safe';
  return 'neutral';
}

function getReportTime(report: ReportSummary) {
  const value = report.created_at || report.timestamp || '';
  const time = new Date(value).getTime();
  return Number.isNaN(time) ? 0 : time;
}

function ProfileContent() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [groups, setGroups] = useState<ReportGroup[]>([]);
  const [activeGroupId, setActiveGroupId] = useState('all');
  const [newGroupName, setNewGroupName] = useState('');
  const [showGroupForm, setShowGroupForm] = useState(false);
  const [openingId, setOpeningId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    const auth = getAuthState();
    setEmail(auth?.email || 'A-DAP-T user');
    const key = `adpt_groups_${auth?.uid || 'anon'}`;
    const rawGroups = localStorage.getItem(key);
    if (rawGroups) {
      try { setGroups(JSON.parse(rawGroups)); } catch { setGroups([]); }
    }

    apiFetch<ReportSummary[]>('/reports')
      .then((data) => setReports(Array.isArray(data) ? data : []))
      .catch((err) => setError(formatApiError(err, 'Could not load saved reports.')))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    const auth = getAuthState();
    if (!auth?.uid) return;
    localStorage.setItem(`adpt_groups_${auth.uid}`, JSON.stringify(groups));
  }, [groups]);

  const sortedReports = useMemo(() => [...reports].sort((a, b) => getReportTime(b) - getReportTime(a)), [reports]);

  const organized = useMemo(() => {
    const groupedIds = new Set(groups.flatMap((group) => group.reportIds));
    const groupedMap: Record<string, ReportSummary[]> = {};
    groups.forEach((group) => {
      groupedMap[group.id] = sortedReports.filter((report) => group.reportIds.includes(getReportId(report) || ''));
    });
    return {
      groupedMap,
      ungrouped: sortedReports.filter((report) => !groupedIds.has(getReportId(report) || '')),
    };
  }, [groups, sortedReports]);

  const chartReports = useMemo(() => {
    if (activeGroupId === 'all') return sortedReports;
    if (activeGroupId === 'ungrouped') return organized.ungrouped;
    return organized.groupedMap[activeGroupId] || [];
  }, [activeGroupId, sortedReports, organized]);

  const latestScore = sortedReports[0]?.safety_score ?? '—';
  const riskyReports = sortedReports.filter((report) => String(report.deployment_gate?.decision || '').toUpperCase() === 'BLOCK').length;

  function createGroup() {
    const name = newGroupName.trim();
    if (!name) return;
    setGroups((current) => {
      const updated = [...current, { id: `group_${Date.now()}`, name, reportIds: [] }];
      if (typeof pendo !== 'undefined') {
        pendo.track('project_group_created', {
          group_name: name,
          total_groups_count: updated.length,
        });
      }
      return updated;
    });
    setNewGroupName('');
    setShowGroupForm(false);
    setNotice(`Project group "${name}" created.`);
  }

  function renameGroup(groupId: string) {
    const group = groups.find((item) => item.id === groupId);
    if (!group) return;
    const next = window.prompt('Rename project group', group.name)?.trim();
    if (!next) return;
    setGroups((current) => current.map((item) => item.id === groupId ? { ...item, name: next } : item));
  }

  function deleteGroup(groupId: string) {
    const group = groups.find((item) => item.id === groupId);
    if (!group) return;
    if (!window.confirm(`Delete project group "${group.name}"? Reports will stay saved and move to Ungrouped.`)) return;
    if (typeof pendo !== 'undefined') {
      pendo.track('project_group_deleted', {
        group_id: groupId,
        group_name: group.name,
        reports_in_group_count: group.reportIds.length,
      });
    }
    setGroups((current) => current.filter((item) => item.id !== groupId));
    if (activeGroupId === groupId) setActiveGroupId('all');
  }

  function moveReport(reportId: string, targetGroupId: string) {
    const targetGroup = groups.find((g) => g.id === targetGroupId);
    if (typeof pendo !== 'undefined') {
      pendo.track('report_moved_to_group', {
        report_id: reportId,
        target_group_id: targetGroupId || '',
        target_group_name: targetGroup?.name || '',
        moved_to_ungrouped: !targetGroupId,
      });
    }
    setGroups((current) => current.map((group) => {
      const withoutReport = group.reportIds.filter((id) => id !== reportId);
      if (targetGroupId && group.id === targetGroupId) return { ...group, reportIds: [...withoutReport, reportId] };
      return { ...group, reportIds: withoutReport };
    }));
    setNotice(targetGroupId ? 'Report moved to project group.' : 'Report moved to Ungrouped.');
  }

  async function openReport(report: ReportSummary) {
    const id = getReportId(report);
    setError(''); setNotice(''); setOpeningId(id || report.project_name || 'report');
    try {
      const fullReport = id ? await apiFetch<ScanReport>(`/reports/${encodeURIComponent(id)}`) : report;
      saveCurrentReport(fullReport);

      if (typeof pendo !== 'undefined') {
        const createdAt = report.created_at || report.timestamp;
        const reportAgeDays = createdAt ? Math.floor((Date.now() - new Date(createdAt).getTime()) / 86400000) : -1;
        pendo.track('report_opened_from_history', {
          report_id: id || '',
          project_name: report.project_name || '',
          scan_type: report.scan_type || '',
          safety_score: Number(report.safety_score ?? 0),
          report_age_days: reportAgeDays,
        });
      }

      router.push('/report/current');
    } catch (err) {
      setError(formatApiError(err, 'Could not open this report.'));
    } finally {
      setOpeningId(null);
    }
  }

  async function deleteReport(report: ReportSummary) {
    const id = getReportId(report);
    if (!id || !window.confirm('Delete this report from saved history?')) return;
    setDeletingId(id);
    setError(''); setNotice('');
    try {
      await apiFetch(`/reports/${encodeURIComponent(id)}`, { method: 'DELETE' });
      if (typeof pendo !== 'undefined') {
        pendo.track('report_deleted', {
          report_id: id,
          project_name: report.project_name || '',
          scan_type: report.scan_type || '',
          safety_score: Number(report.safety_score ?? 0),
        });
      }
      setReports((current) => current.filter((item) => getReportId(item) !== id));
      setGroups((current) => current.map((group) => ({ ...group, reportIds: group.reportIds.filter((reportId) => reportId !== id) })));
      setNotice('Report deleted from saved history.');
    } catch (err) {
      setError(formatApiError(err, 'Could not delete this report.'));
    } finally {
      setDeletingId(null);
    }
  }

  function renderReportCard(report: ReportSummary) {
    const id = getReportId(report);
    const summary = report.summary || {};
    const decision = report.deployment_gate?.decision || report.status;
    return (
      <article className="solid-card report-history-card" key={id || `${report.project_name}-${report.created_at}`}>
        <div className="report-card-topline">
          <span className="pill neutral">{report.scan_type || 'saved scan'}</span>
          <span className={`pill ${decisionClass(decision)}`}>{String(decision || 'SAVED').toUpperCase()}</span>
        </div>
        <div className="report-card-main">
          <div className="report-card-copy">
            <h3 className="panel-title report-card-title">{report.project_name || report.upload_name || 'A-DAP-T Scan'}</h3>
            <p className="muted report-card-source">{report.repo_url || 'Saved report from scan history.'}</p>
          </div>
          <div className="report-score-orb"><strong>{report.safety_score ?? '—'}</strong><span>score</span></div>
        </div>
        <div className="report-card-meta">
          <span>{formatDate(report.created_at || report.timestamp)}</span>
          <span>{summary.critical || 0} critical</span>
          <span>{summary.high || 0} high</span>
        </div>
        <div className="report-card-actions">
          <button className="btn btn-primary btn-small" type="button" onClick={() => openReport(report)} disabled={openingId === id}>
            {openingId === id ? 'Opening...' : 'View Report'}
          </button>
          <select className="input input-compact" value={groups.find((group) => group.reportIds.includes(id || ''))?.id || ''} onChange={(event) => id && moveReport(id, event.target.value)} disabled={!id}>
            <option value="">Ungrouped</option>
            {groups.map((group) => <option key={group.id} value={group.id}>{group.name}</option>)}
          </select>
          <button className="btn btn-danger btn-small" type="button" onClick={() => deleteReport(report)} disabled={deletingId === id}>
            {deletingId === id ? 'Deleting...' : 'Delete'}
          </button>
        </div>
      </article>
    );
  }

  return (
    <main className="page-shell profile-page">
      <div className="container">
        <div className="page-head split profile-headline">
          <div>
            <div className="tech-label page-kicker"><span className="pulse-dot" /> REPORT HISTORY</div>
            <h1 className="page-title">Project workspace.</h1>
            <p className="page-desc">Track saved scans, compare improvements, and organize reports by project before the next deployment review.</p>
          </div>
          <div className="hero-actions">
            <button className="btn btn-secondary" type="button" onClick={() => setShowGroupForm(true)}><FolderPlus size={16} /> New Group</button>
            <Link className="btn btn-primary" href="/scanner">Run Scan</Link>
          </div>
        </div>

        <section className="profile-summary-grid">
          <div className="solid-card stat profile-identity-card"><div className="profile-avatar">DG</div><div><div className="stat-label">Account</div><div className="profile-email">{email}</div></div></div>
          <div className="solid-card stat"><div className="stat-value">{reports.length}</div><div className="stat-label">Saved Reports</div></div>
          <div className="solid-card stat"><div className="stat-value">{latestScore}</div><div className="stat-label">Latest Score</div></div>
          <div className="solid-card stat"><div className="stat-value">{riskyReports}</div><div className="stat-label">Blocked Reports</div></div>
        </section>

        {showGroupForm && (
          <div className="modal-overlay">
            <section className="solid-card panel group-modal">
              <div className="panel-label">Project Group</div>
              <h2 className="panel-title">Create a report group</h2>
              <p className="muted">Groups are local workspace labels for organizing saved reports during review.</p>
              <div className="form-stack">
                <input className="input" placeholder="Production agents, Client demo, Before fixes..." value={newGroupName} onChange={(event) => setNewGroupName(event.target.value)} autoFocus />
                <div className="modal-actions"><button className="btn btn-primary" type="button" onClick={createGroup}>Create Group</button><button className="btn btn-secondary" type="button" onClick={() => setShowGroupForm(false)}>Cancel</button></div>
              </div>
            </section>
          </div>
        )}

        {notice && <div className="form-success">{notice}</div>}
        {error && <div className="form-error">{error}</div>}

        {loading && <section className="solid-card panel empty-history-card"><p className="muted">Loading saved reports...</p></section>}

        {!loading && !reports.length && (
          <section className="solid-card panel empty-history-card">
            <h2 className="panel-title">No saved reports yet.</h2>
            <p className="muted">Run a demo, GitHub, or ZIP scan and save the result. Your reports will appear here for review and comparison.</p>
            <Link className="btn btn-primary" href="/scanner">Open Scanner</Link>
          </section>
        )}

        {!!reports.length && (
          <>
            <section className="solid-card panel profile-trends-panel">
              <div className="panel-head">
                <div>
                  <div className="panel-label">Progress Trend</div>
                  <h2 className="panel-title">Safety score movement</h2>
                </div>
                <select className="input input-compact" value={activeGroupId} onChange={(event) => setActiveGroupId(event.target.value)}>
                  <option value="all">All reports</option>
                  <option value="ungrouped">Ungrouped</option>
                  {groups.map((group) => <option key={group.id} value={group.id}>{group.name}</option>)}
                </select>
              </div>
              <div className="chart-shell"><TrendsChart reports={chartReports} groupBy="none" /></div>
            </section>

            <section className="report-history-section">
              <div className="section-strip">
                <div>
                  <div className="tech-label page-kicker"><span className="pulse-dot" /> SAVED REPORTS</div>
                  <h2 className="section-title compact-title">Recent scan history</h2>
                </div>
                <Link className="btn btn-secondary btn-small" href="/compare">Compare Reports</Link>
              </div>
              <div className="report-grid">{organized.ungrouped.map(renderReportCard)}</div>
            </section>

            {groups.map((group) => (
              <section className="report-history-section" key={group.id}>
                <div className="section-strip">
                  <div>
                    <div className="tech-label page-kicker"><span className="pulse-dot" /> PROJECT GROUP</div>
                    <h2 className="section-title compact-title">{group.name}</h2>
                  </div>
                  <div className="group-actions"><span className="pill neutral">{organized.groupedMap[group.id]?.length || 0} reports</span><button className="btn btn-secondary btn-small" type="button" onClick={() => renameGroup(group.id)}><Edit2 size={13} /> Rename</button><button className="btn btn-danger btn-small" type="button" onClick={() => deleteGroup(group.id)}><Trash2 size={13} /> Delete</button></div>
                </div>
                <div className="report-grid">
                  {(organized.groupedMap[group.id] || []).length ? organized.groupedMap[group.id].map(renderReportCard) : <div className="solid-card panel"><p className="muted">No reports in this group yet.</p></div>}
                </div>
              </section>
            ))}
          </>
        )}
      </div>
    </main>
  );
}

export default function ProfilePage() {
  return (
    <AuthGate nextPath="/profile" label="Checking saved report access...">
      <ProfileContent />
    </AuthGate>
  );
}
