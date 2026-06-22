'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import type { ScanReport } from '@/types/scan';
import { getAuthState } from '@/lib/auth';
import { loadCurrentReport } from '@/lib/report-storage';
import { ReportWorkspace } from '@/components/report/ReportWorkspace';

export default function CurrentReportPage() {
  const router = useRouter();
  const [report, setReport] = useState<ScanReport | null>(null);
  const [checked, setChecked] = useState(false);

  useEffect(() => {
    if (!getAuthState()) {
      router.replace(`/signin?next=${encodeURIComponent('/report/current')}`);
      return;
    }

    setReport(loadCurrentReport());
    setChecked(true);
  }, [router]);

  if (!checked) {
    return (
      <main className="page-shell">
        <div className="container"><div className="form-success">Loading report workspace...</div></div>
      </main>
    );
  }

  if (!report) {
    return (
      <main className="page-shell">
        <div className="container">
          <section className="glass-card panel shimmer" style={{ textAlign: 'center', padding: '64px 24px' }}>
            <div className="tech-label" style={{ justifyContent: 'center' }}><span className="pulse-dot" /> NO ACTIVE REPORT</div>
            <h1 className="section-title" style={{ margin: '18px auto', maxWidth: 720 }}>Run a scan to open the V2 report workspace.</h1>
            <p className="page-desc" style={{ margin: '0 auto 26px' }}>The current report page reads the latest scan from local session storage. Start with the vulnerable demo for the strongest walkthrough.</p>
            <Link className="btn btn-primary" href="/scanner">Go to scanner</Link>
          </section>
        </div>
      </main>
    );
  }

  return <ReportWorkspace report={report} />;
}
