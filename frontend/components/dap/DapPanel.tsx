'use client';

import { FormEvent, useState } from 'react';
import type { ScanReport } from '@/types/scan';
import { apiFetch, formatApiError } from '@/lib/api';

type Message = { role: 'user' | 'bot'; text: string };

const quickQuestions = [
  'What should I fix first?',
  'Can I deploy this?',
  'Prove the highest risk path.',
  'Which patch should I use?'
];

export function DapPanel({ report }: { report: ScanReport }) {
  const [question, setQuestion] = useState('');
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<Message[]>([
    { role: 'bot', text: 'Ask DAP about this report. I can use findings, Prove Mode, patch previews, and the deployment gate.' }
  ]);
  const [loading, setLoading] = useState(false);

  async function ask(text: string) {
    const clean = text.trim();
    if (!clean || loading) return;
    setOpen(true);
    setMessages((prev) => [...prev, { role: 'user', text: clean }, { role: 'bot', text: 'Thinking through the report...' }]);
    setQuestion('');
    setLoading(true);

    const isQuickQuestion = quickQuestions.includes(clean);
    let responseSuccess = false;
    let responseLength = 0;

    try {
      const data = await apiFetch<{ answer?: string }>('/assistant/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question: clean, scan_result: report }),
      });
      responseSuccess = true;
      responseLength = (data.answer || '').length;
      setMessages((prev) => [...prev.slice(0, -1), { role: 'bot', text: data.answer || 'DAP could not produce an answer.' }]);
    } catch (error) {
      setMessages((prev) => [...prev.slice(0, -1), { role: 'bot', text: formatApiError(error, 'DAP is unavailable right now.') }]);
    } finally {
      if (typeof pendo !== 'undefined') {
        pendo.track('dap_question_asked', {
          question_text: clean.substring(0, 200),
          is_quick_question: isQuickQuestion,
          question_source: isQuickQuestion ? 'quick_button' : 'text_input',
          response_success: responseSuccess,
          response_length: responseLength,
          project_name: report.project_name || report.repo_name || '',
          safety_score: Number(report.safety_score ?? 0),
        });
      }
      setLoading(false);
    }
  }

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    ask(question);
  }

  return (
    <>
      {open && <button className="dap-backdrop" type="button" aria-label="Close DAP assistant" onClick={() => setOpen(false)} />}
      <button className="dap-floating-button" type="button" onClick={() => setOpen(true)} aria-label="Open DAP assistant">
        <span className="dap-bot-mark" aria-hidden="true">
          <svg className="dap-bot-icon" viewBox="0 0 24 24" role="img" focusable="false">
            <path d="M12 2.75a.75.75 0 0 1 .75.75v1.38h1.05c3.35 0 5.7 2.28 5.7 5.55v4.1c0 3.28-2.35 5.55-5.7 5.55H10.2c-3.35 0-5.7-2.27-5.7-5.55v-4.1c0-3.27 2.35-5.55 5.7-5.55h1.05V3.5a.75.75 0 0 1 .75-.75Z" />
            <path d="M8.15 11.25c0-.83.67-1.5 1.5-1.5s1.5.67 1.5 1.5-.67 1.5-1.5 1.5-1.5-.67-1.5-1.5Zm4.7 0c0-.83.67-1.5 1.5-1.5s1.5.67 1.5 1.5-.67 1.5-1.5 1.5-1.5-.67-1.5-1.5Z" className="dap-bot-eye" />
            <path d="M9.15 15.45c0-.36.29-.65.65-.65h4.4c.36 0 .65.29.65.65s-.29.65-.65.65H9.8a.65.65 0 0 1-.65-.65Z" className="dap-bot-mouth" />
          </svg>
        </span>
        <span className="dap-bot-copy">Ask DAP</span>
      </button>
      <aside className={`dap-drawer ${open ? 'open' : ''}`} aria-hidden={!open}>
        <div className="glass-card panel dap-box">
          <div className="panel-head dap-drawer-head">
            <div>
              <div className="panel-label">DAP assistant</div>
              <h2 className="panel-title">Ask the report.</h2>
            </div>
            <button className="btn btn-secondary btn-small" type="button" onClick={() => setOpen(false)}>Close</button>
          </div>
          <div className="dap-quick-row">
            {quickQuestions.map((item) => (
              <button key={item} className="btn btn-secondary btn-small" type="button" onClick={() => ask(item)} disabled={loading}>{item}</button>
            ))}
          </div>
          <div className="dap-messages">
            {messages.map((message, index) => (
              <div className={`dap-msg ${message.role === 'user' ? 'user' : ''}`} key={`${message.role}-${index}`}>{message.text}</div>
            ))}
          </div>
          <form className="form-stack dap-form" onSubmit={onSubmit}>
            <input className="input" value={question} onChange={(e) => setQuestion(e.target.value)} placeholder="Ask about this scan..." />
            <button className="btn btn-primary" type="submit" disabled={loading}>{loading ? 'Asking DAP...' : 'Ask DAP'}</button>
          </form>
        </div>
      </aside>
    </>
  );
}
