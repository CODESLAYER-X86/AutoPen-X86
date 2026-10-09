import type { ReactNode } from 'react';
import { useState } from 'react';
import { z } from 'zod';
import { pageSchema, ReportSummarySchema, FindingDetailResponseSchema } from '@aegis/contracts';
import { apiRequest, ApiError } from '../../lib/api.js';
import { useResource } from '../../hooks/useResource.js';
import { ErrorBanner, Loading, EmptyState } from '../../components/Feedback.js';

const ReportsPageSchema = pageSchema(ReportSummarySchema);
const FindingsForReportSchema = pageSchema(FindingDetailResponseSchema);

const REPORT_TYPES = ['TECHNICAL', 'EXECUTIVE', 'MACHINE'] as const;
const REPORT_FORMATS = ['JSON', 'MARKDOWN', 'HTML', 'PDF'] as const;

export function ReportsTab({ engagementId }: { engagementId: string }): ReactNode {
  const [type, setType] = useState<(typeof REPORT_TYPES)[number]>('TECHNICAL');
  const [formats, setFormats] = useState<Array<(typeof REPORT_FORMATS)[number]>>(['JSON', 'MARKDOWN']);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [lastValidation, setLastValidation] = useState<Array<{ code: string; message: string; severity: string }>>([]);

  const { data, error, loading, reload } = useResource(
    () => apiRequest('GET', `/api/engagements/${engagementId}/reports`, ReportsPageSchema),
    [engagementId],
  );
  const findings = useResource(
    () => apiRequest('GET', `/api/engagements/${engagementId}/findings`, FindingsForReportSchema),
    [engagementId],
  );

  const verifiedCount =
    findings.data?.items.filter((f) => f.status === 'VERIFIED' || f.status === 'ACCEPTED').length ?? 0;

  const toggleFormat = (format: (typeof REPORT_FORMATS)[number]): void => {
    setFormats((current) =>
      current.includes(format) ? current.filter((f) => f !== format) : [...current, format],
    );
  };

  const generate = async (): Promise<void> => {
    setBusy(true);
    setActionError(null);
    setLastValidation([]);
    try {
      const result = await apiRequest(
        'POST',
        `/api/engagements/${engagementId}/reports/generate`,
        z.any(),
        { type, formats, include_evidence: true, include_remediation: true },
      );
      const report = (result as { report?: { status?: string } }).report;
      const issues = (result as { validation_issues?: Array<{ code: string; message: string; severity: string }> })
        .validation_issues;
      if (issues) setLastValidation(issues);
      if (report?.status === 'REJECTED') {
        setActionError('Report REJECTED by the validation gate (§65): see issues below.');
      }
      reload();
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card">
      <div className="toolbar">
        <div className="card-title" style={{ margin: 0, border: 'none' }}>
          Reports {data ? `(${data.total})` : ''}
        </div>
        <button type="button" className="btn btn-small" onClick={reload}>
          Refresh
        </button>
      </div>
      <p className="page-subtitle">
        Reports are generated from STRUCTURED verified facts through the pipeline: normalization →
        deduplication → severity → confidence → evidence selection → redaction → composition →
        validation → export (§31). Reports with unsupported claims, unredacted secrets or
        nonexistent evidence references are rejected before export (§65). {verifiedCount} verified
        finding(s) available.
      </p>

      <div className="toolbar" style={{ gap: 8, flexWrap: 'wrap' }}>
        <label>
          Type{' '}
          <select value={type} onChange={(e) => setType(e.target.value as (typeof REPORT_TYPES)[number])}>
            {REPORT_TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </label>
        <span>Formats:</span>
        {REPORT_FORMATS.map((format) => (
          <label key={format} style={{ display: 'inline-flex', gap: 4, alignItems: 'center' }}>
            <input
              type="checkbox"
              checked={formats.includes(format)}
              onChange={() => toggleFormat(format)}
            />
            {format}
          </label>
        ))}
        <button type="button" className="btn" disabled={busy || formats.length === 0} onClick={generate}>
          {busy ? 'Generating…' : 'Generate report'}
        </button>
      </div>

      {actionError && <ErrorBanner message={actionError} />}
      {lastValidation.length > 0 && (
        <div className="card" style={{ marginTop: 12, padding: 12 }}>
          <strong>Validation issues (§65)</strong>
          <ul style={{ margin: '8px 0 0', paddingLeft: 18 }}>
            {lastValidation.map((issue, index) => (
              <li key={index} className={issue.severity === 'ERROR' ? 'text-danger' : undefined}>
                <span className="mono">{issue.code}</span>: {issue.message}
              </li>
            ))}
          </ul>
        </div>
      )}

      {loading && <Loading label="loading reports" />}
      {error && <ErrorBanner message={error} />}
      {data && data.items.length === 0 && (
        <EmptyState>
          No reports yet. Generate a report once findings are verified. Only VERIFIED findings are
          reportable (§65).
        </EmptyState>
      )}

      {data && data.items.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>Title</th>
              <th>Type</th>
              <th>Status</th>
              <th>Version</th>
              <th>Claims</th>
              <th>Redactions</th>
              <th>Generated</th>
              <th>Download</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((report) => (
              <tr key={report.id}>
                <td style={{ maxWidth: 320 }}>{report.title}</td>
                <td>{report.type}</td>
                <td>{report.status}</td>
                <td>v{report.version}</td>
                <td>{report.claims.length}</td>
                <td>{report.redactions.length}</td>
                <td>{report.generated_at.slice(0, 19).replace('T', ' ')}</td>
                <td>
                  {REPORT_FORMATS.map((format) => (
                    <a
                      key={format}
                      className="btn btn-small"
                      style={{ marginRight: 4 }}
                      href={`/api/engagements/${engagementId}/reports/${report.id}/export?format=${format}`}
                      target="_blank"
                      rel="noreferrer"
                    >
                      {format}
                    </a>
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
