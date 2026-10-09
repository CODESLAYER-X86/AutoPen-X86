/**
 * Part 7 API routes — verification, findings, reports (spec Part 7 §60, §67,
 * §31, §63, §65, §8, §12, §21).
 *
 *  - POST /api/engagements/:id/findings — create candidate finding (§6)
 *  - GET  /api/engagements/:id/findings/:findingId — detail + lifecycle
 *  - GET  /api/engagements/:id/findings/:findingId/evidence-graph (§21, §30)
 *  - POST /api/engagements/:id/findings/:findingId/verify (§8-§14)
 *  - POST /api/engagements/:id/findings/:findingId/severity (§17-§18)
 *  - POST /api/engagements/:id/findings/:findingId/deduplicate (§19-§20)
 *  - POST /api/engagements/:id/findings/:findingId/review (§67-§68)
 *  - POST /api/engagements/:id/findings/:findingId/retest (§37-§38)
 *  - POST /api/engagements/:id/reports/generate (§31)
 *  - GET  /api/engagements/:id/reports (list)
 *  - GET  /api/engagements/:id/reports/:reportId (detail)
 *  - GET  /api/engagements/:id/reports/:reportId/export?format= (§63)
 *
 * All routes are ownership-guarded; 501 when Part 7 is disabled by
 * configuration (honest degradation).
 */
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { NotImplementedError, ValidationError } from '@aegis/shared';
import {
  ComputeSeverityRequestSchema,
  CreateCandidateFindingRequestSchema,
  ExportReportRequestSchema,
  GenerateReportRequestSchema,
  ReviewFindingRequestSchema,
  RequestRetestRequestSchema,
  VerifyFindingRequestSchema,
} from '@aegis/contracts';
import type { ReportFormat } from '@aegis/shared';
import { parseBody } from '../lib/validate.js';
import { requireOwnedEngagement } from '../lib/ownership.js';

const MIME_BY_FORMAT: Record<string, string> = {
  JSON: 'application/json',
  HTML: 'text/html; charset=utf-8',
  MARKDOWN: 'text/markdown; charset=utf-8',
  PDF: 'application/pdf',
};

export async function reportingRoutes(app: FastifyInstance): Promise<void> {
  const ctx = () => app.ctx;

  const engine = () => {
    const c = ctx();
    if (!c.vr) {
      throw new NotImplementedError(
        'The verification/reporting engine (Part 7) is disabled in this deployment; set FEATURE_REPORTING=true to enable it',
        'VR_ENGINE_DISABLED',
      );
    }
    return c.vr;
  };

  const requireFinding = async (
    engagementId: string,
    findingId: string,
  ): Promise<ReturnType<typeof engine> extends never ? never : import('@aegis/database').FindingRecord> => {
    const finding = await ctx().repos.findings.findByIdAndEngagement(findingId, engagementId);
    if (!finding) {
      throw new ValidationError('Finding not found for this engagement', 'FINDING_NOT_FOUND');
    }
    return finding;
  };

  // -------------------------------------------------------- findings (§6, §4)

  app.post('/api/engagements/:id/findings', async (request: FastifyRequest, reply) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const body = parseBody(CreateCandidateFindingRequestSchema, request.body ?? {});
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const finding = await engine().findings.createCandidate({
      engagementId: engagement.id,
      hypothesisId: body.hypothesis_id,
      category: body.category,
      title: body.title,
      description: body.observed_behavior,
      observedBehavior: body.observed_behavior,
      expectedBehavior: body.expected_behavior ?? null,
      severity: 'MEDIUM',
      evidenceIds: body.evidence_ids,
      testIds: body.test_ids,
      targetRefs: body.target_refs,
      endpointRefs: body.endpoint_refs,
      identityRefs: body.identity_refs,
    });
    await c.audit({
      actorUserId: request.user.id,
      action: 'FINDING_CANDIDATE_CREATED',
      resource: 'finding',
      resourceId: finding.id,
      engagementId: engagement.id,
      metadata: { category: body.category },
    });
    return reply.code(201).send({ finding });
  });

  app.get('/api/engagements/:id/findings/:findingId', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id, findingId } = request.params as { id: string; findingId: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const finding = await requireFinding(engagement.id, findingId);
    const lifecycle = await c.repos.findings.listLifecycleEvents(findingId);
    const quality = await c.repos.findings.listEvidenceQuality(findingId);
    const verifications = await c.repos.verificationResults.listByFinding(engagement.id, findingId);
    const reviews = await c.repos.findingReviews.listByFinding(engagement.id, findingId);
    return {
      finding,
      lifecycle,
      evidence_quality: quality,
      verifications,
      reviews,
    };
  });

  // ------------------------------------------------------- evidence graph (§21)

  app.get('/api/engagements/:id/findings/:findingId/evidence-graph', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id, findingId } = request.params as { id: string; findingId: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    await requireFinding(engagement.id, findingId);
    return { graph: await engine().findings.evidenceGraph(engagement.id, findingId) };
  });

  // --------------------------------------------------------- verification (§8)

  app.post('/api/engagements/:id/findings/:findingId/verify', async (request: FastifyRequest, reply) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id, findingId } = request.params as { id: string; findingId: string };
    const body = parseBody(VerifyFindingRequestSchema, request.body ?? {});
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const finding = await requireFinding(engagement.id, findingId);
    const result = await engine().verifier.verifyFinding(engagement.id, finding, {
      strategies: body.strategies as never,
    });
    // Apply the verdict to the lifecycle (§14 -> §4) + confidence (§15).
    await engine().findings.applyVerificationResult(engagement.id, result.result).catch(() => undefined);
    await engine().findings
      .recalculateConfidence(engagement.id, findingId, result.result)
      .catch(() => undefined);
    await c.audit({
      actorUserId: request.user.id,
      action: 'FINDING_VERIFICATION_EXECUTED',
      resource: 'finding',
      resourceId: findingId,
      engagementId: engagement.id,
      metadata: { verdict: result.result.status, plan_id: result.planId },
    });
    return reply.code(200).send({
      verification: result.result,
      plan_id: result.planId,
      policy_violations: result.violations,
    });
  });

  // ------------------------------------------------------------ severity (§17)

  app.post('/api/engagements/:id/findings/:findingId/severity', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id, findingId } = request.params as { id: string; findingId: string };
    const body = parseBody(ComputeSeverityRequestSchema, request.body ?? {});
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    await requireFinding(engagement.id, findingId);
    const computation = await engine().findings.computeSeverity(
      engagement.id,
      findingId,
      body.input as never,
    );
    await c.audit({
      actorUserId: request.user.id,
      action: 'FINDING_SEVERITY_COMPUTED',
      resource: 'finding',
      resourceId: findingId,
      engagementId: engagement.id,
      metadata: { severity: computation.severity, cvss: computation.cvss.base_score },
    });
    return computation;
  });

  // ------------------------------------------------------ deduplication (§19)

  app.post('/api/engagements/:id/findings/:findingId/deduplicate', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id, findingId } = request.params as { id: string; findingId: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    await requireFinding(engagement.id, findingId);
    return engine().findings.deduplicate(engagement.id, findingId);
  });

  // -------------------------------------------------------- human review (§67)

  app.post('/api/engagements/:id/findings/:findingId/review', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id, findingId } = request.params as { id: string; findingId: string };
    const body = parseBody(ReviewFindingRequestSchema, request.body ?? {});
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    await requireFinding(engagement.id, findingId);
    const outcome = await engine().reviews.review(engagement.id, findingId, {
      decision: body.decision,
      reviewer: request.user.id,
      reason: body.reason,
      severity: body.severity,
      remediation: body.remediation,
      duplicateOf: body.duplicate_of,
    });
    await c.audit({
      actorUserId: request.user.id,
      action: 'FINDING_HUMAN_REVIEWED',
      resource: 'finding',
      resourceId: findingId,
      engagementId: engagement.id,
      metadata: { decision: body.decision, disagreement: outcome.review.agent_human_disagreement },
    });
    return outcome;
  });

  // -------------------------------------------------------------- retest (§37)

  app.post('/api/engagements/:id/findings/:findingId/retest', async (request: FastifyRequest, reply) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id, findingId } = request.params as { id: string; findingId: string };
    const body = parseBody(RequestRetestRequestSchema, request.body ?? {});
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    await requireFinding(engagement.id, findingId);
    const retest = await engine().retests.request(
      engagement.id,
      findingId,
      request.user.id,
      body.note,
    );
    await c.audit({
      actorUserId: request.user.id,
      action: 'FINDING_RETEST_REQUESTED',
      resource: 'finding',
      resourceId: findingId,
      engagementId: engagement.id,
      metadata: { retest_id: retest.id },
    });
    return reply.code(202).send({ retest });
  });

  app.post('/api/engagements/:id/findings/:findingId/retest/run', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id, findingId } = request.params as { id: string; findingId: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    await requireFinding(engagement.id, findingId);
    const outcome = await engine().retests.retest(engagement.id, findingId, request.user.id);
    await c.audit({
      actorUserId: request.user.id,
      action: 'FINDING_RETEST_COMPLETED',
      resource: 'finding',
      resourceId: findingId,
      engagementId: engagement.id,
      metadata: { outcome: outcome.retest.outcome },
    });
    return outcome;
  });

  // -------------------------------------------------------------- reports (§31)

  app.post('/api/engagements/:id/reports/generate', async (request: FastifyRequest, reply) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const body = parseBody(GenerateReportRequestSchema, request.body ?? {});
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const generated = await engine().reports.generate(engagement.id, {
      type: body.type,
      formats: body.formats as ReportFormat[],
      title: body.title,
      includeEvidence: body.include_evidence,
      includeRemediation: body.include_remediation,
      generatedBy: request.user.id,
    });
    await c.audit({
      actorUserId: request.user.id,
      action: 'REPORT_GENERATED',
      resource: 'report',
      resourceId: generated.report.id,
      engagementId: engagement.id,
      metadata: {
        type: body.type,
        status: generated.report.status,
        exports: generated.exports.map((e) => e.format),
      },
    });
    return reply.code(generated.report.status === 'REJECTED' ? 422 : 201).send({
      report: generated.report,
      exports: generated.exports,
      validation_issues: generated.validationIssues,
    });
  });

  app.get('/api/engagements/:id/reports', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const reports = await c.repos.reports.listByEngagement(engagement.id, 100);
    return { items: reports, total: reports.length };
  });

  app.get('/api/engagements/:id/reports/:reportId', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id, reportId } = request.params as { id: string; reportId: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const report = await c.repos.reports.findByIdAndEngagement(reportId, engagement.id);
    if (!report) throw new ValidationError('Report not found for this engagement', 'REPORT_NOT_FOUND');
    const exports = await c.repos.reportExports.listByReport(engagement.id, reportId);
    return { report, exports };
  });

  app.get('/api/engagements/:id/reports/:reportId/export', async (request: FastifyRequest, reply) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id, reportId } = request.params as { id: string; reportId: string };
    const query = parseBody(ExportReportRequestSchema, request.query ?? {});
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const report = await c.repos.reports.findByIdAndEngagement(reportId, engagement.id);
    if (!report) throw new ValidationError('Report not found for this engagement', 'REPORT_NOT_FOUND');
    if (report.status === 'REJECTED') {
      throw new ValidationError('Rejected reports cannot be exported (§65)', 'REPORT_REJECTED');
    }
    const artifact = await engine().reports.getExport(engagement.id, reportId, query.format);
    if (!artifact) {
      throw new ValidationError(`No ${query.format} export exists for this report`, 'EXPORT_NOT_FOUND');
    }
    await c.audit({
      actorUserId: request.user.id,
      action: 'REPORT_EXPORT_DOWNLOADED',
      resource: 'report',
      resourceId: reportId,
      engagementId: engagement.id,
      metadata: { format: query.format, bytes: artifact.byteSize },
    });
    const filename = `report-${reportId}-${query.format.toLowerCase()}`;
    reply.header('content-type', MIME_BY_FORMAT[query.format] ?? 'application/octet-stream');
    reply.header('content-disposition', `attachment; filename="${filename}.${query.format.toLowerCase()}"`);
    reply.header('x-report-sha256', artifact.sha256);
    return reply.send(artifact.bytes);
  });

  // ------------------------------------------------------- feedback loop (§68)
  app.get('/api/engagements/:id/findings/feedback', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    return { disagreements: await engine().reviews.feedbackLoop(engagement.id) };
  });
}
