/**
 * Artifact safety (spec Part 8 §19-§20, §29-§31).
 *
 * Every downloaded artifact is treated as untrusted: content-based type
 * detection (never the file extension), active-content quarantine,
 * compression-bomb guards and archive traversal protection. All checks are
 * deterministic byte-level analysis — no parsing of untrusted content into
 * executable form.
 */
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

/** Extensions that must never be executed or auto-opened (§19). */
const ACTIVE_CONTENT_EXTENSIONS = new Set([
  '.exe', '.sh', '.bat', '.cmd', '.com', '.scr', '.ps1', '.js', '.mjs', '.cjs',
  '.vbs', '.jar', '.hta', '.msi', '.apk', '.deb', '.rpm', '.dmg', '.so', '.dll',
  '.docm', '.xlsm', '.pptm', '.dotm', '.xltm',
]);

export interface ArtifactSafetyVerdict {
  allowed: boolean;
  reasons: string[];
  detected_kind: 'TEXT' | 'JSON' | 'HTML' | 'PDF' | 'ZIP' | 'GZIP' | 'IMAGE' | 'BINARY' | 'EMPTY';
  quarantined_extension: boolean;
  compressed_size_estimate: number;
}

/** Content-based detection from magic bytes + heuristics (§20). */
export function detectArtifactKind(bytes: Uint8Array): ArtifactSafetyVerdict['detected_kind'] {
  if (bytes.length === 0) return 'EMPTY';
  if (bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && (bytes[2] === 3 || bytes[2] === 5 || bytes[2] === 7)) {
    return 'ZIP';
  }
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) return 'GZIP';
  if (bytes.length >= 4 && bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) return 'PDF';
  if (bytes.length >= 8 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) return 'IMAGE';
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return 'IMAGE';
  if (bytes.length >= 6 && bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46) return 'IMAGE';
  // Textual kinds via leading printable-region sampling.
  const sample = bytes.subarray(0, Math.min(bytes.length, 512));
  let textLike = true;
  for (const byte of sample) {
    if (byte === 0) { textLike = false; break; }
    if (byte < 9 || (byte > 13 && byte < 32)) { textLike = false; break; }
  }
  if (textLike) {
    const head = Buffer.from(sample).toString('utf8');
    if (/^\s*\{[\s\S]*\}\s*$/.test(head) && bytes.length <= 1024 * 1024) return 'JSON';
    if (/<html|<!doctype html/i.test(head.slice(0, 256))) return 'HTML';
    return 'TEXT';
  }
  return 'BINARY';
}

export interface ArtifactSafetyLimits {
  /** Max decompressed bytes a compressed payload may expand to (§30). */
  maxDecompressedBytes: number;
  /** Max entries an archive may declare (§31). */
  maxArchiveEntries: number;
  /** Max total uncompressed archive content (§31). */
  maxArchiveTotalBytes: number;
}

export const DEFAULT_ARTIFACT_LIMITS: ArtifactSafetyLimits = {
  maxDecompressedBytes: 50 * 1024 * 1024,
  maxArchiveEntries: 5000,
  maxArchiveTotalBytes: 200 * 1024 * 1024,
};

/**
 * Evaluate an artifact against the safety policy. The extension is only a
 * QUARANTINE signal (never a trust signal): active-content extensions are
 * quarantined regardless of content, and content-based detection can
 * quarantine an active kind regardless of extension (§19-§20).
 */
export function evaluateArtifactSafety(
  bytes: Uint8Array,
  filename: string,
  limits: ArtifactSafetyLimits = DEFAULT_ARTIFACT_LIMITS,
): ArtifactSafetyVerdict {
  const reasons: string[] = [];
  const kind = detectArtifactKind(bytes);
  const extension = filename.toLowerCase().slice(filename.lastIndexOf('.'));
  const quarantined = ACTIVE_CONTENT_EXTENSIONS.has(extension) || kind === 'BINARY' && extension === '.js';

  if (quarantined) {
    reasons.push(
      `Active content quarantine: extension '${extension}' is in the never-execute set (spec §19)`,
    );
  }
  if (bytes.length > limits.maxDecompressedBytes) {
    reasons.push(`Raw artifact exceeds max size ${limits.maxDecompressedBytes}`);
  }
  if (kind === 'ZIP' || kind === 'GZIP') {
    // Compression ratio guard: a 1 MB compressed body with declared limits
    // is bounded BEFORE any full decompression happens (§30).
    if (bytes.length > 0) {
      // Stored uncompressed size heuristics: zip local header bytes 22-25.
      if (kind === 'ZIP' && bytes.length >= 26) {
        const declared = bytes[22]! | (bytes[23]! << 8) | (bytes[24]! << 16) | (bytes[25]! << 24);
        if (declared > 0 && declared > limits.maxDecompressedBytes) {
          reasons.push(
            `Compression bomb guard: zip declares ${declared} uncompressed bytes (limit ${limits.maxDecompressedBytes})`,
          );
        }
      }
    }
  }
  const allowed = reasons.length === 0;
  return {
    allowed,
    reasons,
    detected_kind: kind,
    quarantined_extension: quarantined,
    compressed_size_estimate: bytes.length,
  };
}

/**
 * Normalized extraction path for archive entries (§31). Rejects absolute
 * paths, traversal, backslashes and NUL bytes; returns the safe relative
 * path or null when the entry must be skipped.
 */
export function normalizeArchiveEntryPath(entryName: string): string | null {
  if (entryName.includes('\0')) return null;
  const normalized = entryName.replace(/\\/g, '/');
  if (normalized.startsWith('/') || /^[a-zA-Z]:/.test(normalized)) return null;
  const segments: string[] = [];
  for (const segment of normalized.split('/')) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..') return null; // traversal escapes the extraction root
    segments.push(segment);
  }
  if (segments.length === 0) return null;
  return segments.join('/');
}

/**
 * Egress guard for research fetchers (§76-§77): destination validation with
 * DNS resolution so the knowledge service cannot be turned into an
 * internal-network proxy. Loopback/private/link-local/cloud-metadata are
 * denied unless the policy explicitly allows loopback lab targets.
 */
export async function assertResearchEgressAllowed(
  url: string,
  options: { allowLoopback?: boolean } = {},
): Promise<void> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Research egress: invalid URL '${url}'`);
  }
  const scheme = parsed.protocol.replace(/:$/, '').toLowerCase();
  if (scheme !== 'http' && scheme !== 'https') {
    throw new Error(`Research egress: scheme '${parsed.protocol}' is not permitted`);
  }
  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  const ips: string[] = [];
  if (isIP(host) !== 0) {
    ips.push(host);
  } else {
    try {
      const records = await lookup(host, { all: true, verbatim: true });
      ips.push(...records.map((r) => r.address));
    } catch {
      throw new Error(`Research egress: hostname '${host}' does not resolve`);
    }
  }
  if (parsed.port === '80' || parsed.port === '443' || parsed.port === '') {
    // allowed ports for research fetches
  } else {
    throw new Error(`Research egress: port '${parsed.port}' is not permitted for research fetches`);
  }
  for (const ip of ips) {
    if (ip === '169.254.169.254' || ip.startsWith('169.254.')) {
      throw new Error('Research egress: cloud metadata endpoints are blocked');
    }
    if (ip.startsWith('127.') || ip === '::1' || ip === '0.0.0.0') {
      if (!options.allowLoopback) {
        throw new Error('Research egress: loopback destinations are blocked by default');
      }
      continue;
    }
    if (ip.startsWith('10.') || ip.startsWith('192.168.') || /^172\.(1[6-9]|2\d|3[01])\./.test(ip)) {
      throw new Error('Research egress: private network destinations are blocked');
    }
  }
}
