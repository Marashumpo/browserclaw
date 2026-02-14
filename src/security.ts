import { resolve, normalize, sep } from 'node:path';
import { lookup } from 'node:dns/promises';

/**
 * Validate that an output file path is safe — no directory traversal or escape.
 * Rejects paths containing `..` segments or relative paths that could escape
 * the intended output directory.
 *
 * @param path - The output path to validate
 * @param allowedRoots - Optional list of allowed root directories. If provided,
 *   the resolved path must be within one of these roots.
 * @throws If the path is unsafe
 */
export function assertSafeOutputPath(path: string, allowedRoots?: string[]): void {
  if (!path || typeof path !== 'string') {
    throw new Error('Output path is required.');
  }

  const normalized = normalize(path);

  // Reject paths with traversal segments
  if (normalized.includes('..')) {
    throw new Error(`Unsafe output path: directory traversal detected in "${path}".`);
  }

  // If allowed roots are specified, resolved path must be within one of them
  if (allowedRoots?.length) {
    const resolved = resolve(normalized);
    const withinRoot = allowedRoots.some(root => {
      const normalizedRoot = resolve(root);
      return resolved === normalizedRoot || resolved.startsWith(normalizedRoot + sep);
    });
    if (!withinRoot) {
      throw new Error(`Unsafe output path: "${path}" is outside allowed directories.`);
    }
  }
}

/**
 * Check whether an IP address string is internal/private/loopback.
 */
function isInternalIP(ip: string): boolean {
  // IPv4
  if (/^127\./.test(ip)) return true;
  if (/^10\./.test(ip)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return true;
  if (/^192\.168\./.test(ip)) return true;
  if (/^169\.254\./.test(ip)) return true;
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(ip)) return true;
  if (ip === '0.0.0.0') return true;

  // IPv6
  const lower = ip.toLowerCase();
  if (lower === '::1') return true;
  if (lower.startsWith('fe80:')) return true;  // link-local
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true;  // ULA
  if (lower.startsWith('::ffff:')) {
    // IPv4-mapped IPv6 — check the embedded IPv4
    const v4 = lower.replace(/^::ffff:/, '');
    return isInternalIP(v4);
  }

  return false;
}

/**
 * Check whether a URL targets a loopback or private/internal network address.
 * Synchronous hostname-based check. Used to prevent SSRF attacks.
 */
export function isInternalUrl(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    // Fail closed: treat unparseable URLs as internal/blocked
    return true;
  }

  const hostname = parsed.hostname.toLowerCase();

  // Direct hostname checks
  // Note: URL.hostname strips IPv6 brackets, so [::1] becomes ::1
  if (hostname === 'localhost') return true;

  // Check if hostname is an IP literal
  if (isInternalIP(hostname)) return true;

  // .local, .internal, .localhost TLDs
  if (hostname.endsWith('.local') || hostname.endsWith('.internal') || hostname.endsWith('.localhost')) {
    return true;
  }

  return false;
}

/**
 * Async version that also resolves DNS to catch rebinding attacks
 * where a public hostname resolves to an internal IP.
 */
export async function isInternalUrlResolved(url: string): Promise<boolean> {
  // First do the fast synchronous check
  if (isInternalUrl(url)) return true;

  // Then resolve DNS to catch rebinding
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return true;
  }

  try {
    const { address } = await lookup(parsed.hostname);
    if (isInternalIP(address)) return true;
  } catch {
    // DNS resolution failed — fail closed
    return true;
  }

  return false;
}
