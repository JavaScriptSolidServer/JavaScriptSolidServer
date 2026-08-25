/**
 * Storage quota management
 * Tracks and enforces per-pod storage limits
 */

import { promises as fs } from 'fs';
import { join } from 'path';
import { getDataRoot } from '../utils/url.js';

const QUOTA_FILE = '.quota.json';
// Temp files created by saveQuota live next to the quota file; they must be
// excluded from disk-usage reconciliation so an orphan (e.g. from a crash
// between writeFile and rename) doesn't inflate pod usage.
const QUOTA_TMP_PREFIX = `${QUOTA_FILE}.tmp.`;

/**
 * Per-pod serialization of read-modify-write on .quota.json.
 *
 * saveQuota is already atomic (temp file + rename), which stops a concurrent
 * reader from seeing a truncated file (#309). But atomicity of a single write
 * does not stop a lost update: two writers that both `loadQuota` the same
 * `used` value, each add their bytes and `saveQuota`, race to clobber one
 * another — and, worse, both can pass a `checkQuota` before either records its
 * usage, letting concurrent writes overshoot the limit. Serializing the whole
 * load→mutate→save critical section per pod closes both windows. This mirrors
 * QuotaPolicy::reserve in the solid-pod-rs parity port, which holds a per-pod
 * lock for atomic check-and-commit.
 */
const podLocks = new Map();

function withPodLock(podName, fn) {
  const prev = podLocks.get(podName) || Promise.resolve();
  // Chain onto the previous holder regardless of how it settled.
  const run = prev.then(fn, fn);
  // Store a tail that never rejects so the chain can't wedge on an error.
  const tail = run.then(() => {}, () => {});
  podLocks.set(podName, tail);
  // Opportunistic cleanup so the map doesn't grow unbounded across many pods.
  tail.then(() => {
    if (podLocks.get(podName) === tail) podLocks.delete(podName);
  });
  return run;
}

/**
 * Get quota file path for a pod
 */
function getQuotaPath(podName) {
  return join(getDataRoot(), podName, QUOTA_FILE);
}

/**
 * Coerce a parsed quota object to a sane shape so all callers can do
 * arithmetic on it without worrying about undefined/NaN/negative values.
 */
function sanitizeQuota(q) {
  const toNum = (v) => {
    const n = Number(v);
    return Number.isFinite(n) && n >= 0 ? n : 0;
  };
  return { limit: toNum(q?.limit), used: toNum(q?.used) };
}

/**
 * Load quota data for a pod
 * @param {string} podName - The pod name
 * @returns {Promise<{limit: number, used: number}>}
 */
export async function loadQuota(podName) {
  try {
    const data = await fs.readFile(getQuotaPath(podName), 'utf-8');
    // Empty/partial file can appear if a write was interrupted (or from a
    // racing non-atomic save on older versions). Treat as missing and
    // reconcile against on-disk usage so we don't under-count.
    if (!data.trim()) return { limit: 0, used: await calculatePodSize(podName) };
    return sanitizeQuota(JSON.parse(data));
  } catch (err) {
    if (err.code === 'ENOENT') return { limit: 0, used: 0 };
    if (err instanceof SyntaxError) {
      return { limit: 0, used: await calculatePodSize(podName) };
    }
    throw err;
  }
}

/**
 * Save quota data for a pod
 * @param {string} podName - The pod name
 * @param {object} quota - Quota data
 */
export async function saveQuota(podName, quota) {
  // Atomic write: fs.writeFile truncates before writing, which lets concurrent
  // readers see an empty file. Write to a temp file and rename (POSIX-atomic).
  // Any failure (writeFile or rename) cleans up the temp file so failed writes
  // don't accumulate orphans.
  const finalPath = getQuotaPath(podName);
  const tmpPath = `${finalPath}.tmp.${process.pid}.${Date.now()}.${Math.random().toString(36).slice(2)}`;
  try {
    await fs.writeFile(tmpPath, JSON.stringify(quota, null, 2));
    await fs.rename(tmpPath, finalPath);
  } catch (err) {
    await fs.unlink(tmpPath).catch(() => {});
    throw err;
  }
}

/**
 * Initialize quota for a new pod
 * @param {string} podName - The pod name
 * @param {number} limit - Quota limit in bytes
 */
export async function initializeQuota(podName, limit) {
  const quota = { limit, used: 0 };
  await saveQuota(podName, quota);
  return quota;
}

/**
 * Calculate actual disk usage for a pod (for reconciliation)
 * @param {string} podName - The pod name
 * @returns {Promise<number>} Total bytes used
 */
export async function calculatePodSize(podName) {
  const podPath = join(getDataRoot(), podName);
  return calculateDirSize(podPath);
}

/**
 * Recursively calculate directory size
 */
async function calculateDirSize(dirPath) {
  let total = 0;

  try {
    const entries = await fs.readdir(dirPath, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = join(dirPath, entry.name);

      // Skip the quota file and any orphaned temp files from saveQuota.
      if (entry.name === QUOTA_FILE) continue;
      if (entry.name.startsWith(QUOTA_TMP_PREFIX)) continue;

      if (entry.isDirectory()) {
        total += await calculateDirSize(fullPath);
      } else if (entry.isFile()) {
        const stat = await fs.stat(fullPath);
        total += stat.size;
      }
    }
  } catch (err) {
    // Directory might not exist or be inaccessible
    if (err.code !== 'ENOENT') {
      throw err;
    }
  }

  return total;
}

/**
 * Check if a write operation would exceed quota
 * @param {string} podName - The pod name
 * @param {number} additionalBytes - Bytes to be added
 * @param {number} defaultQuota - Default quota limit
 * @returns {Promise<{allowed: boolean, quota: object, error?: string}>}
 */
export async function checkQuota(podName, additionalBytes, defaultQuota) {
  let quota = await loadQuota(podName);

  // Initialize if no quota set. loadQuota already sanitizes shape, so `used`
  // is a finite non-negative number here — preserve it so reconciled usage
  // from a recovered corrupt/empty file is not reset to 0.
  if (quota.limit === 0 && defaultQuota > 0) {
    quota = { limit: defaultQuota, used: quota.used };
    await saveQuota(podName, quota);
  }

  // No quota enforcement if limit is 0
  if (quota.limit === 0) {
    return { allowed: true, quota };
  }

  const projectedUsage = quota.used + additionalBytes;

  if (projectedUsage > quota.limit) {
    const usedMB = (quota.used / (1024 * 1024)).toFixed(2);
    const limitMB = (quota.limit / (1024 * 1024)).toFixed(2);
    return {
      allowed: false,
      quota,
      error: `Storage quota exceeded. Used: ${usedMB}MB / ${limitMB}MB`
    };
  }

  return { allowed: true, quota };
}

/**
 * Atomically reserve quota for a pending write: check-and-commit under a
 * per-pod lock so concurrent writers cannot both pass the check and then
 * overshoot the limit. On success the reserved bytes are already recorded in
 * `used`, so callers must NOT also call updateQuotaUsage for the same bytes —
 * instead, release the reservation with `updateQuotaUsage(pod, -bytes)` if the
 * write subsequently fails.
 *
 * This is the authoritative enforcement point and the only one the write path
 * uses. checkQuota remains exported as a lock-free read-only probe for callers
 * that want to inspect headroom without reserving it, but it performs no
 * pre-check for PUT/POST any more — do not go looking for one. Mirrors
 * QuotaPolicy::reserve in the solid-pod-rs parity port.
 *
 * @param {string} podName - The pod name
 * @param {number} additionalBytes - Bytes to reserve (expected >= 0)
 * @param {number} defaultQuota - Default quota limit
 * @returns {Promise<{allowed: boolean, quota: object, error?: string}>}
 */
export async function reserveQuota(podName, additionalBytes, defaultQuota) {
  return withPodLock(podName, async () => {
    let quota = await loadQuota(podName);

    // Initialize limit from the default on first use, preserving any usage
    // reconciled from a recovered corrupt/empty file (see checkQuota).
    if (quota.limit === 0 && defaultQuota > 0) {
      quota = { limit: defaultQuota, used: quota.used };
    }

    // No enforcement (and no tracking) when no limit is in effect — matches
    // updateQuotaUsage, which skips uninitialized quotas.
    if (quota.limit === 0) {
      return { allowed: true, quota };
    }

    const projectedUsage = quota.used + additionalBytes;

    if (additionalBytes > 0 && projectedUsage > quota.limit) {
      const usedMB = (quota.used / (1024 * 1024)).toFixed(2);
      const limitMB = (quota.limit / (1024 * 1024)).toFixed(2);
      return {
        allowed: false,
        quota,
        error: `Storage quota exceeded. Used: ${usedMB}MB / ${limitMB}MB`
      };
    }

    // Commit the reservation as part of the same locked critical section.
    quota.used = Math.max(0, projectedUsage);
    await saveQuota(podName, quota);
    return { allowed: true, quota };
  });
}

/**
 * Update quota usage after a write (or to release a reservation).
 * @param {string} podName - The pod name
 * @param {number} bytesChange - Bytes added (positive) or removed (negative)
 */
export async function updateQuotaUsage(podName, bytesChange) {
  return withPodLock(podName, async () => {
    const quota = await loadQuota(podName);

    // Skip if no quota initialized
    if (quota.limit === 0) return quota;

    quota.used = Math.max(0, quota.used + bytesChange);
    await saveQuota(podName, quota);
    return quota;
  });
}

/**
 * Set quota limit for a pod
 * @param {string} podName - The pod name
 * @param {number} limit - New limit in bytes
 */
export async function setQuotaLimit(podName, limit) {
  let quota = await loadQuota(podName);

  // If no quota exists, calculate current usage
  if (quota.limit === 0) {
    quota.used = await calculatePodSize(podName);
  }

  quota.limit = limit;
  await saveQuota(podName, quota);
  return quota;
}

/**
 * Get quota info for a pod
 * @param {string} podName - The pod name
 * @returns {Promise<{limit: number, used: number, percent: number}>}
 */
export async function getQuotaInfo(podName) {
  const quota = await loadQuota(podName);
  const percent = quota.limit > 0 ? Math.round((quota.used / quota.limit) * 100) : 0;
  return { ...quota, percent };
}

/**
 * Reconcile quota with actual disk usage
 * @param {string} podName - The pod name
 */
export async function reconcileQuota(podName) {
  const quota = await loadQuota(podName);
  if (quota.limit === 0) return quota;

  const actualUsed = await calculatePodSize(podName);
  quota.used = actualUsed;
  await saveQuota(podName, quota);
  return quota;
}

/**
 * Format bytes as human-readable string
 */
export function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}
