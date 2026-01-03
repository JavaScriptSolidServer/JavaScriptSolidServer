/**
 * Storage quota management
 * Tracks and enforces per-pod storage limits
 */

import { promises as fs } from 'fs';
import { join } from 'path';
import { getDataRoot } from '../utils/url.js';

const QUOTA_FILE = '.quota.json';

/**
 * Get quota file path for a pod
 */
function getQuotaPath(podName) {
  return join(getDataRoot(), podName, QUOTA_FILE);
}

/**
 * Load quota data for a pod
 * @param {string} podName - The pod name
 * @returns {Promise<{limit: number, used: number}>}
 */
export async function loadQuota(podName) {
  try {
    const data = await fs.readFile(getQuotaPath(podName), 'utf-8');
    return JSON.parse(data);
  } catch (err) {
    if (err.code === 'ENOENT') {
      // No quota file - return defaults (will be initialized on first write)
      return { limit: 0, used: 0 };
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
  await fs.writeFile(getQuotaPath(podName), JSON.stringify(quota, null, 2));
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

      // Skip quota file itself
      if (entry.name === QUOTA_FILE) continue;

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

  // Initialize if no quota set
  if (quota.limit === 0 && defaultQuota > 0) {
    quota = await initializeQuota(podName, defaultQuota);
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
 * Update quota usage after a write
 * @param {string} podName - The pod name
 * @param {number} bytesChange - Bytes added (positive) or removed (negative)
 */
export async function updateQuotaUsage(podName, bytesChange) {
  const quota = await loadQuota(podName);

  // Skip if no quota initialized
  if (quota.limit === 0) return quota;

  quota.used = Math.max(0, quota.used + bytesChange);
  await saveQuota(podName, quota);
  return quota;
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
