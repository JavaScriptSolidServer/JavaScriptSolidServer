/**
 * ActivityPub SQLite Storage
 * Persistence layer for federation data
 *
 * Uses sql.js (WASM) for cross-platform compatibility
 * Works on Android/Termux, Windows, and all platforms
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs'
import { dirname } from 'path'

let db = null
let dbPath = null

// SQL schema
const SCHEMA = `
  -- Followers (people following us)
  CREATE TABLE IF NOT EXISTS followers (
    id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    inbox TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  -- Following (people we follow)
  CREATE TABLE IF NOT EXISTS following (
    id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    accepted INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  -- Activities (inbox)
  CREATE TABLE IF NOT EXISTS activities (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    actor TEXT,
    object TEXT,
    raw TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  -- Posts (our outbox)
  CREATE TABLE IF NOT EXISTS posts (
    id TEXT PRIMARY KEY,
    content TEXT NOT NULL,
    in_reply_to TEXT,
    published TEXT DEFAULT CURRENT_TIMESTAMP
  );

  -- Known actors (cache)
  CREATE TABLE IF NOT EXISTS actors (
    id TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    fetched_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`

/**
 * Initialize the database
 * Uses sql.js (WASM) for cross-platform compatibility
 * @param {string} path - Path to SQLite file
 */
export async function initStore(path = 'data/activitypub.db') {
  // Ensure directory exists
  const dir = dirname(path)
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true })
  }

  dbPath = path

  // Use sql.js (WASM, works everywhere)
  const initSqlJs = (await import('sql.js')).default
  const SQL = await initSqlJs()

  // Load existing database if it exists
  if (existsSync(path)) {
    const buffer = readFileSync(path)
    db = new SQL.Database(buffer)
  } else {
    db = new SQL.Database()
  }

  db.run(SCHEMA)

  // Save initial database
  saveDatabase()

  return db
}

/**
 * Save sql.js database to disk
 */
function saveDatabase() {
  if (db && dbPath) {
    const data = db.export()
    const buffer = Buffer.from(data)
    writeFileSync(dbPath, buffer)
  }
}

/**
 * Get database instance
 */
export function getStore() {
  if (!db) {
    throw new Error('Store not initialized. Call initStore() first.')
  }
  return db
}

// Helper functions for sql.js API
function runStmt(sql, params = []) {
  db.run(sql, params)
  saveDatabase()
}

function getOne(sql, params = []) {
  const stmt = db.prepare(sql)
  stmt.bind(params)
  if (stmt.step()) {
    const row = stmt.getAsObject()
    stmt.free()
    return row
  }
  stmt.free()
  return null
}

function getAll(sql, params = []) {
  const results = []
  const stmt = db.prepare(sql)
  stmt.bind(params)
  while (stmt.step()) {
    results.push(stmt.getAsObject())
  }
  stmt.free()
  return results
}

// Followers

export function addFollower(actorId, inbox) {
  runStmt(
    'INSERT OR REPLACE INTO followers (id, actor, inbox) VALUES (?, ?, ?)',
    [actorId, actorId, inbox]
  )
}

export function removeFollower(actorId) {
  runStmt('DELETE FROM followers WHERE id = ?', [actorId])
}

export function getFollowers() {
  return getAll('SELECT * FROM followers ORDER BY created_at DESC')
}

export function getFollowerCount() {
  const row = getOne('SELECT COUNT(*) as count FROM followers')
  return row ? row.count : 0
}

export function getFollowerInboxes() {
  return getAll('SELECT DISTINCT inbox FROM followers WHERE inbox IS NOT NULL')
    .map(row => row.inbox)
}

// Following

export function addFollowing(actorId, accepted = false) {
  runStmt(
    'INSERT OR REPLACE INTO following (id, actor, accepted) VALUES (?, ?, ?)',
    [actorId, actorId, accepted ? 1 : 0]
  )
}

export function acceptFollowing(actorId) {
  runStmt('UPDATE following SET accepted = 1 WHERE id = ?', [actorId])
}

export function removeFollowing(actorId) {
  runStmt('DELETE FROM following WHERE id = ?', [actorId])
}

export function getFollowing() {
  return getAll('SELECT * FROM following WHERE accepted = 1 ORDER BY created_at DESC')
}

export function getFollowingCount() {
  const row = getOne('SELECT COUNT(*) as count FROM following WHERE accepted = 1')
  return row ? row.count : 0
}

// Activities

export function saveActivity(activity) {
  runStmt(
    'INSERT OR REPLACE INTO activities (id, type, actor, object, raw) VALUES (?, ?, ?, ?, ?)',
    [
      activity.id,
      activity.type,
      typeof activity.actor === 'string' ? activity.actor : activity.actor?.id,
      typeof activity.object === 'string' ? activity.object : JSON.stringify(activity.object),
      JSON.stringify(activity)
    ]
  )
}

export function getActivities(limit = 20) {
  return getAll('SELECT * FROM activities ORDER BY created_at DESC LIMIT ?', [limit])
    .map(row => ({
      ...row,
      raw: JSON.parse(row.raw)
    }))
}

// Posts

export function savePost(id, content, inReplyTo = null) {
  runStmt(
    'INSERT INTO posts (id, content, in_reply_to) VALUES (?, ?, ?)',
    [id, content, inReplyTo]
  )
}

export function getPosts(limit = 20) {
  return getAll('SELECT * FROM posts ORDER BY published DESC LIMIT ?', [limit])
}

export function getPost(id) {
  return getOne('SELECT * FROM posts WHERE id = ?', [id])
}

export function getPostCount() {
  const row = getOne('SELECT COUNT(*) as count FROM posts')
  return row ? row.count : 0
}

// Actor cache

export function cacheActor(actor) {
  runStmt(
    "INSERT OR REPLACE INTO actors (id, data, fetched_at) VALUES (?, ?, datetime('now'))",
    [actor.id, JSON.stringify(actor)]
  )
}

export function getCachedActor(id) {
  const row = getOne('SELECT * FROM actors WHERE id = ?', [id])
  return row ? JSON.parse(row.data) : null
}

export default {
  initStore,
  getStore,
  addFollower,
  removeFollower,
  getFollowers,
  getFollowerCount,
  getFollowerInboxes,
  addFollowing,
  acceptFollowing,
  removeFollowing,
  getFollowing,
  getFollowingCount,
  saveActivity,
  getActivities,
  savePost,
  getPosts,
  getPost,
  getPostCount,
  cacheActor,
  getCachedActor
}
