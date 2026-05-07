/**
 * ActivityPub SQLite Storage
 * Persistence layer for federation data
 *
 * Uses sql.js (WASM) for cross-platform compatibility
 * Works on Android/Termux, Windows, and all platforms
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs'
import { dirname, join } from 'path'

let db = null
let dbPath = null

// SQL schema — username column on all user-scoped tables
const SCHEMA = `
  -- Followers (people following us)
  CREATE TABLE IF NOT EXISTS followers (
    id TEXT NOT NULL,
    username TEXT NOT NULL,
    actor TEXT NOT NULL,
    inbox TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, username)
  );
  CREATE INDEX IF NOT EXISTS idx_followers_username ON followers(username);

  -- Following (people we follow)
  CREATE TABLE IF NOT EXISTS following (
    id TEXT NOT NULL,
    username TEXT NOT NULL,
    actor TEXT NOT NULL,
    accepted INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, username)
  );
  CREATE INDEX IF NOT EXISTS idx_following_username ON following(username);

  -- Activities (inbox)
  CREATE TABLE IF NOT EXISTS activities (
    id TEXT NOT NULL,
    username TEXT NOT NULL,
    type TEXT NOT NULL,
    actor TEXT,
    object TEXT,
    raw TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, username)
  );
  CREATE INDEX IF NOT EXISTS idx_activities_username ON activities(username);

  -- Posts (our outbox)
  CREATE TABLE IF NOT EXISTS posts (
    id TEXT NOT NULL,
    username TEXT NOT NULL,
    content TEXT NOT NULL,
    in_reply_to TEXT,
    published TEXT DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, username)
  );
  CREATE INDEX IF NOT EXISTS idx_posts_username ON posts(username);

  -- Known actors (cache — global, not per-user)
  CREATE TABLE IF NOT EXISTS actors (
    id TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    fetched_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`

/**
 * Get the default DB path under DATA_ROOT/{username}/.ap/
 */
function getDefaultDbPath(username = 'me') {
  const dataRoot = process.env.DATA_ROOT || './data'
  return join(dataRoot, username, '.ap', 'activitypub.db')
}

/**
 * Initialize the database
 * @param {string} [path] - Path to SQLite file (defaults to {DATA_ROOT}/{username}/.ap/activitypub.db)
 * @param {string} [username] - Username used when defaulting path (default: me)
 */
export async function initStore(path, username = 'me') {
  const resolvedPath = path || getDefaultDbPath(username)

  // Ensure directory exists
  const dir = dirname(resolvedPath)
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true })
  }

  dbPath = resolvedPath

  // Use sql.js (WASM, works everywhere)
  const initSqlJs = (await import('sql.js')).default
  const SQL = await initSqlJs()

  // Load existing database if it exists
  if (existsSync(resolvedPath)) {
    const buffer = readFileSync(resolvedPath)
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

export function addFollower(username, actorId, inbox) {
  runStmt(
    'INSERT OR REPLACE INTO followers (id, username, actor, inbox) VALUES (?, ?, ?, ?)',
    [actorId, username, actorId, inbox]
  )
}

export function removeFollower(username, actorId) {
  runStmt('DELETE FROM followers WHERE id = ? AND username = ?', [actorId, username])
}

export function getFollowers(username) {
  return getAll('SELECT * FROM followers WHERE username = ? ORDER BY created_at DESC', [username])
}

export function getFollowerCount(username) {
  const row = getOne('SELECT COUNT(*) as count FROM followers WHERE username = ?', [username])
  return row ? row.count : 0
}

export function getFollowerInboxes(username) {
  return getAll('SELECT DISTINCT inbox FROM followers WHERE username = ? AND inbox IS NOT NULL', [username])
    .map(row => row.inbox)
}

// Following

export function addFollowing(username, actorId, accepted = false) {
  runStmt(
    'INSERT OR REPLACE INTO following (id, username, actor, accepted) VALUES (?, ?, ?, ?)',
    [actorId, username, actorId, accepted ? 1 : 0]
  )
}

export function acceptFollowing(username, actorId) {
  runStmt('UPDATE following SET accepted = 1 WHERE actor = ? AND username = ?', [actorId, username])
  const row = getOne('SELECT id FROM following WHERE actor = ? AND username = ?', [actorId, username])
  if (!row) {
    runStmt(
      'INSERT INTO following (id, username, actor, accepted) VALUES (?, ?, ?, 1)',
      [actorId, username, actorId]
    )
  }
}

export function removeFollowing(username, actorId) {
  runStmt('DELETE FROM following WHERE id = ? AND username = ?', [actorId, username])
}

export function getFollowing(username) {
  return getAll('SELECT * FROM following WHERE username = ? AND accepted = 1 ORDER BY created_at DESC', [username])
}

export function getFollowingCount(username) {
  const row = getOne('SELECT COUNT(*) as count FROM following WHERE username = ? AND accepted = 1', [username])
  return row ? row.count : 0
}

// Activities

export function saveActivity(username, activity) {
  runStmt(
    'INSERT OR REPLACE INTO activities (id, username, type, actor, object, raw) VALUES (?, ?, ?, ?, ?, ?)',
    [
      activity.id,
      username,
      activity.type,
      typeof activity.actor === 'string' ? activity.actor : activity.actor?.id,
      typeof activity.object === 'string' ? activity.object : JSON.stringify(activity.object),
      JSON.stringify(activity)
    ]
  )
}

export function getActivities(username, limit = 20) {
  return getAll('SELECT * FROM activities WHERE username = ? ORDER BY created_at DESC LIMIT ?', [username, limit])
    .map(row => ({
      ...row,
      raw: JSON.parse(row.raw)
    }))
}

// Posts

export function savePost(username, id, content, inReplyTo = null) {
  runStmt(
    'INSERT INTO posts (id, username, content, in_reply_to) VALUES (?, ?, ?, ?)',
    [id, username, content, inReplyTo]
  )
}

export function getPosts(username, limit = 20) {
  return getAll('SELECT * FROM posts WHERE username = ? ORDER BY published DESC LIMIT ?', [username, limit])
}

export function getPost(username, id) {
  return getOne('SELECT * FROM posts WHERE id = ? AND username = ?', [id, username])
}

export function getPostById(id) {
  return getOne('SELECT * FROM posts WHERE id = ?', [id])
}

export function updatePost(username, id, content) {
  runStmt('UPDATE posts SET content = ? WHERE id = ? AND username = ?', [content, id, username])
}

export function getPostCount(username) {
  const row = getOne('SELECT COUNT(*) as count FROM posts WHERE username = ?', [username])
  return row ? row.count : 0
}

// Actor cache (global — not per-user)

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
  getPostById,
  updatePost,
  getPostCount,
  cacheActor,
  getCachedActor
}
