/**
 * ActivityPub SQLite Storage
 * Persistence layer for federation data
 */

import Database from 'better-sqlite3'
import { existsSync, mkdirSync } from 'fs'
import { dirname } from 'path'

let db = null

/**
 * Initialize the database
 * @param {string} path - Path to SQLite file
 */
export function initStore(path = 'data/activitypub.db') {
  // Ensure directory exists
  const dir = dirname(path)
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true })
  }

  db = new Database(path)

  // Create tables
  db.exec(`
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
  `)

  return db
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

// Followers

export function addFollower(actorId, inbox) {
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO followers (id, actor, inbox)
    VALUES (?, ?, ?)
  `)
  stmt.run(actorId, actorId, inbox)
}

export function removeFollower(actorId) {
  const stmt = db.prepare('DELETE FROM followers WHERE id = ?')
  stmt.run(actorId)
}

export function getFollowers() {
  const stmt = db.prepare('SELECT * FROM followers ORDER BY created_at DESC')
  return stmt.all()
}

export function getFollowerCount() {
  const stmt = db.prepare('SELECT COUNT(*) as count FROM followers')
  return stmt.get().count
}

export function getFollowerInboxes() {
  const stmt = db.prepare('SELECT DISTINCT inbox FROM followers WHERE inbox IS NOT NULL')
  return stmt.all().map(row => row.inbox)
}

// Following

export function addFollowing(actorId, accepted = false) {
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO following (id, actor, accepted)
    VALUES (?, ?, ?)
  `)
  stmt.run(actorId, actorId, accepted ? 1 : 0)
}

export function acceptFollowing(actorId) {
  const stmt = db.prepare('UPDATE following SET accepted = 1 WHERE id = ?')
  stmt.run(actorId)
}

export function removeFollowing(actorId) {
  const stmt = db.prepare('DELETE FROM following WHERE id = ?')
  stmt.run(actorId)
}

export function getFollowing() {
  const stmt = db.prepare('SELECT * FROM following WHERE accepted = 1 ORDER BY created_at DESC')
  return stmt.all()
}

export function getFollowingCount() {
  const stmt = db.prepare('SELECT COUNT(*) as count FROM following WHERE accepted = 1')
  return stmt.get().count
}

// Activities

export function saveActivity(activity) {
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO activities (id, type, actor, object, raw)
    VALUES (?, ?, ?, ?, ?)
  `)
  stmt.run(
    activity.id,
    activity.type,
    typeof activity.actor === 'string' ? activity.actor : activity.actor?.id,
    typeof activity.object === 'string' ? activity.object : JSON.stringify(activity.object),
    JSON.stringify(activity)
  )
}

export function getActivities(limit = 20) {
  const stmt = db.prepare('SELECT * FROM activities ORDER BY created_at DESC LIMIT ?')
  return stmt.all(limit).map(row => ({
    ...row,
    raw: JSON.parse(row.raw)
  }))
}

// Posts

export function savePost(id, content, inReplyTo = null) {
  const stmt = db.prepare(`
    INSERT INTO posts (id, content, in_reply_to)
    VALUES (?, ?, ?)
  `)
  stmt.run(id, content, inReplyTo)
}

export function getPosts(limit = 20) {
  const stmt = db.prepare('SELECT * FROM posts ORDER BY published DESC LIMIT ?')
  return stmt.all(limit)
}

export function getPost(id) {
  const stmt = db.prepare('SELECT * FROM posts WHERE id = ?')
  return stmt.get(id)
}

export function getPostCount() {
  const stmt = db.prepare('SELECT COUNT(*) as count FROM posts')
  return stmt.get().count
}

// Actor cache

export function cacheActor(actor) {
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO actors (id, data, fetched_at)
    VALUES (?, ?, CURRENT_TIMESTAMP)
  `)
  stmt.run(actor.id, JSON.stringify(actor))
}

export function getCachedActor(id) {
  const stmt = db.prepare('SELECT * FROM actors WHERE id = ?')
  const row = stmt.get(id)
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
