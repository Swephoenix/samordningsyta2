const path = require("path");
const crypto = require("crypto");
const express = require("express");
const cookieParser = require("cookie-parser");
const Database = require("better-sqlite3");

const app = express();
const PORT = Number(process.env.PORT || 8000);
const DB_PATH = path.join(__dirname, "app.db");
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7;
const ONLINE_WINDOW_SECONDS = 20;
const PBKDF2_ITERATIONS = 240000;
const SESSION_COOKIE = "session_token";

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  iterations INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS notes (
  user_id INTEGER PRIMARY KEY,
  content TEXT NOT NULL DEFAULT '',
  updated_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS chat_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  message TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS chat_reads (
  user_id INTEGER PRIMARY KEY,
  last_read_message_id INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS direct_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id INTEGER NOT NULL,
  recipient_id INTEGER NOT NULL,
  message TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  read_at INTEGER,
  FOREIGN KEY(sender_id) REFERENCES users(id),
  FOREIGN KEY(recipient_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS chat_groups (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_by INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS chat_group_members (
  group_id TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  joined_at INTEGER NOT NULL,
  PRIMARY KEY(group_id, user_id),
  FOREIGN KEY(group_id) REFERENCES chat_groups(id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS chat_group_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  group_id TEXT NOT NULL,
  sender_id INTEGER NOT NULL,
  message TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(group_id) REFERENCES chat_groups(id),
  FOREIGN KEY(sender_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS chat_group_reads (
  group_id TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  last_read_message_id INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(group_id, user_id),
  FOREIGN KEY(group_id) REFERENCES chat_groups(id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS chat_group_invites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  group_id TEXT NOT NULL,
  inviter_id INTEGER NOT NULL,
  invitee_id INTEGER NOT NULL,
  token TEXT UNIQUE NOT NULL,
  created_at INTEGER NOT NULL,
  accepted_at INTEGER,
  FOREIGN KEY(group_id) REFERENCES chat_groups(id),
  FOREIGN KEY(inviter_id) REFERENCES users(id),
  FOREIGN KEY(invitee_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  date_key TEXT NOT NULL,
  title TEXT NOT NULL,
  link TEXT,
  created_by INTEGER,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(created_by) REFERENCES users(id)
);
`);

db.exec(`
CREATE INDEX IF NOT EXISTS idx_sessions_user_activity
  ON sessions(user_id, expires_at, last_seen_at);

CREATE INDEX IF NOT EXISTS idx_events_date_key
  ON events(date_key);

CREATE INDEX IF NOT EXISTS idx_direct_messages_sender_recipient_created
  ON direct_messages(sender_id, recipient_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_direct_messages_recipient_sender_created
  ON direct_messages(recipient_id, sender_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_direct_messages_recipient_sender_read
  ON direct_messages(recipient_id, sender_id, read_at);

CREATE INDEX IF NOT EXISTS idx_chat_group_members_user_group
  ON chat_group_members(user_id, group_id);

CREATE INDEX IF NOT EXISTS idx_chat_group_messages_group_id
  ON chat_group_messages(group_id, id DESC);
`);

function nowTs() {
  return Math.floor(Date.now() / 1000);
}

function localDateKey(date = new Date()) {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, "0");
  const d = String(date.getDate()).padStart(2, "0");
  return `${y}-${m}-${d}`;
}

function hashPassword(password, saltHex, iterations) {
  return crypto
    .pbkdf2Sync(password, Buffer.from(saltHex, "hex"), iterations, 32, "sha256")
    .toString("hex");
}

function ensureDefaultUser(email, password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const passwordHash = hashPassword(password, salt, PBKDF2_ITERATIONS);
  db.prepare(
    `INSERT INTO users(email, password_hash, salt, iterations, created_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(email) DO NOTHING`
  ).run(email, passwordHash, salt, PBKDF2_ITERATIONS, nowTs());
}

function seedEventsIfEmpty() {
  const count = db.prepare("SELECT COUNT(*) AS c FROM events").get().c;
  if (count > 0) return;

  const today = new Date();
  const todayKey = localDateKey(today);
  const thisMonth = String(today.getMonth() + 1).padStart(2, "0");
  const thisYear = today.getFullYear();
  const extraDate = `${thisYear}-${thisMonth}-24`;
  const extraDate2 = `${thisYear}-${thisMonth}-31`;

  const ins = db.prepare(
    "INSERT INTO events(date_key, title, link, created_by, created_at) VALUES (?, ?, ?, ?, ?)"
  );

  ins.run(todayKey, "Veckomöte Team Alpha", "https://zoom.us/j/12345", null, nowTs());
  ins.run(todayKey, "Kundavstämning (Zoom)", "https://zoom.us/j/67890", null, nowTs());
  ins.run(todayKey, "Designreview", "https://zoom.us/j/24680", null, nowTs());
  ins.run(extraDate, "Projektgenomgång", "https://zoom.us/j/11111", null, nowTs());
  ins.run(extraDate2, "Månadsavslut", "https://zoom.us/j/22222", null, nowTs());
}

function ensureColumn(table, column, ddl) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  const exists = cols.some((c) => c.name === column);
  if (!exists) db.exec(`ALTER TABLE ${table} ADD COLUMN ${ddl}`);
}

ensureColumn("sessions", "last_seen_at", "last_seen_at INTEGER NOT NULL DEFAULT 0");

ensureDefaultUser("admin", "admin");
ensureDefaultUser("user1", "user1");
ensureDefaultUser("user2", "user2");
seedEventsIfEmpty();

app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());
app.use(express.static(__dirname));

function createSession(userId) {
  const token = crypto.randomBytes(48).toString("base64url");
  const expiresAt = nowTs() + SESSION_TTL_SECONDS;
  db.prepare(
    "INSERT INTO sessions(token, user_id, expires_at, last_seen_at, created_at) VALUES (?, ?, ?, ?, ?)"
  ).run(token, userId, expiresAt, nowTs(), nowTs());
  return token;
}

function getUserFromSession(req) {
  const token = req.cookies[SESSION_COOKIE];
  if (!token) return null;

  const row = db
    .prepare(
      `SELECT u.id, u.email, u.created_at, s.expires_at, s.token
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.token = ?`
    )
    .get(token);

  if (!row) return null;
  if (row.expires_at <= nowTs()) {
    db.prepare("DELETE FROM sessions WHERE token = ?").run(token);
    return null;
  }

  return {
    id: row.id,
    email: row.email,
    created_at: row.created_at,
    token: row.token
  };
}

function setSessionCookie(res, token) {
  res.cookie(SESSION_COOKIE, token, {
    maxAge: SESSION_TTL_SECONDS * 1000,
    httpOnly: true,
    sameSite: "lax",
    path: "/"
  });
}

function clearSessionCookie(res) {
  res.clearCookie(SESSION_COOKIE, {
    httpOnly: true,
    sameSite: "lax",
    path: "/"
  });
}

function requireAuth(req, res) {
  const user = getUserFromSession(req);
  if (!user) {
    res.status(401).json({ error: "Inte inloggad." });
    return null;
  }
  db.prepare("UPDATE sessions SET last_seen_at = ? WHERE token = ?").run(nowTs(), user.token);
  return user;
}

function isAdmin(user) {
  return String(user.email || "").toLowerCase() === "admin";
}

app.post("/api/register", (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");

  if (!email || email.length < 2) {
    return res.status(400).json({ error: "Ogiltigt användarnamn/e-post." });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: "Lösenord måste vara minst 8 tecken." });
  }

  const salt = crypto.randomBytes(16).toString("hex");
  const passwordHash = hashPassword(password, salt, PBKDF2_ITERATIONS);

  try {
    const result = db
      .prepare(
        `INSERT INTO users(email, password_hash, salt, iterations, created_at)
         VALUES (?, ?, ?, ?, ?)`
      )
      .run(email, passwordHash, salt, PBKDF2_ITERATIONS, nowTs());

    const token = createSession(result.lastInsertRowid);
    setSessionCookie(res, token);
    return res.status(201).json({ ok: true, email });
  } catch (err) {
    if (String(err.message).includes("UNIQUE")) {
      return res.status(409).json({ error: "Användarnamnet/e-postadressen är redan registrerad." });
    }
    return res.status(500).json({ error: "Internt serverfel." });
  }
});

app.post("/api/login", (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");

  if (!email || !password) {
    return res.status(400).json({ error: "Användarnamn/e-post och lösenord krävs." });
  }

  const user = db
    .prepare("SELECT id, email, password_hash, salt, iterations FROM users WHERE email = ?")
    .get(email);

  if (!user) {
    return res.status(401).json({ error: "Fel användarnamn/e-post eller lösenord." });
  }

  const candidateHash = hashPassword(password, user.salt, user.iterations);
  const ok = crypto.timingSafeEqual(
    Buffer.from(candidateHash, "hex"),
    Buffer.from(user.password_hash, "hex")
  );

  if (!ok) {
    return res.status(401).json({ error: "Fel användarnamn/e-post eller lösenord." });
  }

  const token = createSession(user.id);
  setSessionCookie(res, token);
  return res.json({ ok: true, email: user.email });
});

app.post("/api/logout", (req, res) => {
  const token = req.cookies[SESSION_COOKIE];
  if (token) {
    db.prepare("DELETE FROM sessions WHERE token = ?").run(token);
  }
  clearSessionCookie(res);
  return res.json({ ok: true });
});

app.get("/api/me", (req, res) => {
  const user = getUserFromSession(req);
  if (!user) {
    return res.status(401).json({ error: "Inte inloggad." });
  }
  return res.json({
    id: user.id,
    email: user.email,
    created_at: user.created_at,
    is_admin: isAdmin(user)
  });
});

app.get("/api/users", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const activeSince = nowTs() - ONLINE_WINDOW_SECONDS;
  const rows = db
    .prepare(
      `SELECT u.id, u.email,
              CASE
                WHEN EXISTS (
                  SELECT 1
                  FROM sessions s
                  WHERE s.user_id = u.id
                    AND s.expires_at > ?
                    AND s.last_seen_at >= ?
                ) THEN 1 ELSE 0
              END AS is_online
       FROM users u
       WHERE u.id != ?
       ORDER BY u.email ASC`
    )
    .all(nowTs(), activeSince, user.id);

  return res.json({
    users: rows.map((r) => ({
      id: r.id,
      email: r.email,
      online: !!r.is_online
    }))
  });
});

app.get("/api/messenger/threads", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const activeSince = nowTs() - ONLINE_WINDOW_SECONDS;
  const rows = db
    .prepare(
      `SELECT
         u.id,
         u.email,
         CASE
           WHEN EXISTS (
             SELECT 1
             FROM sessions s
             WHERE s.user_id = u.id
               AND s.expires_at > ?
               AND s.last_seen_at >= ?
           ) THEN 1 ELSE 0
         END AS is_online,
         (
           SELECT dm.message
           FROM direct_messages dm
           WHERE (dm.sender_id = u.id AND dm.recipient_id = ?)
              OR (dm.sender_id = ? AND dm.recipient_id = u.id)
           ORDER BY dm.created_at DESC, dm.id DESC
           LIMIT 1
         ) AS last_message_text,
         (
           SELECT dm.created_at
           FROM direct_messages dm
           WHERE (dm.sender_id = u.id AND dm.recipient_id = ?)
              OR (dm.sender_id = ? AND dm.recipient_id = u.id)
           ORDER BY dm.created_at DESC, dm.id DESC
           LIMIT 1
         ) AS last_message_at,
         (
           SELECT dm.sender_id
           FROM direct_messages dm
           WHERE (dm.sender_id = u.id AND dm.recipient_id = ?)
              OR (dm.sender_id = ? AND dm.recipient_id = u.id)
           ORDER BY dm.created_at DESC, dm.id DESC
           LIMIT 1
         ) AS last_sender_id,
         (
           SELECT COUNT(*)
           FROM direct_messages dm
           WHERE dm.sender_id = u.id
             AND dm.recipient_id = ?
             AND dm.read_at IS NULL
         ) AS unread_count
       FROM users u
       WHERE u.id != ?
       ORDER BY COALESCE(last_message_at, 0) DESC, u.email ASC`
    )
    .all(
      nowTs(),
      activeSince,
      user.id,
      user.id,
      user.id,
      user.id,
      user.id,
      user.id,
      user.id,
      user.id
    );

  const groupRows = db
    .prepare(
      `SELECT
         g.id,
         g.name,
         (
           SELECT gm.message
           FROM chat_group_messages gm
           WHERE gm.group_id = g.id
           ORDER BY gm.id DESC
           LIMIT 1
         ) AS last_message_text,
         (
           SELECT gm.created_at
           FROM chat_group_messages gm
           WHERE gm.group_id = g.id
           ORDER BY gm.id DESC
           LIMIT 1
         ) AS last_message_at,
         (
           SELECT gm.sender_id
           FROM chat_group_messages gm
           WHERE gm.group_id = g.id
           ORDER BY gm.id DESC
           LIMIT 1
         ) AS last_sender_id,
         (
           SELECT COUNT(*)
           FROM chat_group_members gm
           WHERE gm.group_id = g.id
         ) AS member_count,
         (
           SELECT COUNT(*)
           FROM chat_group_messages gm
           WHERE gm.group_id = g.id
             AND gm.id > COALESCE((
               SELECT gr.last_read_message_id
               FROM chat_group_reads gr
               WHERE gr.group_id = g.id
                 AND gr.user_id = ?
             ), 0)
             AND gm.sender_id != ?
         ) AS unread_count
       FROM chat_groups g
       JOIN chat_group_members m ON m.group_id = g.id
       WHERE m.user_id = ?`
    )
    .all(user.id, user.id, user.id);

  const directThreads = rows.map((r) => ({
    kind: "direct",
    id: String(r.id),
    email: r.email,
    name: r.email,
    online: !!r.is_online,
    unread_count: Number(r.unread_count || 0),
    last_message_text: r.last_message_text || "",
    last_message_at: r.last_message_at ? Number(r.last_message_at) : null,
    last_message_from_me: Number(r.last_sender_id || 0) === user.id
  }));

  const groupThreads = groupRows.map((g) => ({
    kind: "group",
    id: String(g.id),
    name: g.name,
    online: true,
    member_count: Number(g.member_count || 0),
    unread_count: Number(g.unread_count || 0),
    last_message_text: g.last_message_text || "",
    last_message_at: g.last_message_at ? Number(g.last_message_at) : null,
    last_message_from_me: Number(g.last_sender_id || 0) === user.id
  }));

  return res.json({ threads: directThreads.concat(groupThreads) });
});

app.get("/api/messenger/messages/:userId", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const otherUserId = Number(req.params.userId);
  if (!Number.isInteger(otherUserId) || otherUserId <= 0 || otherUserId === user.id) {
    return res.status(400).json({ error: "Ogiltig mottagare." });
  }

  const other = db
    .prepare("SELECT id, email FROM users WHERE id = ?")
    .get(otherUserId);
  if (!other) {
    return res.status(404).json({ error: "Användaren hittades inte." });
  }

  const rows = db
    .prepare(
      `SELECT id, sender_id, recipient_id, message, created_at
       FROM (
         SELECT id, sender_id, recipient_id, message, created_at
         FROM direct_messages
         WHERE (sender_id = ? AND recipient_id = ?)
            OR (sender_id = ? AND recipient_id = ?)
         ORDER BY created_at DESC, id DESC
         LIMIT 500
       ) recent
       ORDER BY created_at ASC, id ASC`
    )
    .all(user.id, otherUserId, otherUserId, user.id);

  db.prepare(
    `UPDATE direct_messages
     SET read_at = ?
     WHERE sender_id = ?
       AND recipient_id = ?
       AND read_at IS NULL`
  ).run(nowTs(), otherUserId, user.id);

  return res.json({
    messages: rows.map((m) => ({
      id: m.id,
      text: m.message,
      created_at: m.created_at,
      from_me: m.sender_id === user.id
    }))
  });
});

app.post("/api/messenger/messages", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const recipientId = Number(req.body?.recipient_id);
  const message = String(req.body?.message || "").trim();

  if (!Number.isInteger(recipientId) || recipientId <= 0 || recipientId === user.id) {
    return res.status(400).json({ error: "Ogiltig mottagare." });
  }
  if (!message) {
    return res.status(400).json({ error: "Meddelandet är tomt." });
  }
  if (message.length > 2000) {
    return res.status(400).json({ error: "Meddelandet är för långt." });
  }

  const recipient = db
    .prepare("SELECT id FROM users WHERE id = ?")
    .get(recipientId);
  if (!recipient) {
    return res.status(404).json({ error: "Mottagaren hittades inte." });
  }

  db.prepare(
    "INSERT INTO direct_messages(sender_id, recipient_id, message, created_at, read_at) VALUES (?, ?, ?, ?, NULL)"
  ).run(user.id, recipientId, message, nowTs());

  return res.status(201).json({ ok: true });
});

app.get("/api/messenger/groups/:groupId/messages", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const groupId = String(req.params.groupId || "").trim();
  if (!groupId) {
    return res.status(400).json({ error: "Ogiltigt grupp-id." });
  }

  const membership = db
    .prepare("SELECT 1 FROM chat_group_members WHERE group_id = ? AND user_id = ?")
    .get(groupId, user.id);
  if (!membership) {
    return res.status(403).json({ error: "Du är inte medlem i gruppen." });
  }

  const rows = db
    .prepare(
      `SELECT gm.id, gm.message, gm.created_at, gm.sender_id, u.email
       FROM (
         SELECT id, message, created_at, sender_id
         FROM chat_group_messages
         WHERE group_id = ?
         ORDER BY id DESC
         LIMIT 500
       ) gm
       JOIN users u ON u.id = gm.sender_id
       ORDER BY gm.id ASC`
    )
    .all(groupId);

  const latestId = rows.length ? Number(rows[rows.length - 1].id) : 0;
  db.prepare(
    `INSERT INTO chat_group_reads(group_id, user_id, last_read_message_id, updated_at)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(group_id, user_id) DO UPDATE SET
       last_read_message_id = excluded.last_read_message_id,
       updated_at = excluded.updated_at`
  ).run(groupId, user.id, latestId, nowTs());

  return res.json({
    messages: rows.map((m) => ({
      id: m.id,
      text: m.message,
      created_at: m.created_at,
      from_me: Number(m.sender_id) === user.id,
      sender_email: m.email
    }))
  });
});

app.post("/api/messenger/groups/:groupId/messages", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const groupId = String(req.params.groupId || "").trim();
  const message = String(req.body?.message || "").trim();
  if (!groupId) {
    return res.status(400).json({ error: "Ogiltigt grupp-id." });
  }
  if (!message) {
    return res.status(400).json({ error: "Meddelandet är tomt." });
  }
  if (message.length > 2000) {
    return res.status(400).json({ error: "Meddelandet är för långt." });
  }

  const membership = db
    .prepare("SELECT 1 FROM chat_group_members WHERE group_id = ? AND user_id = ?")
    .get(groupId, user.id);
  if (!membership) {
    return res.status(403).json({ error: "Du är inte medlem i gruppen." });
  }

  db.prepare(
    "INSERT INTO chat_group_messages(group_id, sender_id, message, created_at) VALUES (?, ?, ?, ?)"
  ).run(groupId, user.id, message, nowTs());

  return res.status(201).json({ ok: true });
});

app.post("/api/messenger/groups", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const name = String(req.body?.name || "").trim();
  const inviteeIdsRaw = Array.isArray(req.body?.invitee_ids) ? req.body.invitee_ids : [];
  const inviteeIds = [...new Set(inviteeIdsRaw.map((x) => Number(x)).filter((x) => Number.isInteger(x) && x > 0 && x !== user.id))];

  if (!name) {
    return res.status(400).json({ error: "Gruppnamn krävs." });
  }
  if (!inviteeIds.length) {
    return res.status(400).json({ error: "Välj minst en användare." });
  }

  const validInvitees = db
    .prepare(
      `SELECT id, email
       FROM users
       WHERE id IN (${inviteeIds.map(() => "?").join(",")})`
    )
    .all(...inviteeIds);
  if (!validInvitees.length) {
    return res.status(400).json({ error: "Inga giltiga användare valdes." });
  }

  const groupId = "grp_" + crypto.randomBytes(6).toString("hex");
  const now = nowTs();

  const tx = db.transaction(() => {
    db.prepare(
      "INSERT INTO chat_groups(id, name, created_by, created_at) VALUES (?, ?, ?, ?)"
    ).run(groupId, name, user.id, now);

    db.prepare(
      "INSERT INTO chat_group_members(group_id, user_id, joined_at) VALUES (?, ?, ?)"
    ).run(groupId, user.id, now);

    for (const invitee of validInvitees) {
      const token = crypto.randomBytes(16).toString("hex");
      db.prepare(
        "INSERT INTO chat_group_invites(group_id, inviter_id, invitee_id, token, created_at, accepted_at) VALUES (?, ?, ?, ?, ?, NULL)"
      ).run(groupId, user.id, invitee.id, token, now);

      const link = `${req.protocol}://${req.get("host")}/group-invite/${groupId}?token=${token}`;
      const message = `Du är inbjuden till gruppen "${name}". Gå med via länken: ${link}`;
      db.prepare(
        "INSERT INTO direct_messages(sender_id, recipient_id, message, created_at, read_at) VALUES (?, ?, ?, ?, NULL)"
      ).run(user.id, invitee.id, message, now);
    }
  });
  tx();

  return res.status(201).json({ ok: true, group_id: groupId, name });
});

app.post("/api/messenger/invites/accept", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const groupId = String(req.body?.group_id || "").trim();
  const token = String(req.body?.token || "").trim();
  if (!groupId || !token) {
    return res.status(400).json({ error: "Ogiltig inbjudan." });
  }

  const invite = db
    .prepare(
      `SELECT id, accepted_at
       FROM chat_group_invites
       WHERE group_id = ?
         AND token = ?
         AND invitee_id = ?`
    )
    .get(groupId, token, user.id);

  if (!invite) {
    return res.status(404).json({ error: "Inbjudan hittades inte." });
  }

  const now = nowTs();
  const tx = db.transaction(() => {
    db.prepare(
      "INSERT INTO chat_group_members(group_id, user_id, joined_at) VALUES (?, ?, ?) ON CONFLICT(group_id, user_id) DO NOTHING"
    ).run(groupId, user.id, now);
    if (!invite.accepted_at) {
      db.prepare("UPDATE chat_group_invites SET accepted_at = ? WHERE id = ?").run(now, invite.id);
    }
  });
  tx();

  return res.json({ ok: true, group_id: groupId });
});

app.get("/api/notes/me", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const note = db
    .prepare("SELECT content, updated_at FROM notes WHERE user_id = ?")
    .get(user.id);

  return res.json({
    content: note?.content || "",
    updated_at: note?.updated_at || null
  });
});

app.put("/api/notes/me", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const content = String(req.body?.content || "");
  db.prepare(
    `INSERT INTO notes(user_id, content, updated_at)
     VALUES (?, ?, ?)
     ON CONFLICT(user_id) DO UPDATE SET
       content = excluded.content,
       updated_at = excluded.updated_at`
  ).run(user.id, content, nowTs());

  return res.json({ ok: true });
});

app.get("/api/chat/messages", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const limitRaw = Number(req.query.limit || 100);
  const limit = Math.max(1, Math.min(limitRaw, 500));

  const rows = db
    .prepare(
      `SELECT m.id, m.message, m.created_at, u.email
       FROM chat_messages m
       JOIN users u ON u.id = m.user_id
       ORDER BY m.id DESC
       LIMIT ?`
    )
    .all(limit)
    .reverse();

  const latestMessageId = rows.length ? rows[rows.length - 1].id : 0;
  db.prepare(
    `INSERT INTO chat_reads(user_id, last_read_message_id, updated_at)
     VALUES (?, ?, ?)
     ON CONFLICT(user_id) DO UPDATE SET
       last_read_message_id = excluded.last_read_message_id,
       updated_at = excluded.updated_at`
  ).run(user.id, latestMessageId, nowTs());

  const readRows = db
    .prepare(
      `SELECT r.user_id, r.last_read_message_id, u.email
       FROM chat_reads r
       JOIN users u ON u.id = r.user_id`
    )
    .all();

  const messages = rows.map((m) => {
    const seenBy = readRows
      .filter((r) => r.last_read_message_id >= m.id)
      .map((r) => r.email);
    return {
      ...m,
      seen_by: seenBy,
      seen_count: seenBy.length
    };
  });

  return res.json({ messages, current_user_email: user.email });
});

app.post("/api/chat/messages", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const message = String(req.body?.message || "").trim();
  if (!message) {
    return res.status(400).json({ error: "Meddelandet är tomt." });
  }
  if (message.length > 2000) {
    return res.status(400).json({ error: "Meddelandet är för långt." });
  }

  db.prepare("INSERT INTO chat_messages(user_id, message, created_at) VALUES (?, ?, ?)").run(
    user.id,
    message,
    nowTs()
  );

  return res.status(201).json({ ok: true });
});

app.get("/api/chat/presence", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const activeSince = nowTs() - ONLINE_WINDOW_SECONDS;
  const online = db
    .prepare(
      `SELECT DISTINCT u.email
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.expires_at > ? AND s.last_seen_at >= ?
       ORDER BY u.email ASC`
    )
    .all(nowTs(), activeSince)
    .map((r) => r.email);

  return res.json({
    online_users: online,
    online_count: online.length
  });
});

app.get("/api/events", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const year = Number(req.query.year);
  const month = Number(req.query.month);
  if (!Number.isInteger(year) || !Number.isInteger(month) || month < 1 || month > 12) {
    return res.status(400).json({ error: "Ogiltig månad eller år." });
  }

  const yyyymm = `${year}-${String(month).padStart(2, "0")}`;
  const rows = db
    .prepare(
      `SELECT id, date_key, title, link
       FROM events
       WHERE substr(date_key, 1, 7) = ?
       ORDER BY date_key ASC, id ASC`
    )
    .all(yyyymm);

  return res.json({ events: rows });
});

app.get("/api/meetings/today", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const todayKey = localDateKey();
  const rows = db
    .prepare(
      `SELECT id, date_key, title, link
       FROM events
       WHERE date_key = ?
       ORDER BY id ASC`
    )
    .all(todayKey);

  return res.json({ date_key: todayKey, meetings: rows });
});

app.post("/api/events", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!isAdmin(user)) {
    return res.status(403).json({ error: "Endast admin kan skapa möten." });
  }

  const dateKey = String(req.body?.date_key || "").trim();
  const title = String(req.body?.title || "").trim();
  const link = String(req.body?.link || "").trim();

  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateKey)) {
    return res.status(400).json({ error: "Ogiltigt datumformat. Använd YYYY-MM-DD." });
  }
  if (!title) {
    return res.status(400).json({ error: "Titel krävs." });
  }

  const result = db
    .prepare("INSERT INTO events(date_key, title, link, created_by, created_at) VALUES (?, ?, ?, ?, ?)")
    .run(dateKey, title, link || null, user.id, nowTs());

  return res.status(201).json({ ok: true, id: result.lastInsertRowid });
});

app.put("/api/events/:id", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!isAdmin(user)) {
    return res.status(403).json({ error: "Endast admin kan redigera möten." });
  }

  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "Ogiltigt event-id." });
  }

  const dateKey = String(req.body?.date_key || "").trim();
  const title = String(req.body?.title || "").trim();
  const link = String(req.body?.link || "").trim();

  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateKey)) {
    return res.status(400).json({ error: "Ogiltigt datumformat. Använd YYYY-MM-DD." });
  }
  if (!title) {
    return res.status(400).json({ error: "Titel krävs." });
  }

  const result = db
    .prepare("UPDATE events SET date_key = ?, title = ?, link = ? WHERE id = ?")
    .run(dateKey, title, link || null, id);

  if (result.changes === 0) {
    return res.status(404).json({ error: "Mötet hittades inte." });
  }
  return res.json({ ok: true });
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "login.html"));
});

app.get("/group-invite/:groupId", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, () => {
  console.log(`Server started on http://localhost:${PORT}`);
});
