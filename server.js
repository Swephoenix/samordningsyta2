const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const net = require("net");
const tls = require("tls");
const express = require("express");
const cookieParser = require("cookie-parser");
const Database = require("better-sqlite3");

function loadEnvFromFile(filePath, override) {
  if (!fs.existsSync(filePath)) return;
  const content = fs.readFileSync(filePath, "utf8");
  content.split(/\r?\n/).forEach((line) => {
    const trimmed = String(line || "").trim();
    if (!trimmed || trimmed.startsWith("#")) return;
    const idx = trimmed.indexOf("=");
    if (idx <= 0) return;
    const key = trimmed.slice(0, idx).trim();
    let val = trimmed.slice(idx + 1).trim();
    if (
      (val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))
    ) {
      val = val.slice(1, -1);
    }
    if (!override && process.env[key] !== undefined) return;
    process.env[key] = val;
  });
}

loadEnvFromFile(path.join(__dirname, ".env.example"), false);
loadEnvFromFile(path.join(__dirname, ".env"), true);

const app = express();
const PORT = Number(process.env.PORT || 8000);
const DB_PATH = path.join(__dirname, "data", "app.db");
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7;
const PASSWORD_RESET_TTL_SECONDS = 60 * 30;
const PASSWORD_RESET_RATE_LIMIT_WINDOW_SECONDS = 60 * 10;
const PASSWORD_RESET_RATE_LIMIT_MAX_ATTEMPTS = 5;
const LOGIN_RATE_LIMIT_WINDOW_SECONDS = 60 * 10;
const LOGIN_RATE_LIMIT_MAX_ATTEMPTS = 10;
const ONLINE_WINDOW_SECONDS = 20;
const PBKDF2_ITERATIONS = 240000;
const SESSION_COOKIE = "session_token";
const UPLOAD_DIR = path.join(__dirname, "uploads", "chat");
const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;
const REGISTER_ALLOWED_DOMAIN = "@ambitionsverige.se";
const FORCED_SMTP_IDENTITY = "mail@ambitionsverige.se";
const passwordResetRateLimit = new Map();
const loginRateLimit = new Map();
const REGISTER_ANIMAL_NAMES = [
  "Räven",
  "Ugglan",
  "Björnen",
  "Vargen",
  "Lodjuret",
  "Örnen",
  "Ekorren",
  "Renen",
  "Sälen",
  "Haren",
  "Älgen",
  "Tigern",
  "Lejonet",
  "Falken",
  "Uttern",
  "Delfinen",
  "Valen",
  "Svanen",
  "Hjorten",
  "Pantern"
];
const REGISTER_CITIES = [
  "Avesta",
  "Blekinge/Sölvesborg",
  "Boden",
  "Borlänge",
  "Borås",
  "Eskilstuna",
  "Falköping",
  "Gislaved",
  "Gotland",
  "Göteborg",
  "Halmstad",
  "Heby",
  "Hedemora",
  "Helsingborg",
  "Härjedalen",
  "Härnösand",
  "Hässleholm",
  "Högsby",
  "Hörby",
  "Jämtland",
  "Jönköping",
  "Kalmar",
  "Kramfors",
  "Kungsbacka",
  "Kungälv",
  "Leksand",
  "Lidköping",
  "Ljusdal",
  "Malmö",
  "Malå",
  "Motala",
  "Norrköping",
  "Nynäshamn",
  "Nässjö",
  "Osby",
  "Oskarshamn",
  "Ovanåker",
  "Ramsberg",
  "Roslagen",
  "Sala",
  "Sjuhärad",
  "Skellefteå",
  "Skåne östra",
  "Stenungsund",
  "Stockholm Farsta",
  "Stockholm Norra",
  "Stockholm Sollentuna",
  "Stockholm Täby",
  "Storuman",
  "Strängnäs",
  "Sundsvall",
  "Söderköping",
  "Södertälje",
  "Södra Lappland",
  "Trollhättan",
  "Umeå",
  "Uppsala",
  "Valdemarsvik",
  "Vetlanda",
  "Värmland Norra",
  "Värmland Södra",
  "Värnamo",
  "Västerås",
  "Västra Götaland Norra",
  "Ystad",
  "Ängelholm",
  "Örebro",
  "Örnsköldsvik"
];

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

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

CREATE TABLE IF NOT EXISTS important_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  icon TEXT NOT NULL DEFAULT '📢',
  text TEXT NOT NULL,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_by INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY(created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS app_data (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS qna_questions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  question TEXT NOT NULL,
  image_url TEXT,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS qna_answers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  question_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  answer TEXT NOT NULL,
  image_url TEXT,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(question_id) REFERENCES qna_questions(id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS idea_bank_ideas (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  tag TEXT NOT NULL DEFAULT 'Ny',
  image_url TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token_hash TEXT UNIQUE NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
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

CREATE INDEX IF NOT EXISTS idx_qna_questions_created
  ON qna_questions(created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_qna_answers_question_created
  ON qna_answers(question_id, created_at ASC, id ASC);

CREATE INDEX IF NOT EXISTS idx_idea_bank_ideas_created
  ON idea_bank_ideas(created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_exp
  ON password_reset_tokens(user_id, expires_at);
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

function hashResetToken(token) {
  return crypto.createHash("sha256").update(String(token || "")).digest("hex");
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

function getConfiguredAdminIdentifier() {
  const fromEmail = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
  const fromUsername = String(process.env.ADMIN_USERNAME || "").trim().toLowerCase();
  if (fromEmail) return fromEmail;
  if (fromUsername) return fromUsername;
  return "admin";
}

function getConfiguredAdminPassword() {
  const fromEnv = String(process.env.ADMIN_PASSWORD || "");
  if (fromEnv) return fromEnv;
  return "admin";
}

function seedEventsIfEmpty() {
  // Seed endast om det uttryckligen aktiverats.
  if (String(process.env.SEED_DEMO_EVENTS || "") !== "1") return;

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

function removeLegacySeededDemoEvents() {
  // Rensa tidigare demo-seedade möten så listor visar enbart verkliga möten.
  const demoPairs = [
    ["Veckomöte Team Alpha", "https://zoom.us/j/12345"],
    ["Kundavstämning (Zoom)", "https://zoom.us/j/67890"],
    ["Designreview", "https://zoom.us/j/24680"],
    ["Projektgenomgång", "https://zoom.us/j/11111"],
    ["Månadsavslut", "https://zoom.us/j/22222"]
  ];
  const delStmt = db.prepare(
    "DELETE FROM events WHERE created_by IS NULL AND title = ? AND IFNULL(link, '') = ?"
  );
  const tx = db.transaction(() => {
    demoPairs.forEach(([title, link]) => {
      delStmt.run(title, link);
    });
  });
  tx();
}

function seedImportantMessagesIfEmpty() {
  const now = nowTs();
  const demoMessages = [
    { icon: "🚨", text: "Systemuppdatering inatt kl 02:00." },
    { icon: "📢", text: "Deadline för Q3-rapporten är på fredag." },
    { icon: "🛠️", text: "Planerat underhåll av filsystemet söndag 09:00-10:00." },
    { icon: "✅", text: "Nya rutiner för delade mappar är nu aktiva." },
    { icon: "🔒", text: "Säkerhetsgranskning genomförs den här veckan." },
    { icon: "🎯", text: "Mål: 100% uppdaterade kundcase innan månadsskifte." }
  ];

  const findByText = db.prepare("SELECT id FROM important_messages WHERE text = ? LIMIT 1");
  const nextSortOrderStmt = db.prepare(
    "SELECT COALESCE(MAX(sort_order), -1) + 1 AS next_order FROM important_messages"
  );
  const insStmt = db.prepare(
    "INSERT INTO important_messages(icon, text, sort_order, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)"
  );
  demoMessages.forEach((msg, idx) => {
    const exists = findByText.get(msg.text);
    if (exists) return;
    const nextOrder = Number(nextSortOrderStmt.get().next_order);
    const sortOrder = Number.isInteger(nextOrder) ? nextOrder : idx;
    insStmt.run(msg.icon, msg.text, sortOrder, null, now, now);
  });
}

function seedIdeaBankIfEmpty() {
  const count = Number(db.prepare("SELECT COUNT(*) AS c FROM idea_bank_ideas").get().c || 0);
  if (count > 0) return;

  const admin = db.prepare("SELECT id FROM users WHERE email = ? LIMIT 1").get("admin");
  const fallbackUser = db.prepare("SELECT id FROM users ORDER BY id ASC LIMIT 1").get();
  const userId = Number((admin && admin.id) || (fallbackUser && fallbackUser.id) || 0);
  if (!userId) return;

  const now = nowTs();
  const rows = [
    {
      title: "Grönare kontor",
      description: "Vi borde införa fler växter och automatisk bevattning för att förbättra luftkvaliteten.",
      tag: "Miljö",
      image_url: "https://images.unsplash.com/photo-1524758631624-e2822e304c36?w=400"
    },
    {
      title: "Digital fika",
      description: "En slumpmässig matchning varje torsdag så fler team lär känna varandra.",
      tag: "Kultur",
      image_url: "https://images.unsplash.com/photo-1517048676732-d65bc937f952?w=400"
    },
    {
      title: "Lånecyklar",
      description: "Erbjud elcyklar som personalen kan låna för kortare ärenden under lunchtid.",
      tag: "Hälsa",
      image_url: "https://images.unsplash.com/photo-1507035895480-2b3156c31fc8?w=400"
    }
  ];

  const ins = db.prepare(
    "INSERT INTO idea_bank_ideas(user_id, title, description, tag, image_url, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
  );
  rows.forEach((row) => {
    ins.run(
      userId,
      row.title,
      row.description,
      row.tag,
      row.image_url,
      now,
      now
    );
  });
}

function ensureColumn(table, column, ddl) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  const exists = cols.some((c) => c.name === column);
  if (!exists) db.exec(`ALTER TABLE ${table} ADD COLUMN ${ddl}`);
}

function defaultFsState() {
  return {
    name: "root",
    type: "folder",
    created_by_email: "admin",
    created_by_admin: true,
    children: {
      "Gemensam mapp": {
        type: "folder",
        created_by_email: "admin",
        created_by_admin: true,
        children: {
          "Projektplan.pdf": {
            type: "file",
            content: "Projektplan version 1.2",
            created_by_email: "admin",
            created_by_admin: true
          },
          "Roadmap.txt": {
            type: "file",
            content: "Q1: Planering\nQ2: Leverans",
            created_by_email: "admin",
            created_by_admin: true
          }
        }
      },
      Privat: {
        type: "folder",
        created_by_email: "admin",
        created_by_admin: true,
        children: {},
        user_homes: {
          admin: {
            type: "folder",
            created_by_email: "admin",
            created_by_admin: true,
            children: {
              "Anteckningar.txt": {
                type: "file",
                content: "Mina privata anteckningar.",
                created_by_email: "admin",
                created_by_admin: true
              }
            }
          }
        }
      },
      "Delat med mig": {
        type: "folder",
        created_by_email: "admin",
        created_by_admin: true,
        children: {},
        user_homes: {}
      }
    }
  };
}

function getAppDataJson(key) {
  const row = db.prepare("SELECT value FROM app_data WHERE key = ?").get(key);
  if (!row) return null;
  try {
    return JSON.parse(row.value);
  } catch (_) {
    return null;
  }
}

function setAppDataJson(key, value) {
  db.prepare(
    `INSERT INTO app_data(key, value, updated_at)
     VALUES (?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET
       value = excluded.value,
       updated_at = excluded.updated_at`
  ).run(key, JSON.stringify(value), nowTs());
}

function ensureFsState() {
  const current = getAppDataJson("fs_state_v1");
  if (current && typeof current === "object") return;
  setAppDataJson("fs_state_v1", defaultFsState());
}

function getAllowRegistrations() {
  const value = getAppDataJson("allow_registrations_v1");
  if (typeof value === "boolean") return value;
  if (value && typeof value === "object" && typeof value.enabled === "boolean") {
    return value.enabled;
  }
  return true;
}

function setAllowRegistrations(allowed) {
  setAppDataJson("allow_registrations_v1", !!allowed);
}

function ensureRegistrationSetting() {
  if (getAppDataJson("allow_registrations_v1") === null) {
    setAllowRegistrations(true);
  }
}

function inferAcademyLinkType(url) {
  const lower = String(url || "").toLowerCase();
  if (!lower) return null;
  if (/\.pdf(?:[?#].*)?$/.test(lower)) return "pdf";
  if (
    /(?:youtube\.com|youtu\.be|vimeo\.com)/.test(lower) ||
    /\.(?:mp4|webm|ogg|mov|m4v)(?:[?#].*)?$/.test(lower)
  ) {
    return "video";
  }
  return null;
}

function isAllowedAcademyUrl(url) {
  const value = String(url || "").trim();
  if (!value) return false;
  if (/^https?:\/\//i.test(value)) return true;
  // Tillåt lokala uppladdade filer från appens chat-uploadmapp.
  if (/^\/uploads\/chat\/[a-zA-Z0-9._-]+(?:[?#].*)?$/.test(value)) return true;
  return false;
}

function isAllowedUploadUrl(url) {
  const value = String(url || "").trim();
  if (!value) return false;
  if (/^\/uploads\/chat\/[a-zA-Z0-9._-]+(?:[?#].*)?$/.test(value)) return true;
  if (/^https?:\/\//i.test(value)) return true;
  return false;
}

function normalizeAcademyLink(row) {
  if (!row || typeof row !== "object") return null;
  const id = String(row.id || "").trim();
  const title = String(row.title || "").trim();
  const url = String(row.url || "").trim();
  const typeRaw = String(row.type || "").trim().toLowerCase();
  const inferredType = inferAcademyLinkType(url);
  const type = typeRaw === "video" || typeRaw === "pdf" ? typeRaw : inferredType;
  if (!id) return null;
  if (!title && !url) return null;
  if (url && !type) return null;
  if (!url && type) return null;
  return {
    id: id,
    title: title.slice(0, 140),
    url: url ? url.slice(0, 2000) : "",
    type: type || "",
    created_at: Number(row.created_at || 0) || nowTs(),
    updated_at: Number(row.updated_at || 0) || nowTs(),
    created_by: Number(row.created_by || 0) || null
  };
}

function getFacebookAcademyLinks() {
  const value = getAppDataJson("facebook_academy_links_v1");
  if (!Array.isArray(value)) return [];
  return value
    .map((row) => normalizeAcademyLink(row))
    .filter(Boolean)
    .sort((a, b) => Number(b.updated_at || 0) - Number(a.updated_at || 0));
}

function setFacebookAcademyLinks(links) {
  const safe = Array.isArray(links)
    ? links.map((row) => normalizeAcademyLink(row)).filter(Boolean)
    : [];
  setAppDataJson("facebook_academy_links_v1", safe);
}

ensureColumn("sessions", "last_seen_at", "last_seen_at INTEGER NOT NULL DEFAULT 0");
ensureColumn("users", "contact_email", "contact_email TEXT");
ensureColumn("users", "city", "city TEXT");
ensureColumn("users", "first_name", "first_name TEXT");
ensureColumn("users", "last_name", "last_name TEXT");
ensureColumn("users", "phone", "phone TEXT");
ensureColumn("qna_questions", "image_url", "image_url TEXT");
ensureColumn("qna_answers", "image_url", "image_url TEXT");

if (String(process.env.NODE_ENV || "").toLowerCase() !== "production") {
  ensureDefaultUser(getConfiguredAdminIdentifier(), getConfiguredAdminPassword());
  ensureDefaultUser("user1", "user1");
  ensureDefaultUser("user2", "user2");
}
seedEventsIfEmpty();
removeLegacySeededDemoEvents();
seedImportantMessagesIfEmpty();
seedIdeaBankIfEmpty();
ensureFsState();
ensureRegistrationSetting();

app.use(express.json({ limit: "15mb" }));
app.use(cookieParser());
app.set("trust proxy", 1);

const PUBLIC_FILE_ROUTES = new Set([
  "index.html",
  "login.html",
  "registrera.html",
  "medlemshantering.html",
  "messenger.html",
  "folder-system.html",
  "facebook.png",
  "fbacademy.png",
  "newgroup.png",
  "qna.png",
  "folder.svg",
  "pdf.svg",
  "text-file.svg"
]);

app.get("/uploads/chat/:fileName", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const fileName = String(req.params.fileName || "").trim();
  if (!/^[a-zA-Z0-9._-]+$/.test(fileName)) {
    return res.status(400).json({ error: "Ogiltigt filnamn." });
  }
  const filePath = path.join(UPLOAD_DIR, fileName);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: "Filen hittades inte." });
  }
  return res.sendFile(filePath);
});

app.get("/:publicFile", (req, res, next) => {
  const publicFile = String(req.params.publicFile || "").trim();
  if (!PUBLIC_FILE_ROUTES.has(publicFile)) return next();
  return res.sendFile(path.join(__dirname, publicFile));
});

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
    secure: process.env.NODE_ENV === "production",
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

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function slugify(value) {
  return String(value || "")
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
}

function makeRandomPassword(length = 14) {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%";
  const bytes = crypto.randomBytes(length);
  let out = "";
  for (let i = 0; i < length; i += 1) {
    out += alphabet[bytes[i] % alphabet.length];
  }
  return out;
}

function generateUniqueUsername() {
  const findExisting = db.prepare("SELECT id FROM users WHERE email = ? LIMIT 1");
  for (let i = 0; i < 5000; i += 1) {
    const animal = REGISTER_ANIMAL_NAMES[Math.floor(Math.random() * REGISTER_ANIMAL_NAMES.length)];
    const number = Math.floor(Math.random() * 90) + 10; // 10-99
    const candidate = `${animal}${number}`;
    const exists = findExisting.get(candidate);
    if (!exists) return candidate;
  }
  for (let i = 0; i < 5000; i += 1) {
    const animal = REGISTER_ANIMAL_NAMES[Math.floor(Math.random() * REGISTER_ANIMAL_NAMES.length)];
    const number = Math.floor(Math.random() * 900) + 100; // 100-999
    const candidate = `${animal}${number}`;
    const exists = findExisting.get(candidate);
    if (!exists) return candidate;
  }
  const tail = crypto.randomBytes(2).toString("hex");
  return `Räven${tail}`;
}

async function sendMailViaSmtp({ toEmail, subject, text }) {
  const smtpHost = String(process.env.SMTP_HOST || "").trim();
  const smtpPort = Number(process.env.SMTP_PORT || 587);
  const smtpPass = String(process.env.SMTP_PASS || "").trim();
  const smtpSecureRaw = String(process.env.SMTP_SECURE || "").trim().toLowerCase();
  const smtpFrom = FORCED_SMTP_IDENTITY;
  const smtpAuthUser = FORCED_SMTP_IDENTITY;
  const smtpSecure = smtpSecureRaw
    ? ["1", "true", "yes", "on"].includes(smtpSecureRaw)
    : smtpPort === 465;

  if (!smtpHost || !smtpPass) {
    throw new Error("SMTP-inställningar saknas i .env/.env.example.");
  }

  function waitForSmtpResponse(socket, timeoutMs = 20000) {
    return new Promise((resolve, reject) => {
      let buffer = "";
      const timer = setTimeout(() => {
        cleanup();
        reject(new Error("SMTP timeout"));
      }, timeoutMs);

      function cleanup() {
        clearTimeout(timer);
        socket.off("data", onData);
        socket.off("error", onErr);
        socket.off("close", onClose);
      }

      function onErr(err) {
        cleanup();
        reject(err);
      }

      function onClose() {
        cleanup();
        reject(new Error("SMTP connection closed"));
      }

      function onData(chunk) {
        buffer += chunk.toString("utf8");
        const lines = buffer.split(/\r?\n/);
        buffer = lines.pop() || "";
        for (const line of lines) {
          const m = line.match(/^(\d{3})([ -])(.*)$/);
          if (!m) continue;
          if (m[2] === " ") {
            cleanup();
            resolve({ code: Number(m[1]), line: line });
            return;
          }
        }
      }

      socket.on("data", onData);
      socket.on("error", onErr);
      socket.on("close", onClose);
    });
  }

  async function smtpCommand(socket, command, allowedCodes) {
    if (command) socket.write(command + "\r\n");
    const resp = await waitForSmtpResponse(socket);
    if (!allowedCodes.includes(resp.code)) {
      throw new Error(`SMTP fel (${resp.code}): ${resp.line}`);
    }
    return resp;
  }

  async function sendViaSocket(socket) {
    await smtpCommand(socket, null, [220]);
    await smtpCommand(socket, "EHLO ambitionsverige.se", [250]);

    if (!smtpSecure) {
      // Prova STARTTLS, men fortsätt utan om servern inte svarar som väntat.
      try {
        await smtpCommand(socket, "STARTTLS", [220]);
        const upgraded = await new Promise((resolve, reject) => {
          const tlsSocket = tls.connect(
            {
              socket: socket,
              servername: smtpHost
            },
            () => resolve(tlsSocket)
          );
          tlsSocket.on("error", reject);
        });
        socket = upgraded;
        await smtpCommand(socket, "EHLO ambitionsverige.se", [250]);
      } catch (_) {
      }
    }

    await smtpCommand(socket, "AUTH LOGIN", [334]);
    await smtpCommand(socket, Buffer.from(smtpAuthUser, "utf8").toString("base64"), [334]);
    await smtpCommand(socket, Buffer.from(smtpPass, "utf8").toString("base64"), [235]);
    await smtpCommand(socket, `MAIL FROM:<${smtpFrom}>`, [250]);
    await smtpCommand(socket, `RCPT TO:<${toEmail}>`, [250, 251]);
    await smtpCommand(socket, "DATA", [354]);

    const body = [
      `From: ${smtpFrom}`,
      `To: ${toEmail}`,
      `Subject: ${subject}`,
      "Content-Type: text/plain; charset=utf-8",
      "",
      text
    ].join("\r\n");
    socket.write(body.replace(/^\./gm, "..") + "\r\n.\r\n");
    await smtpCommand(socket, null, [250]);
    try {
      await smtpCommand(socket, "QUIT", [221]);
    } catch (_) {
    }
    socket.end();
  }

  const initialSocket = await new Promise((resolve, reject) => {
    const socket = smtpSecure
      ? tls.connect({ host: smtpHost, port: smtpPort, servername: smtpHost }, () => resolve(socket))
      : net.connect({ host: smtpHost, port: smtpPort }, () => resolve(socket));
    socket.setTimeout(20000, () => {
      socket.destroy(new Error("SMTP socket timeout"));
    });
    socket.on("error", reject);
  });
  await sendViaSocket(initialSocket);
  return { mode: "smtp", auth_user: smtpAuthUser };
}

async function sendGeneratedCredentialsEmail({ workEmail, username, password, city }) {
  const subject = "Dina inloggningsuppgifter - Ambition Sverige";
  const text = [
    "Hej!",
    "",
    `Din registrering för ort: ${city} är klar.`,
    "",
    "Dina inloggningsuppgifter:",
    `Användarnamn: ${username}`,
    `Lösenord: ${password}`,
    "",
    "Logga in på samordningsytan och byt lösenord direkt.",
    "",
    "Vänliga hälsningar,",
    "Ambition Sverige"
  ].join("\n");
  return sendMailViaSmtp({
    toEmail: workEmail,
    subject: subject,
    text: text
  });
}

async function sendPasswordResetEmail({ recipientEmail, username, resetCode }) {
  const subject = "Återställ lösenord - Ambition Sverige";
  const text = [
    "Hej!",
    "",
    "Du har begärt återställning av lösenord.",
    "",
    "Kontouppgifter:",
    `Användarnamn: ${username}`,
    "",
    "Använd denna kod för att sätta ett nytt lösenord:",
    `${resetCode}`,
    "",
    `Koden gäller i ${Math.floor(PASSWORD_RESET_TTL_SECONDS / 60)} minuter.`,
    "",
    "Om du inte begärde detta kan du ignorera mailet.",
    "",
    "Vänliga hälsningar,",
    "Ambition Sverige"
  ].join("\n");
  return sendMailViaSmtp({
    toEmail: recipientEmail,
    subject: subject,
    text: text
  });
}

app.get("/api/register/options", (_req, res) => {
  return res.json({
    allowed_domain: REGISTER_ALLOWED_DOMAIN,
    cities: REGISTER_CITIES
  });
});

app.post("/api/register", async (req, res) => {
  if (!getAllowRegistrations()) {
    return res.status(403).json({ error: "Registrering är avstängd av administratör." });
  }

  const workEmail = normalizeEmail(req.body?.work_email || req.body?.email || "");
  const city = String(req.body?.city || "").trim();
  const firstName = String(req.body?.first_name || "").trim();
  const lastName = String(req.body?.last_name || "").trim();
  const phone = String(req.body?.phone || "").trim();

  if (!firstName) {
    return res.status(400).json({ error: "Förnamn krävs." });
  }
  if (!lastName) {
    return res.status(400).json({ error: "Efternamn krävs." });
  }
  if (!phone) {
    return res.status(400).json({ error: "Telefonnummer krävs." });
  }
  const phoneDigits = phone.replace(/[^\d+]/g, "");
  if (phoneDigits.length < 7) {
    return res.status(400).json({ error: "Ogiltigt telefonnummer." });
  }

  if (!workEmail || !workEmail.endsWith(REGISTER_ALLOWED_DOMAIN)) {
    return res.status(400).json({ error: `Endast e-post med domänen ${REGISTER_ALLOWED_DOMAIN} är tillåten.` });
  }
  if (!REGISTER_CITIES.includes(city)) {
    return res.status(400).json({ error: "Välj en giltig ort från listan." });
  }

  const existingByContact = db
    .prepare("SELECT id FROM users WHERE lower(contact_email) = ? LIMIT 1")
    .get(workEmail);
  if (existingByContact) {
    return res.status(409).json({ error: "Den här e-postadressen är redan registrerad." });
  }

  const username = generateUniqueUsername();
  const password = makeRandomPassword(14);

  const salt = crypto.randomBytes(16).toString("hex");
  const passwordHash = hashPassword(password, salt, PBKDF2_ITERATIONS);

  let createdId = null;
  try {
    const result = db
      .prepare(
        `INSERT INTO users(email, password_hash, salt, iterations, created_at, contact_email, city, first_name, last_name, phone)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        username,
        passwordHash,
        salt,
        PBKDF2_ITERATIONS,
        nowTs(),
        workEmail,
        city,
        firstName,
        lastName,
        phone
      );
    createdId = Number(result.lastInsertRowid || 0);

    const delivery = await sendGeneratedCredentialsEmail({
      workEmail,
      username,
      password,
      city
    });

    return res.status(201).json({
      ok: true,
      message: "Konto skapat. Inloggningsuppgifter har skickats till din e-post.",
      delivery_mode: delivery.mode
    });
  } catch (err) {
    if (createdId) {
      try {
        db.prepare("DELETE FROM users WHERE id = ?").run(createdId);
      } catch (_) {
      }
    }
    if (String(err.message).includes("UNIQUE")) {
      return res.status(409).json({ error: "Användarnamnet/e-postadressen är redan registrerad." });
    }
    const detail = String(err && err.message ? err.message : "okänt fel");
    return res.status(500).json({
      error: `Kunde inte slutföra registreringen eller skicka e-post. Detalj: ${detail}`
    });
  }
});

app.post("/api/login", (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  const ip = String(req.ip || "unknown");
  const rateKey = `login:${email || "empty"}:${ip}`;
  const now = nowTs();
  const rate = loginRateLimit.get(rateKey) || { count: 0, reset_at: now + LOGIN_RATE_LIMIT_WINDOW_SECONDS };
  if (rate.reset_at <= now) {
    rate.count = 0;
    rate.reset_at = now + LOGIN_RATE_LIMIT_WINDOW_SECONDS;
  }
  rate.count += 1;
  loginRateLimit.set(rateKey, rate);
  if (rate.count > LOGIN_RATE_LIMIT_MAX_ATTEMPTS) {
    return res.status(429).json({ error: "För många inloggningsförsök. Vänta en stund och försök igen." });
  }

  if (!email || !password) {
    return res.status(400).json({ error: "Användarnamn/e-post och lösenord krävs." });
  }

  const user = db
    .prepare("SELECT id, email, password_hash, salt, iterations FROM users WHERE lower(email) = ?")
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

  loginRateLimit.delete(rateKey);
  const token = createSession(user.id);
  setSessionCookie(res, token);
  return res.json({ ok: true, email: user.email });
});

app.post("/api/password/reset-request", async (req, res) => {
  const identifier = normalizeEmail(req.body?.identifier || req.body?.email || "");
  const genericMessage = "Om kontot finns har återställningsinstruktioner skickats till din e-post.";
  if (!identifier || identifier.length < 2) {
    return res.json({ ok: true, message: genericMessage });
  }

  const rateKey = `pwreset:${identifier}`;
  const now = nowTs();
  const rate = passwordResetRateLimit.get(rateKey) || { count: 0, reset_at: now + PASSWORD_RESET_RATE_LIMIT_WINDOW_SECONDS };
  if (rate.reset_at <= now) {
    rate.count = 0;
    rate.reset_at = now + PASSWORD_RESET_RATE_LIMIT_WINDOW_SECONDS;
  }
  rate.count += 1;
  passwordResetRateLimit.set(rateKey, rate);
  if (rate.count > PASSWORD_RESET_RATE_LIMIT_MAX_ATTEMPTS) {
    return res.json({ ok: true, message: genericMessage });
  }

  const targetUser = db
    .prepare(
      `SELECT id, email, contact_email
       FROM users
       WHERE lower(email) = ? OR lower(contact_email) = ?
       LIMIT 1`
    )
    .get(identifier, identifier);

  if (!targetUser) {
    return res.json({ ok: true, message: genericMessage });
  }

  const recipientEmail = normalizeEmail(targetUser.contact_email || "");
  if (!recipientEmail || !recipientEmail.endsWith(REGISTER_ALLOWED_DOMAIN)) {
    return res.json({ ok: true, message: genericMessage });
  }

  const rawToken = crypto.randomBytes(24).toString("base64url");
  const tokenHash = hashResetToken(rawToken);
  const expiresAt = now + PASSWORD_RESET_TTL_SECONDS;

  try {
    db.prepare(
      "DELETE FROM password_reset_tokens WHERE user_id = ? OR expires_at <= ? OR used_at IS NOT NULL"
    ).run(Number(targetUser.id), now);
    db.prepare(
      `INSERT INTO password_reset_tokens(user_id, token_hash, expires_at, used_at, created_at)
       VALUES (?, ?, ?, NULL, ?)`
    ).run(Number(targetUser.id), tokenHash, expiresAt, now);

    await sendPasswordResetEmail({
      recipientEmail: recipientEmail,
      username: String(targetUser.email || ""),
      resetCode: rawToken
    });
  } catch (err) {
    return res.status(500).json({
      error: "Kunde inte återställa lösenord just nu. Försök igen strax."
    });
  }

  return res.json({ ok: true, message: genericMessage });
});

app.post("/api/password/reset-confirm", (req, res) => {
  const token = String(req.body?.token || "").trim();
  const newPassword = String(req.body?.new_password || req.body?.password || "");
  if (!token || !newPassword || newPassword.length < 10) {
    return res.status(400).json({ error: "Ogiltig kod eller för kort lösenord (minst 10 tecken)." });
  }

  const tokenHash = hashResetToken(token);
  const row = db
    .prepare(
      `SELECT id, user_id, expires_at, used_at
       FROM password_reset_tokens
       WHERE token_hash = ?
       LIMIT 1`
    )
    .get(tokenHash);

  if (!row || Number(row.used_at || 0) > 0 || Number(row.expires_at || 0) <= nowTs()) {
    return res.status(400).json({ error: "Koden är ogiltig eller har gått ut." });
  }

  const salt = crypto.randomBytes(16).toString("hex");
  const passwordHash = hashPassword(newPassword, salt, PBKDF2_ITERATIONS);
  const now = nowTs();
  const tx = db.transaction(() => {
    db.prepare("UPDATE users SET password_hash = ?, salt = ?, iterations = ? WHERE id = ?")
      .run(passwordHash, salt, PBKDF2_ITERATIONS, Number(row.user_id));
    db.prepare("UPDATE password_reset_tokens SET used_at = ? WHERE id = ?")
      .run(now, Number(row.id));
    db.prepare("DELETE FROM sessions WHERE user_id = ?")
      .run(Number(row.user_id));
  });
  tx();

  return res.json({ ok: true });
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

app.get("/api/me/profile", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const row = db
    .prepare("SELECT id, email, contact_email, city, first_name, last_name, phone FROM users WHERE id = ?")
    .get(user.id);
  if (!row) {
    return res.status(404).json({ error: "Användaren hittades inte." });
  }
  return res.json({
    id: Number(row.id),
    username: String(row.email || ""),
    contact_email: String(row.contact_email || ""),
    city: String(row.city || ""),
    first_name: String(row.first_name || ""),
    last_name: String(row.last_name || ""),
    phone: String(row.phone || "")
  });
});

app.put("/api/me/profile", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const firstName = String(req.body?.first_name || "").trim();
  const lastName = String(req.body?.last_name || "").trim();
  const phone = String(req.body?.phone || "").trim();
  const contactEmail = normalizeEmail(req.body?.contact_email || "");
  const city = String(req.body?.city || "").trim();

  if (!firstName) return res.status(400).json({ error: "Förnamn krävs." });
  if (!lastName) return res.status(400).json({ error: "Efternamn krävs." });
  if (!phone) return res.status(400).json({ error: "Telefonnummer krävs." });
  if (!contactEmail || !contactEmail.endsWith(REGISTER_ALLOWED_DOMAIN)) {
    return res.status(400).json({ error: `E-post måste sluta med ${REGISTER_ALLOWED_DOMAIN}.` });
  }
  if (!city || !REGISTER_CITIES.includes(city)) {
    return res.status(400).json({ error: "Välj en giltig ort." });
  }

  const conflict = db
    .prepare("SELECT id FROM users WHERE lower(contact_email) = ? AND id != ? LIMIT 1")
    .get(contactEmail, user.id);
  if (conflict) {
    return res.status(409).json({ error: "E-postadressen används redan av en annan användare." });
  }

  db.prepare(
    "UPDATE users SET first_name = ?, last_name = ?, phone = ?, contact_email = ?, city = ? WHERE id = ?"
  ).run(firstName, lastName, phone, contactEmail, city, user.id);

  return res.json({ ok: true });
});

app.get("/api/settings/public", (_req, res) => {
  return res.json({
    allow_registrations: getAllowRegistrations()
  });
});

app.get("/api/admin/settings", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!isAdmin(user)) {
    return res.status(403).json({ error: "Endast admin har åtkomst." });
  }
  return res.json({
    allow_registrations: getAllowRegistrations()
  });
});

app.put("/api/admin/settings/registrations", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!isAdmin(user)) {
    return res.status(403).json({ error: "Endast admin kan ändra registreringsinställningen." });
  }
  const allow = !!req.body?.allow_registrations;
  setAllowRegistrations(allow);
  return res.json({
    ok: true,
    allow_registrations: getAllowRegistrations()
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

app.get("/api/admin/users", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!isAdmin(user)) {
    return res.status(403).json({ error: "Endast admin har åtkomst." });
  }

  const activeSince = nowTs() - ONLINE_WINDOW_SECONDS;
  const rows = db
    .prepare(
      `SELECT u.id, u.email, u.contact_email, u.city, u.first_name, u.last_name, u.phone,
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
       ORDER BY u.email ASC`
    )
    .all(nowTs(), activeSince);

  return res.json({
    users: rows.map((r) => ({
      id: Number(r.id),
      email: String(r.email || ""),
      contact_email: String(r.contact_email || ""),
      city: String(r.city || ""),
      first_name: String(r.first_name || ""),
      last_name: String(r.last_name || ""),
      phone: String(r.phone || ""),
      online: !!r.is_online,
      is_admin: String(r.email || "").toLowerCase() === "admin"
    }))
  });
});

app.put("/api/admin/users/:id", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!isAdmin(user)) {
    return res.status(403).json({ error: "Endast admin kan redigera användare." });
  }

  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "Ogiltigt användar-id." });
  }
  const target = db.prepare("SELECT id, email FROM users WHERE id = ?").get(id);
  if (!target) {
    return res.status(404).json({ error: "Användaren hittades inte." });
  }

  const nextEmail = String(req.body?.email || "").trim().toLowerCase();
  const nextContactEmail = normalizeEmail(req.body?.contact_email || "");
  const nextCity = String(req.body?.city || "").trim();
  const nextFirstName = String(req.body?.first_name || "").trim();
  const nextLastName = String(req.body?.last_name || "").trim();
  const nextPhone = String(req.body?.phone || "").trim();

  if (!nextEmail || nextEmail.length < 2) {
    return res.status(400).json({ error: "Ogiltigt användarnamn." });
  }
  if (String(target.email || "").toLowerCase() === "admin" && nextEmail !== "admin") {
    return res.status(400).json({ error: "Admin-användaren kan inte byta användarnamn." });
  }
  if (nextContactEmail && !nextContactEmail.endsWith(REGISTER_ALLOWED_DOMAIN)) {
    return res.status(400).json({ error: `Kontaktmail måste sluta med ${REGISTER_ALLOWED_DOMAIN}.` });
  }
  if (nextCity && !REGISTER_CITIES.includes(nextCity)) {
    return res.status(400).json({ error: "Ogiltig ort." });
  }

  try {
    const result = db
      .prepare(
        "UPDATE users SET email = ?, contact_email = ?, city = ?, first_name = ?, last_name = ?, phone = ? WHERE id = ?"
      )
      .run(
        nextEmail,
        nextContactEmail || null,
        nextCity || null,
        nextFirstName || null,
        nextLastName || null,
        nextPhone || null,
        id
      );
    if (result.changes === 0) {
      return res.status(404).json({ error: "Användaren hittades inte." });
    }
    return res.json({ ok: true });
  } catch (err) {
    if (String(err.message).includes("UNIQUE")) {
      return res.status(409).json({ error: "Användarnamnet används redan." });
    }
    return res.status(500).json({ error: "Kunde inte uppdatera användaren." });
  }
});

app.delete("/api/admin/users/:id", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!isAdmin(user)) {
    return res.status(403).json({ error: "Endast admin kan ta bort användare." });
  }

  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "Ogiltigt användar-id." });
  }
  if (id === Number(user.id)) {
    return res.status(400).json({ error: "Du kan inte ta bort dig själv." });
  }

  const target = db.prepare("SELECT id, email FROM users WHERE id = ?").get(id);
  if (!target) {
    return res.status(404).json({ error: "Användaren hittades inte." });
  }
  if (String(target.email || "").toLowerCase() === "admin") {
    return res.status(400).json({ error: "Admin-användaren kan inte tas bort." });
  }

  const tx = db.transaction(() => {
    db.prepare("DELETE FROM sessions WHERE user_id = ?").run(id);
    db.prepare("DELETE FROM notes WHERE user_id = ?").run(id);
    db.prepare("DELETE FROM chat_reads WHERE user_id = ?").run(id);
    db.prepare("DELETE FROM chat_group_reads WHERE user_id = ?").run(id);
    db.prepare("DELETE FROM chat_group_members WHERE user_id = ?").run(id);
    db.prepare("DELETE FROM chat_group_invites WHERE inviter_id = ? OR invitee_id = ?").run(id, id);
    db.prepare("DELETE FROM direct_messages WHERE sender_id = ? OR recipient_id = ?").run(id, id);
    db.prepare("DELETE FROM chat_messages WHERE user_id = ?").run(id);
    db.prepare("UPDATE events SET created_by = NULL WHERE created_by = ?").run(id);
    db.prepare("UPDATE important_messages SET created_by = NULL WHERE created_by = ?").run(id);
    db.prepare("UPDATE chat_groups SET created_by = ? WHERE created_by = ?").run(Number(user.id), id);
    db.prepare("DELETE FROM users WHERE id = ?").run(id);
  });

  try {
    tx();
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: "Kunde inte ta bort användaren." });
  }
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

app.get("/api/fs/state", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const state = getAppDataJson("fs_state_v1");
  if (!state || typeof state !== "object") {
    const fresh = defaultFsState();
    setAppDataJson("fs_state_v1", fresh);
    return res.json({ state: fresh });
  }
  return res.json({ state });
});

app.put("/api/fs/state", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const state = req.body?.state;
  if (!state || typeof state !== "object" || Array.isArray(state)) {
    return res.status(400).json({ error: "Ogiltigt filsystem-state." });
  }
  setAppDataJson("fs_state_v1", state);
  return res.json({ ok: true });
});

app.post("/api/files/upload", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const nameRaw = String(req.body?.name || "").trim();
  const mimeRaw = String(req.body?.mime || "").trim();
  const dataBase64 = String(req.body?.data_base64 || "").trim();

  if (!nameRaw || !dataBase64) {
    return res.status(400).json({ error: "Filnamn och filinnehåll krävs." });
  }

  let buffer;
  try {
    buffer = Buffer.from(dataBase64, "base64");
  } catch (_) {
    return res.status(400).json({ error: "Ogiltig fildata." });
  }
  if (!buffer || !buffer.length) {
    return res.status(400).json({ error: "Tom fil." });
  }
  if (buffer.length > MAX_UPLOAD_BYTES) {
    return res.status(400).json({ error: "Filen är för stor (max 10 MB)." });
  }

  const safeName = nameRaw.replace(/[^a-zA-Z0-9._-]+/g, "_").slice(0, 120) || "file.bin";
  const ext = path.extname(safeName) || "";
  const base = path.basename(safeName, ext);
  const fileName = `${Date.now()}_${crypto.randomBytes(6).toString("hex")}_${base}${ext}`;
  const targetPath = path.join(UPLOAD_DIR, fileName);
  fs.writeFileSync(targetPath, buffer);

  const publicUrl = `/uploads/chat/${fileName}`;
  return res.status(201).json({
    ok: true,
    file: {
      name: nameRaw,
      mime: mimeRaw || "application/octet-stream",
      size: buffer.length,
      url: publicUrl
    }
  });
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

  const requestedDateKey = String(req.query.date_key || "").trim();
  const todayKey = /^\d{4}-\d{2}-\d{2}$/.test(requestedDateKey) ? requestedDateKey : localDateKey();
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

app.get("/api/important-messages", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const rows = db
    .prepare(
      `SELECT id, icon, text, sort_order, created_at, updated_at
       FROM important_messages
       ORDER BY sort_order ASC, id ASC`
    )
    .all();

  return res.json({ messages: rows });
});

app.post("/api/important-messages", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!isAdmin(user)) {
    return res.status(403).json({ error: "Endast admin kan skapa viktiga meddelanden." });
  }

  const icon = String(req.body?.icon || "📢").trim().slice(0, 8) || "📢";
  const text = String(req.body?.text || "").trim();
  const sortOrderRaw = Number(req.body?.sort_order);

  if (!text) return res.status(400).json({ error: "Text krävs." });
  if (text.length > 500) return res.status(400).json({ error: "Texten är för lång (max 500 tecken)." });

  const fallbackOrder = Number(
    db.prepare("SELECT COALESCE(MAX(sort_order), -1) + 1 AS next_order FROM important_messages").get().next_order
  );
  const sortOrder = Number.isInteger(sortOrderRaw) ? sortOrderRaw : fallbackOrder;
  const now = nowTs();

  const result = db
    .prepare(
      "INSERT INTO important_messages(icon, text, sort_order, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)"
    )
    .run(icon, text, sortOrder, user.id, now, now);

  return res.status(201).json({ ok: true, id: result.lastInsertRowid });
});

app.put("/api/important-messages/:id", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!isAdmin(user)) {
    return res.status(403).json({ error: "Endast admin kan redigera viktiga meddelanden." });
  }

  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "Ogiltigt id." });
  }

  const icon = String(req.body?.icon || "📢").trim().slice(0, 8) || "📢";
  const text = String(req.body?.text || "").trim();
  const sortOrderRaw = Number(req.body?.sort_order);
  const sortOrder = Number.isInteger(sortOrderRaw) ? sortOrderRaw : null;

  if (!text) return res.status(400).json({ error: "Text krävs." });
  if (text.length > 500) return res.status(400).json({ error: "Texten är för lång (max 500 tecken)." });

  const now = nowTs();
  let result;
  if (sortOrder === null) {
    result = db
      .prepare("UPDATE important_messages SET icon = ?, text = ?, updated_at = ? WHERE id = ?")
      .run(icon, text, now, id);
  } else {
    result = db
      .prepare("UPDATE important_messages SET icon = ?, text = ?, sort_order = ?, updated_at = ? WHERE id = ?")
      .run(icon, text, sortOrder, now, id);
  }

  if (result.changes === 0) {
    return res.status(404).json({ error: "Meddelandet hittades inte." });
  }
  return res.json({ ok: true });
});

app.delete("/api/important-messages/:id", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!isAdmin(user)) {
    return res.status(403).json({ error: "Endast admin kan ta bort viktiga meddelanden." });
  }

  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "Ogiltigt id." });
  }
  const result = db.prepare("DELETE FROM important_messages WHERE id = ?").run(id);
  if (result.changes === 0) {
    return res.status(404).json({ error: "Meddelandet hittades inte." });
  }
  return res.json({ ok: true });
});

app.get("/api/facebook-academy/links", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  return res.json({ links: getFacebookAcademyLinks() });
});

app.post("/api/facebook-academy/links", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!isAdmin(user)) {
    return res.status(403).json({ error: "Endast admin kan lägga till länkar." });
  }

  const title = String(req.body?.title || "").trim();
  const url = String(req.body?.url || "").trim();
  const typeRaw = String(req.body?.type || "").trim().toLowerCase();

  if (!title && !url) {
    return res.status(400).json({ error: "Ange text, länk eller båda." });
  }
  if (url && !isAllowedAcademyUrl(url)) {
    return res.status(400).json({
      error: "Ogiltig länk. Använd http(s)-länk eller uppladdad PDF från /uploads/chat/."
    });
  }

  let type = "";
  if (url) {
    type = typeRaw === "video" || typeRaw === "pdf" ? typeRaw : inferAcademyLinkType(url);
  }
  if (url && !type) {
    return res.status(400).json({ error: "Kunde inte avgöra länktyp. Välj video eller pdf." });
  }

  const now = nowTs();
  const links = getFacebookAcademyLinks();
  const item = normalizeAcademyLink({
    id: "aca_" + crypto.randomBytes(8).toString("hex"),
    title: title,
    url: url,
    type: type,
    created_at: now,
    updated_at: now,
    created_by: user.id
  });
  if (!item) return res.status(400).json({ error: "Ogiltig länk." });
  links.unshift(item);
  setFacebookAcademyLinks(links);
  return res.status(201).json({ ok: true, item: item });
});

app.put("/api/facebook-academy/links/:id", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!isAdmin(user)) {
    return res.status(403).json({ error: "Endast admin kan redigera länkar." });
  }

  const id = String(req.params.id || "").trim();
  if (!id) return res.status(400).json({ error: "Ogiltigt id." });

  const title = String(req.body?.title || "").trim();
  const url = String(req.body?.url || "").trim();
  const typeRaw = String(req.body?.type || "").trim().toLowerCase();
  if (!title && !url) {
    return res.status(400).json({ error: "Ange text, länk eller båda." });
  }
  if (url && !isAllowedAcademyUrl(url)) {
    return res.status(400).json({
      error: "Ogiltig länk. Använd http(s)-länk eller uppladdad PDF från /uploads/chat/."
    });
  }
  let type = "";
  if (url) {
    type = typeRaw === "video" || typeRaw === "pdf" ? typeRaw : inferAcademyLinkType(url);
  }
  if (url && !type) {
    return res.status(400).json({ error: "Kunde inte avgöra länktyp. Välj video eller pdf." });
  }

  const links = getFacebookAcademyLinks();
  const idx = links.findIndex((x) => String(x.id) === id);
  if (idx < 0) return res.status(404).json({ error: "Länken hittades inte." });

  const current = links[idx];
  const updated = normalizeAcademyLink({
    id: current.id,
    title: title,
    url: url,
    type: type,
    created_at: current.created_at,
    updated_at: nowTs(),
    created_by: current.created_by || user.id
  });
  if (!updated) return res.status(400).json({ error: "Ogiltig länk." });
  links[idx] = updated;
  setFacebookAcademyLinks(links);
  return res.json({ ok: true, item: updated });
});

app.delete("/api/facebook-academy/links/:id", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!isAdmin(user)) {
    return res.status(403).json({ error: "Endast admin kan ta bort länkar." });
  }

  const id = String(req.params.id || "").trim();
  if (!id) return res.status(400).json({ error: "Ogiltigt id." });

  const links = getFacebookAcademyLinks();
  const next = links.filter((x) => String(x.id) !== id);
  if (next.length === links.length) {
    return res.status(404).json({ error: "Länken hittades inte." });
  }
  setFacebookAcademyLinks(next);
  return res.json({ ok: true });
});

app.post("/api/facebook-academy/upload-pdf", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!isAdmin(user)) {
    return res.status(403).json({ error: "Endast admin kan ladda upp PDF." });
  }

  const nameRaw = String(req.body?.name || "").trim();
  const mimeRaw = String(req.body?.mime || "").trim().toLowerCase();
  const dataBase64 = String(req.body?.data_base64 || "").trim();

  if (!nameRaw || !dataBase64) {
    return res.status(400).json({ error: "Filnamn och filinnehåll krävs." });
  }
  if (mimeRaw && mimeRaw !== "application/pdf") {
    return res.status(400).json({ error: "Endast PDF-filer är tillåtna." });
  }

  let buffer;
  try {
    buffer = Buffer.from(dataBase64, "base64");
  } catch (_) {
    return res.status(400).json({ error: "Ogiltig fildata." });
  }
  if (!buffer || !buffer.length) {
    return res.status(400).json({ error: "Tom fil." });
  }
  if (buffer.length > MAX_UPLOAD_BYTES) {
    return res.status(400).json({ error: "Filen är för stor (max 10 MB)." });
  }

  const hasPdfExt = /\.pdf$/i.test(nameRaw);
  const normalizedName = hasPdfExt ? nameRaw : `${nameRaw}.pdf`;
  const safeName = normalizedName.replace(/[^a-zA-Z0-9._-]+/g, "_").slice(0, 120) || "academy.pdf";
  const ext = ".pdf";
  const base = path.basename(safeName, path.extname(safeName)) || "academy";
  const fileName = `${Date.now()}_${crypto.randomBytes(6).toString("hex")}_${base}${ext}`;
  const targetPath = path.join(UPLOAD_DIR, fileName);
  fs.writeFileSync(targetPath, buffer);

  const publicUrl = `/uploads/chat/${fileName}`;
  return res.status(201).json({
    ok: true,
    file: {
      name: normalizedName,
      mime: "application/pdf",
      size: buffer.length,
      url: publicUrl
    }
  });
});

app.get("/api/qna/questions", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const search = String(req.query.q || "").trim().toLowerCase();
  const like = `%${search}%`;
  const questionRows = db
    .prepare(
      `SELECT q.id, q.question, q.image_url, q.created_at, u.email AS user_email
       FROM qna_questions q
       JOIN users u ON u.id = q.user_id
       WHERE (
         ? = ''
         OR lower(q.question) LIKE ?
         OR lower(u.email) LIKE ?
         OR EXISTS (
           SELECT 1
           FROM qna_answers a
           JOIN users au ON au.id = a.user_id
           WHERE a.question_id = q.id
             AND (
               lower(a.answer) LIKE ?
               OR lower(au.email) LIKE ?
             )
         )
       )
       ORDER BY q.created_at DESC, q.id DESC
       LIMIT 200`
    )
    .all(search, like, like, like, like);

  const questionIds = questionRows.map((q) => Number(q.id)).filter((id) => Number.isInteger(id) && id > 0);
  let answersRows = [];
  if (questionIds.length) {
    answersRows = db
      .prepare(
        `SELECT a.id, a.question_id, a.answer, a.image_url, a.created_at, u.email AS user_email
         FROM qna_answers a
         JOIN users u ON u.id = a.user_id
         WHERE a.question_id IN (${questionIds.map(() => "?").join(",")})
         ORDER BY a.created_at ASC, a.id ASC`
      )
      .all(...questionIds);
  }

  const answersByQuestion = new Map();
  answersRows.forEach((row) => {
    const key = Number(row.question_id);
    if (!answersByQuestion.has(key)) answersByQuestion.set(key, []);
    answersByQuestion.get(key).push({
      id: Number(row.id),
      answer: String(row.answer || ""),
      image_url: String(row.image_url || ""),
      created_at: Number(row.created_at || 0),
      user_email: String(row.user_email || "")
    });
  });

  const questions = questionRows.map((row) => ({
    id: Number(row.id),
    question: String(row.question || ""),
    image_url: String(row.image_url || ""),
    created_at: Number(row.created_at || 0),
    user_email: String(row.user_email || ""),
    answers: answersByQuestion.get(Number(row.id)) || []
  }));
  return res.json({ questions });
});

app.post("/api/qna/questions", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const question = String(req.body?.question || "").trim();
  const imageUrl = String(req.body?.image_url || "").trim();
  if (!question && !imageUrl) {
    return res.status(400).json({ error: "Fråga eller bild krävs." });
  }
  if (question.length > 2000) {
    return res.status(400).json({ error: "Frågan är för lång (max 2000 tecken)." });
  }
  if (imageUrl && !isAllowedUploadUrl(imageUrl)) {
    return res.status(400).json({ error: "Ogiltig bildlänk." });
  }

  const now = nowTs();
  const result = db
    .prepare("INSERT INTO qna_questions(user_id, question, image_url, created_at) VALUES (?, ?, ?, ?)")
    .run(user.id, question, imageUrl || null, now);
  return res.status(201).json({
    ok: true,
    question: {
      id: Number(result.lastInsertRowid || 0),
      question: question,
      image_url: imageUrl || "",
      created_at: now,
      user_email: user.email,
      answers: []
    }
  });
});

app.post("/api/qna/questions/:id/answers", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const questionId = Number(req.params.id);
  if (!Number.isInteger(questionId) || questionId <= 0) {
    return res.status(400).json({ error: "Ogiltigt fråge-id." });
  }
  const answer = String(req.body?.answer || "").trim();
  const imageUrl = String(req.body?.image_url || "").trim();
  if (!answer && !imageUrl) {
    return res.status(400).json({ error: "Svar eller bild krävs." });
  }
  if (answer.length > 2000) {
    return res.status(400).json({ error: "Svaret är för långt (max 2000 tecken)." });
  }
  if (imageUrl && !isAllowedUploadUrl(imageUrl)) {
    return res.status(400).json({ error: "Ogiltig bildlänk." });
  }

  const existing = db.prepare("SELECT id FROM qna_questions WHERE id = ?").get(questionId);
  if (!existing) {
    return res.status(404).json({ error: "Frågan hittades inte." });
  }

  const now = nowTs();
  const result = db
    .prepare("INSERT INTO qna_answers(question_id, user_id, answer, image_url, created_at) VALUES (?, ?, ?, ?, ?)")
    .run(questionId, user.id, answer, imageUrl || null, now);
  return res.status(201).json({
    ok: true,
    answer: {
      id: Number(result.lastInsertRowid || 0),
      question_id: questionId,
      answer: answer,
      image_url: imageUrl || "",
      created_at: now,
      user_email: user.email
    }
  });
});

app.get("/api/idea-bank/ideas", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const q = String(req.query.q || "").trim().toLowerCase();
  const like = `%${q}%`;
  const rows = db
    .prepare(
      `SELECT i.id, i.title, i.description, i.tag, i.image_url, i.created_at, i.updated_at, u.email AS user_email
       FROM idea_bank_ideas i
       JOIN users u ON u.id = i.user_id
       WHERE (
         ? = ''
         OR lower(i.title) LIKE ?
         OR lower(i.description) LIKE ?
         OR lower(i.tag) LIKE ?
         OR lower(u.email) LIKE ?
       )
       ORDER BY i.created_at DESC, i.id DESC
       LIMIT 300`
    )
    .all(q, like, like, like, like);

  return res.json({
    ideas: rows.map((row) => ({
      id: Number(row.id || 0),
      title: String(row.title || ""),
      description: String(row.description || ""),
      tag: String(row.tag || "Ny"),
      image_url: String(row.image_url || ""),
      created_at: Number(row.created_at || 0),
      updated_at: Number(row.updated_at || 0),
      user_email: String(row.user_email || "")
    }))
  });
});

app.post("/api/idea-bank/ideas", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const title = String(req.body?.title || "").trim();
  const description = String(req.body?.description || "").trim();
  const tag = String(req.body?.tag || "Ny").trim() || "Ny";
  const imageUrl = String(req.body?.image_url || "").trim();

  if (!title) return res.status(400).json({ error: "Titel krävs." });
  if (!description) return res.status(400).json({ error: "Beskrivning krävs." });
  if (title.length > 160) return res.status(400).json({ error: "Titeln är för lång (max 160 tecken)." });
  if (description.length > 5000) return res.status(400).json({ error: "Beskrivningen är för lång (max 5000 tecken)." });
  if (tag.length > 40) return res.status(400).json({ error: "Taggen är för lång (max 40 tecken)." });
  if (imageUrl && !isAllowedUploadUrl(imageUrl)) {
    return res.status(400).json({ error: "Ogiltig bildlänk." });
  }

  const now = nowTs();
  const result = db
    .prepare(
      "INSERT INTO idea_bank_ideas(user_id, title, description, tag, image_url, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    .run(user.id, title, description, tag, imageUrl || null, now, now);

  return res.status(201).json({
    ok: true,
    idea: {
      id: Number(result.lastInsertRowid || 0),
      title: title,
      description: description,
      tag: tag,
      image_url: imageUrl || "",
      created_at: now,
      updated_at: now,
      user_email: user.email
    }
  });
});

app.put("/api/idea-bank/ideas/:id", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "Ogiltigt idé-id." });
  }

  const existing = db
    .prepare(
      `SELECT i.id, i.user_id, u.email AS user_email
       FROM idea_bank_ideas i
       JOIN users u ON u.id = i.user_id
       WHERE i.id = ?`
    )
    .get(id);
  if (!existing) {
    return res.status(404).json({ error: "Idén hittades inte." });
  }

  const canEdit = Number(existing.user_id) === Number(user.id) || isAdmin(user);
  if (!canEdit) {
    return res.status(403).json({ error: "Du får bara redigera dina egna idéer." });
  }

  const title = String(req.body?.title || "").trim();
  const description = String(req.body?.description || "").trim();
  const tag = String(req.body?.tag || "Ny").trim() || "Ny";
  const imageUrl = String(req.body?.image_url || "").trim();

  if (!title) return res.status(400).json({ error: "Titel krävs." });
  if (!description) return res.status(400).json({ error: "Beskrivning krävs." });
  if (title.length > 160) return res.status(400).json({ error: "Titeln är för lång (max 160 tecken)." });
  if (description.length > 5000) return res.status(400).json({ error: "Beskrivningen är för lång (max 5000 tecken)." });
  if (tag.length > 40) return res.status(400).json({ error: "Taggen är för lång (max 40 tecken)." });
  if (imageUrl && !isAllowedUploadUrl(imageUrl)) {
    return res.status(400).json({ error: "Ogiltig bildlänk." });
  }

  const now = nowTs();
  db.prepare(
    "UPDATE idea_bank_ideas SET title = ?, description = ?, tag = ?, image_url = ?, updated_at = ? WHERE id = ?"
  ).run(title, description, tag, imageUrl || null, now, id);

  return res.json({
    ok: true,
    idea: {
      id: id,
      title: title,
      description: description,
      tag: tag,
      image_url: imageUrl || "",
      updated_at: now
    }
  });
});

app.delete("/api/idea-bank/ideas/:id", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "Ogiltigt idé-id." });
  }

  const existing = db
    .prepare("SELECT id, user_id FROM idea_bank_ideas WHERE id = ?")
    .get(id);
  if (!existing) {
    return res.status(404).json({ error: "Idén hittades inte." });
  }

  const canDelete = Number(existing.user_id) === Number(user.id) || isAdmin(user);
  if (!canDelete) {
    return res.status(403).json({ error: "Du får bara ta bort dina egna idéer." });
  }

  db.prepare("DELETE FROM idea_bank_ideas WHERE id = ?").run(id);
  return res.json({ ok: true });
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "login.html"));
});

app.get("/registrera", (req, res) => {
  if (!getAllowRegistrations()) {
    return res.redirect("/login.html?register=closed");
  }
  return res.sendFile(path.join(__dirname, "registrera.html"));
});

app.get("/group-invite/:groupId", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

const server = app.listen(PORT, () => {
  console.log(`Server started on http://localhost:${PORT}`);
});

server.on("error", (err) => {
  if (err && err.code === "EADDRINUSE") {
    console.error(`[startup] Port ${PORT} används redan.`);
    console.error(`[startup] Stoppa befintlig process eller starta med annan port, t.ex. PORT=${PORT + 1} npm start`);
    process.exit(1);
    return;
  }
  console.error("[startup] Serverfel:", err);
  process.exit(1);
});
