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

const ENV_IS_PRODUCTION = String(process.env.NODE_ENV || "").toLowerCase() === "production";
const SESSION_SECRET_FROM_ENV = String(process.env.SESSION_SECRET || "").trim();
if (ENV_IS_PRODUCTION && !SESSION_SECRET_FROM_ENV) {
  throw new Error("SESSION_SECRET måste vara satt i production.");
}
const EFFECTIVE_SESSION_SECRET = SESSION_SECRET_FROM_ENV || crypto.randomBytes(32).toString("hex");
if (!SESSION_SECRET_FROM_ENV) {
  console.warn("SESSION_SECRET saknas - använder tillfällig nyckel (endast lämpligt i dev).");
}

const app = express();
const PORT = Number(process.env.PORT || 8000);
const DB_PATH = path.join(__dirname, "data", "app.db");
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7;
const PASSWORD_RESET_TTL_SECONDS = 60 * 30;
const PASSWORD_RESET_RATE_LIMIT_WINDOW_SECONDS = 60 * 10;
const PASSWORD_RESET_RATE_LIMIT_MAX_ATTEMPTS = 5;
const REGISTER_RATE_LIMIT_WINDOW_SECONDS = 60 * 10;
const REGISTER_RATE_LIMIT_MAX_ATTEMPTS = 20;
const REGISTER_EMAIL_COOLDOWN_SECONDS = 90;
const LOGIN_RATE_LIMIT_WINDOW_SECONDS = 60 * 10;
const LOGIN_RATE_LIMIT_MAX_ATTEMPTS = 10;
const LOGIN_CODE_TTL_SECONDS = 60 * 10;
const LOGIN_CODE_RATE_LIMIT_WINDOW_SECONDS = 60 * 10;
const LOGIN_CODE_RATE_LIMIT_MAX_ATTEMPTS = 8;
const LOGIN_CODE_EMAIL_COOLDOWN_SECONDS = 90;
const ONLINE_WINDOW_SECONDS = 20;
const PBKDF2_ITERATIONS = 240000;
const SESSION_COOKIE = "session_token";
const CSRF_COOKIE = "csrf_token";
const UPLOAD_DIR = path.join(__dirname, "uploads", "chat");
const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;
const REGISTER_ALLOWED_DOMAIN = "@ambitionsverige.se";
const DEFAULT_SMTP_IDENTITY = "mail@ambitionsverige.se";
const TEST_ACCOUNT_IDENTIFIER = normalizeEmail(
  process.env.TEST_USERNAME || process.env.TEST_ACCOUNT_USERNAME || "test"
) || "test";
const TEST_ACCOUNT_PASSWORD = String(
  process.env.TEST_PASSWORD || process.env.TEST_ACCOUNT_PASSWORD || "test"
);
const TEST_ACCOUNT_CONTACT_EMAIL = normalizeEmail(
  process.env.TEST_EMAIL || process.env.TEST_ACCOUNT_EMAIL || ""
);
const SECRETARY_TEST_IDENTIFIER = normalizeEmail(process.env.SECRETARY_TEST_USERNAME || "sekreterare1") || "sekreterare1";
const SECRETARY_TEST_PASSWORD = String(process.env.SECRETARY_TEST_PASSWORD || "sekreterare1");
const SECRETARY_TEST_CONTACT_EMAIL = normalizeEmail(process.env.SECRETARY_TEST_EMAIL || "");
const PARTIKANSLIET_API_KEY = String(process.env.PARTIKANSLIET_API_KEY || "").trim();
const passwordResetRateLimit = new Map();
const registerRateLimit = new Map();
const registerEmailCooldown = new Map();
const loginRateLimit = new Map();
const loginCodeRequestRateLimit = new Map();
const loginCodeVerifyRateLimit = new Map();
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

CREATE TABLE IF NOT EXISTS event_attachments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER NOT NULL,
  file_url TEXT NOT NULL,
  file_name TEXT NOT NULL,
  file_mime TEXT,
  file_size INTEGER,
  created_by INTEGER,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE,
  FOREIGN KEY(created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS event_attendance (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER NOT NULL,
  attendee_name TEXT NOT NULL,
  present INTEGER NOT NULL DEFAULT 0,
  created_by INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE,
  FOREIGN KEY(created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS important_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  icon TEXT NOT NULL DEFAULT '📢',
  text TEXT NOT NULL,
  color TEXT NOT NULL DEFAULT 'info',
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
  category TEXT NOT NULL DEFAULT 'other',
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

CREATE TABLE IF NOT EXISTS tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  image_url TEXT,
  priority TEXT NOT NULL DEFAULT 'low',
  created_by INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY(created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS task_assignments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  assigned_by INTEGER NOT NULL,
  assigned_at INTEGER NOT NULL,
  solved_at INTEGER,
  UNIQUE(task_id, user_id),
  FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(assigned_by) REFERENCES users(id)
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

CREATE TABLE IF NOT EXISTS login_code_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  code_hash TEXT NOT NULL,
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

CREATE INDEX IF NOT EXISTS idx_event_attachments_event_id
  ON event_attachments(event_id);

CREATE INDEX IF NOT EXISTS idx_event_attendance_event_id
  ON event_attendance(event_id);

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

CREATE INDEX IF NOT EXISTS idx_tasks_created
  ON tasks(created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_task_assignments_user_solved
  ON task_assignments(user_id, solved_at, assigned_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_task_assignments_task_solved
  ON task_assignments(task_id, solved_at, assigned_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_exp
  ON password_reset_tokens(user_id, expires_at);

CREATE INDEX IF NOT EXISTS idx_login_code_tokens_user_exp
  ON login_code_tokens(user_id, expires_at);
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
  return crypto
    .createHmac("sha256", EFFECTIVE_SESSION_SECRET)
    .update(`token:${String(token || "")}`)
    .digest("hex");
}

function signSessionRaw(raw) {
  return crypto
    .createHmac("sha256", EFFECTIVE_SESSION_SECRET)
    .update(`session:${String(raw || "")}`)
    .digest("base64url");
}

function safeEqualText(a, b) {
  const aa = String(a || "");
  const bb = String(b || "");
  if (aa.length !== bb.length) return false;
  return crypto.timingSafeEqual(Buffer.from(aa, "utf8"), Buffer.from(bb, "utf8"));
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

function getConfiguredAdminFromEnv({ emailKey, usernameKey, passwordKey, label }) {
  const contactEmail = normalizeEmail(process.env[emailKey] || "");
  const username = normalizeEmail(process.env[usernameKey] || "");
  const identifier = username || contactEmail;
  const password = String(process.env[passwordKey] || "");
  return {
    label,
    emailKey,
    usernameKey,
    passwordKey,
    identifier,
    contactEmail,
    password
  };
}

function getConfiguredAdmins() {
  return [
    getConfiguredAdminFromEnv({
      label: "ADMIN1",
      emailKey: "ADMIN_EMAIL",
      usernameKey: "ADMIN_USERNAME",
      passwordKey: "ADMIN_PASSWORD"
    }),
    getConfiguredAdminFromEnv({
      label: "ADMIN2",
      emailKey: "ADMIN2_EMAIL",
      usernameKey: "ADMIN2_USERNAME",
      passwordKey: "ADMIN2_PASSWORD"
    })
  ];
}

function syncConfiguredAdminContactEmail(identifier, contactEmail) {
  const id = String(identifier || "").trim().toLowerCase();
  const mail = String(contactEmail || "").trim().toLowerCase();
  if (!id || !mail) return;
  const owner = db
    .prepare("SELECT id FROM users WHERE lower(email) = ? LIMIT 1")
    .get(id);
  if (!owner || !Number(owner.id)) return;
  const conflict = db
    .prepare("SELECT email FROM users WHERE lower(contact_email) = ? AND id != ? LIMIT 1")
    .get(mail, Number(owner.id));
  if (conflict && conflict.email) {
    console.warn(`Hoppar över kontaktmail-sync för ${id}: ${mail} används redan av ${String(conflict.email || "").trim().toLowerCase()}.`);
    return;
  }
  db.prepare("UPDATE users SET contact_email = ? WHERE id = ?").run(mail, Number(owner.id));
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

function ensureUniqueContactEmailIndex() {
  const duplicateRow = db
    .prepare(
      `SELECT lower(trim(contact_email)) AS key_email, COUNT(*) AS c
       FROM users
       WHERE contact_email IS NOT NULL AND trim(contact_email) <> ''
       GROUP BY lower(trim(contact_email))
       HAVING COUNT(*) > 1
       LIMIT 1`
    )
    .get();
  if (duplicateRow) {
    console.warn("Kunde inte skapa unikt index för contact_email: dubbletter finns redan i users.");
    return;
  }
  db.exec(`
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_contact_email_lower_unique
  ON users(lower(contact_email))
  WHERE contact_email IS NOT NULL AND trim(contact_email) <> '';
`);
}

function isStateChangingMethod(method) {
  const m = String(method || "").toUpperCase();
  return m === "POST" || m === "PUT" || m === "PATCH" || m === "DELETE";
}

function makeCsrfToken() {
  return crypto.randomBytes(24).toString("base64url");
}

const DANGEROUS_UPLOAD_EXTENSIONS = new Set([
  ".html", ".htm", ".xhtml", ".xml", ".svg", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
  ".php", ".phtml", ".pl", ".py", ".rb", ".sh", ".bat", ".cmd", ".ps1", ".exe", ".dll",
  ".msi", ".com", ".scr", ".jar", ".vbs", ".wsf"
]);

const ALLOWED_UPLOAD_EXTENSIONS = new Set([
  ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".heic",
  ".txt", ".csv", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
  ".zip", ".rar", ".7z", ".mp4", ".webm", ".mov", ".m4v", ".ogg"
]);

const ALLOWED_UPLOAD_MIME_EXACT = new Set([
  "application/pdf",
  "text/plain",
  "text/csv",
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.ms-excel",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "application/vnd.ms-powerpoint",
  "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  "application/zip",
  "application/x-zip-compressed",
  "application/x-rar-compressed",
  "application/vnd.rar",
  "application/x-7z-compressed"
]);

function isAllowedUploadFile(nameRaw, mimeRaw) {
  const name = String(nameRaw || "").trim();
  const mime = String(mimeRaw || "").trim().toLowerCase();
  const ext = path.extname(name).toLowerCase();
  if (!name || !ext) return false;
  if (DANGEROUS_UPLOAD_EXTENSIONS.has(ext)) return false;

  const safeByExt = ALLOWED_UPLOAD_EXTENSIONS.has(ext);
  const safeByMime =
    mime.startsWith("image/") ||
    mime.startsWith("video/") ||
    ALLOWED_UPLOAD_MIME_EXACT.has(mime);

  if (mime === "application/octet-stream") return safeByExt;
  return safeByExt || safeByMime;
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

function ensureRuleWikiEntries() {
  if (!Array.isArray(getAppDataJson("rule_wiki_entries_v1"))) {
    setRuleWikiEntries(defaultRuleWikiEntries());
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

function isAllowedMeetingAttachmentUrl(url) {
  const value = String(url || "").trim();
  return /^\/uploads\/chat\/[a-zA-Z0-9._-]+(?:[?#].*)?$/.test(value);
}

function normalizeEventAttachments(payload) {
  if (payload === undefined || payload === null || payload === "") return [];
  if (!Array.isArray(payload)) {
    throw new Error("Bilagor måste skickas som en lista.");
  }
  if (payload.length > 20) {
    throw new Error("Max 20 bilagor per möte.");
  }

  const normalized = [];
  const seen = new Set();
  payload.forEach((item) => {
    if (!item || typeof item !== "object") {
      throw new Error("Ogiltigt bilageformat.");
    }
    const url = String(item.url || "").trim();
    const name = String(item.name || "").trim();
    const mime = String(item.mime || "").trim().toLowerCase().slice(0, 120);
    const sizeRaw = Number(item.size);
    const size = Number.isFinite(sizeRaw) && sizeRaw >= 0 ? Math.floor(sizeRaw) : null;
    if (!url || !name) {
      throw new Error("Varje bilaga måste ha url och namn.");
    }
    if (!isAllowedMeetingAttachmentUrl(url)) {
      throw new Error("Ogiltig bilage-url. Använd uppladdad fil från /uploads/chat/.");
    }
    if (name.length > 180) {
      throw new Error("Bilagens namn är för långt (max 180 tecken).");
    }
    if (size !== null && size > MAX_UPLOAD_BYTES) {
      throw new Error("Bilagans storlek är för stor (max 10 MB).");
    }
    const key = `${url}::${name}`;
    if (seen.has(key)) return;
    seen.add(key);
    normalized.push({
      url: url,
      name: name,
      mime: mime || null,
      size: size
    });
  });
  return normalized;
}

function normalizeEventAttendance(payload) {
  if (payload === undefined || payload === null || payload === "") return [];
  if (!Array.isArray(payload)) {
    throw new Error("Närvarolistan måste skickas som en lista.");
  }
  if (payload.length > 500) {
    throw new Error("Närvarolistan är för lång (max 500 namn).");
  }

  const normalized = [];
  const seen = new Set();
  payload.forEach((item) => {
    if (!item || typeof item !== "object") {
      throw new Error("Ogiltigt format för närvaropost.");
    }
    const name = String(item.name || "").trim();
    const present = !!item.present;
    if (!name) return;
    if (name.length > 120) {
      throw new Error("Namn i närvarolistan är för långt (max 120 tecken).");
    }
    const key = name.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    normalized.push({ name, present });
  });
  return normalized;
}

function normalizeImportantColor(value) {
  const raw = String(value || "").trim().toLowerCase();
  return ["danger", "warning", "success", "info"].includes(raw) ? raw : "info";
}

function normalizeImportantSource(value) {
  const raw = String(value || "").trim().toLowerCase();
  return raw === "partikansliet" ? "partikansliet" : "admin";
}

function defaultImportantSourceLabel(source) {
  return source === "partikansliet" ? "Partikansliet" : "admin";
}

function normalizeImportantSourceLabel(value, source) {
  const trimmed = String(value || "").trim();
  if (!trimmed) return defaultImportantSourceLabel(source);
  return trimmed.slice(0, 80);
}

function normalizeImportantExternalId(value) {
  const trimmed = String(value || "").trim();
  if (!trimmed) return "";
  return trimmed.slice(0, 120);
}

function readApiKeyFromRequest(req) {
  const headerKey = String(req.get("x-api-key") || "").trim();
  if (headerKey) return headerKey;
  const authHeader = String(req.get("authorization") || "").trim();
  const m = authHeader.match(/^Bearer\s+(.+)$/i);
  return m ? String(m[1] || "").trim() : "";
}

function requirePartikanslietIntegration(req, res) {
  if (!PARTIKANSLIET_API_KEY) {
    res.status(503).json({ error: "Integrationen är inte aktiverad." });
    return false;
  }
  const provided = readApiKeyFromRequest(req);
  if (!provided || !safeEqualText(provided, PARTIKANSLIET_API_KEY)) {
    res.status(401).json({ error: "Ogiltig integrationsnyckel." });
    return false;
  }
  return true;
}

function mapImportantMessageRow(row) {
  const source = normalizeImportantSource(row && row.source);
  return {
    id: Number(row && row.id || 0),
    icon: String(row && row.icon || "📢"),
    text: String(row && row.text || ""),
    color: normalizeImportantColor(row && row.color),
    sort_order: Number(row && row.sort_order || 0),
    created_at: Number(row && row.created_at || 0),
    updated_at: Number(row && row.updated_at || 0),
    source: source,
    source_label: normalizeImportantSourceLabel(row && row.source_label, source),
    external_id: row && row.external_id ? String(row.external_id) : null
  };
}

function listImportantMessages(whereClause, params) {
  const where = String(whereClause || "").trim();
  const sql = `
    SELECT id, icon, text, color, sort_order, created_at, updated_at, source, source_label, external_id
    FROM important_messages
    ${where ? `WHERE ${where}` : ""}
    ORDER BY sort_order ASC, id ASC`;
  return db.prepare(sql).all(...(Array.isArray(params) ? params : []));
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

function defaultRuleWikiEntries() {
  return [
    {
      id: "membership-values",
      title: "1. Medlemskap och värdegrund",
      body: "Medlemskap i partiet innebär att medlemmen följer stadgar, partiprogram och intern uppförandekod.",
      bullets: [
        "Medlem förväntas bidra konstruktivt i lokal eller nationell verksamhet.",
        "Utträde sker skriftligt till lokal förening eller medlemsservice.",
        "Vid allvarliga stadgebrott kan medlemskap frysas i väntan på beslut."
      ]
    },
    {
      id: "meeting-process",
      title: "2. Mötesordning och beslutsprocess",
      body: "Partiets beslut fattas i demokratiska forum med tydlig beredning, mötesordning och protokoll.",
      bullets: [
        "Kallelse, dagordning och underlag ska publiceras i rimlig tid före mötet.",
        "Röstlängd fastställs i början av mötet innan beslutsärenden behandlas.",
        "Alla beslut dokumenteras med ansvarig funktion och tidsram."
      ]
    },
    {
      id: "nominations",
      title: "3. Nomineringar och kandidaturer",
      body: "Nominering till uppdrag och vallistor ska ske öppet, transparent och enligt fastställd kandidatpolicy.",
      bullets: [
        "Valberedningens arbete ska vara sakligt, opartiskt och dokumenterat.",
        "Kandidater ska godkänna partiets etiska riktlinjer innan nominering fastställs.",
        "Jäv ska alltid anmälas i nominerings- och tillsättningsärenden."
      ]
    },
    {
      id: "public-communication",
      title: "4. Offentlig kommunikation",
      body: "Partiets externa kommunikation ska vara faktabaserad, respektfull och följa beslutad politisk linje.",
      bullets: [
        "Officiella uttalanden görs av utsedda talespersoner eller ansvariga företrädare.",
        "Interna diskussioner publiceras inte externt utan uttryckligt mandat.",
        "Felaktigheter i extern kommunikation ska rättas skyndsamt och öppet."
      ]
    },
    {
      id: "conduct-discipline",
      title: "5. Uppförandekod och disciplin",
      body: "Partiet accepterar inte hot, hat, trakasserier eller diskriminering inom den egna organisationen.",
      bullets: [
        "Alla medlemmar ska bidra till ett tryggt och professionellt arbetsklimat.",
        "Rapporterade överträdelser utreds enligt intern disciplinprocess.",
        "Åtgärder kan omfatta varning, tillfällig avstängning eller uteslutning."
      ]
    },
    {
      id: "finance-reporting",
      title: "6. Ekonomi, bidrag och redovisning",
      body: "Partiets ekonomi ska hanteras med full spårbarhet, intern kontroll och efterlevnad av gällande regelverk.",
      bullets: [
        "Alla utbetalningar kräver korrekt attest enligt fastställd delegationsordning.",
        "Donationer och bidrag registreras och rapporteras enligt lag och interna rutiner.",
        "Kampanjmedel följs upp separat för att säkerställa transparens."
      ]
    },
    {
      id: "privacy-security",
      title: "7. Integritet, säkerhet och visselblåsning",
      body: "Partiet skyddar personuppgifter och intern information genom tydliga rutiner för säkerhet och rapportering.",
      bullets: [
        "Åtkomst till medlemsdata ges enbart till behöriga roller.",
        "Säkerhetsincidenter rapporteras omedelbart till ansvarig funktion.",
        "Visselblåsning kan ske via intern kanal med skydd för rapporterande person."
      ]
    }
  ];
}

function defaultRuleWikiDocument() {
  return {
    title: "📘 Partiets Regelbok",
    subtitle: "Intern regelbok för partiets arbetssätt, beslutsvägar och uppförandekod.",
    assistant_text: "Kommande feature.\nRegelassistenten är inte aktiv ännu.",
    footer_text: "Pedagogisk regelbok",
    pages: [
      {
        id: "organisation",
        title: "Organisation",
        description: "Grundstruktur för hur partiet är organiserat och hur beslut fattas.",
        rules: [
          {
            id: "organisation-1",
            title: "1. Organisation",
            text: "Partiet organiseras i nationell nivå, regionnivå och lokal nivå.",
            explanation: "Det betyder att partiet har tre nivåer av beslut. Lokala föreningar hanterar lokala frågor medan nationella beslut tas centralt."
          },
          {
            id: "organisation-2",
            title: "2. Mötesordning och beslutsprocess",
            text: "Partiets beslut fattas i demokratiska forum med tydlig beredning, mötesordning och protokoll.",
            explanation: "Kallelser, underlag och ansvarsfördelning ska vara tydliga så att beslut går att följa upp."
          }
        ]
      },
      {
        id: "medlemskap",
        title: "Medlemskap",
        description: "Regler för medlemskap, värdegrund och disciplinära frågor.",
        rules: [
          {
            id: "membership-1",
            title: "1. Medlemskap",
            text: "Medlemskap beviljas personer som accepterar partiets stadgar och värdegrund.",
            explanation: "Medlemskap innebär rätt att delta i möten och bidra till partiets arbete."
          },
          {
            id: "membership-2",
            title: "2. Uppförandekod",
            text: "Partiet accepterar inte hot, hat, trakasserier eller diskriminering inom organisationen.",
            explanation: "Alla medlemmar förväntas bidra till ett tryggt och professionellt arbetsklimat."
          }
        ]
      },
      {
        id: "kommunikation",
        title: "Kommunikation",
        description: "Regler för extern och intern kommunikation.",
        rules: [
          {
            id: "communication-1",
            title: "1. Kommunikation",
            text: "Officiella uttalanden görs av utsedda talespersoner.",
            explanation: "Detta förhindrar att olika budskap sprids samtidigt och skapar tydlighet externt."
          }
        ]
      },
      {
        id: "valarbete",
        title: "Valarbete",
        description: "Regler för nomineringar, kandidaturer och valorganisation.",
        rules: [
          {
            id: "election-1",
            title: "1. Valarbete",
            text: "Valorganisationen ansvarar för kampanjstrategi och material.",
            explanation: "Valgruppen samordnar aktiviteter, budskap och resurser inför val."
          }
        ]
      }
    ]
  };
}

function normalizeRuleWikiEntry(row, index) {
  if (!row || typeof row !== "object") return null;
  const idx = Number(index || 0) + 1;
  const title = String(row.title || "").trim().slice(0, 180);
  const body = String(row.body || "").trim().slice(0, 4000);
  const bullets = Array.isArray(row.bullets)
    ? row.bullets.map((item) => String(item || "").trim().slice(0, 500)).filter(Boolean).slice(0, 12)
    : [];
  if (!title || !body) return null;
  const idRaw = String(row.id || "").trim().toLowerCase();
  const safeId = (idRaw || `rule-${idx}`).replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80) || `rule-${idx}`;
  return {
    id: safeId,
    title: title,
    body: body,
    bullets: bullets
  };
}

function normalizeRuleWikiRule(row, index) {
  if (!row || typeof row !== "object") return null;
  const idx = Number(index || 0) + 1;
  const title = String(row.title || "").trim().slice(0, 180);
  const text = String(row.text || row.body || "").trim().slice(0, 4000);
  const explanation = String(row.explanation || "").trim().slice(0, 4000);
  if (!title || !text) return null;
  const idRaw = String(row.id || "").trim().toLowerCase();
  const safeId = (idRaw || `rule-${idx}`).replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80) || `rule-${idx}`;
  return {
    id: safeId,
    title: title,
    text: text,
    explanation: explanation
  };
}

function normalizeRuleWikiPage(row, index) {
  if (!row || typeof row !== "object") return null;
  const idx = Number(index || 0) + 1;
  const title = String(row.title || "").trim().slice(0, 180);
  const description = String(row.description || "").trim().slice(0, 1200);
  const category = String(row.category || "").trim().slice(0, 80);
  const rules = Array.isArray(row.rules)
    ? row.rules.map((rule, ruleIndex) => normalizeRuleWikiRule(rule, ruleIndex)).filter(Boolean)
    : [];
  if (!title || !rules.length) return null;
  const idRaw = String(row.id || "").trim().toLowerCase();
  const safeId = (idRaw || `page-${idx}`).replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80) || `page-${idx}`;
  return {
    id: safeId,
    title: title,
    description: description,
    category: category,
    rules: rules
  };
}

function normalizeRuleWikiDocument(value) {
  if (!value || typeof value !== "object") return null;
  const pages = Array.isArray(value.pages)
    ? value.pages.map((page, index) => normalizeRuleWikiPage(page, index)).filter(Boolean)
    : [];
  if (!pages.length) return null;
  return {
    title: String(value.title || "📘 Partiets Regelbok").trim().slice(0, 180) || "📘 Partiets Regelbok",
    subtitle: String(value.subtitle || "").trim().slice(0, 1200),
    assistant_text: String(value.assistant_text || "").trim().slice(0, 2000),
    footer_text: String(value.footer_text || "").trim().slice(0, 200),
    pages: pages
  };
}

function getRuleWikiDocument() {
  const raw = getAppDataJson("rule_wiki_document_v1");
  const normalized = normalizeRuleWikiDocument(raw);
  return normalized || null;
}

function setRuleWikiDocument(doc) {
  const normalized = normalizeRuleWikiDocument(doc);
  setAppDataJson("rule_wiki_document_v1", normalized || defaultRuleWikiDocument());
}

function getRuleWikiEntries() {
  const raw = getAppDataJson("rule_wiki_entries_v1");
  const normalized = Array.isArray(raw)
    ? raw.map((row, index) => normalizeRuleWikiEntry(row, index)).filter(Boolean)
    : [];
  return normalized.length ? normalized : defaultRuleWikiEntries();
}

function setRuleWikiEntries(entries) {
  const safe = Array.isArray(entries)
    ? entries.map((row, index) => normalizeRuleWikiEntry(row, index)).filter(Boolean)
    : [];
  setAppDataJson("rule_wiki_entries_v1", safe.length ? safe : defaultRuleWikiEntries());
}

ensureColumn("sessions", "last_seen_at", "last_seen_at INTEGER NOT NULL DEFAULT 0");
ensureColumn("users", "contact_email", "contact_email TEXT");
ensureColumn("users", "city", "city TEXT");
ensureColumn("users", "first_name", "first_name TEXT");
ensureColumn("users", "last_name", "last_name TEXT");
ensureColumn("users", "phone", "phone TEXT");
ensureColumn("users", "profile_image_url", "profile_image_url TEXT");
ensureColumn("users", "role", "role TEXT NOT NULL DEFAULT 'user'");
ensureColumn("qna_questions", "image_url", "image_url TEXT");
ensureColumn("qna_questions", "category", "category TEXT NOT NULL DEFAULT 'other'");
ensureColumn("qna_answers", "image_url", "image_url TEXT");
ensureColumn("important_messages", "color", "color TEXT NOT NULL DEFAULT 'info'");
ensureColumn("important_messages", "source", "source TEXT NOT NULL DEFAULT 'admin'");
ensureColumn("important_messages", "source_label", "source_label TEXT NOT NULL DEFAULT 'admin'");
ensureColumn("important_messages", "external_id", "external_id TEXT");
ensureColumn("chat_messages", "pinned", "pinned INTEGER NOT NULL DEFAULT 0");
ensureColumn("chat_messages", "pinned_at", "pinned_at INTEGER");
ensureColumn("chat_messages", "pinned_by", "pinned_by INTEGER");
ensureColumn("sessions", "csrf_token", "csrf_token TEXT");
ensureColumn("tasks", "priority", "priority TEXT NOT NULL DEFAULT 'low'");
ensureUniqueContactEmailIndex();
db.exec(`
CREATE UNIQUE INDEX IF NOT EXISTS idx_important_messages_source_external_id
  ON important_messages(source, external_id)
  WHERE external_id IS NOT NULL;
`);

const isProduction = ENV_IS_PRODUCTION;
const configuredAdmins = getConfiguredAdmins();
const validConfiguredAdmins = configuredAdmins.filter((admin) => admin.identifier);
const configuredItAdmin = getConfiguredAdminFromEnv({
  label: "IT_ADMIN",
  emailKey: "IT_ADMIN_EMAIL",
  usernameKey: "IT_ADMIN_USERNAME",
  passwordKey: "IT_ADMIN_PASSWORD"
});
const configuredItAdminIdentifier = normalizeEmail(configuredItAdmin.identifier);
if (validConfiguredAdmins.length !== 2) {
  throw new Error(
    "Du måste sätta två admin-konton i .env (ADMIN_* och ADMIN2_* med username eller email)."
  );
}
if (!configuredItAdminIdentifier) {
  throw new Error("Du måste sätta ett IT-admin-konto i .env (IT_ADMIN_* med username eller email).");
}
const configuredAdminIdentifierList = validConfiguredAdmins.map((admin) => normalizeEmail(admin.identifier));
const configuredAdminAllIdentifierList = [...configuredAdminIdentifierList, configuredItAdminIdentifier];
const configuredAdminAllIdentifierSet = new Set(configuredAdminAllIdentifierList);
if (configuredAdminAllIdentifierSet.size !== configuredAdminAllIdentifierList.length) {
  throw new Error("ADMIN_*, ADMIN2_* och IT_ADMIN_* måste vara unika användarnamn.");
}
if (configuredAdminAllIdentifierSet.has(TEST_ACCOUNT_IDENTIFIER)) {
  throw new Error("TEST_USERNAME måste vara separat från admin- och IT-admin-konton.");
}
if (configuredAdminAllIdentifierSet.has(SECRETARY_TEST_IDENTIFIER)) {
  throw new Error("SECRETARY_TEST_USERNAME måste vara separat från admin- och IT-admin-konton.");
}
const configuredAdminContactByIdentifier = new Map();
validConfiguredAdmins.forEach((admin) => {
  if (!admin.password) {
    throw new Error(`${admin.passwordKey} saknas i .env. Båda admin-lösenord måste sättas.`);
  }
  ensureDefaultUser(admin.identifier, admin.password);
  if (admin.contactEmail) {
    configuredAdminContactByIdentifier.set(normalizeEmail(admin.identifier), normalizeEmail(admin.contactEmail));
  }
});
if (!configuredItAdmin.password) {
  throw new Error("IT_ADMIN_PASSWORD saknas i .env.");
}
ensureDefaultUser(configuredItAdminIdentifier, configuredItAdmin.password);
if (configuredItAdmin.contactEmail) {
  configuredAdminContactByIdentifier.set(configuredItAdminIdentifier, normalizeEmail(configuredItAdmin.contactEmail));
}
const primaryConfiguredAdminIdentifier = configuredAdminIdentifierList[0] || "";
const itConfiguredAdminIdentifier = configuredItAdminIdentifier;
const primaryConfiguredAdminContactEmail = configuredAdminContactByIdentifier.get(primaryConfiguredAdminIdentifier) || "";
const secondaryConfiguredAdminContactEmail = configuredAdminContactByIdentifier.get(configuredAdminIdentifierList[1] || "") || "";
const itConfiguredAdminContactEmail = configuredAdminContactByIdentifier.get(itConfiguredAdminIdentifier) || "";
if (
  primaryConfiguredAdminContactEmail &&
  secondaryConfiguredAdminContactEmail &&
  primaryConfiguredAdminContactEmail === secondaryConfiguredAdminContactEmail
) {
  throw new Error("ADMIN_EMAIL och ADMIN2_EMAIL måste vara olika för separata konton.");
}
if (
  itConfiguredAdminContactEmail &&
  (
    itConfiguredAdminContactEmail === primaryConfiguredAdminContactEmail ||
    itConfiguredAdminContactEmail === secondaryConfiguredAdminContactEmail
  )
) {
  throw new Error("IT_ADMIN_EMAIL måste vara separat från ADMIN_EMAIL och ADMIN2_EMAIL.");
}
if (
  TEST_ACCOUNT_CONTACT_EMAIL &&
  [
    primaryConfiguredAdminContactEmail,
    secondaryConfiguredAdminContactEmail,
    itConfiguredAdminContactEmail
  ].includes(TEST_ACCOUNT_CONTACT_EMAIL)
) {
  throw new Error("TEST_EMAIL måste vara separat från ADMIN_EMAIL, ADMIN2_EMAIL och IT_ADMIN_EMAIL.");
}
if (
  SECRETARY_TEST_CONTACT_EMAIL &&
  [
    primaryConfiguredAdminContactEmail,
    secondaryConfiguredAdminContactEmail,
    itConfiguredAdminContactEmail
  ].includes(SECRETARY_TEST_CONTACT_EMAIL)
) {
  throw new Error("SECRETARY_TEST_EMAIL måste vara separat från ADMIN_EMAIL, ADMIN2_EMAIL och IT_ADMIN_EMAIL.");
}
if (
  SECRETARY_TEST_IDENTIFIER === TEST_ACCOUNT_IDENTIFIER
) {
  throw new Error("SECRETARY_TEST_USERNAME måste vara separat från TEST_USERNAME.");
}
const allReservedContactEmailEntries = [
  ["ADMIN_EMAIL", primaryConfiguredAdminContactEmail],
  ["ADMIN2_EMAIL", secondaryConfiguredAdminContactEmail],
  ["IT_ADMIN_EMAIL", itConfiguredAdminContactEmail],
  ["TEST_EMAIL", TEST_ACCOUNT_CONTACT_EMAIL],
  ["SECRETARY_TEST_EMAIL", SECRETARY_TEST_CONTACT_EMAIL]
].filter((row) => !!row[1]);
const seenReservedContactEmails = new Map();
allReservedContactEmailEntries.forEach(([key, mail]) => {
  const existing = seenReservedContactEmails.get(mail);
  if (existing) {
    throw new Error(`${key} och ${existing} måste vara olika kontaktmail.`);
  }
  seenReservedContactEmails.set(mail, key);
});
const primaryConfiguredAdminDisplayName = "admin";
const secondaryConfiguredAdminIdentifier = configuredAdminIdentifierList[1] || "";
const secondaryConfiguredAdminDisplayName = "admin";
const itConfiguredAdminDisplayName = "IT-admin";

function isConfiguredAdminIdentifier(value) {
  return configuredAdminAllIdentifierSet.has(normalizeEmail(value));
}

function getUserDisplayNameByIdentifier(identifier) {
  const normalized = normalizeEmail(identifier);
  if (!normalized) return "";
  const row = db
    .prepare("SELECT first_name, last_name FROM users WHERE lower(email) = ? LIMIT 1")
    .get(normalized);
  const fullName = `${String(row && row.first_name || "").trim()} ${String(row && row.last_name || "").trim()}`.trim();
  if (fullName) return fullName;
  if (normalized === primaryConfiguredAdminIdentifier) return primaryConfiguredAdminDisplayName;
  if (normalized === secondaryConfiguredAdminIdentifier) return secondaryConfiguredAdminDisplayName;
  if (normalized === itConfiguredAdminIdentifier) return itConfiguredAdminDisplayName;
  if (isConfiguredAdminIdentifier(normalized)) return primaryConfiguredAdminDisplayName;
  return String(identifier || "");
}

function configuredAdminContactEmailForIdentifier(identifier) {
  const normalized = normalizeEmail(identifier);
  if (!normalized || !isConfiguredAdminIdentifier(normalized)) return "";
  const row = db
    .prepare("SELECT contact_email FROM users WHERE lower(email) = ? LIMIT 1")
    .get(normalized);
  const fromDb = normalizeEmail(row && row.contact_email || "");
  if (fromDb) return fromDb;
  return normalizeEmail(configuredAdminContactByIdentifier.get(normalized) || "");
}

function isContactEmailUsedByOtherConfiguredAdmin(identifier, contactEmail) {
  const normalizedId = normalizeEmail(identifier);
  const normalizedContact = normalizeEmail(contactEmail);
  if (!normalizedId || !normalizedContact || !isConfiguredAdminIdentifier(normalizedId)) return false;
  for (const adminId of configuredAdminAllIdentifierList) {
    if (adminId === normalizedId) continue;
    const otherContact = configuredAdminContactEmailForIdentifier(adminId);
    if (otherContact && otherContact === normalizedContact) return true;
  }
  return false;
}

// Fast testkonto (kan tas bort av admin i medlemshantering).
ensureDefaultUser(TEST_ACCOUNT_IDENTIFIER, TEST_ACCOUNT_PASSWORD || "test");
ensureDefaultUser(SECRETARY_TEST_IDENTIFIER, SECRETARY_TEST_PASSWORD || "sekreterare1");
db.prepare("UPDATE users SET role = 'secretary' WHERE lower(email) = ?").run(SECRETARY_TEST_IDENTIFIER);
validConfiguredAdmins.forEach((admin) => {
  syncConfiguredAdminContactEmail(admin.identifier, admin.contactEmail);
});
syncConfiguredAdminContactEmail(configuredItAdminIdentifier, configuredItAdmin.contactEmail);
syncConfiguredTestAccountContactEmail();
syncConfiguredSecretaryContactEmail();

if (!isProduction) {
  ensureDefaultUser("user1", "user1");
  ensureDefaultUser("user2", "user2");
}
seedEventsIfEmpty();
removeLegacySeededDemoEvents();
seedImportantMessagesIfEmpty();
seedIdeaBankIfEmpty();
ensureFsState();
ensureRegistrationSetting();
ensureRuleWikiEntries();

app.use(express.json({ limit: "15mb" }));
app.use(cookieParser());
app.set("trust proxy", 1);
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; " +
      "img-src 'self' data: blob: https:; " +
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
      "font-src 'self' data: https://fonts.gstatic.com; " +
      "script-src 'self' 'unsafe-inline'; " +
      "connect-src 'self'; " +
      "frame-src 'self' blob: data: https:; " +
      "object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
  );
  if (isProduction) {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  next();
});

const PUBLIC_FILE_ROUTES = new Set([
  "index.html",
  "login.html",
  "registrera.html",
  "regelboken.html",
  "regelboken.json",
  "medlemshantering.html",
  "messenger.html",
  "folder-system.html",
  "facebook-logo.png",
  "marmor.jpg",
  "marmor2.png",
  "media-academy-logo.png",
  "idebank-icon.png",
  "settings.png",
  "medlemshantering.png",
  "statistik.png",
  "newgroup.png",
  "qna.png",
  "cards_icon.png",
  "tiktok-logo.svg",
  "x-logo.avif",
  "folder.svg",
  "pdf.svg",
  "text-file.svg",
  "ambition-sverige-partibeteckning.svg"
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
  const rawToken = crypto.randomBytes(48).toString("base64url");
  const token = `${rawToken}.${signSessionRaw(rawToken)}`;
  const csrfToken = makeCsrfToken();
  const expiresAt = nowTs() + SESSION_TTL_SECONDS;
  db.prepare(
    "INSERT INTO sessions(token, user_id, expires_at, last_seen_at, created_at, csrf_token) VALUES (?, ?, ?, ?, ?, ?)"
  ).run(token, userId, expiresAt, nowTs(), nowTs(), csrfToken);
  return { token, csrfToken };
}

function getUserFromSession(req) {
  const token = req.cookies[SESSION_COOKIE];
  if (!token) return null;
  const tokenStr = String(token || "");
  const dotPos = tokenStr.lastIndexOf(".");
  if (dotPos <= 0) return null;
  const raw = tokenStr.slice(0, dotPos);
  const sig = tokenStr.slice(dotPos + 1);
  const expectedSig = signSessionRaw(raw);
  if (!safeEqualText(sig, expectedSig)) return null;

  const row = db
    .prepare(
      `SELECT u.id, u.email, u.role, u.created_at, s.expires_at, s.token, s.csrf_token
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.token = ?`
    )
    .get(tokenStr);

  if (!row) return null;
  if (row.expires_at <= nowTs()) {
    db.prepare("DELETE FROM sessions WHERE token = ?").run(token);
    return null;
  }

  return {
    id: row.id,
    email: row.email,
    role: normalizeUserRole(row.role),
    created_at: row.created_at,
    token: row.token,
    csrfToken: String(row.csrf_token || "")
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

function setCsrfCookie(res, csrfToken) {
  res.cookie(CSRF_COOKIE, csrfToken, {
    maxAge: SESSION_TTL_SECONDS * 1000,
    httpOnly: false,
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
  res.clearCookie(CSRF_COOKIE, {
    httpOnly: false,
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
  let csrfToken = String(user.csrfToken || "");
  if (!csrfToken) {
    csrfToken = makeCsrfToken();
    db.prepare("UPDATE sessions SET csrf_token = ? WHERE token = ?").run(csrfToken, user.token);
  }
  setCsrfCookie(res, csrfToken);
  if (isStateChangingMethod(req.method)) {
    const provided = String(req.get("x-csrf-token") || "");
    if (!provided || provided !== csrfToken) {
      res.status(403).json({ error: "Ogiltig CSRF-token." });
      return null;
    }
  }
  db.prepare("UPDATE sessions SET last_seen_at = ? WHERE token = ?").run(nowTs(), user.token);
  return user;
}

function isAdmin(user) {
  return isConfiguredAdminIdentifier(user && user.email || "");
}

function normalizeUserRole(value) {
  const role = String(value || "").trim().toLowerCase();
  return role === "secretary" ? "secretary" : "user";
}

function isSecretary(user) {
  if (!user) return false;
  if (isAdmin(user)) return false;
  return normalizeUserRole(user.role) === "secretary";
}

function canManageAdminFeatures(user) {
  return isAdmin(user) || isSecretary(user);
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function isTestAccountIdentifier(value) {
  return normalizeEmail(value) === TEST_ACCOUNT_IDENTIFIER;
}

function syncConfiguredTestAccountContactEmail() {
  const configuredTestContact = normalizeEmail(TEST_ACCOUNT_CONTACT_EMAIL || "");
  if (!configuredTestContact) return;
  syncConfiguredAdminContactEmail(TEST_ACCOUNT_IDENTIFIER, configuredTestContact);
}

function syncConfiguredSecretaryContactEmail() {
  const configuredSecretaryContact = normalizeEmail(SECRETARY_TEST_CONTACT_EMAIL || "");
  if (!configuredSecretaryContact) return;
  syncConfiguredAdminContactEmail(SECRETARY_TEST_IDENTIFIER, configuredSecretaryContact);
}

function normalizeTaskImageUrl(url) {
  const value = String(url || "").trim();
  if (!value) return "";
  if (!isAllowedUploadUrl(value)) return "";
  return value.slice(0, 2000);
}

function normalizeTaskPriority(value) {
  const priority = String(value || "").trim().toLowerCase();
  if (!priority) return "low";
  if (priority === "low" || priority === "medium" || priority === "high") return priority;
  return "";
}

function mapTaskAssignmentRow(row) {
  return {
    assignment_id: Number(row.assignment_id || 0),
    task_id: Number(row.task_id || 0),
    title: String(row.title || ""),
    description: String(row.description || ""),
    image_url: String(row.image_url || ""),
    priority: normalizeTaskPriority(row.priority),
    assigned_at: Number(row.assigned_at || 0),
    solved_at: row.solved_at ? Number(row.solved_at) : null,
    assigned_to_email: String(row.assigned_to_email || ""),
    assigned_by_email: String(row.assigned_by_email || "")
  };
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
  const smtpUser = String(process.env.SMTP_USER || DEFAULT_SMTP_IDENTITY).trim();
  const mailFrom = String(process.env.MAIL_FROM || smtpUser || DEFAULT_SMTP_IDENTITY).trim();
  const smtpSecureRaw = String(process.env.SMTP_SECURE || "").trim().toLowerCase();
  const smtpFrom = mailFrom || DEFAULT_SMTP_IDENTITY;
  const smtpAuthUser = smtpUser || DEFAULT_SMTP_IDENTITY;
  const smtpSecure = smtpSecureRaw
    ? ["1", "true", "yes", "on"].includes(smtpSecureRaw)
    : smtpPort === 465;

  if (!smtpHost || !smtpPass || !smtpAuthUser) {
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

    const sentAt = new Date();
    const messageId = `<${Date.now()}.${crypto.randomBytes(8).toString("hex")}@ambitionsverige.se>`;
    const body = [
      `From: ${smtpFrom}`,
      `To: ${toEmail}`,
      `Subject: ${subject}`,
      `Date: ${sentAt.toUTCString()}`,
      `Message-ID: ${messageId}`,
      "MIME-Version: 1.0",
      `X-Entity-Ref-ID: ${messageId}`,
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

  async function createSmtpSocket() {
    return new Promise((resolve, reject) => {
      const socket = smtpSecure
        ? tls.connect({ host: smtpHost, port: smtpPort, servername: smtpHost }, () => resolve(socket))
        : net.connect({ host: smtpHost, port: smtpPort }, () => resolve(socket));
      socket.setTimeout(20000, () => {
        socket.destroy(new Error("SMTP socket timeout"));
      });
      socket.on("error", reject);
    });
  }

  function isTransientSmtpError(err) {
    const msg = String(err && err.message ? err.message : "");
    return /SMTP fel \(4\d\d\)/.test(msg) || /timeout/i.test(msg) || /connection closed/i.test(msg);
  }

  const maxAttempts = 2;
  let lastErr = null;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    let socket = null;
    try {
      socket = await createSmtpSocket();
      await sendViaSocket(socket);
      lastErr = null;
      break;
    } catch (err) {
      lastErr = err;
      if (socket && !socket.destroyed) {
        try { socket.destroy(); } catch (_) {}
      }
      if (attempt >= maxAttempts || !isTransientSmtpError(err)) {
        throw err;
      }
      await new Promise((resolve) => setTimeout(resolve, 1200 * attempt));
    }
  }
  if (lastErr) throw lastErr;
  return { mode: "smtp", auth_user: smtpAuthUser };
}

async function sendGeneratedCredentialsEmail({ workEmail, username, city }) {
  const subject = "Ditt användarnamn - Ambition Sverige";
  const text = [
    "Hej!",
    "",
    `Din registrering för ort: ${city} är klar.`,
    "",
    "Ditt användarnamn:",
    `Användarnamn: ${username}`,
    "",
    "När du loggar in anger du användarnamn och får en engångskod via e-post.",
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

function makeNumericLoginCode(length = 6) {
  let out = "";
  for (let i = 0; i < length; i += 1) {
    out += String(crypto.randomInt(0, 10));
  }
  return out;
}

async function sendLoginCodeEmail({ recipientEmail, username, code }) {
  const safeUser = String(username || "").trim() || "konto";
  const subject = `Din inloggningskod (${safeUser}) - Ambition Sverige`;
  const text = [
    "Hej!",
    "",
    "Du har begärt en inloggningskod.",
    "",
    `Användarnamn: ${username}`,
    `Inloggningskod: ${code}`,
    "",
    `Koden gäller i ${Math.floor(LOGIN_CODE_TTL_SECONDS / 60)} minuter.`,
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
  const now = nowTs();
  const ip = String(req.ip || "unknown");

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

  const registerRateKey = `register:${ip}`;
  const registerRate = registerRateLimit.get(registerRateKey) || { count: 0, reset_at: now + REGISTER_RATE_LIMIT_WINDOW_SECONDS };
  if (registerRate.reset_at <= now) {
    registerRate.count = 0;
    registerRate.reset_at = now + REGISTER_RATE_LIMIT_WINDOW_SECONDS;
  }
  registerRate.count += 1;
  registerRateLimit.set(registerRateKey, registerRate);
  if (registerRate.count > REGISTER_RATE_LIMIT_MAX_ATTEMPTS) {
    return res.status(429).json({ error: "För många registreringsförsök. Vänta en stund och prova igen." });
  }

  const cooldownUntil = Number(registerEmailCooldown.get(workEmail) || 0);
  if (cooldownUntil > now) {
    return res.status(429).json({ error: "För många försök för den här e-postadressen. Vänta en stund och prova igen." });
  }

  const existingByContact = db
    .prepare("SELECT id FROM users WHERE lower(contact_email) = ? LIMIT 1")
    .get(workEmail);
  if (existingByContact) {
    return res.status(409).json({ error: "Den här e-postadressen är redan registrerad." });
  }

  const username = generateUniqueUsername();
  const password = makeRandomPassword(24);

  const salt = crypto.randomBytes(16).toString("hex");
  const passwordHash = hashPassword(password, salt, PBKDF2_ITERATIONS);

  let createdId = null;
  try {
    registerEmailCooldown.set(workEmail, now + REGISTER_EMAIL_COOLDOWN_SECONDS);
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
        now,
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
      city
    });

    return res.status(201).json({
      ok: true,
      message: "Konto skapat. Användarnamn har skickats till din e-post.",
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

app.post("/api/login/code/request", async (req, res) => {
  const identifier = normalizeEmail(req.body?.identifier || req.body?.username || req.body?.email || "");
  const genericMessage = "Om användaren finns har en inloggningskod skickats till registrerad e-post.";
  const ip = String(req.ip || "unknown");
  const rateKey = `logincode:req:${identifier || "empty"}:${ip}`;
  const now = nowTs();
  const rate = loginCodeRequestRateLimit.get(rateKey) || { count: 0, reset_at: now + LOGIN_CODE_RATE_LIMIT_WINDOW_SECONDS };
  if (rate.reset_at <= now) {
    rate.count = 0;
    rate.reset_at = now + LOGIN_CODE_RATE_LIMIT_WINDOW_SECONDS;
  }
  rate.count += 1;
  loginCodeRequestRateLimit.set(rateKey, rate);
  if (rate.count > LOGIN_CODE_RATE_LIMIT_MAX_ATTEMPTS) {
    return res.status(429).json({ error: "För många försök. Vänta en stund och prova igen." });
  }

  if (!identifier || identifier.length < 2) {
    return res.json({ ok: true, message: genericMessage });
  }

  const user = db
    .prepare("SELECT id, email, contact_email FROM users WHERE lower(email) = ? LIMIT 1")
    .get(identifier);
  if (!user) {
    return res.json({ ok: true, message: genericMessage });
  }

  const isTestAccount = isTestAccountIdentifier(user.email);
  let recipientEmail = normalizeEmail(user.contact_email || "");
  if (isTestAccount) {
    const configuredTestContact = normalizeEmail(TEST_ACCOUNT_CONTACT_EMAIL || "");
    if (configuredTestContact) {
      recipientEmail = configuredTestContact;
      if (recipientEmail !== normalizeEmail(user.contact_email || "")) {
        db.prepare("UPDATE users SET contact_email = ? WHERE id = ?").run(recipientEmail, Number(user.id));
      }
    }
  } else if (!recipientEmail) {
    const maybeAdmin = isConfiguredAdminIdentifier(user.email);
    const configuredMail = normalizeEmail(
      configuredAdminContactByIdentifier.get(normalizeEmail(user.email || "")) || ""
    );
    if (maybeAdmin && configuredMail) {
      recipientEmail = configuredMail;
      db.prepare("UPDATE users SET contact_email = ? WHERE id = ?").run(recipientEmail, Number(user.id));
    }
  }
  if (!recipientEmail || !recipientEmail.endsWith(REGISTER_ALLOWED_DOMAIN)) {
    return res.json({ ok: true, message: genericMessage });
  }

  const latestLoginCode = db
    .prepare(
      `SELECT created_at
       FROM login_code_tokens
       WHERE user_id = ?
       ORDER BY id DESC
       LIMIT 1`
    )
    .get(Number(user.id));
  if (latestLoginCode) {
    const lastCreatedAt = Number(latestLoginCode.created_at || 0);
    if (lastCreatedAt > 0 && now - lastCreatedAt < LOGIN_CODE_EMAIL_COOLDOWN_SECONDS) {
      return res.json({ ok: true, message: genericMessage });
    }
  }

  const code = makeNumericLoginCode(6);
  const codeHash = hashResetToken(code);
  const expiresAt = now + LOGIN_CODE_TTL_SECONDS;
  try {
    db.prepare(
      "DELETE FROM login_code_tokens WHERE user_id = ? OR expires_at <= ? OR used_at IS NOT NULL"
    ).run(Number(user.id), now);
    db.prepare(
      `INSERT INTO login_code_tokens(user_id, code_hash, expires_at, used_at, created_at)
       VALUES (?, ?, ?, NULL, ?)`
    ).run(Number(user.id), codeHash, expiresAt, now);
    await sendLoginCodeEmail({
      recipientEmail: recipientEmail,
      username: String(user.email || ""),
      code: code
    });
  } catch (_) {
    return res.status(500).json({ error: "Kunde inte skicka inloggningskod just nu." });
  }

  return res.json({ ok: true, message: genericMessage });
});

app.post("/api/login/code/verify", (req, res) => {
  const identifier = normalizeEmail(req.body?.identifier || req.body?.username || req.body?.email || "");
  const code = String(req.body?.code || "").trim();
  const ip = String(req.ip || "unknown");
  const rateKey = `logincode:verify:${identifier || "empty"}:${ip}`;
  const now = nowTs();
  const rate = loginCodeVerifyRateLimit.get(rateKey) || { count: 0, reset_at: now + LOGIN_CODE_RATE_LIMIT_WINDOW_SECONDS };
  if (rate.reset_at <= now) {
    rate.count = 0;
    rate.reset_at = now + LOGIN_CODE_RATE_LIMIT_WINDOW_SECONDS;
  }
  rate.count += 1;
  loginCodeVerifyRateLimit.set(rateKey, rate);
  if (rate.count > LOGIN_CODE_RATE_LIMIT_MAX_ATTEMPTS) {
    return res.status(429).json({ error: "För många försök. Vänta en stund och prova igen." });
  }

  if (!identifier || !/^\d{6}$/.test(code)) {
    return res.status(400).json({ error: "Ange användarnamn och sexsiffrig kod." });
  }

  const user = db
    .prepare("SELECT id, email FROM users WHERE lower(email) = ? LIMIT 1")
    .get(identifier);
  if (!user) {
    return res.status(401).json({ error: "Fel användarnamn eller kod." });
  }

  const codeHash = hashResetToken(code);
  const tokenRow = db
    .prepare(
      `SELECT id
       FROM login_code_tokens
       WHERE user_id = ?
         AND code_hash = ?
         AND used_at IS NULL
         AND expires_at > ?
       ORDER BY id DESC
       LIMIT 1`
    )
    .get(Number(user.id), codeHash, now);
  if (!tokenRow) {
    return res.status(401).json({ error: "Fel användarnamn eller kod." });
  }

  db.prepare("UPDATE login_code_tokens SET used_at = ? WHERE id = ?").run(now, Number(tokenRow.id));
  loginCodeVerifyRateLimit.delete(rateKey);
  const session = createSession(user.id);
  setSessionCookie(res, session.token);
  setCsrfCookie(res, session.csrfToken);
  return res.json({ ok: true, email: user.email });
});

app.post("/api/login", (req, res) => {
  return res.status(410).json({
    error: "Lösenordsinloggning är avstängd. Använd inloggning med engångskod via /api/login/code/request och /api/login/code/verify."
  });
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
  const displayName = getUserDisplayNameByIdentifier(user.email);
  return res.json({
    id: user.id,
    email: user.email,
    display_name: displayName,
    created_at: user.created_at,
    is_admin: isAdmin(user),
    is_secretary: isSecretary(user)
  });
});

app.get("/api/me/profile", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const row = db
    .prepare("SELECT id, email, contact_email, city, first_name, last_name, phone, profile_image_url FROM users WHERE id = ?")
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
    phone: String(row.phone || ""),
    profile_image_url: String(row.profile_image_url || "")
  });
});

app.get("/api/users/profile", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const email = normalizeEmail(req.query?.email || "");
  if (!email) {
    return res.status(400).json({ error: "Ogiltig användare." });
  }

  const row = db
    .prepare("SELECT id, email, city, first_name, last_name, profile_image_url FROM users WHERE lower(email) = ? LIMIT 1")
    .get(email);
  if (!row) {
    return res.status(404).json({ error: "Användaren hittades inte." });
  }

  return res.json({
    id: Number(row.id || 0),
    username: String(row.email || ""),
    city: String(row.city || ""),
    first_name: String(row.first_name || ""),
    last_name: String(row.last_name || ""),
    profile_image_url: String(row.profile_image_url || "")
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
  const profileImageUrl = String(req.body?.profile_image_url || "").trim();

  if (phone) {
    const phoneDigits = phone.replace(/[^\d+]/g, "");
    if (phoneDigits.length < 7) {
      return res.status(400).json({ error: "Ogiltigt telefonnummer." });
    }
  }
  if (contactEmail && !contactEmail.endsWith(REGISTER_ALLOWED_DOMAIN)) {
    return res.status(400).json({ error: `E-post måste sluta med ${REGISTER_ALLOWED_DOMAIN}.` });
  }
  if (contactEmail && isContactEmailUsedByOtherConfiguredAdmin(user.email, contactEmail)) {
    return res.status(409).json({ error: "Admin 1 och admin 2 måste ha olika kontaktmail." });
  }
  if (city && !REGISTER_CITIES.includes(city)) {
    return res.status(400).json({ error: "Välj en giltig ort." });
  }
  if (profileImageUrl && !isAllowedUploadUrl(profileImageUrl)) {
    return res.status(400).json({ error: "Ogiltig URL för profilbild." });
  }

  if (contactEmail) {
    const conflict = db
      .prepare("SELECT id, email FROM users WHERE lower(contact_email) = ? AND id != ? LIMIT 1")
      .get(contactEmail, user.id);
    if (conflict) {
      return res.status(409).json({ error: "E-postadressen används redan av en annan användare." });
    }
  }

  db.prepare(
    "UPDATE users SET first_name = ?, last_name = ?, phone = ?, contact_email = ?, city = ?, profile_image_url = ? WHERE id = ?"
  ).run(firstName, lastName, phone, contactEmail, city, profileImageUrl, user.id);

  if (isAdmin(user) || isTestAccountIdentifier(user.email)) {
    syncConfiguredTestAccountContactEmail();
  }

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
  if (!canManageAdminFeatures(user)) {
    return res.status(403).json({ error: "Endast admin eller sekreterare har åtkomst." });
  }
  return res.json({
    allow_registrations: getAllowRegistrations(),
    is_production: isProduction
  });
});

app.get("/api/rule-wiki", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const document = getRuleWikiDocument();
  return res.json({
    document: document,
    entries: getRuleWikiEntries(),
    source: document ? "app" : "entries"
  });
});

app.put("/api/rule-wiki", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!isAdmin(user)) {
    return res.status(403).json({ error: "Endast admin kan redigera reglerna." });
  }
  const documentPayload = req.body?.document;
  if (documentPayload && typeof documentPayload === "object" && !Array.isArray(documentPayload)) {
    const normalizedDocument = normalizeRuleWikiDocument(documentPayload);
    if (!normalizedDocument) {
      return res.status(400).json({ error: "Ogiltig regelboks-JSON. Minst en sida med regler krävs." });
    }
    setRuleWikiDocument(normalizedDocument);
    return res.json({ ok: true, document: getRuleWikiDocument(), source: "app" });
  }
  const entries = Array.isArray(req.body?.entries) ? req.body.entries : null;
  if (!entries) {
    return res.status(400).json({ error: "Regellistan måste vara en array." });
  }
  const normalized = entries.map((row, index) => normalizeRuleWikiEntry(row, index)).filter(Boolean);
  if (!normalized.length) {
    return res.status(400).json({ error: "Minst ett regelavsnitt krävs." });
  }
  setRuleWikiEntries(normalized);
  return res.json({ ok: true, entries: getRuleWikiEntries(), document: getRuleWikiDocument(), source: getRuleWikiDocument() ? "app" : "entries" });
});

app.put("/api/admin/settings/registrations", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!canManageAdminFeatures(user)) {
    return res.status(403).json({ error: "Endast admin eller sekreterare kan ändra registreringsinställningen." });
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
  if (!canManageAdminFeatures(user)) {
    return res.status(403).json({ error: "Endast admin eller sekreterare har åtkomst." });
  }

  const activeSince = nowTs() - ONLINE_WINDOW_SECONDS;
  const rows = db
    .prepare(
      `SELECT u.id, u.email, u.contact_email, u.city, u.first_name, u.last_name, u.phone, u.role,
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
      role: normalizeUserRole(r.role),
      online: !!r.is_online,
      is_admin: isAdmin({ email: String(r.email || "") }),
      is_secretary: !isAdmin({ email: String(r.email || "") }) && normalizeUserRole(r.role) === "secretary"
    }))
  });
});

app.put("/api/admin/users/:id", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!canManageAdminFeatures(user)) {
    return res.status(403).json({ error: "Endast admin eller sekreterare kan redigera användare." });
  }

  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "Ogiltigt användar-id." });
  }
  const target = db.prepare("SELECT id, email, role FROM users WHERE id = ?").get(id);
  if (!target) {
    return res.status(404).json({ error: "Användaren hittades inte." });
  }

  const nextEmail = String(req.body?.email || "").trim().toLowerCase();
  const nextContactEmail = normalizeEmail(req.body?.contact_email || "");
  const nextCity = String(req.body?.city || "").trim();
  const nextFirstName = String(req.body?.first_name || "").trim();
  const nextLastName = String(req.body?.last_name || "").trim();
  const nextPhone = String(req.body?.phone || "").trim();
  const targetRole = normalizeUserRole(target.role);
  let nextRole = targetRole;
  const hasRoleUpdate = Object.prototype.hasOwnProperty.call(req.body || {}, "role");
  if (hasRoleUpdate) {
    nextRole = normalizeUserRole(req.body?.role);
    if (!isAdmin(user) && nextRole !== targetRole) {
      return res.status(403).json({ error: "Endast admin kan ändra sekreterarroll." });
    }
  }

  if (!nextEmail || nextEmail.length < 2) {
    return res.status(400).json({ error: "Ogiltigt användarnamn." });
  }
  const targetEmail = normalizeEmail(target.email || "");
  const targetIsAdmin = isConfiguredAdminIdentifier(targetEmail);
  if (targetIsAdmin && nextEmail !== targetEmail) {
    return res.status(400).json({ error: "Admin-konton från .env kan inte byta användarnamn." });
  }
  if (targetIsAdmin && hasRoleUpdate && nextRole !== targetRole) {
    return res.status(400).json({ error: "Admin-konton från .env kan inte byta roll." });
  }
  if (!targetIsAdmin && isConfiguredAdminIdentifier(nextEmail)) {
    return res.status(409).json({ error: "Användarnamnet är reserverat för admin från .env." });
  }
  if (nextContactEmail && !nextContactEmail.endsWith(REGISTER_ALLOWED_DOMAIN)) {
    return res.status(400).json({ error: `Kontaktmail måste sluta med ${REGISTER_ALLOWED_DOMAIN}.` });
  }
  if (nextContactEmail && isContactEmailUsedByOtherConfiguredAdmin(nextEmail, nextContactEmail)) {
    return res.status(409).json({ error: "Admin 1 och admin 2 måste ha olika kontaktmail." });
  }
  if (nextCity && !REGISTER_CITIES.includes(nextCity)) {
    return res.status(400).json({ error: "Ogiltig ort." });
  }

  try {
    const result = db
      .prepare(
        "UPDATE users SET email = ?, contact_email = ?, city = ?, first_name = ?, last_name = ?, phone = ?, role = ? WHERE id = ?"
      )
      .run(
        nextEmail,
        nextContactEmail || null,
        nextCity || null,
        nextFirstName || null,
        nextLastName || null,
        nextPhone || null,
        nextRole,
        id
      );
    if (result.changes === 0) {
      return res.status(404).json({ error: "Användaren hittades inte." });
    }
    if (
      isAdmin({ email: target.email }) ||
      isAdmin({ email: nextEmail }) ||
      isTestAccountIdentifier(target.email) ||
      isTestAccountIdentifier(nextEmail)
    ) {
      syncConfiguredTestAccountContactEmail();
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
  if (isConfiguredAdminIdentifier(target.email || "")) {
    return res.status(400).json({ error: "Admin-konton från .env kan inte tas bort." });
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
         u.profile_image_url,
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
    profile_image_url: String(r.profile_image_url || ""),
    name: getUserDisplayNameByIdentifier(r.email),
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
      `SELECT dm.id, dm.sender_id, dm.recipient_id, dm.message, dm.created_at, s.email AS sender_email, s.profile_image_url AS sender_profile_image_url
       FROM (
         SELECT id, sender_id, recipient_id, message, created_at
         FROM direct_messages
         WHERE (sender_id = ? AND recipient_id = ?)
            OR (sender_id = ? AND recipient_id = ?)
         ORDER BY created_at DESC, id DESC
         LIMIT 500
       ) dm
       JOIN users s ON s.id = dm.sender_id
       ORDER BY dm.created_at ASC, dm.id ASC`
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
      from_me: m.sender_id === user.id,
      sender_email: String(m.sender_email || ""),
      sender_display_name: getUserDisplayNameByIdentifier(m.sender_email),
      profile_image_url: String(m.sender_profile_image_url || "")
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
      `SELECT gm.id, gm.message, gm.created_at, gm.sender_id, u.email, u.profile_image_url
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
      sender_email: m.email,
      sender_display_name: getUserDisplayNameByIdentifier(m.email),
      profile_image_url: String(m.profile_image_url || "")
    }))
  });
});

app.get("/api/messenger/groups/:groupId/members", (req, res) => {
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
         END AS is_online
       FROM chat_group_members gm
       JOIN users u ON u.id = gm.user_id
       WHERE gm.group_id = ?
       ORDER BY lower(u.email) ASC`
    )
    .all(nowTs(), activeSince, groupId);

  return res.json({
    members: rows.map((r) => ({
      id: Number(r.id || 0),
      email: String(r.email || ""),
      display_name: getUserDisplayNameByIdentifier(r.email),
      online: !!r.is_online
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
  const mimeRaw = String(req.body?.mime || "").trim().toLowerCase();
  const dataBase64 = String(req.body?.data_base64 || "").trim();

  if (!nameRaw || !dataBase64) {
    return res.status(400).json({ error: "Filnamn och filinnehåll krävs." });
  }
  if (!isAllowedUploadFile(nameRaw, mimeRaw)) {
    return res.status(400).json({ error: "Otillåten filtyp." });
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
      `SELECT m.id, m.message, m.created_at, u.email, u.city AS user_city, u.profile_image_url AS user_profile_image_url,
              m.pinned, m.pinned_at, m.pinned_by, pu.email AS pinned_by_email
       FROM chat_messages m
       JOIN users u ON u.id = m.user_id
       LEFT JOIN users pu ON pu.id = m.pinned_by
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
    const authorEmail = String(m.email || "");
    return {
      ...m,
      email: authorEmail,
      author_display_name: getUserDisplayNameByIdentifier(authorEmail),
      pinned: !!Number(m.pinned || 0),
      pinned_at: Number(m.pinned_at || 0) || null,
      pinned_by_email: String(m.pinned_by_email || ""),
      author_is_admin: isAdmin({ email: authorEmail }),
      profile_image_url: String(m.user_profile_image_url || ""),
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

app.put("/api/chat/messages/:id/pin", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!canManageAdminFeatures(user)) {
    return res.status(403).json({ error: "Endast admin eller sekreterare kan pinna chatinlägg." });
  }

  const id = Number(req.params.id || 0);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "Ogiltigt meddelande-id." });
  }

  const existing = db
    .prepare("SELECT id FROM chat_messages WHERE id = ?")
    .get(id);
  if (!existing) {
    return res.status(404).json({ error: "Meddelandet finns inte." });
  }

  const shouldPin = !!req.body?.pinned;
  db.prepare(
    `UPDATE chat_messages
     SET pinned = ?, pinned_at = ?, pinned_by = ?
     WHERE id = ?`
  ).run(
    shouldPin ? 1 : 0,
    shouldPin ? nowTs() : null,
    shouldPin ? user.id : null,
    id
  );

  return res.json({ ok: true });
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

function attachEventAttachments(rows) {
  if (!Array.isArray(rows) || !rows.length) return [];
  const eventIds = rows
    .map((r) => Number(r.id))
    .filter((id) => Number.isInteger(id) && id > 0);
  if (!eventIds.length) {
    return rows.map((row) => ({ ...row, attachments: [] }));
  }

  const placeholders = eventIds.map(() => "?").join(", ");
  const attachmentRows = db
    .prepare(
      `SELECT event_id, file_url, file_name, file_mime, file_size
       FROM event_attachments
       WHERE event_id IN (${placeholders})
       ORDER BY id ASC`
    )
    .all(...eventIds);

  const grouped = new Map();
  attachmentRows.forEach((row) => {
    const eventId = Number(row.event_id || 0);
    if (!grouped.has(eventId)) grouped.set(eventId, []);
    grouped.get(eventId).push({
      url: String(row.file_url || ""),
      name: String(row.file_name || "bilaga"),
      mime: String(row.file_mime || ""),
      size: row.file_size === null || row.file_size === undefined ? null : Number(row.file_size)
    });
  });

  return rows.map((row) => {
    const eventId = Number(row.id || 0);
    return {
      ...row,
      attachments: grouped.get(eventId) || []
    };
  });
}

function attachEventAttendance(rows) {
  if (!Array.isArray(rows) || !rows.length) return [];
  const eventIds = rows
    .map((r) => Number(r.id))
    .filter((id) => Number.isInteger(id) && id > 0);
  if (!eventIds.length) {
    return rows.map((row) => ({ ...row, attendance: [] }));
  }

  const placeholders = eventIds.map(() => "?").join(", ");
  const attendanceRows = db
    .prepare(
      `SELECT event_id, attendee_name, present
       FROM event_attendance
       WHERE event_id IN (${placeholders})
       ORDER BY lower(attendee_name) ASC, id ASC`
    )
    .all(...eventIds);

  const grouped = new Map();
  attendanceRows.forEach((row) => {
    const eventId = Number(row.event_id || 0);
    if (!grouped.has(eventId)) grouped.set(eventId, []);
    grouped.get(eventId).push({
      name: String(row.attendee_name || ""),
      present: !!row.present
    });
  });

  return rows.map((row) => {
    const eventId = Number(row.id || 0);
    return {
      ...row,
      attendance: grouped.get(eventId) || []
    };
  });
}

function replaceEventAttachments(eventId, attachments, userId) {
  const normalizedEventId = Number(eventId);
  const normalizedUserId = Number(userId) || null;
  db.prepare("DELETE FROM event_attachments WHERE event_id = ?").run(normalizedEventId);
  if (!attachments.length) return;
  const insert = db.prepare(
    `INSERT INTO event_attachments(
        event_id, file_url, file_name, file_mime, file_size, created_by, created_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?)`
  );
  const ts = nowTs();
  attachments.forEach((item) => {
    insert.run(
      normalizedEventId,
      item.url,
      item.name,
      item.mime || null,
      item.size === null || item.size === undefined ? null : Number(item.size),
      normalizedUserId,
      ts
    );
  });
}

function replaceEventAttendance(eventId, attendance, userId) {
  const normalizedEventId = Number(eventId);
  const normalizedUserId = Number(userId) || null;
  db.prepare("DELETE FROM event_attendance WHERE event_id = ?").run(normalizedEventId);
  if (!attendance.length) return;
  const insert = db.prepare(
    `INSERT INTO event_attendance(
        event_id, attendee_name, present, created_by, created_at, updated_at
     ) VALUES (?, ?, ?, ?, ?, ?)`
  );
  const ts = nowTs();
  attendance.forEach((item) => {
    insert.run(
      normalizedEventId,
      item.name,
      item.present ? 1 : 0,
      normalizedUserId,
      ts,
      ts
    );
  });
}

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

  const withAttachments = attachEventAttachments(rows);
  return res.json({ events: attachEventAttendance(withAttachments) });
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

  const withAttachments = attachEventAttachments(rows);
  return res.json({ date_key: todayKey, meetings: attachEventAttendance(withAttachments) });
});

app.post("/api/events", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!canManageAdminFeatures(user)) {
    return res.status(403).json({ error: "Endast admin eller sekreterare kan skapa möten." });
  }

  const dateKey = String(req.body?.date_key || "").trim();
  const title = String(req.body?.title || "").trim();
  const link = String(req.body?.link || "").trim();
  let attachments = [];

  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateKey)) {
    return res.status(400).json({ error: "Ogiltigt datumformat. Använd YYYY-MM-DD." });
  }
  if (!title) {
    return res.status(400).json({ error: "Titel krävs." });
  }
  try {
    attachments = normalizeEventAttachments(req.body?.attachments);
  } catch (err) {
    return res.status(400).json({ error: err.message || "Ogiltiga bilagor." });
  }

  const result = db.transaction(() => {
    const created = db
      .prepare("INSERT INTO events(date_key, title, link, created_by, created_at) VALUES (?, ?, ?, ?, ?)")
      .run(dateKey, title, link || null, user.id, nowTs());
    replaceEventAttachments(created.lastInsertRowid, attachments, user.id);
    return created;
  })();

  return res.status(201).json({ ok: true, id: result.lastInsertRowid });
});

app.put("/api/events/:id", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!canManageAdminFeatures(user)) {
    return res.status(403).json({ error: "Endast admin eller sekreterare kan redigera möten." });
  }

  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "Ogiltigt event-id." });
  }

  const dateKey = String(req.body?.date_key || "").trim();
  const title = String(req.body?.title || "").trim();
  const link = String(req.body?.link || "").trim();
  let attachments = null;

  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateKey)) {
    return res.status(400).json({ error: "Ogiltigt datumformat. Använd YYYY-MM-DD." });
  }
  if (!title) {
    return res.status(400).json({ error: "Titel krävs." });
  }
  if (Object.prototype.hasOwnProperty.call(req.body || {}, "attachments")) {
    try {
      attachments = normalizeEventAttachments(req.body?.attachments);
    } catch (err) {
      return res.status(400).json({ error: err.message || "Ogiltiga bilagor." });
    }
  }

  const result = db.transaction(() => {
    const updated = db
      .prepare("UPDATE events SET date_key = ?, title = ?, link = ? WHERE id = ?")
      .run(dateKey, title, link || null, id);
    if (updated.changes > 0 && attachments !== null) {
      replaceEventAttachments(id, attachments, user.id);
    }
    return updated;
  })();

  if (result.changes === 0) {
    return res.status(404).json({ error: "Mötet hittades inte." });
  }
  return res.json({ ok: true });
});

app.delete("/api/events/:id", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!isAdmin(user)) {
    return res.status(403).json({ error: "Endast admin kan ta bort möten." });
  }

  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "Ogiltigt event-id." });
  }

  const result = db.transaction(() => {
    db.prepare("DELETE FROM event_attachments WHERE event_id = ?").run(id);
    db.prepare("DELETE FROM event_attendance WHERE event_id = ?").run(id);
    return db.prepare("DELETE FROM events WHERE id = ?").run(id);
  })();

  if (result.changes === 0) {
    return res.status(404).json({ error: "Mötet hittades inte." });
  }
  return res.json({ ok: true });
});

app.put("/api/events/:id/attendance", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!canManageAdminFeatures(user)) {
    return res.status(403).json({ error: "Endast admin eller sekreterare kan uppdatera närvarolistan." });
  }

  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "Ogiltigt event-id." });
  }

  const eventExists = db.prepare("SELECT id FROM events WHERE id = ? LIMIT 1").get(id);
  if (!eventExists) {
    return res.status(404).json({ error: "Mötet hittades inte." });
  }

  let attendance = [];
  try {
    attendance = normalizeEventAttendance(req.body?.attendance);
  } catch (err) {
    return res.status(400).json({ error: err.message || "Ogiltig närvarolista." });
  }

  replaceEventAttendance(id, attendance, user.id);
  return res.json({ ok: true, count: attendance.length });
});

app.get("/api/important-messages", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const rows = listImportantMessages();

  return res.json({ messages: rows.map(mapImportantMessageRow) });
});

app.post("/api/important-messages", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!canManageAdminFeatures(user)) {
    return res.status(403).json({ error: "Endast admin eller sekreterare kan skapa viktiga meddelanden." });
  }

  const icon = String(req.body?.icon || "📢").trim().slice(0, 8) || "📢";
  const text = String(req.body?.text || "").trim();
  const color = normalizeImportantColor(req.body?.color);
  const sortOrderRaw = Number(req.body?.sort_order);
  const source = "admin";
  const sourceLabel = defaultImportantSourceLabel(source);

  if (!text) return res.status(400).json({ error: "Text krävs." });
  if (text.length > 500) return res.status(400).json({ error: "Texten är för lång (max 500 tecken)." });

  const fallbackOrder = Number(
    db.prepare("SELECT COALESCE(MAX(sort_order), -1) + 1 AS next_order FROM important_messages").get().next_order
  );
  const sortOrder = Number.isInteger(sortOrderRaw) ? sortOrderRaw : fallbackOrder;
  const now = nowTs();

  const result = db
    .prepare(
      `INSERT INTO important_messages(
          icon, text, color, sort_order, created_by, created_at, updated_at, source, source_label, external_id
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`
    )
    .run(icon, text, color, sortOrder, user.id, now, now, source, sourceLabel);

  return res.status(201).json({ ok: true, id: result.lastInsertRowid });
});

app.put("/api/important-messages/:id", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!canManageAdminFeatures(user)) {
    return res.status(403).json({ error: "Endast admin eller sekreterare kan redigera viktiga meddelanden." });
  }

  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "Ogiltigt id." });
  }

  const icon = String(req.body?.icon || "📢").trim().slice(0, 8) || "📢";
  const text = String(req.body?.text || "").trim();
  const color = normalizeImportantColor(req.body?.color);
  const sortOrderRaw = Number(req.body?.sort_order);
  const sortOrder = Number.isInteger(sortOrderRaw) ? sortOrderRaw : null;

  if (!text) return res.status(400).json({ error: "Text krävs." });
  if (text.length > 500) return res.status(400).json({ error: "Texten är för lång (max 500 tecken)." });

  const now = nowTs();
  let result;
  if (sortOrder === null) {
    result = db
      .prepare("UPDATE important_messages SET icon = ?, text = ?, color = ?, updated_at = ? WHERE id = ?")
      .run(icon, text, color, now, id);
  } else {
    result = db
      .prepare("UPDATE important_messages SET icon = ?, text = ?, color = ?, sort_order = ?, updated_at = ? WHERE id = ?")
      .run(icon, text, color, sortOrder, now, id);
  }

  if (result.changes === 0) {
    return res.status(404).json({ error: "Meddelandet hittades inte." });
  }
  return res.json({ ok: true });
});

app.delete("/api/important-messages/:id", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!canManageAdminFeatures(user)) {
    return res.status(403).json({ error: "Endast admin eller sekreterare kan ta bort viktiga meddelanden." });
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

app.get("/api/integrations/partikansliet/important-messages", (req, res) => {
  if (!requirePartikanslietIntegration(req, res)) return;
  const rows = listImportantMessages("source = ?", ["partikansliet"]);
  return res.json({ messages: rows.map(mapImportantMessageRow) });
});

app.post("/api/integrations/partikansliet/important-messages", (req, res) => {
  if (!requirePartikanslietIntegration(req, res)) return;

  const icon = String(req.body?.icon || "📢").trim().slice(0, 8) || "📢";
  const text = String(req.body?.text || "").trim();
  const color = normalizeImportantColor(req.body?.color);
  const sortOrderRaw = Number(req.body?.sort_order);
  const source = "partikansliet";
  const sourceLabel = normalizeImportantSourceLabel(req.body?.source_label, source);
  const externalId = normalizeImportantExternalId(req.body?.external_id);
  if (!text) return res.status(400).json({ error: "Text krävs." });
  if (text.length > 500) return res.status(400).json({ error: "Texten är för lång (max 500 tecken)." });

  const fallbackOrder = Number(
    db.prepare("SELECT COALESCE(MAX(sort_order), -1) + 1 AS next_order FROM important_messages").get().next_order
  );
  const sortOrder = Number.isInteger(sortOrderRaw) ? sortOrderRaw : fallbackOrder;
  const now = nowTs();

  if (externalId) {
    const existing = db
      .prepare("SELECT id FROM important_messages WHERE source = ? AND external_id = ? LIMIT 1")
      .get(source, externalId);
    if (existing) {
      db.prepare(
        "UPDATE important_messages SET icon = ?, text = ?, color = ?, sort_order = ?, source_label = ?, updated_at = ? WHERE id = ?"
      ).run(icon, text, color, sortOrder, sourceLabel, now, Number(existing.id));
      return res.json({ ok: true, id: Number(existing.id), updated: true });
    }
  }

  const result = db.prepare(
    `INSERT INTO important_messages(
        icon, text, color, sort_order, created_by, created_at, updated_at, source, source_label, external_id
     ) VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)`
  ).run(icon, text, color, sortOrder, now, now, source, sourceLabel, externalId || null);
  return res.status(201).json({ ok: true, id: Number(result.lastInsertRowid || 0), updated: false });
});

app.put("/api/integrations/partikansliet/important-messages/:id", (req, res) => {
  if (!requirePartikanslietIntegration(req, res)) return;

  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "Ogiltigt id." });
  }
  const icon = String(req.body?.icon || "📢").trim().slice(0, 8) || "📢";
  const text = String(req.body?.text || "").trim();
  const color = normalizeImportantColor(req.body?.color);
  const sortOrderRaw = Number(req.body?.sort_order);
  const sortOrder = Number.isInteger(sortOrderRaw) ? sortOrderRaw : null;
  const sourceLabel = normalizeImportantSourceLabel(req.body?.source_label, "partikansliet");
  if (!text) return res.status(400).json({ error: "Text krävs." });
  if (text.length > 500) return res.status(400).json({ error: "Texten är för lång (max 500 tecken)." });

  const existing = db
    .prepare("SELECT id FROM important_messages WHERE id = ? AND source = ? LIMIT 1")
    .get(id, "partikansliet");
  if (!existing) {
    return res.status(404).json({ error: "Meddelandet hittades inte." });
  }
  const now = nowTs();
  let result;
  if (sortOrder === null) {
    result = db.prepare(
      "UPDATE important_messages SET icon = ?, text = ?, color = ?, source_label = ?, updated_at = ? WHERE id = ? AND source = ?"
    ).run(icon, text, color, sourceLabel, now, id, "partikansliet");
  } else {
    result = db.prepare(
      "UPDATE important_messages SET icon = ?, text = ?, color = ?, sort_order = ?, source_label = ?, updated_at = ? WHERE id = ? AND source = ?"
    ).run(icon, text, color, sortOrder, sourceLabel, now, id, "partikansliet");
  }
  if (result.changes === 0) {
    return res.status(404).json({ error: "Meddelandet hittades inte." });
  }
  return res.json({ ok: true, id: id });
});

app.delete("/api/integrations/partikansliet/important-messages/:id", (req, res) => {
  if (!requirePartikanslietIntegration(req, res)) return;

  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "Ogiltigt id." });
  }
  const result = db
    .prepare("DELETE FROM important_messages WHERE id = ? AND source = ?")
    .run(id, "partikansliet");
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
  if (!canManageAdminFeatures(user)) {
    return res.status(403).json({ error: "Endast admin eller sekreterare kan lägga till länkar." });
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
  if (!canManageAdminFeatures(user)) {
    return res.status(403).json({ error: "Endast admin eller sekreterare kan redigera länkar." });
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
  if (!canManageAdminFeatures(user)) {
    return res.status(403).json({ error: "Endast admin eller sekreterare kan ta bort länkar." });
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
  if (!canManageAdminFeatures(user)) {
    return res.status(403).json({ error: "Endast admin eller sekreterare kan ladda upp PDF." });
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
      `SELECT q.id, q.question, q.category, q.image_url, q.created_at, u.email AS user_email
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
    category: String(row.category || "other"),
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
  const rawCategory = String(req.body?.category || "").trim().toLowerCase();
  const normalizedCategory = rawCategory === "twitter" ? "x" : rawCategory;
  const allowedCategories = new Set(["facebook", "x", "tiktok", "other"]);
  const category = allowedCategories.has(normalizedCategory) ? normalizedCategory : "other";
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
    .prepare("INSERT INTO qna_questions(user_id, question, category, image_url, created_at) VALUES (?, ?, ?, ?, ?)")
    .run(user.id, question, category, imageUrl || null, now);
  return res.status(201).json({
    ok: true,
    question: {
      id: Number(result.lastInsertRowid || 0),
      question: question,
      category: category,
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

  const canEdit = Number(existing.user_id) === Number(user.id) || canManageAdminFeatures(user);
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

  const canDelete = Number(existing.user_id) === Number(user.id) || canManageAdminFeatures(user);
  if (!canDelete) {
    return res.status(403).json({ error: "Du får bara ta bort dina egna idéer." });
  }

  db.prepare("DELETE FROM idea_bank_ideas WHERE id = ?").run(id);
  return res.json({ ok: true });
});

app.get("/api/tasks/my", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const rows = db
    .prepare(
      `SELECT a.id AS assignment_id, a.task_id, a.assigned_at, a.solved_at,
              t.title, t.description, t.image_url, t.priority,
              u.email AS assigned_to_email,
              ab.email AS assigned_by_email
       FROM task_assignments a
       JOIN tasks t ON t.id = a.task_id
       JOIN users u ON u.id = a.user_id
       JOIN users ab ON ab.id = a.assigned_by
       WHERE a.user_id = ?
       ORDER BY CASE WHEN a.solved_at IS NULL THEN 0 ELSE 1 END ASC,
                COALESCE(a.solved_at, a.assigned_at) DESC,
                a.id DESC`
    )
    .all(user.id);

  return res.json({
    tasks: rows.map(mapTaskAssignmentRow)
  });
});

app.put("/api/tasks/assignments/:id/solve", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const assignmentId = Number(req.params.id);
  if (!Number.isInteger(assignmentId) || assignmentId <= 0) {
    return res.status(400).json({ error: "Ogiltigt uppdrags-id." });
  }

  const existing = db
    .prepare(
      `SELECT a.id, a.user_id
       FROM task_assignments a
       WHERE a.id = ?`
    )
    .get(assignmentId);
  if (!existing) {
    return res.status(404).json({ error: "Uppdraget hittades inte." });
  }
  if (Number(existing.user_id) !== Number(user.id)) {
    return res.status(403).json({ error: "Du kan bara uppdatera dina egna uppdrag." });
  }

  const solved = req.body && Object.prototype.hasOwnProperty.call(req.body, "solved")
    ? !!req.body.solved
    : true;
  const solvedAt = solved ? nowTs() : null;

  db.prepare("UPDATE task_assignments SET solved_at = ? WHERE id = ?").run(solvedAt, assignmentId);

  const row = db
    .prepare(
      `SELECT a.id AS assignment_id, a.task_id, a.assigned_at, a.solved_at,
              t.title, t.description, t.image_url, t.priority,
              u.email AS assigned_to_email,
              ab.email AS assigned_by_email
       FROM task_assignments a
       JOIN tasks t ON t.id = a.task_id
       JOIN users u ON u.id = a.user_id
       JOIN users ab ON ab.id = a.assigned_by
       WHERE a.id = ?`
    )
    .get(assignmentId);

  return res.json({
    ok: true,
    task: row ? mapTaskAssignmentRow(row) : null
  });
});

app.post("/api/admin/tasks", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!canManageAdminFeatures(user)) {
    return res.status(403).json({ error: "Endast admin eller sekreterare kan skapa uppdrag." });
  }

  const title = String(req.body?.title || "").trim();
  const description = String(req.body?.description || "").trim();
  const imageUrl = normalizeTaskImageUrl(req.body?.image_url || "");
  const rawPriority = String(req.body?.priority || "").trim();
  const priority = normalizeTaskPriority(rawPriority);
  const audience = String(req.body?.audience || "all").trim().toLowerCase();
  const requestedUserIds = Array.isArray(req.body?.user_ids) ? req.body.user_ids : [];

  if (!title) return res.status(400).json({ error: "Titel krävs." });
  if (!description) return res.status(400).json({ error: "Beskrivning krävs." });
  if (title.length > 160) return res.status(400).json({ error: "Titeln är för lång (max 160 tecken)." });
  if (description.length > 5000) return res.status(400).json({ error: "Beskrivningen är för lång (max 5000 tecken)." });
  if (String(req.body?.image_url || "").trim() && !imageUrl) {
    return res.status(400).json({ error: "Ogiltig fil-länk." });
  }
  if (rawPriority && !priority) {
    return res.status(400).json({ error: "Ogiltig prioritet. Tillåtna värden: low, medium, high." });
  }
  if (!["all", "selected"].includes(audience)) {
    return res.status(400).json({ error: "Ogiltigt målval för uppdrag." });
  }

  let recipientIds = [];
  if (audience === "all") {
    recipientIds = db
      .prepare("SELECT id FROM users ORDER BY id ASC")
      .all()
      .map((r) => Number(r.id))
      .filter((id) => Number.isInteger(id) && id > 0);
  } else {
    recipientIds = requestedUserIds
      .map((id) => Number(id))
      .filter((id) => Number.isInteger(id) && id > 0);
    recipientIds = Array.from(new Set(recipientIds));
  }

  if (!recipientIds.length) {
    return res.status(400).json({ error: "Välj minst en mottagare." });
  }

  const validRows = db
    .prepare(
      `SELECT id
       FROM users
       WHERE id IN (${recipientIds.map(() => "?").join(",")})`
    )
    .all(...recipientIds);
  const validIds = new Set(validRows.map((r) => Number(r.id)));
  recipientIds = recipientIds.filter((id) => validIds.has(id));
  if (!recipientIds.length) {
    return res.status(400).json({ error: "Inga giltiga mottagare valdes." });
  }

  const now = nowTs();
  const insertTask = db.prepare(
    "INSERT INTO tasks(title, description, image_url, priority, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
  );
  const insertAssignment = db.prepare(
    "INSERT INTO task_assignments(task_id, user_id, assigned_by, assigned_at, solved_at) VALUES (?, ?, ?, ?, NULL)"
  );
  const tx = db.transaction(() => {
    const taskResult = insertTask.run(title, description, imageUrl || null, priority, user.id, now, now);
    const taskId = Number(taskResult.lastInsertRowid || 0);
    let createdAssignments = 0;
    recipientIds.forEach((recipientId) => {
      insertAssignment.run(taskId, recipientId, user.id, now);
      createdAssignments += 1;
    });
    return { taskId, createdAssignments };
  });

  const result = tx();
  return res.status(201).json({
    ok: true,
    task_id: Number(result.taskId || 0),
    assigned_count: Number(result.createdAssignments || 0)
  });
});

app.put("/api/admin/tasks/assignments/:id", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!canManageAdminFeatures(user)) {
    return res.status(403).json({ error: "Endast admin eller sekreterare kan redigera uppdrag." });
  }

  const assignmentId = Number(req.params.id);
  if (!Number.isInteger(assignmentId) || assignmentId <= 0) {
    return res.status(400).json({ error: "Ogiltigt uppdrags-id." });
  }

  const existing = db
    .prepare(
      `SELECT a.id, a.task_id, a.solved_at
       FROM task_assignments a
       WHERE a.id = ?`
    )
    .get(assignmentId);
  if (!existing) {
    return res.status(404).json({ error: "Uppdraget hittades inte." });
  }
  if (existing.solved_at) {
    return res.status(400).json({ error: "Lösta uppdrag kan inte redigeras." });
  }

  const title = String(req.body?.title || "").trim();
  const description = String(req.body?.description || "").trim();
  const imageUrl = normalizeTaskImageUrl(req.body?.image_url || "");
  const rawPriority = String(req.body?.priority || "").trim();
  const priority = normalizeTaskPriority(rawPriority);

  if (!title) return res.status(400).json({ error: "Titel krävs." });
  if (!description) return res.status(400).json({ error: "Beskrivning krävs." });
  if (title.length > 160) return res.status(400).json({ error: "Titeln är för lång (max 160 tecken)." });
  if (description.length > 5000) return res.status(400).json({ error: "Beskrivningen är för lång (max 5000 tecken)." });
  if (String(req.body?.image_url || "").trim() && !imageUrl) {
    return res.status(400).json({ error: "Ogiltig fil-länk." });
  }
  if (rawPriority && !priority) {
    return res.status(400).json({ error: "Ogiltig prioritet. Tillåtna värden: low, medium, high." });
  }

  const now = nowTs();
  db.prepare(
    "UPDATE tasks SET title = ?, description = ?, image_url = ?, priority = ?, updated_at = ? WHERE id = ?"
  ).run(title, description, imageUrl || null, priority, now, Number(existing.task_id));

  const row = db
    .prepare(
      `SELECT a.id AS assignment_id, a.task_id, a.assigned_at, a.solved_at,
              t.title, t.description, t.image_url, t.priority,
              u.email AS assigned_to_email,
              ab.email AS assigned_by_email
       FROM task_assignments a
       JOIN tasks t ON t.id = a.task_id
       JOIN users u ON u.id = a.user_id
       JOIN users ab ON ab.id = a.assigned_by
       WHERE a.id = ?`
    )
    .get(assignmentId);

  return res.json({
    ok: true,
    task: row ? mapTaskAssignmentRow(row) : null
  });
});

app.get("/api/admin/tasks/library", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!canManageAdminFeatures(user)) {
    return res.status(403).json({ error: "Endast admin eller sekreterare har åtkomst." });
  }

  const rows = db
    .prepare(
      `SELECT a.id AS assignment_id, a.task_id, a.assigned_at, a.solved_at,
              t.title, t.description, t.image_url, t.priority,
              u.email AS assigned_to_email,
              ab.email AS assigned_by_email
       FROM task_assignments a
       JOIN tasks t ON t.id = a.task_id
       JOIN users u ON u.id = a.user_id
       JOIN users ab ON ab.id = a.assigned_by
       ORDER BY CASE WHEN a.solved_at IS NULL THEN 0 ELSE 1 END ASC,
                COALESCE(a.solved_at, a.assigned_at) DESC,
                a.id DESC`
    )
    .all();

  const mapped = rows.map(mapTaskAssignmentRow);
  const unsolved = mapped.filter((row) => !row.solved_at);
  const solved = mapped.filter((row) => !!row.solved_at);

  return res.json({
    unsolved: unsolved,
    solved: solved
  });
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
