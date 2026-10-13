require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = Number(process.env.PORT || 4000);
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("ERROR: Set JWT_SECRET in .env to a random string of at least 32 characters.");
  process.exit(1);
}

// This frontend currently uses inline script/event handlers; keep CSP compatible while retaining Helmet protections.
app.use(helmet({ contentSecurityPolicy: { directives: {
  scriptSrc: ["'self'", "'unsafe-inline'"],
  styleSrc: ["'self'", "'unsafe-inline'"],
  imgSrc: ["'self'", "data:", "https:"],
  upgradeInsecureRequests: null
} } }));
app.use(cors({
  origin: (process.env.FRONTEND_ORIGIN || "http://127.0.0.1:5500").split(",").map(x => x.trim()),
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json({ limit: "100kb" }));
// Serve the connected CampusFix frontend from the same Node.js origin.
app.use(express.static(path.join(__dirname, "..", "public")));

const dataDir = path.join(__dirname, "..", "data");
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, "campusfix.db"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT UNIQUE,
  email TEXT UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('student','admin','owner')),
  university TEXT NOT NULL,
  department TEXT,
  student_id TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS otp_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  phone TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_otp_phone ON otp_codes(phone);
CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  university TEXT NOT NULL,
  department TEXT NOT NULL,
  category TEXT NOT NULL,
  priority TEXT NOT NULL CHECK(priority IN ('Normal','High','Urgent')),
  location TEXT NOT NULL,
  description TEXT NOT NULL,
  urgent INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN ('Pending','In Progress','Resolved')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_university ON reports(university);
CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at);
`);

const universities = [
  "University of Dhaka","University of Rajshahi","University of Chittagong","Jahangirnagar University",
  "Islamic University, Bangladesh","Shahjalal University of Science & Technology","Khulna University",
  "Jagannath University","Comilla University","Jatiya Kabi Kazi Nazrul Islam University",
  "Begum Rokeya University, Rangpur","Barishal University","Rabindra University, Bangladesh",
  "Netrokona University","Kishoreganj University","Jamalpur Science and Technology University",
  "University of Frontier Technology, Bangladesh","Gopalganj Science and Technology University",
  "Bangladesh University of Engineering and Technology (BUET)","Chittagong University of Engineering & Technology (CUET)",
  "Khulna University of Engineering & Technology (KUET)","Rajshahi University of Engineering & Technology (RUET)",
  "Dhaka University of Engineering & Technology (DUET)","Bangladesh University of Professionals (BUP)",
  "Bangladesh University of Textiles (BUTEX)","Bangladesh Open University","National University",
  "Bangladesh Agricultural University","Sher-e-Bangla Agricultural University",
  "Bangabandhu Sheikh Mujibur Rahman Agricultural University","Sylhet Agricultural University",
  "Chittagong Veterinary and Animal Sciences University","Patuakhali Science and Technology University",
  "Hajee Mohammad Danesh Science and Technology University","Mawlana Bhashani Science and Technology University",
  "Noakhali Science and Technology University","Pabna University of Science and Technology",
  "Jashore University of Science and Technology","Rangamati Science and Technology University",
  "Sunamganj Science and Technology University","Chandpur Science and Technology University",
  "Bangabandhu Sheikh Mujibur Rahman University, Kishoreganj","Kurigram Agricultural University",
  "Habiganj Agricultural University","Gazipur Agricultural University","Khulna Agricultural University",
  "Sylhet Medical University","Rangpur Medical University","Rajshahi Medical University",
  "Bangladesh Maritime University","Aviation and Aerospace University, Bangladesh",
  "Bangladesh University of Health Sciences"
];
const categories = ["Infrastructure","Internet","Water","Electricity","Ragging","Fire","Safety","Other"];
const priorities = ["Normal","High","Urgent"];
const statuses = ["Pending","In Progress","Resolved"];
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: "draft-7", legacyHeaders: false });
const otpLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 5, standardHeaders: "draft-7", legacyHeaders: false });

function httpError(status, message) { const e = new Error(message); e.status = status; return e; }
function cleanString(v, max = 300) { return typeof v === "string" ? v.trim().slice(0, max) : ""; }
function validBdPhone(phone) { return /^01[3-9]\d{8}$/.test(phone); }
function signToken(user) {
  return jwt.sign({ sub: user.id, role: user.role, university: user.university }, JWT_SECRET, { expiresIn: "8h", issuer: "campusfix-api" });
}
function publicUser(u) {
  return { id: u.id, name: u.name, phone: u.phone, email: u.email, role: u.role,
    university: u.university, department: u.department, studentId: u.student_id };
}
function getUserById(id) { return db.prepare("SELECT * FROM users WHERE id = ?").get(id); }
function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    if (!header.startsWith("Bearer ")) throw httpError(401, "Login required.");
    const payload = jwt.verify(header.slice(7), JWT_SECRET, { issuer: "campusfix-api" });
    const user = getUserById(Number(payload.sub));
    if (!user) throw httpError(401, "Account no longer exists.");
    req.user = user;
    next();
  } catch (e) { next(e.status ? e : httpError(401, "Invalid or expired login session.")); }
}
function allowRoles(...roles) {
  return (req, res, next) => roles.includes(req.user.role) ? next() : next(httpError(403, "You do not have permission for this action."));
}
function requireFields(obj, fields) {
  for (const f of fields) if (!cleanString(obj[f], 2000)) throw httpError(400, `${f} is required.`);
}
function newReportId() { return "CF-" + Date.now().toString(36).toUpperCase() + "-" + crypto.randomBytes(2).toString("hex").toUpperCase(); }
function reportDto(r, includeReporter = false) {
  const out = {
    id: r.id, university: r.university, department: r.department, category: r.category,
    priority: r.priority, location: r.location, description: r.description,
    urgent: Boolean(r.urgent), status: r.status, created: r.created_at, updated: r.updated_at
  };
  if (includeReporter) { out.reporter = r.reporter_name; out.phone = r.reporter_phone; }
  return out;
}
const reportSelect = `
SELECT r.*, u.name AS reporter_name, u.phone AS reporter_phone
FROM reports r JOIN users u ON u.id = r.user_id`;

// Plug your SMS provider in here. Do not return the OTP to browsers in production.
async function sendOtpSms(phone, code) {
  if (process.env.NODE_ENV === "production") {
    throw httpError(503, "SMS provider is not configured. Contact the site administrator.");
  }
  console.log(`[DEV ONLY] CampusFix OTP for ${phone}: ${code}`);
}

app.get("/api/health", (req, res) => res.json({ ok: true, service: "CampusFix API", version: "1.0.0" }));
app.get("/api/universities", (req, res) => res.json({ universities: [...universities].sort((a,b) => a.localeCompare(b)) }));

// Student signup starts with an OTP request; account is created only after verification.
app.post("/api/auth/student/request-otp", authLimiter, otpLimiter, async (req, res, next) => {
  try {
    const name = cleanString(req.body.name, 120);
    const phone = cleanString(req.body.phone, 20);
    const university = cleanString(req.body.university, 200);
    const department = cleanString(req.body.department, 100);
    const studentId = cleanString(req.body.studentId, 100);
    const password = typeof req.body.password === "string" ? req.body.password : "";
    requireFields({ name, phone, university, department, password }, ["name","phone","university","department","password"]);
    if (!validBdPhone(phone)) throw httpError(400, "Enter a valid Bangladesh mobile number (01XXXXXXXXX).");
    if (!universities.includes(university)) throw httpError(400, "Select a university from the list.");
    if (password.length < 8) throw httpError(400, "Password must be at least 8 characters.");
    if (db.prepare("SELECT id FROM users WHERE phone = ?").get(phone)) throw httpError(409, "This phone number already has an account.");
    const code = String(crypto.randomInt(100000, 1000000));
    const expiresAt = Date.now() + Number(process.env.OTP_TTL_MINUTES || 5) * 60 * 1000;
    db.prepare("DELETE FROM otp_codes WHERE phone = ?").run(phone);
    db.prepare("INSERT INTO otp_codes(phone,code_hash,payload_json,expires_at,created_at) VALUES(?,?,?,?,?)")
      .run(phone, await bcrypt.hash(code, 10), JSON.stringify({ name, phone, university, department, studentId, passwordHash: await bcrypt.hash(password, 12) }), expiresAt, Date.now());
    await sendOtpSms(phone, code);
    const result = { message: "OTP requested. In development, check the backend terminal." };
    if (process.env.NODE_ENV !== "production" && process.env.OTP_DEV_RETURN === "true") result.devOtp = code;
    res.status(200).json(result);
  } catch (e) { next(e); }
});

app.post("/api/auth/student/verify-otp", authLimiter, async (req, res, next) => {
  try {
    const phone = cleanString(req.body.phone, 20);
    const code = cleanString(req.body.otp, 6);
    requireFields({ phone, code }, ["phone","otp"]);
    const row = db.prepare("SELECT * FROM otp_codes WHERE phone = ? ORDER BY id DESC LIMIT 1").get(phone);
    if (!row || row.expires_at < Date.now()) throw httpError(400, "OTP expired or not requested. Request a new OTP.");
    if (row.attempts >= 5) { db.prepare("DELETE FROM otp_codes WHERE phone = ?").run(phone); throw httpError(429, "Too many incorrect OTP attempts."); }
    if (!(await bcrypt.compare(code, row.code_hash))) {
      db.prepare("UPDATE otp_codes SET attempts = attempts + 1 WHERE id = ?").run(row.id);
      throw httpError(400, "Incorrect OTP.");
    }
    const p = JSON.parse(row.payload_json);
    const result = db.prepare(`INSERT INTO users(name,phone,password_hash,role,university,department,student_id)
      VALUES(?,?,?,'student',?,?,?)`).run(p.name, p.phone, p.passwordHash, p.university, p.department, p.studentId || null);
    db.prepare("DELETE FROM otp_codes WHERE phone = ?").run(phone);
    const user = getUserById(result.lastInsertRowid);
    res.status(201).json({ message: "Student account created.", token: signToken(user), user: publicUser(user) });
  } catch (e) { next(e); }
});

app.post("/api/auth/login", authLimiter, async (req, res, next) => {
  try {
    const identity = cleanString(req.body.identity, 200).toLowerCase();
    const password = typeof req.body.password === "string" ? req.body.password : "";
    requireFields({ identity, password }, ["identity","password"]);
    const user = db.prepare("SELECT * FROM users WHERE lower(phone) = ? OR lower(email) = ?").get(identity, identity);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) throw httpError(401, "Incorrect login details.");
    res.json({ token: signToken(user), user: publicUser(user) });
  } catch (e) { next(e); }
});
app.get("/api/auth/me", auth, (req, res) => res.json({ user: publicUser(req.user) }));

// Public dashboard data is deliberately not exposed; every report request requires login.
// Students can see reports for their own university, but not reporter phone numbers.
app.get("/api/reports", auth, (req, res, next) => {
  try {
    const q = cleanString(req.query.q, 200).toLowerCase();
    const status = cleanString(req.query.status, 30);
    const priority = cleanString(req.query.priority, 30);
    if (status && status !== "All" && !statuses.includes(status)) throw httpError(400, "Invalid status filter.");
    if (priority && priority !== "All" && !priorities.includes(priority)) throw httpError(400, "Invalid priority filter.");
    const where = [];
    const args = [];
    if (req.user.role !== "owner") { where.push("r.university = ?"); args.push(req.user.university); }
    if (status && status !== "All") { where.push("r.status = ?"); args.push(status); }
    if (priority && priority !== "All") { where.push("r.priority = ?"); args.push(priority); }
    if (q) { where.push("(lower(r.id) LIKE ? OR lower(r.category) LIKE ? OR lower(r.location) LIKE ? OR lower(r.description) LIKE ?)"); args.push(...Array(4).fill(`%${q}%`)); }
    const rows = db.prepare(`${reportSelect} WHERE ${where.join(" AND ")} ORDER BY r.created_at DESC LIMIT 500`).all(...args);
    res.json({ reports: rows.map(r => reportDto(r, req.user.role !== "student")) });
  } catch (e) { next(e); }
});

app.post("/api/reports", auth, allowRoles("student"), (req, res, next) => {
  try {
    requireFields(req.body, ["department","category","priority","location","description"]);
    const department = cleanString(req.body.department, 100);
    const category = cleanString(req.body.category, 50);
    const priority = cleanString(req.body.priority, 20);
    const location = cleanString(req.body.location, 250);
    const description = cleanString(req.body.description, 4000);
    if (!categories.includes(category)) throw httpError(400, "Invalid report category.");
    if (!priorities.includes(priority)) throw httpError(400, "Invalid priority.");
    const urgent = Boolean(req.body.urgent) || priority === "Urgent" || category === "Fire";
    const now = new Date().toISOString();
    const id = newReportId();
    db.prepare(`INSERT INTO reports(id,user_id,university,department,category,priority,location,description,urgent,status,created_at,updated_at)
      VALUES(?,?,?,?,?,?,?,?,?,'Pending',?,?)`).run(id, req.user.id, req.user.university, department, category, priority, location, description, urgent ? 1 : 0, now, now);
    const row = db.prepare(`${reportSelect} WHERE r.id = ?`).get(id);
    res.status(201).json({ message: "Report submitted.", report: reportDto(row, false) });
  } catch (e) { next(e); }
});

app.patch("/api/reports/:id/status", auth, allowRoles("admin","owner"), (req, res, next) => {
  try {
    const status = cleanString(req.body.status, 30);
    if (!statuses.includes(status)) throw httpError(400, "Choose a valid status.");
    const report = db.prepare("SELECT * FROM reports WHERE id = ?").get(req.params.id);
    if (!report) throw httpError(404, "Report not found.");
    if (req.user.role !== "owner" && report.university !== req.user.university) throw httpError(403, "You can only manage reports from your assigned university.");
    db.prepare("UPDATE reports SET status = ?, updated_at = ? WHERE id = ?").run(status, new Date().toISOString(), report.id);
    const updated = db.prepare(`${reportSelect} WHERE r.id = ?`).get(report.id);
    res.json({ message: "Report status updated.", report: reportDto(updated, true) });
  } catch (e) { next(e); }
});

// Admin registration is disabled by default to prevent anyone self-assigning admin privileges.
// An owner can enable/invite admins later via a protected endpoint or a controlled provisioning script.
app.post("/api/auth/admin/register", auth, allowRoles("owner"), async (req, res, next) => {
  try {
    const name = cleanString(req.body.name, 120);
    const email = cleanString(req.body.email, 200).toLowerCase();
    const phone = cleanString(req.body.phone, 20);
    const password = typeof req.body.password === "string" ? req.body.password : "";
    const university = cleanString(req.body.university, 200);
    requireFields({ name, email, password, university }, ["name","email","password","university"]);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw httpError(400, "Enter a valid email.");
    if (password.length < 12) throw httpError(400, "Admin password must be at least 12 characters.");
    if (!universities.includes(university)) throw httpError(400, "Select a university from the list.");
    const result = db.prepare("INSERT INTO users(name,email,phone,password_hash,role,university) VALUES(?,?,?,?, 'admin', ?)")
      .run(name, email, phone || null, await bcrypt.hash(password, 12), university);
    res.status(201).json({ message: "Admin account created.", user: publicUser(getUserById(result.lastInsertRowid)) });
  } catch (e) {
    if (String(e.code || "").startsWith("SQLITE_CONSTRAINT")) return next(httpError(409, "Email or phone is already registered."));
    next(e);
  }
});

app.use((req, res) => res.status(404).json({ error: "Endpoint not found." }));
app.use((err, req, res, next) => {
  const status = err.status || 500;
  if (status >= 500) console.error(err);
  res.status(status).json({ error: status === 500 ? "Internal server error." : err.message });
});

// Seed owner from environment only if credentials are supplied and account doesn't already exist.
(function seedOwner() {
  const name = cleanString(process.env.OWNER_NAME, 120);
  const email = cleanString(process.env.OWNER_EMAIL, 200).toLowerCase();
  const password = process.env.OWNER_PASSWORD || "";
  if (!name || !email || password.length < 12) return;
  const existing = db.prepare("SELECT id FROM users WHERE lower(email) = ?").get(email);
  if (!existing) {
    const firstUniversity = "Jamalpur Science and Technology University";
    const hash = bcrypt.hashSync(password, 12);
    db.prepare("INSERT INTO users(name,email,password_hash,role,university) VALUES(?,?,?,'owner',?)")
      .run(name, email, hash, firstUniversity);
    console.log(`Owner account created for ${email}. Change/remove OWNER_PASSWORD after initial setup.`);
  }
})();

app.listen(PORT, () => console.log(`CampusFix API listening at http://localhost:${PORT}`));
