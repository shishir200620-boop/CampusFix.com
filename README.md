# CampusFix Node.js Backend (v1.0 starter)

এই backend আপনার `EEE project.html`-এর CampusFix project-এর জন্য Node.js + Express + SQLite ব্যবহার করে তৈরি।

## কী আছে
- Student registration: OTP request + OTP verification, password bcrypt hash করে রাখা
- Login: phone বা email + password; JWT session
- Report submit: logged-in student-এর profile থেকে university নেওয়া হয়, request body থেকে নয়
- Reports list: login ছাড়া দেখা যাবে না; শুধু নিজের university-এর report; student-দের কাছে reporter phone প্রকাশ করা হয় না
- Admin status update: admin শুধু নিজের assigned university-এর report update করতে পারে
- Admin creation: শুধু owner login করা অবস্থায় admin তৈরি করতে পারে
- Input validation, rate limits, Helmet, CORS, parameterized SQLite queries

## চালানোর নিয়ম
1. Node.js 20+ install করুন: https://nodejs.org/
2. এই folder-এ terminal খুলুন।
3. চালান:
   ```bash
   npm install
   ```
4. `.env.example` কপি করে `.env` বানান।
5. `.env`-এ `JWT_SECRET`-কে কমপক্ষে 32 অক্ষরের random secret দিন এবং `OWNER_PASSWORD` পরিবর্তন করুন।
6. `FRONTEND_ORIGIN`-এ আপনার frontend-এর origin দিন। VS Code Live Server সাধারণত `http://127.0.0.1:5500` ব্যবহার করে।
7. চালান:
   ```bash
   npm run dev
   ```
8. ব্রাউজারে `http://localhost:4000/api/health` খুলুন। `{"ok":true,...}` এলে backend চলছে।
9. Connected website খুলতে `http://localhost:4000` ভিজিট করুন। `public/index.html` হলো আপনার আপলোড করা HTML-এর backend-connected সংস্করণ।

## গুরুত্বপূর্ণ OTP বিষয়
Development-এ OTP backend terminal-এ print হবে এবং `.env`-এ `OTP_DEV_RETURN=true` থাকলে API response-এও থাকবে, যাতে testing করা যায়। এটা শুধু local testing-এর জন্য। Production-এ `NODE_ENV=production`, `OTP_DEV_RETURN=false` সেট করুন এবং `sendOtpSms()` function-এ একটি SMS gateway যুক্ত করুন। SMS provider না বসালে production OTP endpoint ইচ্ছাকৃতভাবে কাজ করবে না।

## API overview
| Method | Endpoint | Login | কাজ |
|---|---|---|---|
| GET | `/api/health` | না | health check |
| GET | `/api/universities` | না | university list |
| POST | `/api/auth/student/request-otp` | না | OTP request |
| POST | `/api/auth/student/verify-otp` | না | OTP verify + student account create |
| POST | `/api/auth/login` | না | login |
| GET | `/api/auth/me` | হ্যাঁ | current user |
| GET | `/api/reports` | হ্যাঁ | own-university reports |
| POST | `/api/reports` | Student | report submit |
| PATCH | `/api/reports/:id/status` | Admin/Owner | status update |
| POST | `/api/auth/admin/register` | Owner | admin account create |

### Request examples

**Student OTP**
```json
POST /api/auth/student/request-otp
{
  "name":"Demo Student",
  "phone":"01712345678",
  "university":"Jamalpur Science and Technology University",
  "department":"CSE",
  "studentId":"CSE-001",
  "password":"StudentPass123"
}
```

**Verify OTP**
```json
POST /api/auth/student/verify-otp
{"phone":"01712345678","otp":"123456"}
```

**Login**
```json
POST /api/auth/login
{"identity":"01712345678","password":"StudentPass123"}
```

**Submit report** (send `Authorization: Bearer <token>`)
```json
POST /api/reports
{
  "department":"CSE",
  "category":"Fire",
  "priority":"Urgent",
  "location":"Academic Building, 2nd Floor",
  "description":"Smoke reported near the lab.",
  "urgent":true
}
```

**Update status** (admin token)
```json
PATCH /api/reports/CF-.../status
{"status":"In Progress"}
```

## Frontend integration
`public/index.html` হলো আপলোড করা CampusFix HTML-এর connected version। Node server frontend ও API একই origin-এ serve করে। Student login/registration, OTP flow, report submit/list এবং admin status update এই API-গুলো ব্যবহার করে। Student report list-এ শুধু তার university-এর reports আসে; admin-ও নিজের assigned university-তেই সীমাবদ্ধ, owner সব university দেখতে পারে।

Example:
```js
const API = "http://localhost:4000/api";
const token = localStorage.getItem("campusfix_token");

const response = await fetch(`${API}/reports`, {
  headers: { Authorization: `Bearer ${token}` }
});
const data = await response.json();
if (!response.ok) throw new Error(data.error || "Request failed");
```

## Before production
- SMS gateway integration ও OTP delivery test করুন।
- HTTPS এবং production secrets configure করুন; `.env` commit/upload করবেন না।
- Persistent database backups, logging, monitoring, privacy notice, retention policy যোগ করুন।
- Owner seed password বদলান; owner/admin account-এ MFA যোগ করার কথা বিবেচনা করুন।
- Production hosting-এ SQLite-এর persistent disk নিশ্চিত করুন; না হলে managed PostgreSQL ব্যবহার করুন।
- Emergency alerts are not guaranteed delivery; website is not a substitute for local emergency services.
