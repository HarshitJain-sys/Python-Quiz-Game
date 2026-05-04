from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, validator, constr, confloat, conint
from typing import Optional, List
import sqlite3, os, shutil, uuid, jwt, bcrypt, random, string, json, logging, time
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

# ── LOGGING ──
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("skillcon.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("skillcon")

app = FastAPI(title="SkillCon API")

# ── CORS — localhost only ──
app.add_middleware(CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000", "null"],
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ── SECURITY HEADERS MIDDLEWARE ──
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: http://127.0.0.1:8000;"
        )
        return response

app.add_middleware(SecurityHeadersMiddleware)

os.makedirs("uploads", exist_ok=True)
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

# ── SECRETS from env ──
SECRET = os.getenv("SKILLCON_JWT_SECRET", "skillcon-secret-key-2024-very-long-CHANGE-IN-PROD")
RAZORPAY_KEY = os.getenv("RAZORPAY_KEY", "rzp_test_DEMO_KEY_REPLACE_ME")
security = HTTPBearer()

# ── RATE LIMITING (in-memory) ──
_login_attempts: dict = {}  # ip -> {"count": int, "locked_until": float}
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 15 * 60  # 15 minutes

def check_rate_limit(ip: str):
    now = time.time()
    entry = _login_attempts.get(ip)
    if entry:
        if entry["locked_until"] and now < entry["locked_until"]:
            remaining = int((entry["locked_until"] - now) / 60) + 1
            logger.warning(f"LOGIN BLOCKED — IP {ip} is locked out for {remaining} more minutes")
            raise HTTPException(429, f"Too many failed attempts. Try again in {remaining} minutes.")
        if entry["locked_until"] and now >= entry["locked_until"]:
            _login_attempts[ip] = {"count": 0, "locked_until": None}

def record_failed_login(ip: str, email: str):
    now = time.time()
    entry = _login_attempts.get(ip, {"count": 0, "locked_until": None})
    entry["count"] += 1
    if entry["count"] >= MAX_ATTEMPTS:
        entry["locked_until"] = now + LOCKOUT_SECONDS
        logger.warning(f"SECURITY — IP {ip} locked out after {MAX_ATTEMPTS} failed attempts (last email: {email})")
    _login_attempts[ip] = entry

def clear_login_attempts(ip: str):
    _login_attempts.pop(ip, None)

# ── ALLOWED UPLOAD EXTENSIONS ──
ALLOWED_IMAGE_EXTS = {".jpg", ".jpeg", ".png"}
ALLOWED_DOC_EXTS = {".jpg", ".jpeg", ".png", ".pdf"}

def validate_file_ext(filename: str, allowed: set, label: str):
    ext = os.path.splitext(filename or "")[1].lower()
    if ext not in allowed:
        logger.warning(f"SECURITY — Rejected unsafe file upload: {filename} (type: {label})")
        raise HTTPException(400, f"Invalid file type. Allowed: {', '.join(allowed)}")
    return ext

def sanitize_str(value: Optional[str], max_len: int = 500) -> Optional[str]:
    if value is None:
        return None
    return str(value).strip()[:max_len]

PROFESSIONS = [
    "Plumber","Electrician","Carpenter","Painter","Cleaner","AC Technician",
    "Appliance Repair","Gardener","Mason","Welder","Mechanic","Plumber",
    "Roofer","Flooring Expert","Glass & Glazing","Pest Control","Waterproofing",
    "Interior Designer","Architect","Civil Engineer","Structural Engineer",
    "Tutor","Teacher","Yoga Instructor","Fitness Trainer","Dance Teacher",
    "Music Teacher","Art Teacher","Language Tutor","Chef","Cook","Baker",
    "Catering","Barista","Delivery Driver","Logistics","Mover & Packer",
    "Courier","Driver","Chauffeur","Security Guard","CCTV Installation",
    "Locksmith","Fire Safety","Photographer","Videographer","Graphic Designer",
    "Web Developer","App Developer","IT Support","Data Entry","Content Writer",
    "Social Media Manager","Digital Marketer","SEO Expert","Video Editor",
    "Accountant","Tax Consultant","Legal Advisor","Insurance Agent",
    "Financial Advisor","HR Consultant","Event Planner","Wedding Planner",
    "Decorator","DJ","Sound Engineer","Lighting Technician","Makeup Artist",
    "Hair Stylist","Beautician","Spa Therapist","Mehendi Artist","Tailor",
    "Embroidery Expert","Laundry & Ironing","Shoe Repair","Watch Repair",
    "Jewellery Repair","Mobile Repair","Laptop Repair","TV Repair",
    "Refrigerator Repair","Washing Machine Repair","Microwave Repair",
    "Geyser Repair","Inverter & Battery","Solar Panel","CCTV & Networking",
    "Astrologer","Vastu Consultant","Numerologist","Custom"
]

SKILL_QUIZ = {
    "Plumber": [
        {"q":"What is used to join two pipes?","opts":["Coupling","Wrench","Drill","Tape"],"ans":0},
        {"q":"What causes water hammer?","opts":["Low pressure","Air in pipes","Sudden valve closure","Rust"],"ans":2},
        {"q":"Which pipe material is best for hot water?","opts":["PVC","CPVC","GI","All same"],"ans":1},
        {"q":"What is a P-trap used for?","opts":["Increase pressure","Block sewer gas","Filter water","Join pipes"],"ans":1},
        {"q":"Unit of water flow rate?","opts":["Pascal","LPM","Watt","Newton"],"ans":1},
    ],
    "Electrician": [
        {"q":"What does MCB stand for?","opts":["Main Circuit Breaker","Miniature Circuit Breaker","Motor Control Board","None"],"ans":1},
        {"q":"Safe voltage for human body?","opts":["48V","220V","110V","12V"],"ans":0},
        {"q":"What is earthing used for?","opts":["Increase voltage","Safety from shocks","Save electricity","Boost signal"],"ans":1},
        {"q":"Which wire is neutral in India?","opts":["Red","Green","Black","Blue"],"ans":3},
        {"q":"What is the frequency of AC in India?","opts":["50 Hz","60 Hz","100 Hz","25 Hz"],"ans":0},
    ],
    "Carpenter": [
        {"q":"Which wood is best for furniture?","opts":["Teak","Pine","Bamboo","Plywood"],"ans":0},
        {"q":"What is a dovetail joint?","opts":["A nail type","A strong wood joint","A saw type","A finish"],"ans":1},
        {"q":"What tool is used for smoothing wood?","opts":["Chisel","Plane","Drill","Hammer"],"ans":1},
        {"q":"MDF stands for?","opts":["Medium Density Fibreboard","Main Door Frame","Metal Design Frame","None"],"ans":0},
        {"q":"What is the purpose of wood primer?","opts":["Colour","Sealing & adhesion","Hardening","Cutting"],"ans":1},
    ],
    "default": [
        {"q":"How important is customer communication?","opts":["Not important","Very important","Somewhat","Depends"],"ans":1},
        {"q":"What should you do if you can't complete a job?","opts":["Leave quietly","Inform client early","Charge anyway","Ignore"],"ans":1},
        {"q":"How should you handle client complaints?","opts":["Ignore","Argue","Listen and resolve","Walk away"],"ans":2},
        {"q":"What is a work estimate?","opts":["Final bill","Approximate cost upfront","Random number","None"],"ans":1},
        {"q":"How should you handle tools on site?","opts":["Leave anywhere","Keep organized and safe","Let client manage","Doesn't matter"],"ans":1},
    ]
}

def get_db():
    conn = sqlite3.connect("skillcon.db", timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
        role TEXT NOT NULL, avatar TEXT, phone TEXT, age INTEGER, gender TEXT,
        city TEXT, created_at TEXT DEFAULT (datetime('now'))
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS professionals (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER UNIQUE NOT NULL,
        category TEXT, custom_category TEXT, skills TEXT, hourly_rate REAL,
        bio TEXT, is_available INTEGER DEFAULT 1, avg_rating REAL DEFAULT 0,
        total_reviews INTEGER DEFAULT 0, years_exp INTEGER DEFAULT 0,
        emergency_contact TEXT, references_text TEXT,
        aadhaar_url TEXT, aadhaar_verified INTEGER DEFAULT 0,
        work_proof_urls TEXT, skill_score INTEGER DEFAULT -1,
        verification_level TEXT DEFAULT 'unverified',
        lat REAL DEFAULT 0, lng REAL DEFAULT 0,
        profile_views INTEGER DEFAULT 0,
        gig_title TEXT, gig_basic_price REAL, gig_basic_desc TEXT,
        gig_standard_price REAL, gig_standard_desc TEXT,
        gig_premium_price REAL, gig_premium_desc TEXT,
        level TEXT DEFAULT 'New',
        FOREIGN KEY (user_id) REFERENCES users(id)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS portfolio (
        id INTEGER PRIMARY KEY AUTOINCREMENT, pro_id INTEGER NOT NULL,
        url TEXT NOT NULL, caption TEXT, created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (pro_id) REFERENCES professionals(id)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, client_id INTEGER NOT NULL,
        professional_id INTEGER NOT NULL, title TEXT NOT NULL, description TEXT,
        status TEXT DEFAULT 'assigned', package TEXT DEFAULT 'basic',
        completion_otp TEXT, review_otp TEXT, review_requested INTEGER DEFAULT 0,
        payment_method TEXT DEFAULT 'cash', payment_status TEXT DEFAULT 'pending',
        total_amount REAL DEFAULT 0, travel_fee REAL DEFAULT 0,
        distance_km REAL DEFAULT 0, created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (client_id) REFERENCES users(id),
        FOREIGN KEY (professional_id) REFERENCES users(id)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT, job_id INTEGER UNIQUE NOT NULL,
        client_id INTEGER NOT NULL, professional_id INTEGER NOT NULL,
        rating INTEGER NOT NULL, comment TEXT, photo_url TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (job_id) REFERENCES jobs(id)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT, job_id INTEGER NOT NULL,
        sender_id INTEGER NOT NULL, content TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (job_id) REFERENCES jobs(id)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
        job_id INTEGER, type TEXT NOT NULL, amount REAL NOT NULL,
        description TEXT, status TEXT DEFAULT 'completed',
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS saved_pros (
        id INTEGER PRIMARY KEY AUTOINCREMENT, client_id INTEGER NOT NULL,
        pro_id INTEGER NOT NULL, created_at TEXT DEFAULT (datetime('now')),
        UNIQUE(client_id, pro_id)
    )""")
    conn.commit(); conn.close()

init_db()

def hash_pw(p): return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()
def verify_pw(p, h): return bcrypt.checkpw(p.encode(), h.encode())

def make_token(uid, role):
    return jwt.encode(
        {"user_id": uid, "role": role, "exp": datetime.utcnow() + timedelta(hours=24)},
        SECRET, algorithm="HS256"
    )

def rand_otp(n=6): return ''.join(random.choices(string.digits, k=n))

def update_verification(conn, pro_id):
    p = conn.execute("SELECT * FROM professionals WHERE id=?", (pro_id,)).fetchone()
    if not p: return
    score = 0
    if p["aadhaar_url"]: score += 1
    if p["work_proof_urls"]: score += 1
    if p["skill_score"] is not None and p["skill_score"] >= 3: score += 1
    if p["references_text"]: score += 1
    if p["emergency_contact"]: score += 1
    level = "unverified" if score == 0 else "partial" if score < 4 else "verified"
    conn.execute("UPDATE professionals SET verification_level=? WHERE id=?", (level, pro_id))

def update_pro_level(conn, pro_id):
    p = conn.execute("SELECT total_reviews, avg_rating FROM professionals WHERE id=?", (pro_id,)).fetchone()
    if not p: return
    jobs = p["total_reviews"] or 0
    rating = p["avg_rating"] or 0
    if jobs >= 50 and rating >= 4.5: level = "Top Rated"
    elif jobs >= 20 and rating >= 4.0: level = "Rising"
    else: level = "New"
    conn.execute("UPDATE professionals SET level=? WHERE id=?", (level, pro_id))

def calc_travel_fee(job_cost, distance_km):
    if distance_km <= 5: return 0
    elif distance_km <= 10: pct = 0.10
    elif distance_km <= 20: pct = 0.15
    elif distance_km <= 30: pct = 0.20
    else: pct = 0.25
    return round(job_cost * pct, 2)

def current_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    try:
        return jwt.decode(creds.credentials, SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired — please log in again")
    except Exception:
        raise HTTPException(401, "Invalid token")

# ── MODELS (strict validation) ──
VALID_ROLES = {"client", "professional"}
VALID_GENDERS = {"Male", "Female", "Other", None}
VALID_PACKAGES = {"basic", "standard", "premium"}
VALID_PAYMENT = {"cash", "online"}

class RegisterIn(BaseModel):
    name: constr(min_length=2, max_length=100, strip_whitespace=True)
    email: EmailStr
    password: constr(min_length=6, max_length=128)
    role: str
    phone: Optional[constr(max_length=15, strip_whitespace=True)] = None
    age: Optional[conint(ge=18, le=100)] = None
    gender: Optional[str] = None
    city: Optional[constr(max_length=100, strip_whitespace=True)] = None

    @validator("role")
    def role_valid(cls, v):
        if v not in VALID_ROLES:
            raise ValueError("role must be 'client' or 'professional'")
        return v

    @validator("gender")
    def gender_valid(cls, v):
        if v is not None and v not in VALID_GENDERS:
            raise ValueError("Invalid gender value")
        return v

class LoginIn(BaseModel):
    email: EmailStr
    password: constr(min_length=1, max_length=128)

class ProfileUpdateIn(BaseModel):
    name: Optional[constr(min_length=2, max_length=100, strip_whitespace=True)] = None
    phone: Optional[constr(max_length=15, strip_whitespace=True)] = None
    age: Optional[conint(ge=18, le=100)] = None
    gender: Optional[str] = None
    city: Optional[constr(max_length=100, strip_whitespace=True)] = None

class ProProfileIn(BaseModel):
    category: Optional[str] = None
    custom_category: Optional[constr(max_length=100, strip_whitespace=True)] = None
    skills: Optional[constr(max_length=500, strip_whitespace=True)] = None
    hourly_rate: Optional[confloat(ge=0, le=100000)] = None
    bio: Optional[constr(max_length=1000, strip_whitespace=True)] = None
    years_exp: Optional[conint(ge=0, le=60)] = None
    emergency_contact: Optional[constr(max_length=15, strip_whitespace=True)] = None
    references_text: Optional[constr(max_length=1000, strip_whitespace=True)] = None
    lat: Optional[confloat(ge=-90, le=90)] = None
    lng: Optional[confloat(ge=-180, le=180)] = None
    gig_title: Optional[constr(max_length=200, strip_whitespace=True)] = None
    gig_basic_price: Optional[confloat(ge=0, le=100000)] = None
    gig_basic_desc: Optional[constr(max_length=500, strip_whitespace=True)] = None
    gig_standard_price: Optional[confloat(ge=0, le=100000)] = None
    gig_standard_desc: Optional[constr(max_length=500, strip_whitespace=True)] = None
    gig_premium_price: Optional[confloat(ge=0, le=100000)] = None
    gig_premium_desc: Optional[constr(max_length=500, strip_whitespace=True)] = None

    @validator("category")
    def category_valid(cls, v):
        if v is not None and v not in PROFESSIONS:
            raise ValueError("Invalid category")
        return v

class JobIn(BaseModel):
    professional_id: int
    title: constr(min_length=3, max_length=200, strip_whitespace=True)
    description: Optional[constr(max_length=2000, strip_whitespace=True)] = None
    package: Optional[str] = "basic"
    payment_method: Optional[str] = "cash"
    client_lat: Optional[confloat(ge=-90, le=90)] = None
    client_lng: Optional[confloat(ge=-180, le=180)] = None

    @validator("package")
    def package_valid(cls, v):
        if v not in VALID_PACKAGES:
            raise ValueError("package must be basic, standard, or premium")
        return v

    @validator("payment_method")
    def payment_valid(cls, v):
        if v not in VALID_PAYMENT:
            raise ValueError("payment_method must be cash or online")
        return v

class CompleteJobIn(BaseModel):
    otp: constr(min_length=4, max_length=10, strip_whitespace=True)

class ReviewIn(BaseModel):
    rating: conint(ge=1, le=5)
    comment: Optional[constr(max_length=1000, strip_whitespace=True)] = None
    otp: constr(min_length=4, max_length=10, strip_whitespace=True)

class MessageIn(BaseModel):
    content: constr(min_length=1, max_length=2000, strip_whitespace=True)

class QuizResultIn(BaseModel):
    score: conint(ge=0, le=5)

# ── AUTH ──
@app.post("/api/register")
def register(d: RegisterIn):
    conn = get_db(); c = conn.cursor()
    try:
        if c.execute("SELECT id FROM users WHERE email=?", (d.email,)).fetchone():
            raise HTTPException(400, "Email already registered")
        uid = c.execute(
            "INSERT INTO users (name,email,password,role,phone,age,gender,city) VALUES (?,?,?,?,?,?,?,?)",
            (d.name, d.email, hash_pw(d.password), d.role, d.phone, d.age, d.gender, d.city)
        ).lastrowid
        if d.role == "professional":
            c.execute("INSERT INTO professionals (user_id) VALUES (?)", (uid,))
        conn.commit()
        logger.info(f"New user registered: {d.email} (role: {d.role})")
        return {"token": make_token(uid, d.role), "role": d.role, "name": d.name, "user_id": uid}
    except HTTPException: raise
    except Exception as e:
        conn.rollback()
        logger.error(f"Register error: {e}")
        raise HTTPException(500, "Registration failed")
    finally: conn.close()

@app.post("/api/login")
def login(d: LoginIn, request: Request):
    ip = request.client.host
    check_rate_limit(ip)
    conn = get_db()
    try:
        u = conn.execute("SELECT * FROM users WHERE email=?", (d.email,)).fetchone()
        if not u or not verify_pw(d.password, u["password"]):
            record_failed_login(ip, d.email)
            logger.warning(f"FAILED LOGIN — email: {d.email}, IP: {ip}")
            raise HTTPException(401, "Invalid credentials")
        clear_login_attempts(ip)
        logger.info(f"Successful login: {d.email} from IP {ip}")
        return {"token": make_token(u["id"], u["role"]), "role": u["role"], "name": u["name"], "user_id": u["id"]}
    finally: conn.close()

@app.get("/api/me")
def me(cu=Depends(current_user)):
    conn = get_db()
    try:
        u = conn.execute("SELECT id,name,email,role,avatar,phone,age,gender,city FROM users WHERE id=?", (cu["user_id"],)).fetchone()
        if not u: raise HTTPException(404, "User not found")
        res = dict(u)
        if u["role"] == "professional":
            p = conn.execute("SELECT * FROM professionals WHERE user_id=?", (u["id"],)).fetchone()
            if p:
                pd = dict(p)
                ports = conn.execute("SELECT * FROM portfolio WHERE pro_id=?", (p["id"],)).fetchall()
                pd["portfolio"] = [dict(x) for x in ports]
                res["professional"] = pd
        return res
    finally: conn.close()

@app.put("/api/me")
def update_me(d: ProfileUpdateIn, cu=Depends(current_user)):
    conn = get_db()
    try:
        fields = {k: v for k, v in d.dict().items() if v is not None}
        if fields:
            sets = ", ".join(f"{k}=?" for k in fields)
            conn.execute(f"UPDATE users SET {sets} WHERE id=?", (*fields.values(), cu["user_id"]))
            conn.commit()
        return {"ok": True}
    finally: conn.close()

# ── UPLOADS ──
@app.post("/api/upload/avatar")
async def upload_avatar(file: UploadFile = File(...), cu=Depends(current_user)):
    ext = validate_file_ext(file.filename, ALLOWED_IMAGE_EXTS, "avatar")
    conn = get_db()
    try:
        name = f"ava_{cu['user_id']}_{uuid.uuid4().hex}{ext}"
        with open(f"uploads/{name}", "wb") as f: shutil.copyfileobj(file.file, f)
        url = f"http://127.0.0.1:8000/uploads/{name}"
        conn.execute("UPDATE users SET avatar=? WHERE id=?", (url, cu["user_id"]))
        conn.commit()
        return {"url": url}
    finally: conn.close()

@app.post("/api/upload/portfolio")
async def upload_portfolio(file: UploadFile = File(...), caption: str = "", cu=Depends(current_user)):
    ext = validate_file_ext(file.filename, ALLOWED_IMAGE_EXTS, "portfolio")
    caption = sanitize_str(caption, 200)
    conn = get_db()
    try:
        p = conn.execute("SELECT id FROM professionals WHERE user_id=?", (cu["user_id"],)).fetchone()
        if not p: raise HTTPException(404, "Professional profile not found")
        name = f"port_{cu['user_id']}_{uuid.uuid4().hex}{ext}"
        with open(f"uploads/{name}", "wb") as f: shutil.copyfileobj(file.file, f)
        url = f"http://127.0.0.1:8000/uploads/{name}"
        conn.execute("INSERT INTO portfolio (pro_id, url, caption) VALUES (?,?,?)", (p["id"], url, caption))
        conn.commit()
        ports = conn.execute("SELECT * FROM portfolio WHERE pro_id=?", (p["id"],)).fetchall()
        return {"url": url, "portfolio": [dict(x) for x in ports]}
    finally: conn.close()

@app.delete("/api/upload/portfolio/{pid}")
def del_portfolio(pid: int, cu=Depends(current_user)):
    conn = get_db()
    try:
        item = conn.execute("SELECT p.*, pr.user_id FROM portfolio p JOIN professionals pr ON p.pro_id=pr.id WHERE p.id=?", (pid,)).fetchone()
        if not item or item["user_id"] != cu["user_id"]: raise HTTPException(403)
        conn.execute("DELETE FROM portfolio WHERE id=?", (pid,))
        conn.commit()
        return {"ok": True}
    finally: conn.close()

@app.post("/api/upload/aadhaar")
async def upload_aadhaar(file: UploadFile = File(...), cu=Depends(current_user)):
    ext = validate_file_ext(file.filename, ALLOWED_DOC_EXTS, "aadhaar")
    conn = get_db()
    try:
        p = conn.execute("SELECT id FROM professionals WHERE user_id=?", (cu["user_id"],)).fetchone()
        if not p: raise HTTPException(404)
        name = f"aadhaar_{cu['user_id']}_{uuid.uuid4().hex}{ext}"
        with open(f"uploads/{name}", "wb") as f: shutil.copyfileobj(file.file, f)
        url = f"http://127.0.0.1:8000/uploads/{name}"
        conn.execute("UPDATE professionals SET aadhaar_url=? WHERE user_id=?", (url, cu["user_id"]))
        update_verification(conn, p["id"])
        conn.commit()
        return {"url": url}
    finally: conn.close()

@app.post("/api/upload/work-proof")
async def upload_work_proof(file: UploadFile = File(...), cu=Depends(current_user)):
    ext = validate_file_ext(file.filename, ALLOWED_DOC_EXTS, "work-proof")
    conn = get_db()
    try:
        p = conn.execute("SELECT id, work_proof_urls FROM professionals WHERE user_id=?", (cu["user_id"],)).fetchone()
        if not p: raise HTTPException(404)
        name = f"proof_{cu['user_id']}_{uuid.uuid4().hex}{ext}"
        with open(f"uploads/{name}", "wb") as f: shutil.copyfileobj(file.file, f)
        url = f"http://127.0.0.1:8000/uploads/{name}"
        existing = json.loads(p["work_proof_urls"] or "[]")
        existing.append(url)
        conn.execute("UPDATE professionals SET work_proof_urls=? WHERE user_id=?", (json.dumps(existing), cu["user_id"]))
        update_verification(conn, p["id"])
        conn.commit()
        return {"url": url, "all": existing}
    finally: conn.close()

# ── QUIZ ──
@app.get("/api/quiz/{category}")
def get_quiz(category: str):
    qs = SKILL_QUIZ.get(category, SKILL_QUIZ["default"])
    return {"questions": qs}

@app.post("/api/quiz/submit")
def submit_quiz(d: QuizResultIn, cu=Depends(current_user)):
    conn = get_db()
    try:
        p = conn.execute("SELECT id FROM professionals WHERE user_id=?", (cu["user_id"],)).fetchone()
        if not p: raise HTTPException(404)
        conn.execute("UPDATE professionals SET skill_score=? WHERE user_id=?", (d.score, cu["user_id"]))
        update_verification(conn, p["id"])
        conn.commit()
        return {"ok": True, "score": d.score}
    finally: conn.close()

# ── PROFESSIONALS ──
@app.get("/api/professions")
def get_professions():
    return {"professions": PROFESSIONS}

@app.get("/api/professionals")
def list_pros(category: Optional[str]=None, city: Optional[str]=None,
              min_rating: Optional[float]=None, search: Optional[str]=None,
              sort: Optional[str]="rating"):
    conn = get_db()
    try:
        q = """SELECT u.id,u.name,u.avatar,u.city,p.id as pro_id,p.category,p.custom_category,
                      p.skills,p.hourly_rate,p.bio,p.is_available,p.avg_rating,p.total_reviews,
                      p.verification_level,p.level,p.lat,p.lng,p.gig_title,
                      p.gig_basic_price,p.gig_standard_price,p.gig_premium_price,p.years_exp
               FROM users u JOIN professionals p ON u.id=p.user_id WHERE 1=1"""
        params = []
        if category and category != "Custom":
            q += " AND (p.category=? OR p.custom_category=?)"; params += [category, category]
        if city: q += " AND u.city LIKE ?"; params.append(f"%{city}%")
        if min_rating: q += " AND p.avg_rating>=?"; params.append(min_rating)
        if search:
            search_clean = sanitize_str(search, 100)
            q += " AND (u.name LIKE ? OR p.skills LIKE ? OR p.bio LIKE ? OR p.category LIKE ? OR p.custom_category LIKE ?)"
            params += [f"%{search_clean}%"] * 5
        rows = conn.execute(q, params).fetchall()
        result = [dict(r) for r in rows]
        if sort == "rating": result.sort(key=lambda x: x["avg_rating"] or 0, reverse=True)
        elif sort == "price": result.sort(key=lambda x: x["hourly_rate"] or 0)
        return result
    finally: conn.close()

@app.get("/api/professionals/{pid}")
def get_pro(pid: int, cu=Depends(current_user)):
    conn = get_db()
    try:
        conn.execute("UPDATE professionals SET profile_views=profile_views+1 WHERE user_id=?", (pid,))
        conn.commit()
        row = conn.execute("""SELECT u.id,u.name,u.avatar,u.city,u.phone,p.*
                              FROM users u JOIN professionals p ON u.id=p.user_id WHERE u.id=?""", (pid,)).fetchone()
        if not row: raise HTTPException(404)
        res = dict(row)
        ports = conn.execute("SELECT * FROM portfolio WHERE pro_id=?", (res["id"],)).fetchall()
        res["portfolio"] = [dict(x) for x in ports]
        revs = conn.execute("""SELECT r.*,u.name as client_name,u.avatar as client_avatar
                               FROM reviews r JOIN users u ON r.client_id=u.id
                               WHERE r.professional_id=? ORDER BY r.created_at DESC""", (pid,)).fetchall()
        res["reviews"] = [dict(r) for r in revs]
        saved = conn.execute("SELECT id FROM saved_pros WHERE client_id=? AND pro_id=?",
                             (cu["user_id"], pid)).fetchone()
        res["is_saved"] = bool(saved)
        return res
    finally: conn.close()

@app.put("/api/professionals/profile")
def update_pro_profile(d: ProProfileIn, cu=Depends(current_user)):
    conn = get_db()
    try:
        fields = {k: v for k, v in d.dict().items() if v is not None}
        if fields:
            sets = ", ".join(f"{k}=?" for k in fields)
            conn.execute(f"UPDATE professionals SET {sets} WHERE user_id=?", (*fields.values(), cu["user_id"]))
            conn.commit()
        return {"ok": True}
    finally: conn.close()

@app.put("/api/professionals/availability")
def toggle_avail(cu=Depends(current_user)):
    conn = get_db()
    try:
        p = conn.execute("SELECT is_available FROM professionals WHERE user_id=?", (cu["user_id"],)).fetchone()
        nv = 0 if p["is_available"] else 1
        conn.execute("UPDATE professionals SET is_available=? WHERE user_id=?", (nv, cu["user_id"]))
        conn.commit()
        return {"is_available": bool(nv)}
    finally: conn.close()

# ── SAVED ──
@app.post("/api/saved/{pro_user_id}")
def save_pro(pro_user_id: int, cu=Depends(current_user)):
    conn = get_db()
    try:
        p = conn.execute("SELECT id FROM professionals WHERE user_id=?", (pro_user_id,)).fetchone()
        if not p: raise HTTPException(404)
        existing = conn.execute("SELECT id FROM saved_pros WHERE client_id=? AND pro_id=?", (cu["user_id"], p["id"])).fetchone()
        if existing:
            conn.execute("DELETE FROM saved_pros WHERE client_id=? AND pro_id=?", (cu["user_id"], p["id"]))
            conn.commit(); return {"saved": False}
        conn.execute("INSERT INTO saved_pros (client_id, pro_id) VALUES (?,?)", (cu["user_id"], p["id"]))
        conn.commit(); return {"saved": True}
    finally: conn.close()

@app.get("/api/saved")
def get_saved(cu=Depends(current_user)):
    conn = get_db()
    try:
        rows = conn.execute("""SELECT u.id,u.name,u.avatar,u.city,p.category,p.custom_category,
                               p.hourly_rate,p.avg_rating,p.verification_level,p.level
                               FROM saved_pros sp
                               JOIN professionals p ON sp.pro_id=p.id
                               JOIN users u ON p.user_id=u.id
                               WHERE sp.client_id=?""", (cu["user_id"],)).fetchall()
        return [dict(r) for r in rows]
    finally: conn.close()

# ── JOBS ──
@app.post("/api/jobs")
def create_job(d: JobIn, cu=Depends(current_user)):
    conn = get_db()
    try:
        if cu["role"] != "client": raise HTTPException(403, "Only clients can create jobs")
        pro = conn.execute("""SELECT p.*,u.name,u.city FROM professionals p
                              JOIN users u ON p.user_id=u.id WHERE p.user_id=?""", (d.professional_id,)).fetchone()
        if not pro: raise HTTPException(404, "Professional not found")
        price_field = f"gig_{d.package}_price"
        price = pro[price_field] or pro["hourly_rate"] or 0
        distance = 0; travel = 0
        if d.client_lat and d.client_lng and pro["lat"] and pro["lng"]:
            import math
            R = 6371
            lat1,lng1,lat2,lng2 = map(math.radians, [d.client_lat, d.client_lng, pro["lat"], pro["lng"]])
            dlat = lat2-lat1; dlng = lng2-lng1
            a = math.sin(dlat/2)**2 + math.cos(lat1)*math.cos(lat2)*math.sin(dlng/2)**2
            distance = round(2*R*math.asin(math.sqrt(a)), 2)
            travel = calc_travel_fee(price, distance)
        total = price + travel
        otp = rand_otp(6)
        jid = conn.execute("""INSERT INTO jobs (client_id,professional_id,title,description,
                               package,payment_method,completion_otp,total_amount,travel_fee,distance_km)
                               VALUES (?,?,?,?,?,?,?,?,?,?)""",
                           (cu["user_id"], d.professional_id, d.title, d.description,
                            d.package, d.payment_method, otp, total, travel, distance)).lastrowid
        conn.commit()
        return {"job_id": jid, "completion_otp": otp, "total_amount": total,
                "base_price": price, "travel_fee": travel, "distance_km": distance}
    except HTTPException: raise
    except Exception as e:
        conn.rollback()
        logger.error(f"Job creation error: {e}")
        raise HTTPException(500, str(e))
    finally: conn.close()

@app.get("/api/jobs")
def get_jobs(cu=Depends(current_user)):
    conn = get_db()
    try:
        if cu["role"] == "client":
            rows = conn.execute("""SELECT j.*,u.name as pro_name,u.avatar as pro_avatar,
                                   p.category,p.verification_level
                                   FROM jobs j JOIN users u ON j.professional_id=u.id
                                   JOIN professionals p ON u.id=p.user_id
                                   WHERE j.client_id=? ORDER BY j.created_at DESC""", (cu["user_id"],)).fetchall()
        else:
            rows = conn.execute("""SELECT j.*,u.name as client_name,u.avatar as client_avatar,
                                   u.phone as client_phone,u.age as client_age,u.city as client_city,u.gender as client_gender
                                   FROM jobs j JOIN users u ON j.client_id=u.id
                                   WHERE j.professional_id=? ORDER BY j.created_at DESC""", (cu["user_id"],)).fetchall()
        return [dict(r) for r in rows]
    finally: conn.close()

@app.get("/api/jobs/{jid}")
def get_job(jid: int, cu=Depends(current_user)):
    conn = get_db()
    try:
        j = conn.execute("SELECT * FROM jobs WHERE id=?", (jid,)).fetchone()
        if not j: raise HTTPException(404)
        if j["client_id"] != cu["user_id"] and j["professional_id"] != cu["user_id"]: raise HTTPException(403)
        return dict(j)
    finally: conn.close()

@app.put("/api/jobs/{jid}/accept")
def accept_job(jid: int, cu=Depends(current_user)):
    conn = get_db()
    try:
        j = conn.execute("SELECT * FROM jobs WHERE id=? AND professional_id=?", (jid, cu["user_id"])).fetchone()
        if not j: raise HTTPException(404)
        conn.execute("UPDATE jobs SET status='accepted' WHERE id=?", (jid,))
        conn.commit(); return {"ok": True}
    finally: conn.close()

@app.put("/api/jobs/{jid}/complete")
def complete_job(jid: int, d: CompleteJobIn, cu=Depends(current_user)):
    conn = get_db()
    try:
        j = conn.execute("SELECT * FROM jobs WHERE id=? AND professional_id=?", (jid, cu["user_id"])).fetchone()
        if not j: raise HTTPException(404)
        if j["status"] != "accepted": raise HTTPException(400, "Job must be accepted first")
        if j["completion_otp"] != d.otp:
            logger.warning(f"SECURITY — Wrong completion OTP for job #{jid} by user #{cu['user_id']}")
            raise HTTPException(400, "Wrong OTP")
        conn.execute("UPDATE jobs SET status='awaiting_review' WHERE id=?", (jid,))
        if j["payment_method"] == "online":
            conn.execute("INSERT INTO transactions (user_id,job_id,type,amount,description) VALUES (?,?,?,?,?)",
                         (j["client_id"], jid, "payment", j["total_amount"], f"Payment for job #{jid}"))
        conn.commit(); return {"ok": True}
    except HTTPException: raise
    except Exception as e: conn.rollback(); raise HTTPException(500, str(e))
    finally: conn.close()

@app.post("/api/jobs/{jid}/request-review")
def request_review(jid: int, cu=Depends(current_user)):
    conn = get_db()
    try:
        j = conn.execute("SELECT * FROM jobs WHERE id=? AND client_id=?", (jid, cu["user_id"])).fetchone()
        if not j: raise HTTPException(404)
        if j["status"] != "awaiting_review": raise HTTPException(400, "Job not ready for review")
        if j["review_requested"]: raise HTTPException(400, "Already requested")
        otp = rand_otp(6)
        conn.execute("UPDATE jobs SET review_requested=1, review_otp=? WHERE id=?", (otp, jid))
        conn.commit(); return {"ok": True}
    finally: conn.close()

@app.get("/api/jobs/{jid}/review-otp")
def get_review_otp(jid: int, cu=Depends(current_user)):
    conn = get_db()
    try:
        j = conn.execute("SELECT * FROM jobs WHERE id=? AND professional_id=?", (jid, cu["user_id"])).fetchone()
        if not j: raise HTTPException(404)
        if not j["review_requested"]: raise HTTPException(400, "Client hasn't requested review yet")
        return {"review_otp": j["review_otp"]}
    finally: conn.close()

@app.post("/api/jobs/{jid}/review")
def submit_review(jid: int, d: ReviewIn, cu=Depends(current_user)):
    conn = get_db()
    try:
        j = conn.execute("SELECT * FROM jobs WHERE id=? AND client_id=?", (jid, cu["user_id"])).fetchone()
        if not j: raise HTTPException(404)
        if j["status"] != "awaiting_review": raise HTTPException(400, "Not ready")
        if j["review_otp"] != d.otp:
            logger.warning(f"SECURITY — Wrong review OTP for job #{jid} by user #{cu['user_id']}")
            raise HTTPException(400, "Incorrect OTP")
        if conn.execute("SELECT id FROM reviews WHERE job_id=?", (jid,)).fetchone(): raise HTTPException(400, "Already reviewed")
        conn.execute("INSERT INTO reviews (job_id,client_id,professional_id,rating,comment) VALUES (?,?,?,?,?)",
                     (jid, cu["user_id"], j["professional_id"], d.rating, d.comment))
        conn.execute("UPDATE jobs SET status='completed' WHERE id=?", (jid,))
        revs = conn.execute("SELECT rating FROM reviews WHERE professional_id=?", (j["professional_id"],)).fetchall()
        avg = sum(r["rating"] for r in revs) / len(revs)
        conn.execute("UPDATE professionals SET avg_rating=?,total_reviews=? WHERE user_id=?",
                     (round(avg, 1), len(revs), j["professional_id"]))
        p = conn.execute("SELECT id FROM professionals WHERE user_id=?", (j["professional_id"],)).fetchone()
        if p: update_pro_level(conn, p["id"])
        conn.commit(); return {"ok": True}
    except HTTPException: raise
    except Exception as e: conn.rollback(); raise HTTPException(500, str(e))
    finally: conn.close()

# ── MESSAGES ──
@app.get("/api/jobs/{jid}/messages")
def get_messages(jid: int, cu=Depends(current_user)):
    conn = get_db()
    try:
        j = conn.execute("SELECT client_id,professional_id FROM jobs WHERE id=?", (jid,)).fetchone()
        if not j: raise HTTPException(404)
        if cu["user_id"] not in (j["client_id"], j["professional_id"]): raise HTTPException(403)
        msgs = conn.execute("""SELECT m.*,u.name as sender_name,u.avatar as sender_avatar
                               FROM messages m JOIN users u ON m.sender_id=u.id
                               WHERE m.job_id=? ORDER BY m.created_at ASC""", (jid,)).fetchall()
        return [dict(m) for m in msgs]
    finally: conn.close()

@app.post("/api/jobs/{jid}/messages")
def send_message(jid: int, d: MessageIn, cu=Depends(current_user)):
    conn = get_db()
    try:
        j = conn.execute("SELECT client_id,professional_id FROM jobs WHERE id=?", (jid,)).fetchone()
        if not j: raise HTTPException(404)
        if cu["user_id"] not in (j["client_id"], j["professional_id"]): raise HTTPException(403)
        conn.execute("INSERT INTO messages (job_id,sender_id,content) VALUES (?,?,?)", (jid, cu["user_id"], d.content))
        conn.commit(); return {"ok": True}
    finally: conn.close()

# ── TRANSACTIONS ──
@app.get("/api/transactions")
def get_transactions(cu=Depends(current_user)):
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM transactions WHERE user_id=? ORDER BY created_at DESC", (cu["user_id"],)).fetchall()
        return [dict(r) for r in rows]
    finally: conn.close()

# ── PAYMENT ──
@app.post("/api/payment/initiate")
def initiate_payment(job_id: int, cu=Depends(current_user)):
    conn = get_db()
    try:
        j = conn.execute("SELECT * FROM jobs WHERE id=? AND client_id=?", (job_id, cu["user_id"])).fetchone()
        if not j: raise HTTPException(404)
        dummy_order_id = f"order_{uuid.uuid4().hex[:16]}"
        # Key comes from env, never hardcoded
        return {"order_id": dummy_order_id, "amount": j["total_amount"],
                "currency": "INR", "key": RAZORPAY_KEY}
    finally: conn.close()

@app.post("/api/payment/verify")
def verify_payment(job_id: int, payment_id: str = "dummy", cu=Depends(current_user)):
    conn = get_db()
    try:
        j = conn.execute("SELECT * FROM jobs WHERE id=? AND client_id=?", (job_id, cu["user_id"])).fetchone()
        if not j: raise HTTPException(404)
        conn.execute("UPDATE jobs SET payment_status='paid' WHERE id=?", (job_id,))
        conn.execute("INSERT INTO transactions (user_id,job_id,type,amount,description,status) VALUES (?,?,?,?,?,?)",
                     (cu["user_id"], job_id, "payment", j["total_amount"], f"Online payment for job #{job_id}", "completed"))
        conn.commit(); return {"ok": True, "payment_id": payment_id}
    finally: conn.close()

# ── SEED ──
@app.post("/api/seed")
def seed_data():
    conn = get_db(); c = conn.cursor()
    try:
        demos = [
            ("Demo Client","client@demo.com","demo123","client","9876543210",22,"Male","Mumbai"),
            ("Ramesh Plumber","pro@demo.com","demo123","professional","9876543211",35,"Male","Mumbai"),
            ("Suresh Electrician","elec@demo.com","demo123","professional","9876543212",40,"Male","Pune"),
        ]
        for d in demos:
            if not c.execute("SELECT id FROM users WHERE email=?", (d[1],)).fetchone():
                uid = c.execute("INSERT INTO users (name,email,password,role,phone,age,gender,city) VALUES (?,?,?,?,?,?,?,?)",
                                (d[0],d[1],hash_pw(d[2]),d[3],d[4],d[5],d[6],d[7])).lastrowid
                if d[3] == "professional":
                    cat = "Plumber" if "Plumber" in d[0] else "Electrician"
                    c.execute("""INSERT INTO professionals (user_id,category,skills,hourly_rate,bio,
                                 years_exp,avg_rating,total_reviews,verification_level,level,
                                 gig_title,gig_basic_price,gig_basic_desc,gig_standard_price,
                                 gig_standard_desc,gig_premium_price,gig_premium_desc,lat,lng)
                                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                              (uid,cat,
                               "pipe fitting, leak repair" if cat=="Plumber" else "wiring, switchboard",
                               350 if cat=="Plumber" else 400,
                               f"Experienced {cat} with 10+ years",
                               10, 4.5, 12, "partial", "Rising",
                               f"{cat} Services",
                               300,"Basic inspection & minor fix",
                               500,"Full service & repair",
                               800,"Complete overhaul with warranty",
                               19.0760, 72.8777))
        conn.commit(); return {"ok": True}
    except Exception as e: conn.rollback(); return {"ok": False, "error": str(e)}
    finally: conn.close()
