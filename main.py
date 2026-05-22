import io
import os
import re
from datetime import date, datetime, timedelta, timezone
from typing import Optional

import openpyxl
from bson import ObjectId
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jose import JWTError, jwt
from passlib.context import CryptContext
from pymongo import ASCENDING, DESCENDING, MongoClient
from starlette.middleware.base import BaseHTTPMiddleware

load_dotenv()

# ── Config ────────────────────────────────────────────────────
MONGO_URL     = os.getenv("MONGO_URL", "mongodb://localhost:27017")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "vulntrack")
SECRET_KEY    = os.getenv("SECRET_KEY", "change_me_in_production")
ALGORITHM     = "HS256"
TOKEN_HOURS   = 8

_mongo = MongoClient(MONGO_URL, serverSelectionTimeoutMS=5000)
_db    = _mongo[MONGO_DB_NAME]

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__truncate_error=False)


def get_db():
    return _db


# ── App ───────────────────────────────────────────────────────
app = FastAPI(title="VulnTrack")
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")


# ── Auth utilities ────────────────────────────────────────────

def _hash_pw(pw: str) -> str:
    return pwd_ctx.hash(pw)


def _verify_pw(pw: str, hashed: str) -> bool:
    return pwd_ctx.verify(pw, hashed)


def _create_token(username: str, role: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(hours=TOKEN_HOURS)
    return jwt.encode({"sub": username, "role": role, "exp": exp},
                      SECRET_KEY, algorithm=ALGORITHM)


def _decode_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])


def _init_admin():
    if _db.users.count_documents({}) == 0:
        pw = "Admin2026"
        _db.users.insert_one({
            "username":      "admin",
            "password_hash": _hash_pw(pw),
            "role":          "admin",
            "created_at":    datetime.now().strftime("%Y-%m-%d %H:%M"),
        })
        print("")
        print("[VulnTrack] ★  Premier démarrage — compte admin créé")
        print("[VulnTrack]    username : admin")
        print(f"[VulnTrack]    password : {pw}")
        print("[VulnTrack]    → Changez ce mot de passe via /admin dès que possible.")
        print("")


# ── Auth Middleware — DÉSACTIVÉ (bypass temporaire) ───────────
# Pour réactiver : décommenter le bloc ci-dessous et supprimer
# le dict _BYPASS_USER dans get_current_user / require_admin.
#
# class AuthMiddleware(BaseHTTPMiddleware):
#     async def dispatch(self, request: Request, call_next):
#         path = request.url.path
#         if path == "/login" or path.startswith("/static/"):
#             return await call_next(request)
#
#         token = request.cookies.get("vt_token")
#         if not token:
#             return RedirectResponse("/login", status_code=302)
#
#         try:
#             payload = _decode_token(token)
#             request.state.user = payload
#         except JWTError:
#             resp = RedirectResponse("/login", status_code=302)
#             resp.delete_cookie("vt_token")
#             return resp
#
#         return await call_next(request)
#
# app.add_middleware(AuthMiddleware)


# ── Startup ───────────────────────────────────────────────────

@app.on_event("startup")
def create_indexes():
    try:
        _db.sap_notes.create_index([("reference_note",   ASCENDING)])
        _db.sap_notes.create_index([("advisory_release", ASCENDING)])
        _db.frun_data.create_index([("client",    ASCENDING)])
        _db.frun_data.create_index([("check_ref", ASCENDING)])
        _db.users.create_index([("username", ASCENDING)], unique=True)
        _init_admin()
    except Exception as e:
        print(f"[startup] MongoDB non disponible ({e}). Les index seront créés à la première connexion.")


STATUS_VALUES = [
    "Not Started", "Started", "Implemented",
    "Validated", "To be checked", "Exception",
]


# ── Route helper & dependencies ───────────────────────────────

def tpl(request: Request, name: str, ctx: Optional[dict] = None):
    user = getattr(request.state, "user", {})
    data: dict = {"current_user": user}
    if ctx:
        data.update(ctx)
    return templates.TemplateResponse(request, name, data)


# Bypass temporaire : toutes les routes sont ouvertes sans login.
# Pour réactiver l'auth, remplacer ces deux fonctions par :
#   def get_current_user(request): return getattr(request.state, "user", {})
#   def require_admin(user=Depends(get_current_user)):
#       if user.get("role") != "admin": raise HTTPException(403)
#       return user
_BYPASS_USER = {"sub": "admin", "role": "admin"}


def get_current_user(request: Request) -> dict:
    return _BYPASS_USER


def require_admin(user: dict = Depends(get_current_user)):
    return user


# ── Business logic utilities ──────────────────────────────────

def clean_check_ref(value) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    digits = re.sub(r"\D", "", str(value))
    return int(digits) if digits else None


def calculate_priority(score) -> Optional[str]:
    if score is None:
        return None
    if score >= 9:
        return "P1"
    if score >= 7:
        return "P2"
    return "P3"


def format_advisory_release(val) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, (datetime, date)):
        return val.strftime("%Y-%m")
    # Excel serial date (days since 1899-12-30, accounts for the 1900 leap-year bug)
    if isinstance(val, (int, float)) and val > 1:
        try:
            d = date(1899, 12, 30) + timedelta(days=int(val))
            if d.year >= 2000:
                return d.strftime("%Y-%m")
        except Exception:
            pass
    s = str(val).strip()
    if re.match(r"\d{4}-\d{2}", s):
        return s[:7]
    return None


_CVSS_PREFIX_RE = re.compile(r'^\[p[1-3]-cvss\s+[\d.]+\]\s*', re.IGNORECASE)


def strip_cvss_prefix(s: Optional[str]) -> Optional[str]:
    if not s:
        return s
    return _CVSS_PREFIX_RE.sub('', s).strip() or s


def apply_dedup(db):
    pipeline = [
        {"$sort": {"version": DESCENDING}},
        {"$group": {
            "_id": "$reference_note",
            "keep_id": {"$first": "$_id"},
            "count":   {"$sum": 1},
        }},
        {"$match": {"count": {"$gt": 1}}},
    ]
    for group in db.sap_notes.aggregate(pipeline):
        db.sap_notes.delete_many({
            "reference_note": group["_id"],
            "_id": {"$ne": group["keep_id"]},
        })


def build_merged_entries(db, client=None, sid=None, reference=None) -> list:
    filt: dict = {}
    if client:
        filt["client"] = {"$regex": re.escape(client), "$options": "i"}
    if sid:
        filt["sid"] = {"$regex": re.escape(sid), "$options": "i"}
    if reference:
        ref_num = clean_check_ref(reference)
        if ref_num:
            filt["check_ref"] = ref_num

    frun_list = list(
        db.frun_data.find(filt).sort([("client", ASCENDING), ("sid", ASCENDING)])
    )
    if not frun_list:
        return []

    check_refs = list({e["check_ref"] for e in frun_list if e.get("check_ref")})
    advisory_map: dict = {}
    if check_refs:
        for note in db.sap_notes.find({"reference_note": {"$in": check_refs}}):
            advisory_map[note["reference_note"]] = note

    results = []
    for frun in frun_list:
        adv   = advisory_map.get(frun.get("check_ref"))
        score = adv.get("cvss_v3_base_score") if adv else None
        results.append({
            "id":             str(frun["_id"]),
            "client":         frun.get("client"),
            "priority":       calculate_priority(score),
            "sid":            frun.get("sid"),
            "status":         frun.get("status", "Not Started"),
            "comment":        frun.get("comment", ""),
            "status_history": frun.get("status_history", []),
            "check_description":                  strip_cvss_prefix(frun.get("check_description")),
            "policy":                             frun.get("policy"),
            "correction_type":                    adv.get("correction_type")                    if adv else None,
            "reference":                          adv.get("reference_note")                     if adv else frun.get("check_ref"),
            "type":                               adv.get("category")                           if adv else None,
            "recommended_implementation_process": adv.get("recommended_implementation_process") if adv else None,
            "downtime_required":                  adv.get("downtime_required")                  if adv else None,
            "landscape":          frun.get("landscape"),
            "configuration_item": frun.get("configuration_item"),
            "value":              frun.get("value"),
            "rule":               frun.get("rule"),
            "valid_since_utc":    frun.get("valid_since_utc"),
            "upload_timestamp":   frun.get("imported_at"),
            "cvss_score":         score,
        })
    return results


def _next_release(current: Optional[str]) -> Optional[str]:
    if not current or current == "—":
        return None
    try:
        year, month = map(int, current.split("-"))
        year, month = (year + 1, 1) if month == 12 else (year, month + 1)
        return f"{year}-{month:02d}"
    except Exception:
        return None


def _client_summary(entries: list, client: str) -> dict:
    total = len(entries)
    p1 = sum(1 for e in entries if e["priority"] == "P1")
    p2 = sum(1 for e in entries if e["priority"] == "P2")
    p3 = sum(1 for e in entries if e["priority"] == "P3")

    by_status: dict[str, int] = {}
    for e in entries:
        by_status[e["status"]] = by_status.get(e["status"], 0) + 1

    done        = sum(1 for e in entries if e["status"] in ("Validated", "Implemented"))
    in_progress = sum(1 for e in entries if e["status"] == "Started")
    not_started = by_status.get("Not Started", 0)
    progress_pct = round(done / total * 100) if total else 0

    critical = [e for e in entries if e["priority"] == "P1"
                and e["status"] in ("Not Started", "Started")]

    sid_map: dict = {}
    for e in entries:
        sid = e["sid"] or "—"
        if sid not in sid_map:
            sid_map[sid] = {"sid": sid, "total": 0, "p1": 0, "p2": 0, "p3": 0,
                            "done": 0, "by_status": {}}
        d = sid_map[sid]
        d["total"] += 1
        if e["priority"] == "P1":   d["p1"] += 1
        elif e["priority"] == "P2": d["p2"] += 1
        elif e["priority"] == "P3": d["p3"] += 1
        if e["status"] in ("Validated", "Implemented"): d["done"] += 1
        d["by_status"][e["status"]] = d["by_status"].get(e["status"], 0) + 1

    for d in sid_map.values():
        d["progress_pct"] = round(d["done"] / d["total"] * 100) if d["total"] else 0

    return {
        "client": client, "total": total,
        "p1": p1, "p2": p2, "p3": p3,
        "no_score": total - p1 - p2 - p3,
        "by_status": by_status,
        "done": done, "in_progress": in_progress, "not_started": not_started,
        "progress_pct": progress_pct,
        "critical_count": len(critical),
        "sid_breakdown": sorted(sid_map.values(), key=lambda x: (-x["p1"], -x["total"])),
        "sids": [d["sid"] for d in sorted(sid_map.values(), key=lambda x: (-x["p1"], -x["total"]))],
    }


# ── Routes : Authentification — DÉSACTIVÉES (bypass temporaire) ─
# Pour réactiver, décommenter ce bloc et rétablir le middleware + dépendances.
#
# @app.get("/login", response_class=HTMLResponse)
# def login_page(request: Request, error: str = ""):
#     token = request.cookies.get("vt_token")
#     if token:
#         try:
#             _decode_token(token)
#             return RedirectResponse("/", status_code=302)
#         except JWTError:
#             pass
#     return templates.TemplateResponse(request, "login.html",
#                                       {"error": error, "current_user": {}})
#
# @app.post("/login")
# async def login(request: Request, db=Depends(get_db)):
#     form     = await request.form()
#     username = str(form.get("username", "")).strip()
#     password = str(form.get("password", ""))
#     user_doc = db.users.find_one({"username": username})
#     if not user_doc or not _verify_pw(password, user_doc["password_hash"]):
#         return templates.TemplateResponse(request, "login.html", {
#             "error": "Identifiants incorrects", "current_user": {}}, status_code=401)
#     token = _create_token(user_doc["username"], user_doc["role"])
#     resp  = RedirectResponse("/", status_code=303)
#     resp.set_cookie("vt_token", token, httponly=True, samesite="lax",
#                     max_age=TOKEN_HOURS * 3600)
#     return resp
#
# @app.post("/logout")
# def logout():
#     resp = RedirectResponse("/login", status_code=303)
#     resp.delete_cookie("vt_token")
#     return resp


# ── Routes : Admin ────────────────────────────────────────────

@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, msg: str = "", db=Depends(get_db),
               _: dict = Depends(require_admin)):
    users = list(db.users.find({}, {"password_hash": 0})
                 .sort("username", ASCENDING))
    return tpl(request, "admin.html", {"users": users, "msg": msg})


@app.post("/admin/users")
async def create_user(request: Request, db=Depends(get_db),
                      _: dict = Depends(require_admin)):
    form     = await request.form()
    username = str(form.get("username", "")).strip().lower()
    password = str(form.get("password", ""))
    role     = str(form.get("role", "consultant"))

    if not username or not password:
        return RedirectResponse("/admin?msg=Username+et+mot+de+passe+requis",
                                status_code=303)
    if role not in ("admin", "consultant"):
        role = "consultant"
    if db.users.find_one({"username": username}):
        return RedirectResponse(f"/admin?msg=L'utilisateur+'{username}'+existe+déjà",
                                status_code=303)

    db.users.insert_one({
        "username":      username,
        "password_hash": _hash_pw(password),
        "role":          role,
        "created_at":    datetime.now().strftime("%Y-%m-%d %H:%M"),
    })
    return RedirectResponse(f"/admin?msg=Compte+'{username}'+créé+avec+succès",
                            status_code=303)


@app.post("/admin/users/{username}/delete")
def delete_user(username: str, db=Depends(get_db),
                admin: dict = Depends(require_admin)):
    if username == admin.get("sub"):
        return RedirectResponse(
            "/admin?msg=Impossible+de+supprimer+votre+propre+compte",
            status_code=303)
    db.users.delete_one({"username": username})
    return RedirectResponse(f"/admin?msg=Compte+'{username}'+supprimé",
                            status_code=303)


# ── Routes : Paramètres ───────────────────────────────────────

@app.post("/settings/reset-db")
def reset_db(db=Depends(get_db), _: dict = Depends(require_admin)):
    db.sap_notes.drop()
    db.frun_data.drop()
    try:
        db.sap_notes.create_index([("reference_note",   ASCENDING)])
        db.sap_notes.create_index([("advisory_release", ASCENDING)])
        db.frun_data.create_index([("client",    ASCENDING)])
        db.frun_data.create_index([("check_ref", ASCENDING)])
    except Exception:
        pass
    return RedirectResponse("/", status_code=303)


# ── Routes : Dashboard ────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def index(request: Request, db=Depends(get_db)):
    advisory_count = db.sap_notes.count_documents({})
    frun_count     = db.frun_data.count_documents({})
    clients_list   = db.frun_data.distinct("client")
    doc = db.sap_notes.find_one({}, sort=[("advisory_release", DESCENDING)])
    max_release = doc["advisory_release"] if doc else "—"

    all_entries = build_merged_entries(db) if frun_count > 0 else []
    total = len(all_entries)
    p1    = sum(1 for e in all_entries if e["priority"] == "P1")
    p2    = sum(1 for e in all_entries if e["priority"] == "P2")
    p3    = sum(1 for e in all_entries if e["priority"] == "P3")
    done  = sum(1 for e in all_entries if e["status"] in ("Validated", "Implemented"))
    progress_pct = round(done / total * 100) if total else 0

    by_status: dict[str, int] = {}
    for e in all_entries:
        by_status[e["status"]] = by_status.get(e["status"], 0) + 1

    client_p1: dict[str, int] = {}
    for e in all_entries:
        if e["priority"] == "P1" and e.get("client"):
            client_p1[e["client"]] = client_p1.get(e["client"], 0) + 1
    top_client = max(client_p1.items(), key=lambda x: x[1]) if client_p1 else None

    return tpl(request, "index.html", {
        "advisory_count":  advisory_count,
        "frun_count":      frun_count,
        "clients":         len(clients_list),
        "max_release":     max_release,
        "dash_total":      total,
        "dash_p1":         p1,
        "dash_p2":         p2,
        "dash_p3":         p3,
        "dash_done":       done,
        "dash_progress":   progress_pct,
        "dash_by_status":  by_status,
        "dash_top_client": top_client,
        "status_order":    STATUS_VALUES,
    })


# ── Routes : Advisory ─────────────────────────────────────────

@app.get("/advisory", response_class=HTMLResponse)
def advisory_page(request: Request, msg: str = "", db=Depends(get_db)):
    count = db.sap_notes.count_documents({})
    doc   = db.sap_notes.find_one({}, sort=[("advisory_release", DESCENDING)])
    mr    = doc["advisory_release"] if doc else "—"
    return tpl(request, "advisory.html", {
        "count":        count,
        "max_release":  mr,
        "next_release": _next_release(mr if mr != "—" else None),
        "msg":          msg,
    })


@app.post("/advisory/upload")
async def upload_advisory(file: UploadFile = File(...), db=Depends(get_db)):
    content = await file.read()
    try:
        wb = openpyxl.load_workbook(io.BytesIO(content), data_only=True)
    except Exception as e:
        return RedirectResponse(f"/advisory?msg=Erreur+fichier:+{e}", status_code=303)

    ws = wb.active
    doc = db.sap_notes.find_one({}, sort=[("advisory_release", DESCENDING)])
    max_release = doc["advisory_release"] if doc else None

    # Détection du format à partir de la ligne d'en-têtes
    headers = [str(c.value).strip() if c.value is not None else "" for c in ws[1]]
    if "Nombre" in headers:
        fmt = "fr"
        col = {h: i for i, h in enumerate(headers)}
    elif "Reference Note" in headers:
        fmt = "en"
        col = None
    else:
        return RedirectResponse(
            "/advisory?msg=Format+non+reconnu+(colonne+'Nombre'+ou+'Reference+Note'+attendue)",
            status_code=303,
        )

    def _s(v):
        return str(v).strip() if v is not None else None

    def _get(row, name):
        idx = col.get(name) if col else None
        return row[idx] if idx is not None and idx < len(row) else None

    def _cvss(raw):
        if raw is None:
            return None
        if isinstance(raw, str):
            try:
                return float(raw.replace(",", "."))
            except Exception:
                return None
        try:
            return float(raw)
        except Exception:
            return None

    new_rows: dict[int, dict] = {}
    skipped = 0

    for row in ws.iter_rows(min_row=2, values_only=True):
        if fmt == "en":
            advisory_release = format_advisory_release(row[0])
        else:
            advisory_release = format_advisory_release(_get(row, "Date/Heure de validation"))

        if not advisory_release:
            continue
        if max_release and advisory_release <= max_release:
            skipped += 1
            continue

        raw_ref = row[2] if fmt == "en" else _get(row, "Nombre")
        if raw_ref is None:
            continue
        try:
            reference_note = int(raw_ref)
        except (ValueError, TypeError):
            continue

        if fmt == "en":
            try:
                version = int(row[3]) if row[3] is not None else 0
            except (ValueError, TypeError):
                version = 0

            data = {
                "advisory_release":    advisory_release,
                "sap_component":       _s(row[1]),
                "reference_note":      reference_note,
                "version":             version,
                "title":               _s(row[4]),
                "category":            _s(row[5]),
                "priority_sap":        _s(row[6]),
                "cvss_v3_base_score":  _cvss(row[11]),
                "correction_type":     _s(row[34]),
                "recommended_implementation_process": _s(row[35]),
                "downtime_required":   _s(row[36]),
            }
            if reference_note not in new_rows or version > new_rows[reference_note]["version"]:
                new_rows[reference_note] = data
        else:
            categorie = _s(_get(row, "Catégorie"))
            data = {
                "advisory_release":    advisory_release,
                "sap_component":       _s(_get(row, "Composant SAP")),
                "reference_note":      reference_note,
                "version":             0,
                "title":               _s(_get(row, "Titre")),
                "category":            categorie,
                "priority_sap":        _s(_get(row, "Priorité")),
                "cvss_v3_base_score":  _cvss(_get(row, "Score CVSS")),
                "correction_type":     categorie,
                "recommended_implementation_process": None,
                "downtime_required":   None,
            }
            if reference_note not in new_rows:
                new_rows[reference_note] = data

    added = updated = 0
    for ref, data in new_rows.items():
        existing = db.sap_notes.find_one({"reference_note": ref})
        if existing:
            if data["version"] > existing.get("version", 0):
                db.sap_notes.replace_one({"reference_note": ref}, data)
                updated += 1
        else:
            db.sap_notes.insert_one(data)
            added += 1

    apply_dedup(db)
    fmt_label = "SAP for Me" if fmt == "fr" else "anglais"
    msg = f"{added} notes ajoutées, {updated} mises à jour, {skipped} ignorées (format {fmt_label})"
    return RedirectResponse(f"/advisory?msg={msg}", status_code=303)


# ── Routes : FRun ─────────────────────────────────────────────

@app.get("/frun", response_class=HTMLResponse)
def frun_page(request: Request, msg: str = "", db=Depends(get_db)):
    count   = db.frun_data.count_documents({})
    clients = db.frun_data.distinct("client")
    return tpl(request, "frun.html", {
        "count":   count,
        "clients": sorted(clients),
        "msg":     msg,
    })


@app.post("/frun/upload")
async def upload_frun(file: UploadFile = File(...), db=Depends(get_db)):
    content = await file.read()
    try:
        wb = openpyxl.load_workbook(io.BytesIO(content), data_only=True)
    except Exception as e:
        return RedirectResponse(f"/frun?msg=Erreur+fichier:+{e}", status_code=303)

    ws  = wb["Sheet1"] if "Sheet1" in wb.sheetnames else wb.active
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    docs = []

    for row in ws.iter_rows(min_row=2, values_only=True):
        client = str(row[0]).strip() if row[0] else None
        if not client:
            continue
        def _s(v): return str(v).strip() if v is not None else None
        docs.append({
            "client":             client,
            "sid":                _s(row[1]),
            "compliant":          _s(row[2]),
            "landscape":          _s(row[3]),
            "check_description":  _s(row[4]),
            "configuration_item": _s(row[5]),
            "value":              _s(row[6]),
            "policy":             _s(row[7]),
            "check_ref":          clean_check_ref(row[8]),
            "rule":               _s(row[9]),
            "valid_since_utc":    _s(row[10]),
            "imported_at":        now,
            "status":             "Not Started",
            "comment":            "",
            "status_history":     [],
        })

    if docs:
        db.frun_data.insert_many(docs)

    msg = f"{len(docs)} entrées importées le {now}"
    return RedirectResponse(f"/frun?msg={msg}", status_code=303)


# ── Routes : Vue fusionnée ────────────────────────────────────

@app.get("/merged", response_class=HTMLResponse)
def merged_view(
    request: Request,
    client: str = "", sid: str = "", reference: str = "",
    db=Depends(get_db),
):
    entries = build_merged_entries(db, client or None, sid or None, reference or None)
    clients = sorted(db.frun_data.distinct("client"))
    return tpl(request, "merged.html", {
        "entries":          entries,
        "status_values":    STATUS_VALUES,
        "filter_client":    client,
        "filter_sid":       sid,
        "filter_reference": reference,
        "clients":          clients,
        "total":            len(entries),
    })


@app.get("/merged/export")
def export_merged(
    client: str = "", sid: str = "", reference: str = "",
    db=Depends(get_db),
):
    from openpyxl.styles import Alignment, Font, PatternFill

    entries = build_merged_entries(db, client or None, sid or None, reference or None)

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "VulnTrack"

    COLUMNS = [
        ("Client",              lambda e: e.get("client")),
        ("SID",                 lambda e: e.get("sid")),
        ("Priority",            lambda e: e.get("priority")),
        ("Statut",              lambda e: e.get("status")),
        ("Reference Note",      lambda e: e.get("reference")),
        ("Check Description",   lambda e: e.get("check_description")),
        ("Policy",              lambda e: e.get("policy")),
        ("Correction Type",     lambda e: e.get("correction_type")),
        ("Recommended Process", lambda e: e.get("recommended_implementation_process")),
        ("Downtime Required",   lambda e: e.get("downtime_required")),
        ("Landscape",           lambda e: e.get("landscape")),
        ("Configuration Item",  lambda e: e.get("configuration_item")),
        ("Value",               lambda e: e.get("value")),
        ("Rule",                lambda e: e.get("rule")),
        ("Valid Since",         lambda e: e.get("valid_since_utc")),
        ("Commentaire",         lambda e: e.get("comment", "")),
    ]
    PRIORITY_COL_IDX = 3

    ws.append([col[0] for col in COLUMNS])

    header_fill = PatternFill("solid", fgColor="FF1E2338")
    for cell in ws[1]:
        cell.font      = Font(bold=True, color="FFFFFF")
        cell.fill      = header_fill
        cell.alignment = Alignment(horizontal="center", vertical="center")
    ws.row_dimensions[1].height = 18

    for e in entries:
        ws.append([fn(e) for _, fn in COLUMNS])

    PRIO_FILL = {
        "P1": PatternFill("solid", fgColor="FFC0392B"),
        "P2": PatternFill("solid", fgColor="FFD35400"),
        "P3": PatternFill("solid", fgColor="FF27AE60"),
    }
    PRIO_FONT = Font(bold=True, color="FFFFFF")

    for row in ws.iter_rows(min_row=2, max_row=ws.max_row):
        prio_cell = row[PRIORITY_COL_IDX - 1]
        fill = PRIO_FILL.get(prio_cell.value)
        if fill:
            prio_cell.fill = fill
            prio_cell.font = PRIO_FONT

    for col in ws.columns:
        max_len = max(
            (len(str(cell.value)) for cell in col if cell.value is not None),
            default=8,
        )
        ws.column_dimensions[col[0].column_letter].width = min(max_len + 4, 60)

    ws.freeze_panes = "A2"

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)

    fname = f"VulnTrack_export_{datetime.now().strftime('%Y-%m-%d')}.xlsx"
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# ── Routes : Entrées (statut, commentaire) ────────────────────

@app.post("/entries/{entry_id}/status")
def update_status(entry_id: str, request_data: dict, db=Depends(get_db)):
    try:
        oid = ObjectId(entry_id)
    except Exception:
        raise HTTPException(status_code=400, detail="ID invalide")

    entry = db.frun_data.find_one({"_id": oid})
    if not entry:
        raise HTTPException(status_code=404, detail="Entrée introuvable")

    new_status = request_data.get("status", "")
    if new_status not in STATUS_VALUES:
        raise HTTPException(status_code=400, detail="Statut invalide")

    old_status = entry.get("status", "Not Started")
    db.frun_data.update_one(
        {"_id": oid},
        {
            "$set": {"status": new_status},
            "$push": {"status_history": {
                "from":       old_status,
                "to":         new_status,
                "changed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }},
        },
    )
    return {"ok": True, "status": new_status}


@app.post("/entries/{entry_id}/comment")
def update_comment(entry_id: str, request_data: dict, db=Depends(get_db)):
    try:
        oid = ObjectId(entry_id)
    except Exception:
        raise HTTPException(status_code=400, detail="ID invalide")

    comment = request_data.get("comment", "")
    result  = db.frun_data.update_one({"_id": oid}, {"$set": {"comment": comment}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Entrée introuvable")
    return {"ok": True}


@app.get("/entries/{entry_id}/history")
def get_history(entry_id: str, db=Depends(get_db)):
    try:
        oid = ObjectId(entry_id)
    except Exception:
        raise HTTPException(status_code=400, detail="ID invalide")

    entry = db.frun_data.find_one({"_id": oid}, {"status_history": 1})
    if not entry:
        raise HTTPException(status_code=404, detail="Entrée introuvable")
    return {"history": entry.get("status_history", [])}


# ── Routes : Visualisation ────────────────────────────────────

@app.get("/view", response_class=HTMLResponse)
def view(request: Request, client: str = "", db=Depends(get_db)):
    all_clients = sorted(db.frun_data.distinct("client"))

    summary = []
    for c in all_clients:
        entries = build_merged_entries(db, client=c)
        summary.append(_client_summary(entries, c))

    all_entries = build_merged_entries(db)
    g_total = len(all_entries)
    g_p1    = sum(1 for e in all_entries if e["priority"] == "P1")
    g_p2    = sum(1 for e in all_entries if e["priority"] == "P2")
    g_p3    = sum(1 for e in all_entries if e["priority"] == "P3")
    g_done  = sum(1 for e in all_entries if e["status"] in ("Validated", "Implemented"))
    g_ns    = sum(1 for e in all_entries if e["status"] == "Not Started")

    pipeline_order = ["Not Started", "Started", "Implemented",
                      "Validated", "To be checked", "Exception"]
    g_by_status: dict[str, int] = {}
    for e in all_entries:
        g_by_status[e["status"]] = g_by_status.get(e["status"], 0) + 1

    global_stats = {
        "total": g_total, "p1": g_p1, "p2": g_p2, "p3": g_p3,
        "done": g_done, "not_started": g_ns,
        "progress_pct": round(g_done / g_total * 100) if g_total else 0,
        "pipeline": [{"label": s, "count": g_by_status.get(s, 0)} for s in pipeline_order],
        "clients": len(all_clients),
    }

    selected_entries = []
    selected_summary = None
    if client:
        selected_entries = build_merged_entries(db, client=client)
        selected_summary = next((s for s in summary if s["client"] == client), None)

    return tpl(request, "view.html", {
        "summary":          summary,
        "global_stats":     global_stats,
        "selected_client":  client,
        "selected_entries": selected_entries,
        "selected_summary": selected_summary,
        "status_values":    STATUS_VALUES,
        "all_clients":      all_clients,
        "pipeline_order":   pipeline_order,
    })
