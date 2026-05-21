import io
import re
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Depends, Request, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, func
from sqlalchemy.orm import declarative_base, sessionmaker, Session
import openpyxl

# ── Database ──────────────────────────────────────────────────────────────────

DATABASE_URL = "sqlite:///./wcomply.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class AdvisoryNote(Base):
    __tablename__ = "advisory_notes"
    id = Column(Integer, primary_key=True, index=True)
    advisory_release = Column(String, index=True)   # YYYY-MM
    sap_component = Column(String, nullable=True)
    reference_note = Column(Integer, unique=True, index=True)
    version = Column(Integer, default=0)
    title = Column(String, nullable=True)
    category = Column(String, nullable=True)        # "Type" in merged view
    priority_sap = Column(String, nullable=True)
    cvss_v3_base_score = Column(Float, nullable=True)
    correction_type = Column(String, nullable=True)
    recommended_implementation_process = Column(String, nullable=True)
    downtime_required = Column(String, nullable=True)


class FRunEntry(Base):
    __tablename__ = "frun_entries"
    id = Column(Integer, primary_key=True, autoincrement=True)
    client = Column(String, index=True)
    sid = Column(String, index=True)
    compliant = Column(String, nullable=True)
    landscape = Column(String, nullable=True)
    check_description = Column(String, nullable=True)
    configuration_item = Column(String, nullable=True)
    value_field = Column(String, nullable=True)
    policy = Column(String, nullable=True)
    check_ref = Column(Integer, index=True)         # cleaned col I → joins advisory.reference_note
    rule = Column(String, nullable=True)
    valid_since_utc = Column(String, nullable=True)
    upload_timestamp = Column(DateTime, default=datetime.now)
    status = Column(String, default="Not Started")


Base.metadata.create_all(bind=engine)

# ── App setup ─────────────────────────────────────────────────────────────────

app = FastAPI(title="WComply")
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

STATUS_VALUES = ["Not Started", "Started", "Implemented", "Validated", "To be checked", "Exception"]


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Utilities ─────────────────────────────────────────────────────────────────

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
    if isinstance(val, datetime):
        return val.strftime("%Y-%m")
    return str(val)


def apply_dedup(db: Session):
    """For each reference_note with duplicates, keep only the highest version."""
    dupes = (
        db.query(AdvisoryNote.reference_note)
        .group_by(AdvisoryNote.reference_note)
        .having(func.count(AdvisoryNote.id) > 1)
        .all()
    )
    for (ref_note,) in dupes:
        rows = (
            db.query(AdvisoryNote)
            .filter(AdvisoryNote.reference_note == ref_note)
            .order_by(AdvisoryNote.version.desc())
            .all()
        )
        for row in rows[1:]:
            db.delete(row)
    db.commit()


def build_merged_entries(db: Session, client=None, sid=None, reference=None):
    query = db.query(FRunEntry, AdvisoryNote).outerjoin(
        AdvisoryNote, FRunEntry.check_ref == AdvisoryNote.reference_note
    )
    if client:
        query = query.filter(FRunEntry.client.ilike(f"%{client}%"))
    if sid:
        query = query.filter(FRunEntry.sid.ilike(f"%{sid}%"))
    if reference:
        ref_num = clean_check_ref(reference)
        if ref_num:
            query = query.filter(FRunEntry.check_ref == ref_num)

    results = []
    for frun, advisory in query.order_by(FRunEntry.client, FRunEntry.sid).all():
        score = advisory.cvss_v3_base_score if advisory else None
        results.append({
            "id": frun.id,
            "client": frun.client,
            "priority": calculate_priority(score),
            "sid": frun.sid,
            "status": frun.status,
            "check_description": frun.check_description,
            "policy": frun.policy,
            "correction_type": advisory.correction_type if advisory else None,
            "reference": advisory.reference_note if advisory else frun.check_ref,
            "type": advisory.category if advisory else None,
            "recommended_implementation_process": advisory.recommended_implementation_process if advisory else None,
            "downtime_required": advisory.downtime_required if advisory else None,
            "landscape": frun.landscape,
            "configuration_item": frun.configuration_item,
            "value": frun.value_field,
            "rule": frun.rule,
            "valid_since_utc": frun.valid_since_utc,
            "upload_timestamp": frun.upload_timestamp.strftime("%Y-%m-%d %H:%M") if frun.upload_timestamp else None,
            "cvss_score": score,
        })
    return results


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def index(request: Request, db: Session = Depends(get_db)):
    advisory_count = db.query(func.count(AdvisoryNote.id)).scalar()
    frun_count = db.query(func.count(FRunEntry.id)).scalar()
    clients = db.query(FRunEntry.client).distinct().count()
    max_release = db.query(func.max(AdvisoryNote.advisory_release)).scalar()
    return templates.TemplateResponse(request, "index.html", {
        "advisory_count": advisory_count,
        "frun_count": frun_count,
        "clients": clients,
        "max_release": max_release or "—",
    })


# ── Advisory upload ───────────────────────────────────────────────────────────

def _next_release(current: Optional[str]) -> Optional[str]:
    """Given 'YYYY-MM', return the following month string."""
    if not current or current == "—":
        return None
    try:
        year, month = map(int, current.split("-"))
        year, month = (year + 1, 1) if month == 12 else (year, month + 1)
        return f"{year}-{month:02d}"
    except Exception:
        return None


@app.get("/advisory", response_class=HTMLResponse)
def advisory_page(request: Request, msg: str = "", db: Session = Depends(get_db)):
    count = db.query(func.count(AdvisoryNote.id)).scalar()
    max_release = db.query(func.max(AdvisoryNote.advisory_release)).scalar()
    mr = max_release or "—"
    return templates.TemplateResponse(request, "advisory.html", {
        "count": count,
        "max_release": mr,
        "next_release": _next_release(max_release),
        "msg": msg,
    })


@app.post("/advisory/upload")
async def upload_advisory(file: UploadFile = File(...), db: Session = Depends(get_db)):
    content = await file.read()
    try:
        wb = openpyxl.load_workbook(io.BytesIO(content), data_only=True)
    except Exception as e:
        return RedirectResponse(f"/advisory?msg=Erreur+lecture+fichier:+{e}", status_code=303)

    ws = wb.active
    max_release = db.query(func.max(AdvisoryNote.advisory_release)).scalar()

    new_rows: dict[int, dict] = {}
    skipped = 0

    for row in ws.iter_rows(min_row=2, values_only=True):
        advisory_release = format_advisory_release(row[0])
        if not advisory_release:
            continue

        # Monthly update: skip already-loaded releases
        if max_release and advisory_release <= max_release:
            skipped += 1
            continue

        reference_note = row[2]
        if reference_note is None:
            continue
        try:
            reference_note = int(reference_note)
        except (ValueError, TypeError):
            continue

        try:
            version = int(row[3]) if row[3] is not None else 0
        except (ValueError, TypeError):
            version = 0

        cvss = row[11]
        if isinstance(cvss, str):
            try:
                cvss = float(cvss)
            except Exception:
                cvss = None
        elif cvss is not None:
            cvss = float(cvss)

        def _str(v):
            return str(v).strip() if v is not None else None

        data = {
            "advisory_release": advisory_release,
            "sap_component": _str(row[1]),
            "reference_note": reference_note,
            "version": version,
            "title": _str(row[4]),
            "category": _str(row[5]),
            "priority_sap": _str(row[6]),
            "cvss_v3_base_score": cvss,
            "correction_type": _str(row[34]),
            "recommended_implementation_process": _str(row[35]),
            "downtime_required": _str(row[36]),
        }

        # In-memory dedup: keep highest version
        if reference_note not in new_rows or version > new_rows[reference_note]["version"]:
            new_rows[reference_note] = data

    added = updated = 0
    for ref, data in new_rows.items():
        existing = db.query(AdvisoryNote).filter(AdvisoryNote.reference_note == ref).first()
        if existing:
            if data["version"] > existing.version:
                for k, v in data.items():
                    setattr(existing, k, v)
                updated += 1
        else:
            db.add(AdvisoryNote(**data))
            added += 1

    db.commit()
    apply_dedup(db)

    msg = f"{added} notes ajoutées, {updated} mises à jour, {skipped} lignes ignorées (déjà chargées)"
    return RedirectResponse(f"/advisory?msg={msg}", status_code=303)


# ── FRun upload ───────────────────────────────────────────────────────────────

@app.get("/frun", response_class=HTMLResponse)
def frun_page(request: Request, msg: str = "", db: Session = Depends(get_db)):
    count = db.query(func.count(FRunEntry.id)).scalar()
    clients = db.query(FRunEntry.client).distinct().all()
    return templates.TemplateResponse(request, "frun.html", {
        "count": count,
        "clients": [c[0] for c in clients],
        "msg": msg,
    })


@app.post("/frun/upload")
async def upload_frun(file: UploadFile = File(...), db: Session = Depends(get_db)):
    content = await file.read()
    try:
        wb = openpyxl.load_workbook(io.BytesIO(content), data_only=True)
    except Exception as e:
        return RedirectResponse(f"/frun?msg=Erreur+lecture+fichier:+{e}", status_code=303)

    ws = wb["Sheet1"] if "Sheet1" in wb.sheetnames else wb.active
    now = datetime.now()
    added = 0

    for row in ws.iter_rows(min_row=2, values_only=True):
        client = str(row[0]).strip() if row[0] else None
        if not client:
            continue

        check_ref = clean_check_ref(row[8])

        def _str(v):
            return str(v).strip() if v is not None else None

        entry = FRunEntry(
            client=client,
            sid=_str(row[1]),
            compliant=_str(row[2]),
            landscape=_str(row[3]),
            check_description=_str(row[4]),
            configuration_item=_str(row[5]),
            value_field=_str(row[6]),
            policy=_str(row[7]),
            check_ref=check_ref,
            rule=_str(row[9]),
            valid_since_utc=_str(row[10]),
            upload_timestamp=now,
            status="Not Started",
        )
        db.add(entry)
        added += 1

    db.commit()
    msg = f"{added} entrées importées le {now.strftime('%Y-%m-%d %H:%M')}"
    return RedirectResponse(f"/frun?msg={msg}", status_code=303)


# ── Merged view ───────────────────────────────────────────────────────────────

@app.get("/merged", response_class=HTMLResponse)
def merged_view(
    request: Request,
    client: str = "",
    sid: str = "",
    reference: str = "",
    db: Session = Depends(get_db),
):
    entries = build_merged_entries(db, client or None, sid or None, reference or None)
    clients = [c[0] for c in db.query(FRunEntry.client).distinct().order_by(FRunEntry.client).all()]
    return templates.TemplateResponse(request, "merged.html", {
        "entries": entries,
        "status_values": STATUS_VALUES,
        "filter_client": client,
        "filter_sid": sid,
        "filter_reference": reference,
        "clients": clients,
        "total": len(entries),
    })


@app.post("/entries/{entry_id}/status")
def update_status(entry_id: int, request_data: dict, db: Session = Depends(get_db)):
    entry = db.query(FRunEntry).filter(FRunEntry.id == entry_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    new_status = request_data.get("status", "")
    if new_status not in STATUS_VALUES:
        raise HTTPException(status_code=400, detail="Invalid status")
    entry.status = new_status
    db.commit()
    return {"ok": True, "status": new_status}


# ── Visualization ─────────────────────────────────────────────────────────────

def _client_summary(entries: list, client: str) -> dict:
    """Compute full analysis stats for one client's entries."""
    total = len(entries)
    p1 = sum(1 for e in entries if e["priority"] == "P1")
    p2 = sum(1 for e in entries if e["priority"] == "P2")
    p3 = sum(1 for e in entries if e["priority"] == "P3")
    no_score = total - p1 - p2 - p3

    by_status: dict[str, int] = {}
    for e in entries:
        by_status[e["status"]] = by_status.get(e["status"], 0) + 1

    done = sum(1 for e in entries if e["status"] in ("Validated", "Implemented"))
    in_progress = sum(1 for e in entries if e["status"] == "Started")
    not_started = by_status.get("Not Started", 0)
    progress_pct = round(done / total * 100) if total else 0

    # P1 items not yet closed
    critical = [e for e in entries if e["priority"] == "P1" and e["status"] in ("Not Started", "Started")]

    # Per-SID breakdown
    sid_map: dict[str, dict] = {}
    for e in entries:
        sid = e["sid"] or "—"
        if sid not in sid_map:
            sid_map[sid] = {"sid": sid, "total": 0, "p1": 0, "p2": 0, "p3": 0, "done": 0, "by_status": {}}
        d = sid_map[sid]
        d["total"] += 1
        if e["priority"] == "P1":   d["p1"] += 1
        elif e["priority"] == "P2": d["p2"] += 1
        elif e["priority"] == "P3": d["p3"] += 1
        if e["status"] in ("Validated", "Implemented"): d["done"] += 1
        d["by_status"][e["status"]] = d["by_status"].get(e["status"], 0) + 1

    for d in sid_map.values():
        d["progress_pct"] = round(d["done"] / d["total"] * 100) if d["total"] else 0

    sid_breakdown = sorted(sid_map.values(), key=lambda x: (-x["p1"], -x["total"]))
    sids = [d["sid"] for d in sid_breakdown]

    return {
        "client": client,
        "total": total,
        "p1": p1, "p2": p2, "p3": p3, "no_score": no_score,
        "by_status": by_status,
        "done": done,
        "in_progress": in_progress,
        "not_started": not_started,
        "progress_pct": progress_pct,
        "critical_count": len(critical),
        "sid_breakdown": sid_breakdown,
        "sids": sids,
    }


@app.get("/view", response_class=HTMLResponse)
def view(request: Request, client: str = "", db: Session = Depends(get_db)):
    all_clients = [c[0] for c in db.query(FRunEntry.client).distinct().order_by(FRunEntry.client).all()]

    summary = []
    for c in all_clients:
        entries = build_merged_entries(db, client=c)
        summary.append(_client_summary(entries, c))

    # Global KPIs across every entry
    all_entries = build_merged_entries(db)
    g_total = len(all_entries)
    g_p1 = sum(1 for e in all_entries if e["priority"] == "P1")
    g_p2 = sum(1 for e in all_entries if e["priority"] == "P2")
    g_p3 = sum(1 for e in all_entries if e["priority"] == "P3")
    g_done = sum(1 for e in all_entries if e["status"] in ("Validated", "Implemented"))
    g_ns   = sum(1 for e in all_entries if e["status"] == "Not Started")
    g_prog = round(g_done / g_total * 100) if g_total else 0

    # Global status pipeline
    pipeline_order = ["Not Started", "Started", "Implemented", "Validated", "To be checked", "Exception"]
    g_by_status = {}
    for e in all_entries:
        g_by_status[e["status"]] = g_by_status.get(e["status"], 0) + 1
    g_pipeline = [{"label": s, "count": g_by_status.get(s, 0)} for s in pipeline_order]

    global_stats = {
        "total": g_total, "p1": g_p1, "p2": g_p2, "p3": g_p3,
        "done": g_done, "not_started": g_ns, "progress_pct": g_prog,
        "pipeline": g_pipeline,
        "clients": len(all_clients),
    }

    selected_entries = []
    selected_summary = None
    if client:
        selected_entries = build_merged_entries(db, client=client)
        selected_summary = next((s for s in summary if s["client"] == client), None)

    return templates.TemplateResponse(request, "view.html", {
        "summary": summary,
        "global_stats": global_stats,
        "selected_client": client,
        "selected_entries": selected_entries,
        "selected_summary": selected_summary,
        "status_values": STATUS_VALUES,
        "all_clients": all_clients,
        "pipeline_order": pipeline_order,
    })
