from fastapi import FastAPI, Request, Depends, HTTPException, Form
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from pydantic import BaseModel, field_validator
from typing import Optional, Any
from datetime import date, datetime
import hashlib, hmac, json, base64, os

from app.database import get_db

SECRET_KEY = os.getenv("SECRET_KEY", "dic_bahrain_erp_secret_key_2026")

def hash_password(raw_password: str) -> str:
    return hashlib.sha256(f"dic_salt_{raw_password}".encode("utf-8")).hexdigest()

def create_session_token(data: dict) -> str:
    payload = base64.urlsafe_b64encode(json.dumps(data).encode("utf-8")).decode("utf-8")
    sig = hmac.new(SECRET_KEY.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"

DEFAULT_PAGE_KEYS = ("about", "donors", "audit", "reconcile", "followup", "so_dashboard", "reports", "reports_matrix", "data_views_export", "users")

def normalize_page_permissions(role_code: Optional[str], raw_perms: Any, valid_keys: tuple = DEFAULT_PAGE_KEYS) -> dict:
    if isinstance(raw_perms, str):
        try:
            raw_perms = json.loads(raw_perms)
        except Exception:
            raw_perms = {}
    if not isinstance(raw_perms, dict):
        raw_perms = {}

    # If explicit page keys already exist in raw_perms, honor them
    if any(k in raw_perms for k in valid_keys):
        base = {k: raw_perms.get(k, "none") for k in valid_keys}
        if "reports_matrix" not in raw_perms and "reports" in raw_perms:
            base["reports_matrix"] = raw_perms.get("reports", "none")
        if "so_dashboard" not in raw_perms and "reports" in raw_perms:
            base["so_dashboard"] = raw_perms.get("reports", "none")
        if "data_views_export" not in raw_perms and "reports" in raw_perms:
            base["data_views_export"] = raw_perms.get("reports", "none")
        base["about"] = raw_perms.get("about", "view")
        for k, v in base.items():
            if v not in ("none", "view", "edit"):
                base[k] = "none"
        return base

    # Fallback based on legacy role_code
    code = (role_code or "").upper()
    if code in ("READ_WRITE", "ADMIN"):
        return {k: "edit" for k in valid_keys}
    return {
        k: ("none" if k == "users" else "view")
        for k in valid_keys
    }

def resolve_page_key(path: str) -> str:
    if path.startswith("/users") or path.startswith("/api/users"):
        return "users"
    if path.startswith("/reports-views") or path.startswith("/api/reports/views"):
        return "data_views_export"
    if path.startswith("/reports-dashboard") or path.startswith("/api/reports/dashboard"):
        return "so_dashboard"
    if path.startswith("/reports-matrix") or path.startswith("/api/reports/matrix"):
        return "reports_matrix"
    if path.startswith("/reports") or path.startswith("/api/reports"):
        return "reports"
    if path.startswith("/bank-codes-audit") or path.startswith("/api/bank-codes-audit"):
        return "audit"
    if path.startswith("/bank-reconcile") or path.startswith("/api/bank-reconcile"):
        return "reconcile"
    if path.startswith("/followup") or path.startswith("/api/followup"):
        return "followup"
    if path in ("/", "/api/init-data") or path.startswith("/api/donors") or path.startswith("/api/standing-orders"):
        return "donors"
    return "about"

def verify_session_token(token: str) -> Optional[dict]:
    if not token or "." not in token:
        return None
    payload, sig = token.rsplit(".", 1)
    expected_sig = hmac.new(SECRET_KEY.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return None
    try:
        data = json.loads(base64.urlsafe_b64decode(payload.encode("utf-8")).decode("utf-8"))
        data["page_permissions"] = normalize_page_permissions(data.get("role_code"), data.get("page_permissions"))
        return data
    except Exception:
        return None

app = FastAPI(title="DIC Standing Orders System - Bahrain")
app.add_middleware(GZipMiddleware, minimum_size=1000)
templates = Jinja2Templates(directory="app/templates")

@app.middleware("http")
async def auth_and_rbac_middleware(request: Request, call_next):
    path = request.url.path
    public_paths = ("/login", "/logout", "/health", "/favicon.ico")
    token = request.cookies.get("dic_session")
    user = verify_session_token(token)
    request.state.user = user

    page_key = resolve_page_key(path)
    request.state.current_page_key = page_key

    if path in public_paths:
        return await call_next(request)

    if not user:
        if path.startswith("/api/"):
            return JSONResponse(status_code=401, content={"detail": "Authentication required. Please sign in."})
        return RedirectResponse(url="/login", status_code=302)

    page_perms = user.get("page_permissions") or normalize_page_permissions(user.get("role_code"), None)
    access_level = page_perms.get(page_key, "none")
    if path.startswith("/api/reports/meta") and access_level == "none":
        # Shared metadata endpoint used by /reports-dashboard, /reports, and /reports-matrix
        if page_perms.get("reports_matrix", "none") != "none":
            access_level = page_perms.get("reports_matrix", "view")
        elif page_perms.get("so_dashboard", "none") != "none":
            access_level = page_perms.get("so_dashboard", "view")
    request.state.current_page_access = access_level

    if access_level == "none":
        if path.startswith("/api/"):
            return JSONResponse(status_code=403, content={"detail": f"Access Denied: No permission for module '{page_key}'."})
        if path != "/about" and page_perms.get("about", "view") != "none":
            return RedirectResponse(url="/about", status_code=302)
        return JSONResponse(status_code=403, content={"detail": f"Access Denied: No permission for page '{page_key}'."})

    if request.method in ("POST", "PUT", "DELETE", "PATCH") and access_level != "edit":
        return JSONResponse(
            status_code=403,
            content={"detail": f"Access Denied: You only have View permission on '{page_key}'."}
        )

    return await call_next(request)


class DonorSaveSchema(BaseModel):
    donor_no: Optional[int] = None
    name_prefix: Optional[int] = 1
    f_nm: Optional[str] = ""
    s_nm: Optional[str] = ""
    t_nm: Optional[str] = ""
    l_nm: Optional[str] = ""
    donor_name: str
    donor_ename: Optional[str] = ""
    gen_cd: Optional[int] = 1
    lang_cd: Optional[int] = 1
    donor_contact: Optional[int] = 1
    donor_cpr: Optional[str] = ""
    care: Optional[str] = "1"
    address_type: Optional[int] = 1
    donor_flat: Optional[int] = None
    donor_building: Optional[str] = ""
    donor_road: Optional[str] = ""
    donor_block: Optional[int] = None
    donor_p_box: Optional[int] = None
    donor_tel1: Optional[str] = ""
    donor_tel2: Optional[str] = ""
    donor_mobile: Optional[str] = ""
    bank2_cd: Optional[int] = 1
    acc_type_no: Optional[int] = 1
    donor_acc_no: Optional[str] = ""
    donor_name_acc: Optional[str] = ""
    status_no: Optional[int] = 1
    user_id: Optional[str] = "TAREK"

    @field_validator("*", mode="before")
    @classmethod
    def clean_values(cls, v: Any, info):
        if v == "" and info.field_name in ("donor_flat", "donor_block", "donor_p_box", "donor_no"):
            return None
        if v is None and info.field_name not in ("donor_flat", "donor_block", "donor_p_box", "donor_no"):
            return ""
        return v

class StandingOrderCreateSchema(BaseModel):
    donor_no: int
    item_no: str = "1"
    monthly_pay: float
    donation_start_date: date
    bank2_cd: int = 1
    donor_acc_no: Optional[str] = ""
    sort_field: str
    alt_so_code: Optional[str] = "0"
    through_form: int = 1
    userid: str = "TAREK"

class ToggleSoStatusSchema(BaseModel):
    reason: Optional[str] = ""
    userid: str = "TAREK"

@app.get("/health")
async def health_check():
    return {"status": "ok", "environment": os.getenv("APP_ENV", "testing")}

@app.get("/", response_class=HTMLResponse)
async def main_donor_screen(request: Request):
    return templates.TemplateResponse("donor_prototype.html", {"request": request})

async def _fetch_single_donor_with_items(db: AsyncSession, donor_no: Optional[int]) -> Optional[dict]:
    if not donor_no:
        return None
    d_res = await db.execute(text("""
        SELECT d.donor_no,
               COALESCE(d.name_prefix, 1) AS name_prefix,
               COALESCE(d.f_nm, '') AS f_nm,
               COALESCE(d.s_nm, '') AS s_nm,
               COALESCE(d.t_nm, '') AS t_nm,
               COALESCE(d.l_nm, '') AS l_nm,
               COALESCE(d.donor_name, '') AS donor_name,
               COALESCE(d.donor_ename, '') AS donor_ename,
               COALESCE(d.gen_cd, 1) AS gen_cd,
               COALESCE(d.lang_cd, 1) AS lang_cd,
               COALESCE(d.donor_contact, 1) AS donor_contact,
               COALESCE(d.donor_cpr, '') AS donor_cpr,
               COALESCE(d.care, '1') AS care,
               COALESCE(d.address_type, 1) AS address_type,
               d.donor_flat,
               COALESCE(d.donor_building, '') AS donor_building,
               COALESCE(d.donor_road, '') AS donor_road,
               d.donor_block,
               d.donor_p_box,
               COALESCE(d.donor_tel1, '') AS donor_tel1,
               COALESCE(d.donor_tel2, '') AS donor_tel2,
               COALESCE(d.donor_mobile, '') AS donor_mobile,
               COALESCE(d.bank2_cd, 1) AS bank2_cd,
               COALESCE(d.acc_type_no, 1) AS acc_type_no,
               COALESCE(d.donor_acc_no, '') AS donor_acc_no,
               COALESCE(d.donor_name_acc, '') AS donor_name_acc,
               COALESCE(d.status_no, 1) AS status_no,
               COALESCE(d.user_id, '') AS user_id,
               COALESCE(TO_CHAR(d.append_date, 'YYYY-MM-DD'), '') AS append_date,
               COALESCE(TO_CHAR(d.last_update, 'YYYY-MM-DD'), '') AS last_update,
               COALESCE(TO_CHAR(d.call_date, 'YYYY-MM-DD'), '') AS call_date,
               COALESCE(NULLIF(TRIM(t.etown_nm), ''), t.town_nm, '') AS town_name,
               (SELECT COUNT(*) FROM donor_followup f WHERE f.donor_no = d.donor_no) AS donor_followup_count
        FROM donor_master d
        LEFT JOIN lkp_towns t ON d.donor_block = t.block_cd
        WHERE d.donor_no = :dno
    """), {"dno": int(donor_no)})
    d_row = d_res.first()
    if not d_row:
        return None
    d = dict(d_row._mapping)

    so_res = await db.execute(text("""
        SELECT so_id,
               donor_no,
               item_no,
               item_no2,
               item_desc,
               COALESCE(NULLIF(TRIM(item_e_desc), ''), item_desc) AS item_e_desc,
               COALESCE(TO_CHAR(donation_start_date, 'YYYY-MM-DD'), '') AS donation_start_date,
               COALESCE(TO_CHAR(donation_expected_edate, 'YYYY-MM-DD'), '') AS donation_expected_edate,
               monthly_pay::float8 AS monthly_pay,
               bank2_cd,
               bank_desc,
               COALESCE(NULLIF(TRIM(bank_e_desc), ''), bank_desc) AS bank_e_desc,
               COALESCE(donor_acc_no, '') AS donor_acc_no,
               COALESCE(sort_field, '') AS sort_field,
               COALESCE(alt_so_code, '') AS alt_so_code,
               (through_form = 1) AS through_form,
               status_no,
               actual_delay_months,
               actual_delay_months AS delay_months,
               virtual_delay_months,
               payment_notes,
               last_followup_summary,
               has_followup
        FROM vw_standing_orders_summary
        WHERE donor_no = :dno
        ORDER BY so_id ASC
    """), {"dno": int(donor_no)})
    d["items"] = [dict(r._mapping) for r in so_res]
    return d

@app.get("/api/donors/record")
async def get_single_donor_record_api(donor_no: int, db: AsyncSession = Depends(get_db)):
    donor = await _fetch_single_donor_with_items(db, donor_no)
    if not donor:
        raise HTTPException(status_code=404, detail="Donor not found")
    return {"donor": donor}

@app.get("/api/init-data")
async def get_initial_screen_data(
    filter_mode: str = "ALL",
    search_q: str = "",
    donor_no: Optional[int] = None,
    include_lookups: bool = True,
    db: AsyncSession = Depends(get_db)
):
    banks = []
    charity_items = []
    prefixes = []
    cares = []
    acc_types = []
    towns_map = {}

    if include_lookups:
        banks_res = await db.execute(text("""
            SELECT bank_cd, bank_desc,
                   COALESCE(NULLIF(TRIM(bank_e_desc), ''), bank_desc) AS bank_e_desc,
                   auto_so_based_code, run_deactivate_delayed_so
            FROM lkp_banks
            ORDER BY bank_cd
        """))
        banks = [dict(r._mapping) for r in banks_res]

        items_lkp_res = await db.execute(text("""
            SELECT item_cd, item_desc,
                   COALESCE(NULLIF(TRIM(item_e_desc), ''), item_desc) AS item_e_desc
            FROM lkp_charity_items
            ORDER BY item_cd
        """))
        charity_items = [dict(r._mapping) for r in items_lkp_res]

        prefixes_res = await db.execute(text("""
            SELECT prefix_cd, prefix_name,
                   COALESCE(NULLIF(TRIM(prefix_ename), ''), prefix_name) AS prefix_ename
            FROM lkp_name_prefixes
            ORDER BY prefix_cd
        """))
        prefixes = [dict(r._mapping) for r in prefixes_res]

        cares_res = await db.execute(text("""
            SELECT care_cd, care_nm,
                   COALESCE(NULLIF(TRIM(care_enm), ''), care_nm) AS care_enm
            FROM lkp_cares
            ORDER BY care_cd
        """))
        cares = [dict(r._mapping) for r in cares_res]

        acc_types_res = await db.execute(text("""
            SELECT acc_type_no, acc_type_desc,
                   COALESCE(NULLIF(TRIM(acc_type_e_desc), ''), acc_type_desc) AS acc_type_e_desc
            FROM lkp_acc_types
            ORDER BY acc_type_no
        """))
        acc_types = [dict(r._mapping) for r in acc_types_res]

        towns_res = await db.execute(text("""
            SELECT block_cd, COALESCE(NULLIF(TRIM(etown_nm), ''), town_nm, '') AS town_enm
            FROM lkp_towns
        """))
        towns_map = {str(r.block_cd): r.town_enm for r in towns_res}

    counts_res = await db.execute(text("""
        SELECT
            COUNT(*) AS total_all,
            COUNT(*) FILTER (WHERE COALESCE(ic.active_cnt, 0) > 0) AS total_active,
            COUNT(*) FILTER (WHERE COALESCE(ic.total_cnt, 0) > 0 AND COALESCE(ic.active_cnt, 0) = 0) AS total_inactive,
            COUNT(*) FILTER (WHERE COALESCE(ic.total_cnt, 0) = 0) AS total_no_items,
            COALESCE(MAX(d.donor_no), 0) AS max_donor_no
        FROM donor_master d
        LEFT JOIN (
            SELECT donor_no,
                   COUNT(*) AS total_cnt,
                   COUNT(*) FILTER (WHERE status_no = 1) AS active_cnt
            FROM donor_item
            GROUP BY donor_no
        ) ic ON d.donor_no = ic.donor_no
    """))
    c_row = counts_res.first()
    counts = {
        "ALL": int(c_row.total_all or 0) if c_row else 0,
        "ACTIVE": int(c_row.total_active or 0) if c_row else 0,
        "INACTIVE": int(c_row.total_inactive or 0) if c_row else 0,
        "NO_ITEMS": int(c_row.total_no_items or 0) if c_row else 0,
    }
    max_donor_no = int(c_row.max_donor_no or 0) if c_row else 0

    where_clauses = ["1=1"]
    params: dict[str, Any] = {}
    fm = (filter_mode or "ALL").upper()
    if fm == "ACTIVE":
        where_clauses.append("COALESCE(ic.active_cnt, 0) > 0")
    elif fm == "INACTIVE":
        where_clauses.append("COALESCE(ic.total_cnt, 0) > 0 AND COALESCE(ic.active_cnt, 0) = 0")
    elif fm == "NO_ITEMS":
        where_clauses.append("COALESCE(ic.total_cnt, 0) = 0")

    q_clean = (search_q or "").strip()
    if q_clean:
        params["q"] = f"%{q_clean}%"
        where_clauses.append("""
            (CAST(d.donor_no AS TEXT) ILIKE :q
             OR COALESCE(d.donor_name, '') ILIKE :q
             OR COALESCE(d.donor_ename, '') ILIKE :q
             OR COALESCE(d.donor_cpr, '') ILIKE :q
             OR COALESCE(d.donor_tel1, '') ILIKE :q
             OR COALESCE(d.donor_tel2, '') ILIKE :q
             OR COALESCE(d.donor_mobile, '') ILIKE :q
             OR EXISTS (
                 SELECT 1 FROM donor_item si
                 WHERE si.donor_no = d.donor_no
                   AND (COALESCE(si.sort_field, '') ILIKE :q OR COALESCE(si.donor_acc_no, '') ILIKE :q)
             ))
        """)

    ids_res = await db.execute(text(f"""
        SELECT d.donor_no
        FROM donor_master d
        LEFT JOIN (
            SELECT donor_no,
                   COUNT(*) AS total_cnt,
                   COUNT(*) FILTER (WHERE status_no = 1) AS active_cnt
            FROM donor_item
            GROUP BY donor_no
        ) ic ON d.donor_no = ic.donor_no
        WHERE {' AND '.join(where_clauses)}
        ORDER BY d.donor_no ASC
    """), params)
    donor_nos = [int(r[0]) for r in ids_res.fetchall()]

    target_dno = None
    current_index = 0
    if donor_nos:
        if donor_no and int(donor_no) in donor_nos:
            target_dno = int(donor_no)
            current_index = donor_nos.index(target_dno)
        else:
            target_dno = donor_nos[0]
            current_index = 0

    current_donor = await _fetch_single_donor_with_items(db, target_dno)

    return {
        "banks": banks,
        "charity_items": charity_items,
        "prefixes": prefixes,
        "cares": cares,
        "acc_types": acc_types,
        "towns_map": towns_map,
        "counts": counts,
        "max_donor_no": max_donor_no,
        "donor_nos": donor_nos,
        "current_index": current_index,
        "current_donor": current_donor,
        "donors": [current_donor] if current_donor else []
    }

@app.post("/api/donors/save")
async def save_donor(payload: DonorSaveSchema, db: AsyncSession = Depends(get_db)):
    if not payload.donor_name or payload.donor_name.strip() in ("", "جاري التحميل..."):
        raise HTTPException(status_code=400, detail="لا يمكن حفظ المتبرع بدون اسم صحيح.")
    existing = await db.execute(text("SELECT status_no FROM donor_master WHERE donor_no = :dno"), {"dno": payload.donor_no})
    row = existing.first()

    data = payload.model_dump()
    data["name_prefix"] = int(data["name_prefix"] or 1)
    data["gen_cd"] = int(data["gen_cd"] or 1)
    data["lang_cd"] = int(data["lang_cd"] or 1)
    data["donor_contact"] = int(data["donor_contact"] or 1)
    data["address_type"] = int(data["address_type"] or 1)
    data["bank2_cd"] = int(data["bank2_cd"] or 1)
    data["acc_type_no"] = int(data["acc_type_no"] or 1)
    data["status_no"] = int(data["status_no"] or 1)

    if row is None:
        if not data["donor_no"]:
            max_res = await db.execute(text("SELECT COALESCE(MAX(donor_no), 0) + 1 FROM donor_master"))
            data["donor_no"] = max_res.scalar()

        insert_sql = text("""
            INSERT INTO donor_master (
                donor_no, name_prefix, f_nm, s_nm, t_nm, l_nm, donor_name, donor_ename,
                gen_cd, lang_cd, donor_contact, donor_cpr, care, address_type,
                donor_flat, donor_building, donor_road, donor_block, donor_p_box,
                donor_tel1, donor_tel2, donor_mobile, bank2_cd, acc_type_no,
                donor_acc_no, donor_name_acc, status_no, user_id, append_date
            ) VALUES (
                :donor_no, :name_prefix, :f_nm, :s_nm, :t_nm, :l_nm, :donor_name, :donor_ename,
                :gen_cd, :lang_cd, :donor_contact, :donor_cpr, :care, :address_type,
                :donor_flat, :donor_building, :donor_road, :donor_block, :donor_p_box,
                :donor_tel1, :donor_tel2, :donor_mobile, :bank2_cd, :acc_type_no,
                :donor_acc_no, :donor_name_acc, :status_no, :user_id, CURRENT_DATE
            )
        """)
        await db.execute(insert_sql, data)
    else:
        old_status = row[0]
        update_sql = text("""
            UPDATE donor_master SET
                name_prefix = :name_prefix, f_nm = :f_nm, s_nm = :s_nm, t_nm = :t_nm, l_nm = :l_nm,
                donor_name = :donor_name, donor_ename = :donor_ename, gen_cd = :gen_cd,
                lang_cd = :lang_cd, donor_contact = :donor_contact, donor_cpr = :donor_cpr,
                care = :care, address_type = :address_type, donor_flat = :donor_flat,
                donor_building = :donor_building, donor_road = :donor_road, donor_block = :donor_block,
                donor_p_box = :donor_p_box, donor_tel1 = :donor_tel1, donor_tel2 = :donor_tel2,
                donor_mobile = :donor_mobile, bank2_cd = :bank2_cd, acc_type_no = :acc_type_no,
                donor_acc_no = :donor_acc_no, donor_name_acc = :donor_name_acc,
                status_no = :status_no, last_update = CURRENT_TIMESTAMP
            WHERE donor_no = :donor_no
        """)
        await db.execute(update_sql, data)

        if old_status == 1 and data["status_no"] == 2:
            await db.execute(
                text("INSERT INTO deactivate_donor_trans (donor_no, append_by, reason_notes) VALUES (:dno, :usr, 'إيقاف من الشاشة الرئيسية')"),
                {"dno": data["donor_no"], "usr": data["user_id"]}
            )

    await db.commit()
    return {"status": "success", "donor_no": data["donor_no"]}

@app.post("/api/standing-orders/add")
async def add_standing_order(payload: StandingOrderCreateSchema, db: AsyncSession = Depends(get_db)):
    insert_so = text("""
        INSERT INTO donor_item (
            donor_no, item_no, item_no2, donation_start_date, monthly_pay,
            bank2_cd, donor_acc_no, sort_field, alt_so_code, through_form,
            status_no, userid, append_date
        ) VALUES (
            :donor_no, :item_no, CAST(:item_no AS SMALLINT), :donation_start_date, :monthly_pay,
            :bank2_cd, :donor_acc_no, :sort_field, :alt_so_code, :through_form,
            1, :userid, CURRENT_DATE
        ) RETURNING so_id
    """)
    res = await db.execute(insert_so, payload.model_dump())
    new_so_id = res.scalar()

    retro_sql = text("""
        INSERT INTO money_trans (
            so_id, month_year, donor_no, item_no, region_no,
            donation_start_date, paid_sum, status_no, original_record,
            bank_cd, st_order_no, alt_st_no
        )
        SELECT
            :so_id, gs::date, :donor_no, :item_no, 0,
            :start_date, :monthly_pay, 2, '1',
            :bank2_cd, :sort_field, :alt_so_code
        FROM generate_series(
            DATE_TRUNC('month', CAST(:start_date AS TIMESTAMP)),
            DATE_TRUNC('month', CURRENT_TIMESTAMP),
            INTERVAL '1 month'
        ) AS gs
        ON CONFLICT (so_id, month_year) DO NOTHING
    """)
    await db.execute(retro_sql, {
        "so_id": new_so_id,
        "donor_no": payload.donor_no,
        "item_no": payload.item_no,
        "start_date": payload.donation_start_date,
        "monthly_pay": payload.monthly_pay,
        "bank2_cd": payload.bank2_cd,
        "sort_field": payload.sort_field,
        "alt_so_code": payload.alt_so_code or "0"
    })

    await db.commit()
    return {"status": "success", "so_id": new_so_id}

@app.post("/api/standing-orders/{so_id}/toggle")
async def toggle_so_status(so_id: int, payload: ToggleSoStatusSchema, db: AsyncSession = Depends(get_db)):
    res = await db.execute(text("SELECT donor_no, item_no, donation_start_date, bank2_cd, status_no FROM donor_item WHERE so_id = :so_id"), {"so_id": so_id})
    so = res.first()
    if not so:
        raise HTTPException(status_code=404, detail="الاستقطاع غير موجود")

    donor_no, item_no, start_date, bank_cd, old_status = so
    new_status = 2 if old_status == 1 else 1

    if new_status == 2:
        await db.execute(text("UPDATE donor_item SET status_no = 2, deactive_date = CURRENT_DATE WHERE so_id = :so_id"), {"so_id": so_id})
        await db.execute(
            text("""
                INSERT INTO donor_item_deactiv_hist (so_id, donor_no, item_no, donation_start_date, delay_month, deactive_date, bank_cd, deactive_reason)
                VALUES (:so_id, :donor_no, CAST(:item_no AS SMALLINT), :start_date, 0, CURRENT_DATE, :bank_cd, :reason)
            """),
            {"so_id": so_id, "donor_no": donor_no, "item_no": item_no, "start_date": start_date, "bank_cd": bank_cd, "reason": payload.reason}
        )
    else:
        await db.execute(text("UPDATE donor_item SET status_no = 1, reactive_by = :usr, reactive_date = CURRENT_DATE WHERE so_id = :so_id"), {"so_id": so_id, "usr": payload.userid})

    await db.execute(
        text("""
            INSERT INTO donor_item_actdeact_trns (so_id, donor_no, item_no, start_date, trans_type)
            VALUES (:so_id, :donor_no, CAST(:item_no AS INT), :start_date, :trans_type)
        """),
        {"so_id": so_id, "donor_no": donor_no, "item_no": item_no, "start_date": start_date, "trans_type": new_status}
    )

    await db.commit()
    return {"status": "success", "new_status": new_status}

# ----------------- المرحلة 3: تدقيق أكواد البنوك وتوليد الاستحقاقات الشهرية -----------------

class BankAuditActionSchema(BaseModel):
    bank_cd: int
    month_str: str  # Format: YYYY-MM

class GenerateMonthlySchema(BaseModel):
    month_str: str  # Format: YYYY-MM

@app.get("/bank-codes-audit", response_class=HTMLResponse)
async def bank_codes_audit_screen(request: Request):
    return templates.TemplateResponse("bank_codes_audit.html", {"request": request})

@app.get("/api/bank-codes-audit")
async def get_bank_codes_audit_data(bank_cd: int = 1, month_str: str = "2026-11", db: AsyncSession = Depends(get_db)):
    month_date = datetime.strptime(f"{month_str}-01", "%Y-%m-%d").date()

    banks_res = await db.execute(text("SELECT bank_cd, bank_desc, bank_e_desc FROM lkp_banks ORDER BY bank_cd"))
    banks = [dict(r._mapping) for r in banks_res]

    # 1. جلب قائمة الاستقطاعات (SO List) لهذا البنك
    so_sql = text("""
        SELECT i.so_id, i.donor_no, i.donation_start_date, i.monthly_pay, i.donor_acc_no,
               COALESCE(i.sort_field, '') AS sort_field, COALESCE(i.alt_so_code, '') AS alt_so_code,
               i.status_no,
               COALESCE(NULLIF(TRIM(d.donor_ename), ''), d.donor_name) AS donor_name,
               COALESCE(NULLIF(TRIM(d.donor_ename), ''), d.donor_name) AS donor_ename,
               lp.last_paid_month AS last_payment
        FROM donor_item i
        JOIN donor_master d ON i.donor_no = d.donor_no
        LEFT JOIN so_payment_summary lp ON i.so_id = lp.so_id
        WHERE i.bank2_cd = :bank_cd
        ORDER BY i.donor_no ASC, i.so_id ASC
    """)
    so_res = await db.execute(so_sql, {"bank_cd": bank_cd})
    so_list = []
    so_map = {}
    active_count = 0
    inactive_count = 0
    active_sum = 0.0

    for r in so_res:
        row = dict(r._mapping)
        row["monthly_pay"] = float(row["monthly_pay"])
        row["donation_start_date"] = row["donation_start_date"].strftime("%Y-%m-%d") if row["donation_start_date"] else ""
        row["last_payment"] = row["last_payment"].strftime("%Y-%m-%d") if row["last_payment"] else ""
        if row["status_no"] == 1:
            active_count += 1
            active_sum += row["monthly_pay"]
        else:
            inactive_count += 1
        so_map[row["so_id"]] = row
        so_list.append(row)

    # 2. جلب حركات الشهر المحدد في MONEY_TRANS ومقارنة الأكواد
    trans_sql = text("""
        SELECT m.so_id, m.donor_no, m.donation_start_date, m.month_year, m.paid_sum, m.status_no,
               COALESCE(m.st_order_no, '') AS st_order_no, COALESCE(m.alt_st_no, '') AS alt_st_no,
               COALESCE(NULLIF(TRIM(d.donor_ename), ''), d.donor_name) AS donor_name,
               COALESCE(NULLIF(TRIM(d.donor_ename), ''), d.donor_name) AS donor_ename,
               COALESCE(i.sort_field, '') AS item_sort_field, COALESCE(i.alt_so_code, '') AS item_alt_code
        FROM money_trans m
        JOIN donor_master d ON m.donor_no = d.donor_no
        LEFT JOIN donor_item i ON m.so_id = i.so_id
        WHERE m.bank_cd = :bank_cd AND m.month_year = :month_date
        ORDER BY m.donor_no ASC, m.so_id ASC
    """)
    trans_res = await db.execute(trans_sql, {"bank_cd": bank_cd, "month_date": month_date})
    money_trans_list = []
    trans_so_ids = set()
    match_orig = 0
    unmatch_orig = 0
    match_alt = 0
    unmatch_alt = 0

    for r in trans_res:
        tr = dict(r._mapping)
        tr["paid_sum"] = float(tr["paid_sum"])
        tr["donation_start_date"] = tr["donation_start_date"].strftime("%Y-%m-%d") if tr["donation_start_date"] else ""
        tr["month_year"] = tr["month_year"].strftime("%Y-%m-%d") if tr["month_year"] else ""
        trans_so_ids.add(tr["so_id"])

        orig_ok = (tr["st_order_no"].strip() == tr["item_sort_field"].strip())
        if orig_ok:
            match_orig += 1
        else:
            unmatch_orig += 1

        alt_ok = True
        if tr["item_alt_code"].strip() or tr["alt_st_no"].strip():
            if tr["alt_st_no"].strip() == tr["item_alt_code"].strip():
                match_alt += 1
            else:
                unmatch_alt += 1
                alt_ok = False

        tr["is_code_matched"] = (orig_ok and alt_ok)
        money_trans_list.append(tr)

    # حساب الاستقطاعات النشطة التي بدأت في أو قبل هذا الشهر وليس لها حركة في MONEY_TRANS
    without_trans = sum(
        1 for s in so_list
        if s["status_no"] == 1
        and s["donation_start_date"] <= month_date.strftime("%Y-%m-%d")
        and s["so_id"] not in trans_so_ids
    )

    stats = {
        "so_total_count": len(so_list),
        "so_active_count": active_count,
        "so_inactive_count": inactive_count,
        "so_active_sum": round(active_sum, 3),
        "trans_count": len(money_trans_list),
        "match_orig": match_orig,
        "unmatch_orig": unmatch_orig,
        "match_alt": match_alt,
        "unmatch_alt": unmatch_alt,
        "without_trans": without_trans
    }

    return {"banks": banks, "so_list": so_list, "money_trans_list": money_trans_list, "stats": stats}

@app.post("/api/bank-codes-audit/update-codes")
async def update_bank_codes_and_missing(payload: BankAuditActionSchema, db: AsyncSession = Depends(get_db)):
    """تحديث الأكواد غير المطابقة وإضافة الحركات الناقصة للبنك والشهر المحددين فقط"""
    month_date = datetime.strptime(f"{payload.month_str}-01", "%Y-%m-%d").date()

    # 1. تحديث الأكواد في جدول الحركات لتطابق جدول الاستقطاعات لهذا البنك والشهر
    upd_sql = text("""
        UPDATE money_trans m
        SET st_order_no = COALESCE(i.sort_field, '0'),
            alt_st_no = i.alt_so_code
        FROM donor_item i
        WHERE m.so_id = i.so_id
          AND m.bank_cd = :bank_cd
          AND m.month_year = :month_date
          AND (COALESCE(m.st_order_no, '') <> COALESCE(i.sort_field, '')
               OR COALESCE(m.alt_st_no, '') <> COALESCE(i.alt_so_code, ''))
    """)
    upd_res = await db.execute(upd_sql, {"bank_cd": payload.bank_cd, "month_date": month_date})

    # 2. إدراج حركات للاستقطاعات النشطة التي ليس لها حركة في هذا الشهر والبنك
    ins_sql = text("""
        INSERT INTO money_trans (
            so_id, month_year, donor_no, item_no, region_no,
            donation_start_date, paid_sum, status_no, bank_cd, st_order_no, alt_st_no
        )
        SELECT
            i.so_id, :month_date, i.donor_no, i.item_no, COALESCE(i.region_no, 0),
            i.donation_start_date, i.monthly_pay, 2, i.bank2_cd, COALESCE(i.sort_field, '0'), i.alt_so_code
        FROM donor_item i
        WHERE i.bank2_cd = :bank_cd
          AND i.status_no = 1
          AND i.donation_start_date <= :month_date
          AND NOT EXISTS (
              SELECT 1 FROM money_trans m
              WHERE m.so_id = i.so_id AND m.month_year = :month_date
          )
    """)
    ins_res = await db.execute(ins_sql, {"bank_cd": payload.bank_cd, "month_date": month_date})

    await db.commit()
    return {
        "status": "success",
        "updated_codes": upd_res.rowcount,
        "inserted_missing": ins_res.rowcount
    }

@app.post("/api/money-trans/generate-monthly")
async def generate_monthly_payments_proc(payload: GenerateMonthlySchema, db: AsyncSession = Depends(get_db)):
    """يحاكي الإجراء المخزن Generat_Payments لتوليد استحقاقات الشهر لكافة الاستقطاعات النشطة"""
    month_date = datetime.strptime(f"{payload.month_str}-01", "%Y-%m-%d").date()

    gen_sql = text("""
        INSERT INTO money_trans (
            so_id, month_year, donor_no, item_no, region_no,
            donation_start_date, paid_sum, status_no, bank_cd, st_order_no, alt_st_no
        )
        SELECT
            s.so_id, :month_date, s.donor_no, s.item_no, COALESCE(s.region_no, 0),
            s.donation_start_date, s.monthly_pay, 2, s.bank2_cd, COALESCE(s.sort_field, '0'), s.alt_so_code
        FROM donor_item s
        WHERE s.status_no = 1
          AND s.donation_start_date <= :month_date
          AND NOT EXISTS (
              SELECT 1 FROM money_trans x
              WHERE x.so_id = s.so_id AND x.month_year = :month_date
          )
    """)
    res = await db.execute(gen_sql, {"month_date": month_date})

    await db.execute(text("DELETE FROM last_update_money_trans"))
    await db.execute(text("INSERT INTO last_update_money_trans (last_up) VALUES (CURRENT_DATE)"))
    await db.commit()

    return {"status": "success", "generated_count": res.rowcount}

# ----------------- المرحلة 4: تحميل قوائم البنوك CSV والمطابقة والتحديث وإغلاق الشهر -----------------
import csv
import io
from fastapi import UploadFile, File, Form

class ReconcileActionSchema(BaseModel):
    bank_cd: int
    month_str: str
    close_month: Optional[bool] = True

@app.get("/bank-reconcile", response_class=HTMLResponse)
async def bank_reconcile_screen(request: Request):
    return templates.TemplateResponse("bank_statement_reconcile.html", {"request": request})

async def _process_and_insert_statement_rows(db: AsyncSession, bank_cd: int, month_date: date, raw_rows: list[dict], user_nm: str = "TAREK"):
    """ينفذ منطق التريجر MANIPULATE_DATA بدقة: يميز النقدي/فوري عن الاستقطاع ويطابق بالكود الأصلي أو البديل"""
    bank_res = await db.execute(
        text("SELECT auto_so_based_code, COALESCE(fawri_keywords, 'FAWRI,CASH,BENEFIT') FROM lkp_banks WHERE bank_cd = :b"),
        {"b": bank_cd}
    )
    b_row = bank_res.first()
    based_code = b_row[0] if b_row else 1
    keywords = [k.strip().upper() for k in (b_row[1] if b_row else "FAWRI,CASH").split(",") if k.strip()]

    for r in raw_rows:
        pay_date_str = str(r.get("date", month_date.strftime("%d/%m/%Y"))).strip()
        desc = str(r.get("desc", "")).strip()
        amt = float(r.get("amt", 0.0))
        upper_desc = desc.upper()

        is_cash = any(kw in upper_desc for kw in keywords)
        cash_deposit = 1 if is_cash else 2
        st_order_no = None if is_cash else desc

        sys_found = 0
        sys_amt = None
        donor_no = None
        item_no = None
        start_date = None
        so_id = None
        money_trans_found = 0

        if st_order_no:
            if based_code == 1:
                so_q = text("""
                    SELECT donor_no, item_no, donation_start_date, monthly_pay, so_id
                    FROM donor_item
                    WHERE UPPER(TRIM(sort_field)) = UPPER(TRIM(:code))
                      AND bank2_cd = :bank_cd AND status_no = 1
                """)
            else:
                so_q = text("""
                    SELECT donor_no, item_no, donation_start_date, monthly_pay, so_id
                    FROM donor_item
                    WHERE UPPER(TRIM(alt_so_code)) = UPPER(TRIM(:code))
                      AND bank2_cd = :bank_cd AND status_no = 1
                """)

            so_matches = (await db.execute(so_q, {"code": st_order_no, "bank_cd": bank_cd})).fetchall()
            sys_found = len(so_matches)

            if sys_found == 1:
                m = so_matches[0]
                donor_no = m[0]
                item_no = int(m[1]) if str(m[1]).isdigit() else 1
                start_date = m[2]
                sys_amt = float(m[3])
                so_id = m[4]

                if based_code == 1:
                    tr_q = text("""
                        SELECT COUNT(*) FROM money_trans
                        WHERE so_id = :so_id AND bank_cd = :bank_cd AND month_year = :m_date
                          AND UPPER(TRIM(st_order_no)) = UPPER(TRIM(:code))
                    """)
                else:
                    tr_q = text("""
                        SELECT COUNT(*) FROM money_trans
                        WHERE so_id = :so_id AND bank_cd = :bank_cd AND month_year = :m_date
                          AND UPPER(TRIM(alt_st_no)) = UPPER(TRIM(:code))
                    """)
                money_trans_found = (await db.execute(tr_q, {"so_id": so_id, "bank_cd": bank_cd, "m_date": month_date, "code": st_order_no})).scalar() or 0

        ins_q = text("""
            INSERT INTO bank_statement_load (
                bank_cd, money_trans_month, bank_stmnt_month, bank_stmnt_paydesc,
                bank_stmnt_payamt, cash_deposit, st_order_no, sys_found, sys_amt,
                money_trans_found, money_trans_status, so_id, donor_no, item_no,
                donation_start_date, user_nm
            ) VALUES (
                :bank_cd, :m_date, :p_date, :desc,
                :amt, :cash_deposit, :st_order_no, :sys_found, :sys_amt,
                :mt_found, 2, :so_id, :donor_no, :item_no,
                :start_date, :user_nm
            )
        """)
        await db.execute(ins_q, {
            "bank_cd": bank_cd, "m_date": month_date, "p_date": pay_date_str, "desc": desc,
            "amt": amt, "cash_deposit": cash_deposit, "st_order_no": st_order_no,
            "sys_found": sys_found, "sys_amt": sys_amt, "mt_found": money_trans_found,
            "so_id": so_id, "donor_no": donor_no, "item_no": item_no,
            "start_date": start_date, "user_nm": user_nm
        })

    await db.execute(text("DELETE FROM last_bank_statement"))
    await db.execute(text("INSERT INTO last_bank_statement (bank_cd, month_year) VALUES (:b, :m)"), {"b": bank_cd, "m": month_date})

@app.get("/api/bank-reconcile/data")
async def get_bank_reconcile_data(bank_cd: int = 1, month_str: str = "2026-11", db: AsyncSession = Depends(get_db)):
    month_date = datetime.strptime(f"{month_str}-01", "%Y-%m-%d").date()

    banks_res = await db.execute(text("SELECT bank_cd, bank_desc, bank_e_desc FROM lkp_banks ORDER BY bank_cd"))
    banks = [dict(r._mapping) for r in banks_res]

    closed_res = await db.execute(
        text("SELECT 1 FROM bankmonthly_stmntupd WHERE bank_cd = :b AND month_year = :m"),
        {"b": bank_cd, "m": month_date}
    )
    is_closed = closed_res.first() is not None

    rows_res = await db.execute(text("""
        SELECT l.*,
               COALESCE(NULLIF(TRIM(d.donor_ename), ''), d.donor_name) AS donor_name,
               COALESCE(NULLIF(TRIM(d.donor_ename), ''), d.donor_name) AS donor_ename
        FROM bank_statement_load l
        LEFT JOIN donor_master d ON l.donor_no = d.donor_no
        WHERE l.bank_cd = :b AND l.money_trans_month = :m
        ORDER BY l.trans_id ASC
    """), {"b": bank_cd, "m": month_date})

    rows = []
    code_counts = {}
    for r in rows_res:
        item = dict(r._mapping)
        item["bank_stmnt_payamt"] = float(item["bank_stmnt_payamt"] or 0)
        item["sys_amt"] = float(item["sys_amt"]) if item["sys_amt"] is not None else None
        item["money_trans_month"] = item["money_trans_month"].strftime("%Y-%m-%d") if item["money_trans_month"] else ""
        item["donation_start_date"] = item["donation_start_date"].strftime("%Y-%m-%d") if item["donation_start_date"] else ""
        item["time_stamp"] = item["time_stamp"].strftime("%Y-%m-%d") if item["time_stamp"] else ""
        if item["cash_deposit"] == 2 and item["st_order_no"]:
            code_counts[item["st_order_no"]] = code_counts.get(item["st_order_no"], 0) + 1
        rows.append(item)

    # حساب مؤشرات ونتائج المطابقة
    so_rows = [r for r in rows if r["cash_deposit"] == 2]
    cash_rows = [r for r in rows if r["cash_deposit"] != 2]

    so_in_bank = len(so_rows)
    so_in_sys = sum(1 for r in so_rows if r["sys_found"] == 1)
    not_in_sys = sum(1 for r in so_rows if r["sys_found"] == 0)
    in_money_trans = sum(1 for r in so_rows if r["sys_found"] == 1 and r["money_trans_found"] == 1)
    matched_no_trans = sum(1 for r in so_rows if r["sys_found"] == 1 and r["money_trans_found"] == 0)
    duplicated_in_bank = sum(1 for r in so_rows if code_counts.get(r["st_order_no"], 0) > 1)
    cannot_update = not_in_sys + matched_no_trans + duplicated_in_bank
    updated_count = sum(1 for r in so_rows if r["money_trans_status"] == 1)

    sum_so_amt = round(sum(r["bank_stmnt_payamt"] for r in so_rows), 3)
    sum_cash_amt = round(sum(r["bank_stmnt_payamt"] for r in cash_rows), 3)
    sum_dup_amt = round(sum(r["bank_stmnt_payamt"] for r in so_rows if code_counts.get(r["st_order_no"], 0) > 1), 3)
    total_loaded_amt = round(sum_so_amt + sum_cash_amt, 3)
    potential_pct = round((in_money_trans / so_in_bank * 100), 1) if so_in_bank > 0 else 0.0

    indicators = {
        "so_in_bank": so_in_bank,
        "so_in_sys": so_in_sys,
        "not_in_sys": not_in_sys,
        "duplicated_in_bank": duplicated_in_bank,
        "cannot_update": cannot_update,
        "unknown_count": not_in_sys,
        "in_money_trans": in_money_trans,
        "matched_no_trans": matched_no_trans,
        "sum_so_amt": sum_so_amt,
        "sum_cash_amt": sum_cash_amt,
        "sum_dup_amt": sum_dup_amt,
        "total_loaded_amt": total_loaded_amt,
        "potential_update_pct": potential_pct,
        "updated_count": updated_count
    }

    return {"banks": banks, "is_closed": is_closed, "rows": rows, "indicators": indicators}

@app.post("/api/bank-reconcile/upload-csv")
async def upload_bank_csv(
    bank_cd: int = Form(...),
    month_str: str = Form(...),
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db)
):
    month_date = datetime.strptime(f"{month_str}-01", "%Y-%m-%d").date()
    content = (await file.read()).decode("utf-8-sig", errors="ignore")
    reader = csv.reader(io.StringIO(content))

    raw_rows = []
    for line in reader:
        if not line or len(line) < 2:
            continue
        # يتخطى سطر العناوين إن وجد
        if "DATE" in line[0].upper() or "تاريخ" in line[0] or "DESC" in line[1].upper():
            continue
        if len(line) >= 3:
            p_date, desc, amt_str = line[0], line[1], line[2]
        else:
            p_date, desc, amt_str = month_date.strftime("17/%m/%Y"), line[0], line[1]
        try:
            amt = float(str(amt_str).replace(",", "").strip())
        except ValueError:
            continue
        raw_rows.append({"date": p_date, "desc": desc, "amt": amt})

    await _process_and_insert_statement_rows(db, bank_cd, month_date, raw_rows)
    await db.commit()
    return {"status": "success", "loaded_count": len(raw_rows)}

@app.post("/api/bank-reconcile/load-sample")
async def load_sample_statement_for_testing(payload: ReconcileActionSchema, db: AsyncSession = Depends(get_db)):
    """يولد كشف حساب تجريبي من الاستقطاعات النشطة للبنك المحدد + حركة FAWRI لتجربة المطابقة فوراً"""
    month_date = datetime.strptime(f"{payload.month_str}-01", "%Y-%m-%d").date()

    # نتأكد أولاً من وجود حركات الشهر في MONEY_TRANS
    await update_bank_codes_and_missing(BankAuditActionSchema(bank_cd=payload.bank_cd, month_str=payload.month_str), db)

    bank_res = await db.execute(text("SELECT auto_so_based_code FROM lkp_banks WHERE bank_cd = :b"), {"b": payload.bank_cd})
    based_code = bank_res.scalar() or 1

    so_res = await db.execute(text("""
        SELECT sort_field, alt_so_code, monthly_pay
        FROM donor_item
        WHERE bank2_cd = :b AND status_no = 1
    """), {"b": payload.bank_cd})

    raw_rows = []
    for r in so_res:
        code = r[0] if based_code == 1 else (r[1] or r[0])
        if code:
            raw_rows.append({
                "date": month_date.strftime("17/%m/%Y"),
                "desc": str(code).strip(),
                "amt": float(r[2])
            })

    # إضافة إيداع فوري مباشر (FAWRI) لاختبار فرز النقدي عن الاستقطاعات
    raw_rows.append({
        "date": month_date.strftime("18/%m/%Y"),
        "desc": "FAWRI+ DIRECT CHARITY TRANSFER",
        "amt": 25.000
    })

    await _process_and_insert_statement_rows(db, payload.bank_cd, month_date, raw_rows)
    await db.commit()
    return {"status": "success", "loaded_count": len(raw_rows)}

@app.post("/api/bank-reconcile/confirm-update")
async def confirm_reconcile_update(payload: ReconcileActionSchema, db: AsyncSession = Depends(get_db)):
    """يحول حالة الأقساط المطابقة في MONEY_TRANS إلى مسدد (1) ويسجل رقم حركة الكشف والمستخدم"""
    month_date = datetime.strptime(f"{payload.month_str}-01", "%Y-%m-%d").date()

    upd_money_trans = text("""
        UPDATE money_trans m
        SET status_no = 1,
            bank_statmnt_transid = l.trans_id,
            bank_statmnt_transdate = CURRENT_TIMESTAMP,
            bank_statmnt_trnauser = 'TAREK'
        FROM bank_statement_load l
        WHERE l.bank_cd = :b
          AND l.money_trans_month = :m
          AND l.cash_deposit = 2
          AND l.sys_found = 1
          AND l.money_trans_found = 1
          AND m.so_id = l.so_id
          AND m.month_year = l.money_trans_month
          AND m.bank_cd = l.bank_cd
    """)
    res = await db.execute(upd_money_trans, {"b": payload.bank_cd, "m": month_date})

    await db.execute(text("""
        UPDATE bank_statement_load
        SET money_trans_status = 1
        WHERE bank_cd = :b AND money_trans_month = :m
          AND cash_deposit = 2 AND sys_found = 1 AND money_trans_found = 1
    """), {"b": payload.bank_cd, "m": month_date})

    await db.commit()
    return {"status": "success", "updated_count": res.rowcount}

@app.post("/api/bank-reconcile/delete-statement")
async def delete_loaded_statement(payload: ReconcileActionSchema, db: AsyncSession = Depends(get_db)):
    """يحذف القائمة المحملة ويقوم التريجر trg_rollback_money_trans_on_delete بإرجاع الحركات إلى غير مسدد تلقائياً"""
    month_date = datetime.strptime(f"{payload.month_str}-01", "%Y-%m-%d").date()
    await db.execute(
        text("DELETE FROM bank_statement_load WHERE bank_cd = :b AND money_trans_month = :m"),
        {"b": payload.bank_cd, "m": month_date}
    )
    await db.commit()
    return {"status": "success"}

@app.post("/api/bank-reconcile/toggle-lock")
async def toggle_month_lock_status(payload: ReconcileActionSchema, db: AsyncSession = Depends(get_db)):
    """إغلاق الشهر في جدول BANKMONTHLY_STMNTUPD أو إعادة فتحه"""
    month_date = datetime.strptime(f"{payload.month_str}-01", "%Y-%m-%d").date()
    if payload.close_month:
        sum_res = await db.execute(
            text("SELECT COALESCE(SUM(bank_stmnt_payamt), 0) FROM bank_statement_load WHERE bank_cd = :b AND money_trans_month = :m"),
            {"b": payload.bank_cd, "m": month_date}
        )
        total_amt = sum_res.scalar() or 0
        await db.execute(text("""
            INSERT INTO bankmonthly_stmntupd (bank_cd, month_year, updated_by, update_date, updated_amt)
            VALUES (:b, :m, 'TAREK', CURRENT_TIMESTAMP, :amt)
            ON CONFLICT (bank_cd, month_year) DO NOTHING
        """), {"b": payload.bank_cd, "m": month_date, "amt": total_amt})
    else:
        await db.execute(
            text("DELETE FROM bankmonthly_stmntupd WHERE bank_cd = :b AND month_year = :m"),
            {"b": payload.bank_cd, "m": month_date}
        )
    await db.commit()
    return {"status": "success"}

# ----------------- المرحلة 5: شاشة متابعة الاستقطاعات المتأخرة وتصدير كشف المتابعة -----------------
from fastapi.responses import StreamingResponse

class FollowupCreateSchema(BaseModel):
    donor_no: int
    call_date: date
    call_time: Optional[str] = ""
    contact_method: int = 1
    call_result_cd: int
    delay_reason_cd: int = 1
    call_result_notes: Optional[str] = ""

class ItemFollowupCreateSchema(BaseModel):
    so_id: int
    donor_no: int
    item_no: Optional[str] = "1"
    donation_start_date: Optional[str] = None
    call_date: date
    call_time: Optional[str] = ""
    call_result_cd: int
    delay_reason_cd: int = 1
    call_result_notes: Optional[str] = ""
    delayed_months: Optional[int] = 0
    last_paid_month: Optional[str] = None

class FollowupContactUpdateSchema(BaseModel):
    donor_no: int
    address_type: Optional[int] = 1
    donor_flat: Optional[Any] = None
    donor_building: Optional[str] = ""
    donor_road: Optional[str] = ""
    donor_block: Optional[Any] = None
    donor_p_box: Optional[Any] = None
    donor_tel1: Optional[str] = ""
    donor_tel2: Optional[str] = ""
    donor_mobile: Optional[str] = ""

@app.get("/followup", response_class=HTMLResponse)
async def donor_followup_screen(request: Request):
    return templates.TemplateResponse("donor_followup.html", {"request": request})

async def _fetch_single_followup_donor(db: AsyncSession, donor_no: Optional[int]) -> Optional[dict]:
    if not donor_no:
        return None
    d_res = await db.execute(text("""
        SELECT d.donor_no,
               COALESCE(NULLIF(TRIM(d.donor_ename), ''), d.donor_name) AS donor_ename,
               COALESCE(NULLIF(TRIM(d.donor_ename), ''), d.donor_name) AS donor_name,
               COALESCE(d.donor_cpr, '') AS donor_cpr,
               COALESCE(d.gen_cd, 1) AS gen_cd,
               COALESCE(d.status_no, 1) AS status_no,
               COALESCE(d.address_type, 1) AS address_type,
               d.donor_flat,
               COALESCE(d.donor_building, '') AS donor_building,
               COALESCE(d.donor_road, '') AS donor_road,
               d.donor_block,
               d.donor_p_box,
               COALESCE(d.donor_tel1, '') AS donor_tel1,
               COALESCE(d.donor_tel2, '') AS donor_tel2,
               COALESCE(d.donor_mobile, '') AS donor_mobile,
               COALESCE(NULLIF(TRIM(t.etown_nm), ''), t.town_nm, '') AS town_name
        FROM donor_master d
        LEFT JOIN lkp_towns t ON d.donor_block = t.block_cd
        WHERE d.donor_no = :dno
    """), {"dno": int(donor_no)})
    d_row = d_res.first()
    if not d_row:
        return None
    d = dict(d_row._mapping)

    so_res = await db.execute(text("""
        SELECT so_id,
               donor_no,
               item_no,
               item_desc,
               COALESCE(NULLIF(TRIM(item_e_desc), ''), item_desc) AS item_e_desc,
               COALESCE(TO_CHAR(donation_start_date, 'YYYY-MM-DD'), '') AS donation_start_date,
               COALESCE(TO_CHAR(donation_expected_edate, 'YYYY-MM-DD'), '') AS donation_expected_edate,
               monthly_pay::float8 AS monthly_pay,
               bank2_cd,
               COALESCE(NULLIF(TRIM(bank_e_desc), ''), bank_desc) AS bank_e_desc,
               COALESCE(NULLIF(TRIM(bank_e_desc), ''), bank_desc) AS bank_desc,
               COALESCE(donor_acc_no, '') AS donor_acc_no,
               COALESCE(sort_field, '') AS sort_field,
               COALESCE(alt_so_code, '') AS alt_so_code,
               (through_form = 1) AS through_form,
               status_no,
               COALESCE(TO_CHAR(last_paid_month, 'YYYY-MM-DD'), '') AS last_paid_month,
               actual_delay_months,
               actual_delay_months AS delay_months,
               virtual_delay_months,
               payment_notes,
               last_followup_summary
        FROM vw_standing_orders_summary
        WHERE donor_no = :dno
        ORDER BY so_id ASC
    """), {"dno": int(donor_no)})
    items = [dict(r._mapping) for r in so_res]

    f_res = await db.execute(text("""
        SELECT f.trans_id,
               f.donor_no,
               COALESCE(TO_CHAR(f.call_date, 'YYYY-MM-DD'), '') AS call_date,
               COALESCE(f.call_time, '') AS call_time,
               COALESCE(f.call_by, '') AS call_by,
               f.call_result_cd,
               f.delay_reason_cd,
               COALESCE(f.contact_method, 1) AS contact_method,
               COALESCE(f.call_result_notes, '') AS call_result_notes,
               COALESCE(TO_CHAR(f.append_date, 'YYYY-MM-DD'), '') AS append_date,
               COALESCE(NULLIF(TRIM(r.result_enm), ''), r.result_nm, '') AS result_nm,
               COALESCE(NULLIF(TRIM(r.result_enm), ''), r.result_nm, '') AS result_enm,
               COALESCE(NULLIF(TRIM(dr.reason_enm), ''), dr.reason_nm, 'Unspecified') AS reason_nm,
               COALESCE(NULLIF(TRIM(dr.reason_enm), ''), dr.reason_nm, 'Unspecified') AS reason_enm,
               CASE f.contact_method
                   WHEN 1 THEN 'Phone Call'
                   WHEN 2 THEN 'SMS / WhatsApp'
                   WHEN 3 THEN 'Email'
                   ELSE 'Phone Call'
               END AS contact_method_nm
        FROM donor_followup f
        LEFT JOIN lkp_follow_results r ON f.call_result_cd = r.result_cd
        LEFT JOIN lkp_delay_reasons dr ON f.delay_reason_cd = dr.reason_cd
        WHERE f.donor_no = :dno
        ORDER BY f.call_date DESC, f.trans_id DESC
    """), {"dno": int(donor_no)})
    followups = [dict(r._mapping) for r in f_res]

    item_f_res = await db.execute(text("""
        SELECT f.trans_id,
               f.so_id,
               f.donor_no,
               COALESCE(f.item_no, '') AS item_no,
               COALESCE(TO_CHAR(f.donation_start_date, 'YYYY-MM-DD'), '') AS donation_start_date,
               COALESCE(TO_CHAR(f.call_date, 'YYYY-MM-DD'), '') AS call_date,
               COALESCE(f.call_time, '') AS call_time,
               COALESCE(f.call_by, '') AS call_by,
               f.call_result_cd,
               f.delay_reason_cd,
               COALESCE(f.call_result_notes, '') AS call_result_notes,
               COALESCE(f.delayed_months, 0) AS delayed_months,
               COALESCE(TO_CHAR(f.last_paid_month, 'YYYY-MM-DD'), '') AS last_paid_month,
               COALESCE(NULLIF(TRIM(r.result_enm), ''), r.result_nm, '') AS result_nm,
               COALESCE(NULLIF(TRIM(r.result_enm), ''), r.result_nm, '') AS result_enm,
               COALESCE(NULLIF(TRIM(d.reason_enm), ''), d.reason_nm, '') AS reason_nm,
               COALESCE(NULLIF(TRIM(d.reason_enm), ''), d.reason_nm, '') AS reason_enm
        FROM donor_item_followup f
        LEFT JOIN lkp_follow_results r ON f.call_result_cd = r.result_cd
        LEFT JOIN lkp_delay_reasons d ON f.delay_reason_cd = d.reason_cd
        WHERE f.donor_no = :dno
        ORDER BY f.call_date DESC, f.trans_id DESC
    """), {"dno": int(donor_no)})
    item_followups = [dict(r._mapping) for r in item_f_res]

    d["items"] = items
    d["followups"] = followups
    d["old_item_followups"] = item_followups
    d["max_delay"] = max((i["delay_months"] for i in items), default=0)
    return d

@app.get("/api/followup/record")
async def get_single_followup_record_api(donor_no: int, db: AsyncSession = Depends(get_db)):
    donor = await _fetch_single_followup_donor(db, donor_no)
    if not donor:
        raise HTTPException(status_code=404, detail="Donor not found")
    return {
        "donor": donor,
        "all_item_followups": donor.get("old_item_followups", [])
    }

@app.get("/api/followup/data")
async def get_followup_screen_data(
    filter_mode: str = "ALL",
    search_q: str = "",
    donor_no: Optional[int] = None,
    include_lookups: bool = True,
    db: AsyncSession = Depends(get_db)
):
    follow_results = []
    delay_reasons = []
    towns_map = {}

    if include_lookups:
        res_lkp = await db.execute(text("""
            SELECT result_cd,
                   COALESCE(NULLIF(TRIM(result_enm), ''), result_nm) AS result_enm,
                   COALESCE(NULLIF(TRIM(result_enm), ''), result_nm) AS result_nm
            FROM lkp_follow_results
            ORDER BY result_cd
        """))
        follow_results = [dict(r._mapping) for r in res_lkp]

        reason_lkp = await db.execute(text("""
            SELECT reason_cd,
                   COALESCE(NULLIF(TRIM(reason_enm), ''), reason_nm) AS reason_enm,
                   COALESCE(NULLIF(TRIM(reason_enm), ''), reason_nm) AS reason_nm
            FROM lkp_delay_reasons
            ORDER BY reason_cd
        """))
        delay_reasons = [dict(r._mapping) for r in reason_lkp]

        towns_res = await db.execute(text("""
            SELECT block_cd, COALESCE(NULLIF(TRIM(etown_nm), ''), town_nm, '') AS town_enm
            FROM lkp_towns
        """))
        towns_map = {str(r.block_cd): r.town_enm for r in towns_res}

    delay_cte = """
        WITH donor_delays AS (
            SELECT i.donor_no,
                   MAX(GREATEST(0, (
                       EXTRACT(YEAR FROM AGE(
                           DATE_TRUNC('month', CASE WHEN i.status_no = 2 AND i.deactive_date IS NOT NULL THEN i.deactive_date ELSE CURRENT_DATE END),
                           DATE_TRUNC('month', COALESCE(lp.last_paid_month, i.donation_start_date))
                       )) * 12 +
                       EXTRACT(MONTH FROM AGE(
                           DATE_TRUNC('month', CASE WHEN i.status_no = 2 AND i.deactive_date IS NOT NULL THEN i.deactive_date ELSE CURRENT_DATE END),
                           DATE_TRUNC('month', COALESCE(lp.last_paid_month, i.donation_start_date))
                       ))
                   )::int)) AS max_delay
            FROM donor_item i
            LEFT JOIN so_payment_summary lp ON i.so_id = lp.so_id
            GROUP BY i.donor_no
        )
    """

    counts_res = await db.execute(text(f"""
        {delay_cte}
        SELECT
            COUNT(*) AS total_all,
            COUNT(*) FILTER (WHERE COALESCE(dd.max_delay, 0) > 2) AS total_delayed,
            COUNT(*) FILTER (WHERE COALESCE(d.status_no, 1) = 2) AS total_inactive
        FROM donor_master d
        LEFT JOIN donor_delays dd ON d.donor_no = dd.donor_no
    """))
    c_row = counts_res.first()
    counts = {
        "ALL": int(c_row.total_all or 0) if c_row else 0,
        "DELAYED": int(c_row.total_delayed or 0) if c_row else 0,
        "INACTIVE": int(c_row.total_inactive or 0) if c_row else 0
    }

    where_clauses = ["1=1"]
    params: dict[str, Any] = {}
    fm = (filter_mode or "ALL").upper()
    if fm == "DELAYED":
        where_clauses.append("COALESCE(dd.max_delay, 0) > 2")
    elif fm == "INACTIVE":
        where_clauses.append("COALESCE(d.status_no, 1) = 2")

    q_clean = (search_q or "").strip()
    if q_clean:
        params["q"] = f"%{q_clean}%"
        where_clauses.append("""
            (CAST(d.donor_no AS TEXT) ILIKE :q
             OR COALESCE(d.donor_name, '') ILIKE :q
             OR COALESCE(d.donor_ename, '') ILIKE :q
             OR COALESCE(d.donor_cpr, '') ILIKE :q
             OR COALESCE(d.donor_tel1, '') ILIKE :q
             OR COALESCE(d.donor_tel2, '') ILIKE :q
             OR COALESCE(d.donor_mobile, '') ILIKE :q)
        """)

    ids_res = await db.execute(text(f"""
        {delay_cte}
        SELECT d.donor_no
        FROM donor_master d
        LEFT JOIN donor_delays dd ON d.donor_no = dd.donor_no
        WHERE {' AND '.join(where_clauses)}
        ORDER BY d.donor_no ASC
    """), params)
    donor_nos = [int(r[0]) for r in ids_res.fetchall()]

    target_dno = None
    current_index = 0
    if donor_nos:
        if donor_no and int(donor_no) in donor_nos:
            target_dno = int(donor_no)
            current_index = donor_nos.index(target_dno)
        else:
            target_dno = donor_nos[0]
            current_index = 0

    current_donor = await _fetch_single_followup_donor(db, target_dno)

    return {
        "donors": [current_donor] if current_donor else [],
        "current_donor": current_donor,
        "donor_nos": donor_nos,
        "current_index": current_index,
        "counts": counts,
        "all_item_followups": current_donor.get("old_item_followups", []) if current_donor else [],
        "follow_results": follow_results,
        "delay_reasons": delay_reasons,
        "towns_map": towns_map
    }

@app.post("/api/followup/add")
async def add_donor_followup(payload: FollowupCreateSchema, request: Request, db: AsyncSession = Depends(get_db)):
    current_logged_in_employee = (request.state.user or {}).get("username") or "HASAN"
    sql = text("""
        INSERT INTO donor_followup (
            donor_no, call_date, call_time, call_by, contact_method,
            call_result_cd, delay_reason_cd, call_result_notes
        ) VALUES (
            :donor_no, :call_date, :call_time, :call_by, :contact_method,
            :call_result_cd, :delay_reason_cd, :call_result_notes
        )
    """)
    data = payload.model_dump()
    data["call_by"] = current_logged_in_employee
    await db.execute(sql, data)
    await db.execute(text("UPDATE donor_master SET call_date = :cdate WHERE donor_no = :dno"), {"cdate": payload.call_date, "dno": payload.donor_no})
    await db.commit()
    return {"status": "success"}

@app.post("/api/followup/item/add")
async def add_item_followup(payload: ItemFollowupCreateSchema, request: Request, db: AsyncSession = Depends(get_db)):
    current_logged_in_employee = (request.state.user or {}).get("username") or "HASAN"
    start_dt = datetime.strptime(payload.donation_start_date[:10], "%Y-%m-%d").date() if payload.donation_start_date else payload.call_date
    last_paid_dt = datetime.strptime(payload.last_paid_month[:10], "%Y-%m-%d").date() if payload.last_paid_month else start_dt
    sql = text("""
        INSERT INTO donor_item_followup (
            so_id, donor_no, item_no, donation_start_date, call_date, call_time,
            call_by, call_result_cd, delay_reason_cd, call_result_notes,
            delayed_months, last_paid_month
        ) VALUES (
            :so_id, :donor_no, :item_no, :start_dt, :call_date, :call_time,
            :call_by, :call_result_cd, :delay_reason_cd, :call_result_notes,
            :delayed_months, :last_paid_dt
        )
    """)
    await db.execute(sql, {
        "so_id": payload.so_id,
        "donor_no": payload.donor_no,
        "item_no": str(payload.item_no or "1"),
        "start_dt": start_dt,
        "call_date": payload.call_date,
        "call_time": payload.call_time or "",
        "call_by": current_logged_in_employee,
        "call_result_cd": payload.call_result_cd,
        "delay_reason_cd": payload.delay_reason_cd,
        "call_result_notes": payload.call_result_notes or "",
        "delayed_months": int(payload.delayed_months or 0),
        "last_paid_dt": last_paid_dt
    })
    await db.commit()
    return {"status": "success"}

@app.post("/api/followup/update-contact")
async def update_donor_contact_from_followup(payload: FollowupContactUpdateSchema, db: AsyncSession = Depends(get_db)):
    def _to_int_or_none(val):
        if val is None or str(val).strip() == "":
            return None
        try:
            return int(str(val).strip())
        except ValueError:
            return None

    await db.execute(text("""
        UPDATE donor_master
        SET address_type = :address_type,
            donor_flat = :donor_flat,
            donor_building = :donor_building,
            donor_road = :donor_road,
            donor_block = :donor_block,
            donor_p_box = :donor_p_box,
            donor_tel1 = :donor_tel1,
            donor_tel2 = :donor_tel2,
            donor_mobile = :donor_mobile,
            last_update = CURRENT_TIMESTAMP
        WHERE donor_no = :donor_no
    """), {
        "donor_no": payload.donor_no,
        "address_type": int(payload.address_type or 1),
        "donor_flat": _to_int_or_none(payload.donor_flat),
        "donor_building": payload.donor_building or "",
        "donor_road": payload.donor_road or "",
        "donor_block": _to_int_or_none(payload.donor_block),
        "donor_p_box": _to_int_or_none(payload.donor_p_box),
        "donor_tel1": payload.donor_tel1 or "",
        "donor_tel2": payload.donor_tel2 or "",
        "donor_mobile": payload.donor_mobile or ""
    })
    await db.commit()
    return {"status": "success"}

@app.get("/api/followup/export-csv")
async def export_followup_excel_csv(db: AsyncSession = Depends(get_db)):
    """Export comprehensive follow-up report from vw_standing_orders_summary in English"""
    query = text("""
        SELECT donor_no,
               COALESCE(NULLIF(TRIM(donor_ename), ''), donor_name) AS donor_ename,
               donor_tel1, donor_tel2, donor_mobile,
               so_id,
               COALESCE(NULLIF(TRIM(bank_e_desc), ''), bank_desc) AS bank_e_desc,
               monthly_pay,
               CASE WHEN status_no = 1 THEN 'Active' ELSE 'Inactive' END AS so_status,
               last_paid_month,
               actual_delay_months,
               virtual_delay_months,
               payment_notes,
               donor_total_so_count,
               donor_active_so_count,
               last_followup_summary
        FROM vw_standing_orders_summary
        ORDER BY virtual_delay_months DESC, donor_no ASC
    """)
    res = await db.execute(query)

    output = io.StringIO()
    output.write('\ufeff')
    writer = csv.writer(output)
    writer.writerow([
        "Donor No", "Donor Name", "Phone 1", "Mobile 1", "Mobile 2",
        "SO ID", "Bank", "Monthly Amount (BHD)", "SO Status",
        "Last Paid Month", "Actual Delay Months", "Virtual Delay Months",
        "Payment Notes", "Donor Total SOs", "Donor Active SOs", "Last Follow-up Summary"
    ])
    for r in res:
        writer.writerow([
            r.donor_no, r.donor_ename, r.donor_tel1 or "", r.donor_tel2 or "", r.donor_mobile or "",
            r.so_id, r.bank_e_desc or "", float(r.monthly_pay), r.so_status,
            r.last_paid_month.strftime("%Y-%m-%d") if r.last_paid_month else "Never Paid",
            r.actual_delay_months, r.virtual_delay_months, r.payment_notes or "",
            r.donor_total_so_count, r.donor_active_so_count, r.last_followup_summary
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=donor_followup_report.csv"}
    )

@app.get("/item-followup-test", response_class=HTMLResponse)
async def item_followup_test_page(request: Request):
    return templates.TemplateResponse("item_followup_test.html", {"request": request})

@app.get("/api/item-followup-test/data")
async def item_followup_test_api(db: AsyncSession = Depends(get_db)):
    res = await db.execute(text("""
        SELECT f.trans_id, f.so_id, f.donor_no, f.item_no,
               TO_CHAR(f.call_date, 'YYYY-MM-DD') AS call_date,
               f.call_time, f.call_by, f.call_result_notes,
               r.result_nm, d.reason_nm
        FROM donor_item_followup f
        LEFT JOIN lkp_follow_results r ON f.call_result_cd = r.result_cd
        LEFT JOIN lkp_delay_reasons d ON f.delay_reason_cd = d.reason_cd
        ORDER BY f.trans_id ASC
    """))
    rows = [dict(r._mapping) for r in res]
    return {"followups": rows}

@app.get("/api/item-followup-test/full-data")
async def item_followup_test_full_api(db: AsyncSession = Depends(get_db)):
    items_res = await db.execute(text("SELECT so_id, donor_no, item_no, monthly_pay, TO_CHAR(donation_start_date, 'YYYY-MM-DD') AS donation_start_date FROM donor_item ORDER BY so_id ASC"))
    items = [dict(r._mapping) for r in items_res]

    f_res = await db.execute(text("""
        SELECT f.trans_id, f.so_id, f.donor_no, 
               TO_CHAR(f.call_date, 'YYYY-MM-DD') AS call_date,
               f.call_time, f.call_by, f.call_result_notes,
               r.result_nm, d.reason_nm
        FROM donor_item_followup f
        LEFT JOIN lkp_follow_results r ON f.call_result_cd = r.result_cd
        LEFT JOIN lkp_delay_reasons d ON f.delay_reason_cd = d.reason_cd
        ORDER BY f.trans_id ASC
    """))
    followups = [dict(r._mapping) for r in f_res]
    return {"items": items, "followups": followups}


@app.delete("/api/donors/{donor_no}")
async def delete_donor(donor_no: int, db: AsyncSession = Depends(get_db)):
    checks = [
        ("استقطاعات", "SELECT COUNT(*) FROM donor_item WHERE donor_no = :dno"),
        ("حركات مالية", "SELECT COUNT(*) FROM money_trans WHERE donor_no = :dno"),
        ("متابعات عامة", "SELECT COUNT(*) FROM donor_followup WHERE donor_no = :dno"),
        ("متابعات استقطاعات", "SELECT COUNT(*) FROM donor_item_followup WHERE donor_no = :dno"),
        ("سجلات إيقاف استقطاع", "SELECT COUNT(*) FROM donor_item_deactiv_hist WHERE donor_no = :dno"),
        ("حركات إيقاف متبرع", "SELECT COUNT(*) FROM deactivate_donor_trans WHERE donor_no = :dno"),
        ("كشوف بنك محملة", "SELECT COUNT(*) FROM bank_statement_load WHERE donor_no = :dno"),
    ]
    reasons = []
    for label, sql in checks:
        res = await db.execute(text(sql), {"dno": donor_no})
        cnt = res.scalar() or 0
        if cnt > 0:
            reasons.append(f"{cnt} {label}")

    if reasons:
        raise HTTPException(
            status_code=400,
            detail=f"لا يمكن حذف هذا المتبرع لوجود سجلات فرعية مرتبطة به: ({'، '.join(reasons)})."
        )

    del_res = await db.execute(text("DELETE FROM donor_master WHERE donor_no = :dno"), {"dno": donor_no})
    await db.commit()
    if del_res.rowcount == 0:
        raise HTTPException(status_code=404, detail="السجل غير موجود في قاعدة البيانات.")
    return {"status": "deleted", "donor_no": donor_no}


@app.delete("/api/standing-orders/{so_id}")
async def delete_standing_order(so_id: int, db: AsyncSession = Depends(get_db)):
    checks = [
        ("حركات تحصيل مسددة", "SELECT COUNT(*) FROM money_trans WHERE so_id = :sid AND status_no = 1"),
        ("متابعات استقطاع", "SELECT COUNT(*) FROM donor_item_followup WHERE so_id = :sid"),
        ("كشوف بنك محملة", "SELECT COUNT(*) FROM bank_statement_load WHERE so_id = :sid"),
        ("سجلات إيقاف سابقة", "SELECT COUNT(*) FROM donor_item_deactiv_hist WHERE so_id = :sid"),
        ("حركات تفعيل/إيقاف", "SELECT COUNT(*) FROM donor_item_actdeact_trns WHERE so_id = :sid"),
    ]
    reasons = []
    for label, sql in checks:
        res = await db.execute(text(sql), {"sid": so_id})
        cnt = res.scalar() or 0
        if cnt > 0:
            reasons.append(f"{cnt} {label}")

    if reasons:
        raise HTTPException(
            status_code=400,
            detail=f"لا يمكن حذف الاستقطاع لوجود حركات مرتبطة به: ({'، '.join(reasons)}). يمكنك إيقاف الاستقطاع بدلاً من حذفه."
        )

    # حذف حركات الاستحقاق غير المسددة (إن وجدت) قبل حذف الاستقطاع
    await db.execute(text("DELETE FROM money_trans WHERE so_id = :sid AND status_no != 1"), {"sid": so_id})
    del_res = await db.execute(text("DELETE FROM donor_item WHERE so_id = :sid"), {"sid": so_id})
    await db.commit()
    if del_res.rowcount == 0:
        raise HTTPException(status_code=404, detail="الاستقطاع غير موجود.")
    return {"status": "deleted", "so_id": so_id}


class UserCreateSchema(BaseModel):
    username: str
    full_name: str
    password: str
    role_id: int = 2
    page_permissions: Optional[dict[str, str]] = None

class UserRoleUpdateSchema(BaseModel):
    role_id: int

class UserPasswordUpdateSchema(BaseModel):
    password: str

async def get_active_page_keys(db: AsyncSession) -> tuple:
    try:
        res = await db.execute(text("SELECT page_key FROM sys_pages WHERE node_type = 'page' AND is_active = TRUE ORDER BY sort_order ASC, page_key ASC"))
        keys = tuple(r.page_key for r in res)
        return keys if keys else DEFAULT_PAGE_KEYS
    except Exception:
        return DEFAULT_PAGE_KEYS

async def load_user_permissions_from_db(db: AsyncSession, user_id: int, role_code: Optional[str], fallback_perms: Any, valid_keys: tuple = DEFAULT_PAGE_KEYS) -> dict:
    try:
        res = await db.execute(
            text("SELECT page_key, access_level FROM sys_user_permissions WHERE user_id = :uid"),
            {"uid": user_id}
        )
        rows = res.fetchall()
        if rows:
            db_map = {r.page_key: r.access_level for r in rows}
            return normalize_page_permissions(role_code, db_map, valid_keys)
    except Exception:
        pass
    return normalize_page_permissions(role_code, fallback_perms, valid_keys)

async def load_page_hierarchy_from_db(db: AsyncSession) -> list:
    res = await db.execute(text("""
        SELECT page_key, parent_key, node_type, title_en, title_ar, route_path, sort_order
        FROM sys_pages
        WHERE is_active = TRUE
        ORDER BY sort_order ASC, page_key ASC
    """))
    all_nodes = [dict(r._mapping) for r in res]
    by_parent: dict[Optional[str], list] = {}
    for n in all_nodes:
        by_parent.setdefault(n["parent_key"], []).append(n)

    def build_module_node(mod: dict) -> dict:
        direct_pages = []
        sub_groups = []
        for child in by_parent.get(mod["page_key"], []):
            if child["node_type"] == "page":
                direct_pages.append({
                    "key": child["page_key"],
                    "label": child["title_en"],
                    "label_ar": child["title_ar"],
                    "route": child["route_path"] or ""
                })
            elif child["node_type"] in ("group", "module"):
                grp_pages = [
                    {
                        "key": leaf["page_key"],
                        "label": leaf["title_en"],
                        "label_ar": leaf["title_ar"],
                        "route": leaf["route_path"] or ""
                    }
                    for leaf in by_parent.get(child["page_key"], [])
                    if leaf["node_type"] == "page"
                ]
                sub_groups.append({
                    "group_id": child["page_key"],
                    "group_label": child["title_en"],
                    "group_label_ar": child["title_ar"],
                    "expanded": True,
                    "pages": grp_pages
                })
        return {
            "group_id": mod["page_key"],
            "group_label": mod["title_en"],
            "group_label_ar": mod["title_ar"],
            "expanded": True,
            "pages": direct_pages,
            "sub_groups": sub_groups
        }

    return [build_module_node(m) for m in by_parent.get(None, []) if m["node_type"] == "module"]

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})

@app.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request, username: str = Form(...), password: str = Form(...), db: AsyncSession = Depends(get_db)):
    uname = username.strip().upper()
    pwd_hash = hash_password(password.strip())
    sql = text("""
        SELECT u.user_id, u.username, u.full_name_en, u.full_name_ar, u.is_active, r.role_id, r.role_code, r.role_name_en, r.permissions
        FROM sys_users u
        JOIN sys_roles r ON u.role_id = r.role_id
        WHERE UPPER(u.username) = :u AND u.password_hash = :p
    """)
    res = await db.execute(sql, {"u": uname, "p": pwd_hash})
    row = res.first()
    if not row:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid username or password."})
    user_data = dict(row._mapping)
    if not user_data["is_active"]:
        return templates.TemplateResponse("login.html", {"request": request, "error": "This user account is disabled."})

    await db.execute(text("UPDATE sys_users SET last_login = CURRENT_TIMESTAMP WHERE user_id = :uid"), {"uid": user_data["user_id"]})
    await db.commit()

    valid_keys = await get_active_page_keys(db)
    page_perms = await load_user_permissions_from_db(db, user_data["user_id"], user_data.get("role_code"), user_data.get("permissions"), valid_keys)
    token = create_session_token({
        "user_id": user_data["user_id"],
        "username": user_data["username"],
        "full_name": user_data["full_name_en"] or user_data["full_name_ar"],
        "role_id": user_data["role_id"],
        "role_code": user_data["role_code"],
        "role_name": user_data["role_name_en"],
        "page_permissions": page_perms
    })
    response = RedirectResponse(url="/about", status_code=302)
    response.set_cookie(key="dic_session", value=token, httponly=True, max_age=86400 * 7)
    return response

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("dic_session")
    return response

@app.get("/about", response_class=HTMLResponse)
async def about_page(request: Request):
    return templates.TemplateResponse("about.html", {"request": request})

@app.get("/users", response_class=HTMLResponse)
async def users_page(request: Request):
    return templates.TemplateResponse("users.html", {"request": request})

class UserPagePermissionsSchema(BaseModel):
    page_permissions: dict[str, str]

@app.get("/api/users")
async def list_users(db: AsyncSession = Depends(get_db)):
    valid_keys = await get_active_page_keys(db)
    hierarchy = await load_page_hierarchy_from_db(db)
    res = await db.execute(text("""
        SELECT u.user_id, u.username, u.full_name_ar, u.full_name_en, u.role_id, u.is_active, r.role_code, r.role_name_en, r.permissions
        FROM sys_users u
        JOIN sys_roles r ON u.role_id = r.role_id
        ORDER BY u.user_id ASC
    """))
    user_rows = [dict(r._mapping) for r in res]
    rows = []
    for item in user_rows:
        item["page_permissions"] = await load_user_permissions_from_db(
            db, item["user_id"], item.get("role_code"), item.get("permissions"), valid_keys
        )
        item.pop("permissions", None)
        rows.append(item)
    return {"users": rows, "module_hierarchy": hierarchy, "page_keys": list(valid_keys)}

@app.post("/api/users/{user_id}/page-permissions")
async def update_user_page_permissions_api(user_id: int, payload: UserPagePermissionsSchema, request: Request, db: AsyncSession = Depends(get_db)):
    u_res = await db.execute(text("""
        SELECT u.user_id, u.username, u.full_name_en, u.full_name_ar, u.role_id, r.role_code, r.role_name_en
        FROM sys_users u
        JOIN sys_roles r ON u.role_id = r.role_id
        WHERE u.user_id = :uid
    """), {"uid": user_id})
    u_row = u_res.first()
    if not u_row:
        raise HTTPException(status_code=404, detail="User not found.")

    valid_keys = await get_active_page_keys(db)
    actor = (request.state.user or {}).get("username") or "ADMIN"
    cleaned = {}
    for k in valid_keys:
        val = payload.page_permissions.get(k, "none")
        cleaned[k] = val if val in ("none", "view", "edit") else "none"
        await db.execute(text("""
            INSERT INTO sys_user_permissions (user_id, page_key, access_level, granted_by, granted_at)
            VALUES (:uid, :pk, :lvl, :by, CURRENT_TIMESTAMP)
            ON CONFLICT (user_id, page_key) DO UPDATE SET
                access_level = EXCLUDED.access_level,
                granted_by = EXCLUDED.granted_by,
                granted_at = CURRENT_TIMESTAMP
        """), {"uid": user_id, "pk": k, "lvl": cleaned[k], "by": actor})

    await db.commit()
    resp = JSONResponse(content={"status": "updated", "page_permissions": cleaned})
    if request.state.user and request.state.user.get("user_id") == user_id:
        new_token = create_session_token({
            "user_id": u_row.user_id,
            "username": u_row.username,
            "full_name": u_row.full_name_en or u_row.full_name_ar,
            "role_id": u_row.role_id,
            "role_code": u_row.role_code,
            "role_name": u_row.role_name_en,
            "page_permissions": cleaned
        })
        resp.set_cookie(key="dic_session", value=new_token, httponly=True, max_age=86400 * 7)
    return resp

@app.post("/api/users/create")
async def create_user_api(payload: UserCreateSchema, request: Request, db: AsyncSession = Depends(get_db)):
    uname = payload.username.strip().upper()
    if not uname or not payload.password:
        raise HTTPException(status_code=400, detail="Username and password are required.")
    pwd_hash = hash_password(payload.password.strip())
    valid_keys = await get_active_page_keys(db)
    actor = (request.state.user or {}).get("username") or "ADMIN"
    try:
        ins_res = await db.execute(text("""
            INSERT INTO sys_users (username, password_hash, full_name_ar, full_name_en, role_id, is_active)
            VALUES (:u, :p, :fn, :fn, :rid, true)
            RETURNING user_id
        """), {"u": uname, "p": pwd_hash, "fn": payload.full_name.strip() or uname, "rid": payload.role_id})
        new_uid = ins_res.scalar()
        raw_p = payload.page_permissions or {}
        for k in valid_keys:
            lvl = raw_p.get(k, "none" if k == "users" else "view")
            if lvl not in ("none", "view", "edit"):
                lvl = "none"
            await db.execute(text("""
                INSERT INTO sys_user_permissions (user_id, page_key, access_level, granted_by)
                VALUES (:uid, :pk, :lvl, :by)
                ON CONFLICT (user_id, page_key) DO UPDATE SET access_level = EXCLUDED.access_level
            """), {"uid": new_uid, "pk": k, "lvl": lvl, "by": actor})
        await db.commit()
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail=f"Could not create user: {str(e)}")
    return {"status": "created", "user_id": new_uid}

@app.post("/api/users/{user_id}/role")
async def update_user_role_api(user_id: int, payload: UserRoleUpdateSchema, db: AsyncSession = Depends(get_db)):
    await db.execute(text("UPDATE sys_users SET role_id = :rid WHERE user_id = :uid"), {"rid": payload.role_id, "uid": user_id})
    await db.commit()
    return {"status": "updated"}

@app.post("/api/users/{user_id}/password")
async def update_user_password_api(user_id: int, payload: UserPasswordUpdateSchema, db: AsyncSession = Depends(get_db)):
    pwd_hash = hash_password(payload.password.strip())
    await db.execute(text("UPDATE sys_users SET password_hash = :p WHERE user_id = :uid"), {"p": pwd_hash, "uid": user_id})
    await db.commit()
    return {"status": "password_updated"}
# ----------------- Module 5: Reports & Analytics (/reports) -----------------
@app.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request):
    return templates.TemplateResponse("reports.html", {"request": request})

@app.get("/api/reports/meta")
async def get_reports_meta(db: AsyncSession = Depends(get_db)):
    banks_res = await db.execute(text("SELECT bank_cd, bank_desc, bank_e_desc FROM lkp_banks ORDER BY bank_cd"))
    banks = [dict(r._mapping) for r in banks_res]
    return {"banks": banks}

def _parse_month_range(from_month: Optional[str], to_month: Optional[str]):
    fm_str = (from_month or "2026-01")[:7]
    tm_str = (to_month or "2026-12")[:7]
    d_from = datetime.strptime(f"{fm_str}-01", "%Y-%m-%d").date()
    d_to = datetime.strptime(f"{tm_str}-01", "%Y-%m-%d").date()
    if d_to < d_from:
        d_from, d_to = d_to, d_from
    return d_from, d_to

@app.get("/api/reports/run")
async def run_report_api(
    report_type: str,
    bank_cd: Optional[int] = None,
    status_filter: Optional[str] = "ALL",
    audit_mode: Optional[str] = "NON_ACTIVE_DONOR_ACTIVE_SO",
    from_month: Optional[str] = None,
    to_month: Optional[str] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    bank_filter_sql = ""
    params: dict[str, Any] = {}
    if bank_cd and int(bank_cd) > 0:
        params["bank_cd"] = int(bank_cd)

    if report_type == "paid_unpaid_so":
        d_from, d_to = _parse_month_range(from_month, to_month)
        params["d_from"] = d_from
        params["d_to"] = d_to
        if "bank_cd" in params:
            bank_filter_sql = " AND m.bank_cd = :bank_cd"
        status_sql = ""
        if status_filter == "PAID":
            status_sql = " AND m.status_no = 1"
        elif status_filter == "UNPAID":
            status_sql = " AND COALESCE(m.status_no, 2) <> 1"

        sql = text(f"""
            SELECT TO_CHAR(m.month_year, 'YYYY-MM') AS month_str,
                   m.donor_no,
                   COALESCE(NULLIF(TRIM(d.donor_ename), ''), d.donor_name) AS donor_name_en,
                   COALESCE(NULLIF(TRIM(c.item_e_desc), ''), c.item_desc, m.item_no) AS item_no,
                   COALESCE(b.bank_e_desc, b.bank_desc, '') AS bank_name,
                   COALESCE(m.st_order_no, '') AS so_code,
                   m.paid_sum AS amount,
                   CASE WHEN m.status_no = 1 THEN 'Paid' ELSE 'Unpaid' END AS payment_status
            FROM money_trans m
            JOIN donor_master d ON m.donor_no = d.donor_no
            LEFT JOIN lkp_banks b ON m.bank_cd = b.bank_cd
            LEFT JOIN lkp_charity_items c ON m.item_no = c.item_cd
            WHERE m.month_year >= :d_from AND m.month_year <= :d_to
            {bank_filter_sql}
            {status_sql}
            ORDER BY m.month_year ASC, m.donor_no ASC
        """)
        res = await db.execute(sql, params)
        rows = [dict(r._mapping) for r in res]
        for r in rows:
            r["amount"] = float(r["amount"] or 0)
        paid_amt = round(sum(r["amount"] for r in rows if r["payment_status"] == "Paid"), 3)
        unpaid_amt = round(sum(r["amount"] for r in rows if r["payment_status"] != "Paid"), 3)
        return {
            "columns": ["month_str", "donor_no", "donor_name_en", "item_no", "bank_name", "so_code", "amount", "payment_status"],
            "headers": ["Month", "Donor No", "Donor Name", "Item", "Bank", "SO Code", "Amount (BHD)", "Status"],
            "rows": rows,
            "summary": {
                "total_rows": len(rows),
                "paid_amount": paid_amt,
                "unpaid_amount": unpaid_amt,
                "total_amount": round(paid_amt + unpaid_amt, 3)
            }
        }

    elif report_type == "so_revenues_summary":
        d_from, d_to = _parse_month_range(from_month, to_month)
        params["d_from"] = d_from
        params["d_to"] = d_to
        if "bank_cd" in params:
            bank_filter_sql = " AND m.bank_cd = :bank_cd"

        sql = text(f"""
            SELECT TO_CHAR(m.month_year, 'YYYY-MM') AS month_str,
                   COALESCE(b.bank_e_desc, b.bank_desc, 'All Banks') AS bank_name,
                   COUNT(*) AS total_txns,
                   SUM(CASE WHEN m.status_no = 1 THEN 1 ELSE 0 END) AS paid_txns,
                   SUM(CASE WHEN COALESCE(m.status_no, 2) <> 1 THEN 1 ELSE 0 END) AS unpaid_txns,
                   COALESCE(SUM(CASE WHEN m.status_no = 1 THEN m.paid_sum ELSE 0 END), 0) AS paid_amount,
                   COALESCE(SUM(CASE WHEN COALESCE(m.status_no, 2) <> 1 THEN m.paid_sum ELSE 0 END), 0) AS unpaid_amount,
                   COALESCE(SUM(m.paid_sum), 0) AS total_amount
            FROM money_trans m
            LEFT JOIN lkp_banks b ON m.bank_cd = b.bank_cd
            WHERE m.month_year >= :d_from AND m.month_year <= :d_to
            {bank_filter_sql}
            GROUP BY TO_CHAR(m.month_year, 'YYYY-MM'), COALESCE(b.bank_e_desc, b.bank_desc, 'All Banks')
            ORDER BY month_str ASC, bank_name ASC
        """)
        res = await db.execute(sql, params)
        rows = [dict(r._mapping) for r in res]
        for r in rows:
            r["paid_amount"] = float(r["paid_amount"] or 0)
            r["unpaid_amount"] = float(r["unpaid_amount"] or 0)
            r["total_amount"] = float(r["total_amount"] or 0)
        return {
            "columns": ["month_str", "bank_name", "total_txns", "paid_txns", "unpaid_txns", "paid_amount", "unpaid_amount", "total_amount"],
            "headers": ["Month", "Bank", "Total Txns", "Paid Txns", "Unpaid Txns", "Paid (BHD)", "Unpaid (BHD)", "Total SO (BHD)"],
            "rows": rows,
            "summary": {
                "total_rows": len(rows),
                "paid_amount": round(sum(r["paid_amount"] for r in rows), 3),
                "unpaid_amount": round(sum(r["unpaid_amount"] for r in rows), 3),
                "total_amount": round(sum(r["total_amount"] for r in rows), 3)
            }
        }

    elif report_type == "bank_statement_income":
        d_from, d_to = _parse_month_range(from_month, to_month)
        params["d_from"] = d_from
        params["d_to"] = d_to
        if "bank_cd" in params:
            bank_filter_sql = " AND l.bank_cd = :bank_cd"

        # Includes Cash/Fawri deposits AND Standing Orders updated via bank statement reconciliation
        sql = text(f"""
            SELECT TO_CHAR(l.money_trans_month, 'YYYY-MM') AS month_str,
                   COALESCE(b.bank_e_desc, b.bank_desc, '') AS bank_name,
                   CASE
                       WHEN COALESCE(l.cash_deposit, 2) <> 2 THEN 'Cash / Fawri'
                       ELSE 'Reconciled Standing Order'
                   END AS income_source,
                   COALESCE(l.donor_no, 0) AS donor_no,
                   COALESCE(l.bank_stmnt_paydesc, '') AS pay_description,
                   l.bank_stmnt_payamt AS amount,
                   CASE WHEN l.money_trans_status = 1 THEN 'Updated / Paid' ELSE 'Loaded Only' END AS recon_status
            FROM bank_statement_load l
            LEFT JOIN lkp_banks b ON l.bank_cd = b.bank_cd
            WHERE l.money_trans_month >= :d_from AND l.money_trans_month <= :d_to
            {bank_filter_sql}
              AND (COALESCE(l.cash_deposit, 2) <> 2 OR l.money_trans_status = 1)
            ORDER BY l.money_trans_month ASC, l.trans_id ASC
        """)
        res = await db.execute(sql, params)
        rows = [dict(r._mapping) for r in res]
        for r in rows:
            r["amount"] = float(r["amount"] or 0)
        cash_amt = round(sum(r["amount"] for r in rows if r["income_source"] == "Cash / Fawri"), 3)
        so_amt = round(sum(r["amount"] for r in rows if r["income_source"] != "Cash / Fawri"), 3)
        return {
            "columns": ["month_str", "bank_name", "income_source", "donor_no", "pay_description", "amount", "recon_status"],
            "headers": ["Month", "Bank", "Source Type", "Donor No", "Description", "Amount (BHD)", "Status"],
            "rows": rows,
            "summary": {
                "total_rows": len(rows),
                "cash_fawri_amount": cash_amt,
                "reconciled_so_amount": so_amt,
                "total_amount": round(cash_amt + so_amt, 3)
            }
        }

    elif report_type == "new_so":
        df_str = from_date or "2026-01-01"
        dt_str = to_date or "2026-12-31"
        params["df"] = datetime.strptime(df_str, "%Y-%m-%d").date()
        params["dt"] = datetime.strptime(dt_str, "%Y-%m-%d").date()
        if "bank_cd" in params:
            bank_filter_sql = " AND i.bank2_cd = :bank_cd"

        sql = text(f"""
            SELECT i.so_id,
                   i.donor_no,
                   COALESCE(NULLIF(TRIM(d.donor_ename), ''), d.donor_name) AS donor_name_en,
                   COALESCE(NULLIF(TRIM(c.item_e_desc), ''), c.item_desc, i.item_no) AS item_no,
                   COALESCE(b.bank_e_desc, b.bank_desc, '') AS bank_name,
                   TO_CHAR(i.donation_start_date, 'YYYY-MM-DD') AS start_date,
                   i.monthly_pay AS amount,
                   CASE WHEN i.status_no = 1 THEN 'Active' ELSE 'Inactive' END AS so_status
            FROM donor_item i
            JOIN donor_master d ON i.donor_no = d.donor_no
            LEFT JOIN lkp_banks b ON i.bank2_cd = b.bank_cd
            LEFT JOIN lkp_charity_items c ON i.item_no = c.item_cd
            WHERE i.donation_start_date >= :df AND i.donation_start_date <= :dt
            {bank_filter_sql}
            ORDER BY i.donation_start_date DESC, i.so_id DESC
        """)
        res = await db.execute(sql, params)
        rows = [dict(r._mapping) for r in res]
        for r in rows:
            r["amount"] = float(r["amount"] or 0)
        return {
            "columns": ["so_id", "donor_no", "donor_name_en", "item_no", "bank_name", "start_date", "amount", "so_status"],
            "headers": ["SO ID", "Donor No", "Donor Name", "Item", "Bank", "Start Date", "Monthly Pay (BHD)", "SO Status"],
            "rows": rows,
            "summary": {
                "total_rows": len(rows),
                "total_amount": round(sum(r["amount"] for r in rows), 3)
            }
        }

    elif report_type == "data_audit":
        if "bank_cd" in params:
            bank_filter_sql = " AND i.bank2_cd = :bank_cd"
        if audit_mode == "ACTIVE_DONOR_INACTIVE_SO":
            sql = text(f"""
                SELECT i.so_id,
                       i.donor_no,
                       COALESCE(NULLIF(TRIM(d.donor_ename), ''), d.donor_name) AS donor_name_en,
                       'Active Donor' AS donor_state,
                       'Inactive SO' AS so_state,
                       COALESCE(b.bank_e_desc, b.bank_desc, '') AS bank_name,
                       i.monthly_pay AS amount
                FROM donor_item i
                JOIN donor_master d ON i.donor_no = d.donor_no
                LEFT JOIN lkp_banks b ON i.bank2_cd = b.bank_cd
                WHERE d.status_no = 1 AND i.status_no <> 1
                {bank_filter_sql}
                ORDER BY i.donor_no ASC, i.so_id ASC
            """)
        else:
            sql = text(f"""
                SELECT i.so_id,
                       i.donor_no,
                       COALESCE(NULLIF(TRIM(d.donor_ename), ''), d.donor_name) AS donor_name_en,
                       'Inactive Donor' AS donor_state,
                       'Active SO' AS so_state,
                       COALESCE(b.bank_e_desc, b.bank_desc, '') AS bank_name,
                       i.monthly_pay AS amount
                FROM donor_item i
                JOIN donor_master d ON i.donor_no = d.donor_no
                LEFT JOIN lkp_banks b ON i.bank2_cd = b.bank_cd
                WHERE d.status_no <> 1 AND i.status_no = 1
                {bank_filter_sql}
                ORDER BY i.donor_no ASC, i.so_id ASC
            """)
        res = await db.execute(sql, params)
        rows = [dict(r._mapping) for r in res]
        for r in rows:
            r["amount"] = float(r["amount"] or 0)
        return {
            "columns": ["so_id", "donor_no", "donor_name_en", "donor_state", "so_state", "bank_name", "amount"],
            "headers": ["SO ID", "Donor No", "Donor Name", "Donor Status", "SO Status", "Bank", "Monthly Pay (BHD)"],
            "rows": rows,
            "summary": {
                "total_rows": len(rows),
                "total_amount": round(sum(r["amount"] for r in rows), 3)
            }
        }

    elif report_type == "unpaid_followup":
        df_str = from_date or "2026-01-01"
        dt_str = to_date or "2026-12-31"
        params["df"] = datetime.strptime(df_str, "%Y-%m-%d").date()
        params["dt"] = datetime.strptime(dt_str, "%Y-%m-%d").date()
        if "bank_cd" in params:
            bank_filter_sql = " AND m.bank_cd = :bank_cd"
        so_status_sql = ""
        if status_filter == "ACTIVE_SO":
            so_status_sql = " AND i.status_no = 1"
        elif status_filter == "INACTIVE_SO":
            so_status_sql = " AND i.status_no <> 1"

        sql = text(f"""
            SELECT m.donor_no,
                   COALESCE(NULLIF(TRIM(d.donor_ename), ''), d.donor_name) AS donor_name_en,
                   COALESCE(d.donor_mobile, d.donor_tel1, '') AS mobile,
                   COALESCE(b.bank_e_desc, b.bank_desc, '') AS bank_name,
                   CASE WHEN i.status_no = 1 THEN 'Active' ELSE 'Inactive' END AS so_status,
                   TO_CHAR(m.month_year, 'YYYY-MM') AS unpaid_month,
                   m.paid_sum AS unpaid_amount
            FROM money_trans m
            JOIN donor_master d ON m.donor_no = d.donor_no
            LEFT JOIN donor_item i ON m.so_id = i.so_id
            LEFT JOIN lkp_banks b ON m.bank_cd = b.bank_cd
            WHERE COALESCE(m.status_no, 2) <> 1
              AND m.month_year >= :df AND m.month_year <= :dt
              {bank_filter_sql}
              {so_status_sql}
            ORDER BY m.month_year DESC, m.donor_no ASC
        """)
        res = await db.execute(sql, params)
        rows = [dict(r._mapping) for r in res]
        for r in rows:
            r["unpaid_amount"] = float(r["unpaid_amount"] or 0)
        return {
            "columns": ["donor_no", "donor_name_en", "mobile", "bank_name", "so_status", "unpaid_month", "unpaid_amount"],
            "headers": ["Donor No", "Donor Name", "Mobile", "Bank", "SO Status", "Unpaid Month", "Unpaid (BHD)"],
            "rows": rows,
            "summary": {
                "total_rows": len(rows),
                "total_amount": round(sum(r["unpaid_amount"] for r in rows), 3)
            }
        }

    raise HTTPException(status_code=400, detail="Unsupported report_type")
# ----------------- Matrix Reports API (/api/reports/matrix) -----------------
@app.get("/reports-matrix", response_class=HTMLResponse)
async def reports_matrix_page(request: Request):
    return templates.TemplateResponse("matrix_reports.html", {"request": request})

@app.get("/api/reports/matrix")
async def get_reports_matrix_api(
    years: Optional[str] = "2025,2026",
    bank_cd: Optional[int] = None,
    search_q: Optional[str] = None,
    page: int = 1,
    page_size: int = 100,
    export_all: bool = False,
    db: AsyncSession = Depends(get_db)
):
    raw_years = [int(y.strip()) for y in (years or "2026").split(",") if y.strip().isdigit()]
    if not raw_years:
        raw_years = [2026]
    selected_years = sorted(set(raw_years))
    single_year = (len(selected_years) == 1)

    month_names = {
        1: "Jan", 2: "Feb", 3: "Mar", 4: "Apr", 5: "May", 6: "Jun",
        7: "Jul", 8: "Aug", 9: "Sep", 10: "Oct", 11: "Nov", 12: "Dec"
    }

    periods = []
    for yr in selected_years:
        for m in range(1, 13):
            periods.append({
                "key": f"{yr}-{m:02d}",
                "month_start": f"{yr}-{m:02d}-01",
                "label": month_names[m] if single_year else f"{yr}-{m:02d}",
                "year": yr,
                "month": m
            })

    period_keys = [p["key"] for p in periods]

    banks_res = await db.execute(text("SELECT bank_cd, bank_desc, bank_e_desc FROM lkp_banks ORDER BY bank_cd"))
    all_banks = [dict(r._mapping) for r in banks_res]
    if bank_cd and int(bank_cd) > 0:
        target_banks = [b for b in all_banks if int(b["bank_cd"]) == int(bank_cd)]
    else:
        target_banks = all_banks

    min_date = date(min(selected_years), 1, 1)
    max_date = date(max(selected_years), 12, 31)
    date_params = {"yrs": selected_years, "min_date": min_date, "max_date": max_date}

    bsl_sql = text(
        "SELECT bank_cd, TO_CHAR(money_trans_month, 'YYYY-MM') AS p_key, "
        "COALESCE(SUM(bank_stmnt_payamt), 0) AS gen_amt "
        "FROM bank_statement_load "
        "WHERE money_trans_month >= :min_date AND money_trans_month <= :max_date "
        "AND EXTRACT(YEAR FROM money_trans_month)::int = ANY(:yrs) "
        "AND (COALESCE(cash_deposit, 2) <> 2 OR money_trans_status = 1) "
        "GROUP BY bank_cd, TO_CHAR(money_trans_month, 'YYYY-MM')"
    )
    bsl_res = await db.execute(bsl_sql, date_params)
    gen_map = {}
    for r in bsl_res:
        m = r._mapping
        gen_map[(int(m["bank_cd"]), str(m["p_key"]))] = float(m["gen_amt"] or 0)

    paid_so_sql = text(
        "SELECT bank_cd, TO_CHAR(month_year, 'YYYY-MM') AS p_key, "
        "COALESCE(SUM(paid_sum), 0) AS so_amt "
        "FROM money_trans "
        "WHERE month_year >= :min_date AND month_year <= :max_date "
        "AND EXTRACT(YEAR FROM month_year)::int = ANY(:yrs) "
        "AND status_no = 1 "
        "GROUP BY bank_cd, TO_CHAR(month_year, 'YYYY-MM')"
    )
    paid_so_res = await db.execute(paid_so_sql, date_params)
    bank_so_map = {}
    for r in paid_so_res:
        m = r._mapping
        bank_so_map[(int(m["bank_cd"]), str(m["p_key"]))] = float(m["so_amt"] or 0)

    bank_rows = []
    period_gen_totals = {k: 0.0 for k in period_keys}
    period_so_totals = {k: 0.0 for k in period_keys}
    grand_gen_total = 0.0
    grand_so_total = 0.0

    for b in target_banks:
        bcd = int(b["bank_cd"])
        bname = b["bank_e_desc"] or b["bank_desc"] or f"Bank #{bcd}"
        cells = {}
        row_gen = 0.0
        row_so = 0.0
        for k in period_keys:
            g_val = round(gen_map.get((bcd, k), 0.0), 3)
            s_val = round(bank_so_map.get((bcd, k), 0.0), 3)
            cells[k] = {"general": g_val, "so": s_val}
            row_gen = round(row_gen + g_val, 3)
            row_so = round(row_so + s_val, 3)
            period_gen_totals[k] = round(period_gen_totals[k] + g_val, 3)
            period_so_totals[k] = round(period_so_totals[k] + s_val, 3)

        grand_gen_total = round(grand_gen_total + row_gen, 3)
        grand_so_total = round(grand_so_total + row_so, 3)

        bank_rows.append({
            "bank_cd": bcd,
            "bank_name": bname,
            "cells": cells,
            "total_general": row_gen,
            "total_so": row_so
        })

    so_params: dict[str, Any] = {"yrs": selected_years, "min_date": min_date, "max_date": max_date}
    # Exclude inactive SOs that have NO paid transaction in the selected years
    so_where = [
        "(i.status_no = 1 OR EXISTS ("
        "SELECT 1 FROM money_trans m "
        "WHERE m.so_id = i.so_id AND m.status_no = 1 "
        "AND m.month_year >= :min_date AND m.month_year <= :max_date "
        "AND EXTRACT(YEAR FROM m.month_year)::int = ANY(:yrs)"
        "))"
    ]
    if bank_cd and int(bank_cd) > 0:
        so_where.append("i.bank2_cd = :bank_cd")
        so_params["bank_cd"] = int(bank_cd)
    if search_q and search_q.strip():
        so_where.append(
            "(CAST(i.so_id AS TEXT) ILIKE :q OR CAST(i.donor_no AS TEXT) ILIKE :q "
            "OR COALESCE(d.donor_ename, '') ILIKE :q OR COALESCE(d.donor_name, '') ILIKE :q)"
        )
        so_params["q"] = f"%{search_q.strip()}%"

    so_list_sql = text(
        "SELECT i.so_id, i.donor_no, "
        "COALESCE(NULLIF(TRIM(d.donor_ename), ''), d.donor_name) AS donor_name_en, "
        "COALESCE(i.monthly_pay, 0)::float8 AS monthly_pay, "
        "COALESCE(i.status_no, 2) AS so_status, "
        "COALESCE(TO_CHAR(i.donation_start_date, 'YYYY-MM-DD'), '') AS start_date_str, "
        "COALESCE(b.bank_e_desc, b.bank_desc, '') AS bank_name "
        "FROM donor_item i "
        "JOIN donor_master d ON i.donor_no = d.donor_no "
        "LEFT JOIN lkp_banks b ON i.bank2_cd = b.bank_cd "
        f"WHERE {' AND '.join(so_where)} "
        "ORDER BY COALESCE(NULLIF(TRIM(d.donor_ename), ''), d.donor_name) ASC, i.so_id ASC"
    )
    so_list_res = await db.execute(so_list_sql, so_params)
    so_rows_raw = so_list_res.fetchall()

    mt_sql = text(
        "SELECT so_id, TO_CHAR(month_year, 'YYYY-MM') AS p_key, "
        "COALESCE(status_no, 2) AS status_no, COALESCE(paid_sum, 0)::float8 AS amt "
        "FROM money_trans "
        "WHERE month_year >= :min_date AND month_year <= :max_date "
        "AND EXTRACT(YEAR FROM month_year)::int = ANY(:yrs)"
    )
    mt_res = await db.execute(mt_sql, date_params)
    mt_by_so: dict[int, dict[str, tuple[int, float]]] = {}
    for sid_val, p_key_val, st_val, amt_val in mt_res.fetchall():
        sub = mt_by_so.get(sid_val)
        if sub is None:
            mt_by_so[sid_val] = {p_key_val: (st_val, amt_val)}
        else:
            sub[p_key_val] = (st_val, amt_val)

    so_matrix_all_rows = []
    col_paid_totals = {k: 0.0 for k in period_keys}
    col_unpaid_totals = {k: 0.0 for k in period_keys}
    all_paid_sum = 0.0
    all_unpaid_sum = 0.0
    period_pairs = [(p["key"], p["month_start"]) for p in periods]

    eff_page_size = max(1, int(page_size or 100))
    total_raw = len(so_rows_raw)
    total_pages_est = max(1, (total_raw + eff_page_size - 1) // eff_page_size)
    cur_page = max(1, min(int(page or 1), total_pages_est))
    start_idx = (cur_page - 1) * eff_page_size
    end_idx = start_idx + eff_page_size

    valid_idx = 0
    for sid, donor_no, donor_name_en, monthly_pay, so_status, start_str, bank_name in so_rows_raw:
        monthly_amt = round(monthly_pay, 3)
        is_so_active = (so_status == 1)
        start_prefix = start_str[:10] if start_str else ""
        so_mt = mt_by_so.get(sid)

        in_page = export_all or (start_idx <= valid_idx < end_idx)
        cells = {} if in_page else None
        row_paid = 0.0
        row_unpaid = 0.0

        for k, m_start in period_pairs:
            rec = so_mt.get(k) if so_mt else None
            if rec is not None:
                st_no, rec_amt = rec
                amt_val = round(rec_amt, 3) if rec_amt > 0 else monthly_amt
                if st_no == 1:
                    if in_page:
                        cells[k] = {"state": "paid", "amt": amt_val}
                    row_paid += amt_val
                    col_paid_totals[k] += amt_val
                else:
                    if in_page:
                        cells[k] = {"state": "unpaid", "amt": amt_val}
                    row_unpaid += amt_val
                    col_unpaid_totals[k] += amt_val
            else:
                if is_so_active and (not start_prefix or start_prefix <= m_start):
                    if in_page:
                        cells[k] = {"state": "unpaid", "amt": monthly_amt}
                    row_unpaid += monthly_amt
                    col_unpaid_totals[k] += monthly_amt
                else:
                    if in_page:
                        cells[k] = {"state": "none", "amt": 0.0}

        if not is_so_active and row_paid <= 0:
            continue

        row_paid = round(row_paid, 3)
        row_unpaid = round(row_unpaid, 3)
        all_paid_sum += row_paid
        all_unpaid_sum += row_unpaid

        if in_page:
            donor_label = donor_name_en.strip() if donor_name_en else f"Donor #{donor_no}"
            so_matrix_all_rows.append({
                "so_id": sid,
                "donor_no": donor_no,
                "donor_name": donor_label,
                "bank_name": bank_name,
                "monthly_pay": monthly_amt,
                "so_active": is_so_active,
                "cells": cells,
                "paid_total": row_paid,
                "unpaid_total": row_unpaid
            })
        valid_idx += 1

    total_valid_rows = valid_idx
    total_pages = max(1, (total_valid_rows + eff_page_size - 1) // eff_page_size)
    if cur_page > total_pages:
        cur_page = total_pages

    for k in period_keys:
        col_paid_totals[k] = round(col_paid_totals[k], 3)
        col_unpaid_totals[k] = round(col_unpaid_totals[k], 3)
    all_paid_sum = round(all_paid_sum, 3)
    all_unpaid_sum = round(all_unpaid_sum, 3)

    return {
        "years": selected_years,
        "periods": periods,
        "banks_matrix": {
            "rows": bank_rows,
            "period_totals": {
                k: {"general": period_gen_totals[k], "so": period_so_totals[k]}
                for k in period_keys
            },
            "grand_total": {"general": grand_gen_total, "so": grand_so_total}
        },
        "so_matrix": {
            "rows": so_matrix_all_rows,
            "period_totals": {
                k: {"paid": col_paid_totals[k], "unpaid": col_unpaid_totals[k]}
                for k in period_keys
            },
            "grand_total": {"paid": all_paid_sum, "unpaid": all_unpaid_sum},
            "pagination": {
                "page": cur_page,
                "page_size": eff_page_size,
                "total_rows": total_valid_rows,
                "total_pages": total_pages
            }
        }
    }

# ----------------- Executive Standing Orders Dashboard (/reports-dashboard) -----------------
@app.get("/reports-dashboard", response_class=HTMLResponse)
async def reports_dashboard_page(request: Request):
    return templates.TemplateResponse("so_dashboard.html", {"request": request})

@app.get("/api/reports/dashboard")
async def get_so_executive_dashboard_api(
    year: int = 2026,
    bank_cd: Optional[int] = None,
    item_no: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    prev_year = year - 1
    yr_start = date(year, 1, 1)
    yr_end = date(year, 12, 31)
    prev_start = date(prev_year, 1, 1)
    prev_end = date(prev_year, 12, 31)

    # 1. Load Setup, Banks & Charity Items
    setup_res = await db.execute(text("SELECT not_paid_month, not_paid_month2, so_min_amt, accepted_delayed_months, grace_period_months FROM sys_donor_setup LIMIT 1"))
    setup_row = setup_res.first()
    ref_month = (setup_row.not_paid_month2 or setup_row.not_paid_month or date(2026, 9, 1)) if setup_row else date(2026, 9, 1)
    accepted_delay = int(setup_row.accepted_delayed_months or 6) if setup_row else 6
    grace_months = int(setup_row.grace_period_months or 2) if setup_row else 2

    banks_res = await db.execute(text("SELECT bank_cd, bank_desc, bank_e_desc FROM lkp_banks ORDER BY bank_cd"))
    all_banks = [dict(r._mapping) for r in banks_res]

    items_res = await db.execute(text("SELECT item_cd, item_desc, item_e_desc FROM lkp_charity_items ORDER BY item_cd"))
    all_items = [dict(r._mapping) for r in items_res]

    # Build dynamic filter clauses
    di_filters = ["1=1"]
    mt_filters = ["1=1"]
    bsl_filters = ["1=1"]
    params: dict[str, Any] = {
        "yr_start": yr_start,
        "yr_end": yr_end,
        "prev_start": prev_start,
        "prev_end": prev_end,
        "ref_month": ref_month
    }

    if bank_cd and int(bank_cd) > 0:
        params["bank_cd"] = int(bank_cd)
        di_filters.append("i.bank2_cd = :bank_cd")
        mt_filters.append("m.bank_cd = :bank_cd")
        bsl_filters.append("b.bank_cd = :bank_cd")

    if item_no and item_no.strip():
        params["item_no"] = item_no.strip()
        di_filters.append("i.item_no = :item_no")
        mt_filters.append("m.item_no = :item_no")

    di_where = " AND ".join(di_filters)
    mt_where = " AND ".join(mt_filters)
    bsl_where = " AND ".join(bsl_filters)

    # 2. Donors & Standing Orders Portfolio Summary
    donors_res = await db.execute(text("""
        SELECT
            COUNT(*) FILTER (WHERE status_no = 1) AS active_donors,
            COUNT(*) FILTER (WHERE status_no <> 1) AS inactive_donors,
            COUNT(*) AS total_donors
        FROM donor_master
    """))
    d_row = donors_res.first()

    portfolio_res = await db.execute(text(f"""
        SELECT
            COUNT(*) FILTER (WHERE i.status_no = 1) AS active_so_count,
            COUNT(*) FILTER (WHERE i.status_no <> 1) AS inactive_so_count,
            COALESCE(SUM(i.monthly_pay) FILTER (WHERE i.status_no = 1), 0) AS expected_monthly_bhd,
            COALESCE(AVG(i.monthly_pay) FILTER (WHERE i.status_no = 1), 0) AS avg_so_bhd,
            COUNT(DISTINCT i.donor_no) FILTER (WHERE i.status_no = 1) AS active_so_donors,
            COUNT(*) FILTER (WHERE i.donation_start_date >= :yr_start AND i.donation_start_date <= :yr_end) AS new_so_count,
            COALESCE(SUM(i.monthly_pay) FILTER (WHERE i.donation_start_date >= :yr_start AND i.donation_start_date <= :yr_end), 0) AS new_so_bhd
        FROM donor_item i
        WHERE {di_where}
    """), params)
    p_row = portfolio_res.first()

    expected_monthly_bhd = round(float(p_row.expected_monthly_bhd or 0), 3)
    active_so_count = int(p_row.active_so_count or 0)
    inactive_so_count = int(p_row.inactive_so_count or 0)
    avg_so_bhd = round(float(p_row.avg_so_bhd or 0), 3)

    # Deactivations in selected year
    deact_where = "h.deactive_date >= :yr_start AND h.deactive_date <= :yr_end"
    if bank_cd and int(bank_cd) > 0:
        deact_where += " AND h.bank_cd = :bank_cd"
    if item_no and item_no.strip():
        deact_where += " AND CAST(h.item_no AS TEXT) = :item_no"

    deact_res = await db.execute(text(f"""
        SELECT
            COUNT(*) AS deact_count,
            COALESCE(SUM(COALESCE(i.monthly_pay, 0)), 0) AS deact_bhd
        FROM donor_item_deactiv_hist h
        LEFT JOIN donor_item i ON (
            h.so_id = i.so_id
            OR (h.so_id IS NULL AND h.donor_no = i.donor_no AND CAST(h.item_no AS TEXT) = i.item_no AND h.donation_start_date = i.donation_start_date)
        )
        WHERE {deact_where}
    """), params)
    deact_row = deact_res.first()
    deact_count = int(deact_row.deact_count or 0)
    deact_bhd = round(float(deact_row.deact_bhd or 0), 3)

    # 3. Monthly Trend for Selected Year & Previous Year (from money_trans)
    mt_trend_res = await db.execute(text(f"""
        SELECT
            EXTRACT(YEAR FROM m.month_year)::int AS yr,
            EXTRACT(MONTH FROM m.month_year)::int AS mo,
            COALESCE(SUM(m.paid_sum) FILTER (WHERE m.status_no = 1), 0) AS collected_bhd,
            COUNT(*) FILTER (WHERE m.status_no = 1) AS paid_count,
            COALESCE(SUM(m.paid_sum) FILTER (WHERE m.status_no <> 1), 0) AS unpaid_bhd,
            COUNT(*) FILTER (WHERE m.status_no <> 1) AS unpaid_count
        FROM money_trans m
        WHERE m.month_year >= :prev_start AND m.month_year <= :yr_end
          AND {mt_where}
        GROUP BY EXTRACT(YEAR FROM m.month_year)::int, EXTRACT(MONTH FROM m.month_year)::int
    """), params)

    mt_by_ym: dict[tuple[int, int], dict] = {}
    for r in mt_trend_res:
        mt_by_ym[(int(r.yr), int(r.mo))] = {
            "collected_bhd": round(float(r.collected_bhd or 0), 3),
            "paid_count": int(r.paid_count or 0),
            "unpaid_bhd": round(float(r.unpaid_bhd or 0), 3),
            "unpaid_count": int(r.unpaid_count or 0)
        }

    # General / Fawri / Cash donations from bank_statement_load in Selected Year
    bsl_trend_res = await db.execute(text(f"""
        SELECT
            EXTRACT(MONTH FROM b.money_trans_month)::int AS mo,
            COALESCE(SUM(b.bank_stmnt_payamt) FILTER (WHERE COALESCE(b.cash_deposit, 2) <> 2), 0) AS general_bhd,
            COUNT(*) AS total_rows,
            COUNT(*) FILTER (WHERE b.sys_found = 1) AS matched_rows,
            COUNT(*) FILTER (WHERE COALESCE(b.sys_found, 0) <> 1) AS unmatched_rows
        FROM bank_statement_load b
        WHERE b.money_trans_month >= :yr_start AND b.money_trans_month <= :yr_end
          AND {bsl_where}
        GROUP BY EXTRACT(MONTH FROM b.money_trans_month)::int
    """), params)
    bsl_by_mo: dict[int, dict] = {}
    for r in bsl_trend_res:
        bsl_by_mo[int(r.mo)] = {
            "general_bhd": round(float(r.general_bhd or 0), 3),
            "total_rows": int(r.total_rows or 0),
            "matched_rows": int(r.matched_rows or 0),
            "unmatched_rows": int(r.unmatched_rows or 0)
        }

    month_labels = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    monthly_trend = []
    ytd_collected_bhd = 0.0
    ytd_paid_installments = 0
    ytd_unpaid_bhd = 0.0
    ytd_unpaid_installments = 0
    prev_year_same_months_bhd = 0.0
    prev_year_full_bhd = 0.0
    ytd_general_bank_bhd = 0.0
    stmnt_total_rows = 0
    stmnt_matched_rows = 0
    stmnt_unmatched_rows = 0
    active_months_in_year = 0

    for m_idx in range(1, 13):
        cur_m = mt_by_ym.get((year, m_idx), {"collected_bhd": 0.0, "paid_count": 0, "unpaid_bhd": 0.0, "unpaid_count": 0})
        prv_m = mt_by_ym.get((prev_year, m_idx), {"collected_bhd": 0.0, "paid_count": 0, "unpaid_bhd": 0.0, "unpaid_count": 0})
        bsl_m = bsl_by_mo.get(m_idx, {"general_bhd": 0.0, "total_rows": 0, "matched_rows": 0, "unmatched_rows": 0})

        col_val = cur_m["collected_bhd"]
        unp_val = cur_m["unpaid_bhd"]
        prv_val = prv_m["collected_bhd"]
        gen_val = bsl_m["general_bhd"]
        exp_val = round(col_val + unp_val, 3) if (col_val + unp_val) > 0 else expected_monthly_bhd

        ytd_collected_bhd = round(ytd_collected_bhd + col_val, 3)
        ytd_paid_installments += cur_m["paid_count"]
        ytd_unpaid_bhd = round(ytd_unpaid_bhd + unp_val, 3)
        ytd_unpaid_installments += cur_m["unpaid_count"]
        prev_year_full_bhd = round(prev_year_full_bhd + prv_val, 3)
        if col_val > 0 or unp_val > 0:
            active_months_in_year += 1
            prev_year_same_months_bhd = round(prev_year_same_months_bhd + prv_val, 3)

        ytd_general_bank_bhd = round(ytd_general_bank_bhd + gen_val, 3)
        stmnt_total_rows += bsl_m["total_rows"]
        stmnt_matched_rows += bsl_m["matched_rows"]
        stmnt_unmatched_rows += bsl_m["unmatched_rows"]

        monthly_trend.append({
            "month_num": m_idx,
            "month_label": month_labels[m_idx - 1],
            "month_key": f"{year}-{m_idx:02d}",
            "expected_so_bhd": exp_val,
            "collected_so_bhd": col_val,
            "unpaid_so_bhd": unp_val,
            "prev_year_so_bhd": prv_val,
            "general_donations_bhd": gen_val,
            "total_inflow_bhd": round(col_val + gen_val, 3)
        })

    ytd_billed_total = round(ytd_collected_bhd + ytd_unpaid_bhd, 3)
    collection_efficiency_pct = round((ytd_collected_bhd / ytd_billed_total) * 100, 1) if ytd_billed_total > 0 else 0.0
    cmp_base = prev_year_same_months_bhd if prev_year_same_months_bhd > 0 else prev_year_full_bhd
    yoy_growth_pct = round(((ytd_collected_bhd - cmp_base) / cmp_base) * 100, 1) if cmp_base > 0 else 0.0
    stmnt_match_rate_pct = round((stmnt_matched_rows / stmnt_total_rows) * 100, 1) if stmnt_total_rows > 0 else 0.0

    # 4. Bank Performance & Statement Freshness Matrix
    bank_perf_res = await db.execute(text(f"""
        SELECT
            b.bank_cd,
            b.bank_desc,
            b.bank_e_desc,
            COALESCE(di.active_so_count, 0) AS active_so_count,
            COALESCE(di.expected_monthly_bhd, 0) AS expected_monthly_bhd,
            COALESCE(mt.collected_bhd, 0) AS ytd_collected_bhd,
            COALESCE(mt.unpaid_bhd, 0) AS ytd_unpaid_bhd,
            COALESCE(bsl.general_bhd, 0) AS ytd_general_bhd,
            COALESCE(bsl.matched_rows, 0) AS stmnt_matched,
            COALESCE(bsl.unmatched_rows, 0) AS stmnt_unmatched,
            TO_CHAR(bsl_max.last_stmnt_month, 'YYYY-MM') AS last_stmnt_month,
            upd.updated_by AS last_updated_by,
            COALESCE(upd.updated_amt, 0) AS last_updated_amt
        FROM lkp_banks b
        LEFT JOIN (
            SELECT bank2_cd AS bank_cd,
                   COUNT(*) FILTER (WHERE status_no = 1) AS active_so_count,
                   SUM(monthly_pay) FILTER (WHERE status_no = 1) AS expected_monthly_bhd
            FROM donor_item i
            WHERE {di_where}
            GROUP BY bank2_cd
        ) di ON b.bank_cd = di.bank_cd
        LEFT JOIN (
            SELECT bank_cd,
                   SUM(paid_sum) FILTER (WHERE status_no = 1) AS collected_bhd,
                   SUM(paid_sum) FILTER (WHERE status_no <> 1) AS unpaid_bhd
            FROM money_trans m
            WHERE m.month_year >= :yr_start AND m.month_year <= :yr_end
              AND {mt_where}
            GROUP BY bank_cd
        ) mt ON b.bank_cd = mt.bank_cd
        LEFT JOIN (
            SELECT bank_cd,
                   SUM(bank_stmnt_payamt) FILTER (WHERE COALESCE(cash_deposit, 2) <> 2) AS general_bhd,
                   COUNT(*) FILTER (WHERE sys_found = 1) AS matched_rows,
                   COUNT(*) FILTER (WHERE COALESCE(sys_found, 0) <> 1) AS unmatched_rows
            FROM bank_statement_load b
            WHERE b.money_trans_month >= :yr_start AND b.money_trans_month <= :yr_end
              AND {bsl_where}
            GROUP BY bank_cd
        ) bsl ON b.bank_cd = bsl.bank_cd
        LEFT JOIN (
            SELECT bank_cd, MAX(money_trans_month) AS last_stmnt_month
            FROM bank_statement_load
            GROUP BY bank_cd
        ) bsl_max ON b.bank_cd = bsl_max.bank_cd
        LEFT JOIN (
            SELECT DISTINCT ON (bank_cd) bank_cd, month_year, updated_by, updated_amt
            FROM bankmonthly_stmntupd
            ORDER BY bank_cd, month_year DESC
        ) upd ON b.bank_cd = upd.bank_cd
        WHERE (COALESCE(di.active_so_count, 0) > 0 OR COALESCE(mt.collected_bhd, 0) > 0 OR COALESCE(bsl.general_bhd, 0) > 0)
        ORDER BY COALESCE(mt.collected_bhd, 0) DESC, COALESCE(di.expected_monthly_bhd, 0) DESC
    """), params)

    banks_performance = []
    latest_overall_stmnt = None
    for r in bank_perf_res:
        col_b = round(float(r.ytd_collected_bhd or 0), 3)
        unp_b = round(float(r.ytd_unpaid_bhd or 0), 3)
        tot_b = round(col_b + unp_b, 3)
        rate_b = round((col_b / tot_b) * 100, 1) if tot_b > 0 else 0.0
        l_mo = r.last_stmnt_month
        if l_mo and (not latest_overall_stmnt or l_mo > latest_overall_stmnt):
            latest_overall_stmnt = l_mo
        banks_performance.append({
            "bank_cd": int(r.bank_cd),
            "bank_name_en": r.bank_e_desc or r.bank_desc,
            "bank_name_ar": r.bank_desc,
            "active_so_count": int(r.active_so_count or 0),
            "expected_monthly_bhd": round(float(r.expected_monthly_bhd or 0), 3),
            "ytd_collected_bhd": col_b,
            "ytd_unpaid_bhd": unp_b,
            "collection_rate_pct": rate_b,
            "ytd_general_bhd": round(float(r.ytd_general_bhd or 0), 3),
            "last_reconciled_month": l_mo or "None",
            "last_updated_by": r.last_updated_by or "-",
            "last_updated_amt": round(float(r.last_updated_amt or 0), 3),
            "stmnt_matched": int(r.stmnt_matched or 0),
            "stmnt_unmatched": int(r.stmnt_unmatched or 0)
        })

    # 5. Delinquency Aging & Risk Funnel across Active Standing Orders
    aging_res = await db.execute(text(f"""
        WITH active_so_delays AS (
            SELECT
                i.so_id,
                i.monthly_pay,
                GREATEST(0, (
                    EXTRACT(YEAR FROM AGE(DATE_TRUNC('month', CAST(:ref_month AS DATE)), DATE_TRUNC('month', COALESCE(lp.last_paid_month, i.donation_start_date)))) * 12 +
                    EXTRACT(MONTH FROM AGE(DATE_TRUNC('month', CAST(:ref_month AS DATE)), DATE_TRUNC('month', COALESCE(lp.last_paid_month, i.donation_start_date))))
                )::int) AS delay_months
            FROM donor_item i
            LEFT JOIN so_payment_summary lp ON i.so_id = lp.so_id
            WHERE i.status_no = 1 AND {di_where}
        )
        SELECT
            CASE
                WHEN delay_months <= 0 THEN 'on_time'
                WHEN delay_months BETWEEN 1 AND 2 THEN 'grace_period'
                WHEN delay_months BETWEEN 3 AND 5 THEN 'followup_needed'
                ELSE 'critical_risk'
            END AS bucket,
            COUNT(*) AS so_count,
            COALESCE(SUM(monthly_pay), 0) AS monthly_bhd
        FROM active_so_delays
        GROUP BY 1
    """), params)

    aging_map = {
        "on_time": {"label": "On-Time (0 Months Delay)", "count": 0, "monthly_bhd": 0.0, "pct": 0.0},
        "grace_period": {"label": "Grace Period (1–2 Months)", "count": 0, "monthly_bhd": 0.0, "pct": 0.0},
        "followup_needed": {"label": "Follow-up Required (3–5 Months)", "count": 0, "monthly_bhd": 0.0, "pct": 0.0},
        "critical_risk": {"label": "Critical / Auto-Deact Risk (6+ Months)", "count": 0, "monthly_bhd": 0.0, "pct": 0.0}
    }
    for r in aging_res:
        b_key = r.bucket
        if b_key in aging_map:
            cnt = int(r.so_count or 0)
            amt = round(float(r.monthly_bhd or 0), 3)
            aging_map[b_key]["count"] = cnt
            aging_map[b_key]["monthly_bhd"] = amt
            aging_map[b_key]["pct"] = round((cnt / active_so_count) * 100, 1) if active_so_count > 0 else 0.0

    # 6. Charity Funds Breakdown
    funds_res = await db.execute(text(f"""
        SELECT
            c.item_cd,
            c.item_desc,
            COALESCE(c.item_e_desc, c.item_desc) AS item_e_desc,
            COUNT(i.so_id) FILTER (WHERE i.status_no = 1) AS active_so_count,
            COALESCE(SUM(i.monthly_pay) FILTER (WHERE i.status_no = 1), 0) AS monthly_portfolio_bhd,
            COALESCE(mt.collected_bhd, 0) AS ytd_collected_bhd
        FROM lkp_charity_items c
        LEFT JOIN donor_item i ON c.item_cd = i.item_no AND ({di_where})
        LEFT JOIN (
            SELECT m.item_no, SUM(m.paid_sum) FILTER (WHERE m.status_no = 1) AS collected_bhd
            FROM money_trans m
            WHERE m.month_year >= :yr_start AND m.month_year <= :yr_end
              AND {mt_where}
            GROUP BY m.item_no
        ) mt ON c.item_cd = mt.item_no
        GROUP BY c.item_cd, c.item_desc, c.item_e_desc, mt.collected_bhd
        HAVING COUNT(i.so_id) FILTER (WHERE i.status_no = 1) > 0 OR COALESCE(mt.collected_bhd, 0) > 0
        ORDER BY COALESCE(SUM(i.monthly_pay) FILTER (WHERE i.status_no = 1), 0) DESC
    """), params)

    charity_funds = []
    for r in funds_res:
        m_bhd = round(float(r.monthly_portfolio_bhd or 0), 3)
        charity_funds.append({
            "item_cd": r.item_cd,
            "item_name_ar": r.item_desc,
            "item_name_en": r.item_e_desc,
            "active_so_count": int(r.active_so_count or 0),
            "monthly_portfolio_bhd": m_bhd,
            "ytd_collected_bhd": round(float(r.ytd_collected_bhd or 0), 3),
            "portfolio_share_pct": round((m_bhd / expected_monthly_bhd) * 100, 1) if expected_monthly_bhd > 0 else 0.0
        })

    # 7. High-Value At-Risk Watchlist (Top 25 active SOs delayed >= 2 months ordered by monthly_pay DESC)
    watchlist_res = await db.execute(text(f"""
        SELECT
            i.so_id,
            i.donor_no,
            COALESCE(NULLIF(TRIM(d.donor_ename), ''), d.donor_name) AS donor_name_en,
            d.donor_name AS donor_name_ar,
            COALESCE(d.donor_mobile, d.donor_tel2, d.donor_tel1, '-') AS mobile,
            COALESCE(b.bank_e_desc, b.bank_desc) AS bank_name,
            i.monthly_pay,
            TO_CHAR(lp.last_paid_month, 'YYYY-MM') AS last_paid_month,
            GREATEST(0, (
                EXTRACT(YEAR FROM AGE(DATE_TRUNC('month', CAST(:ref_month AS DATE)), DATE_TRUNC('month', COALESCE(lp.last_paid_month, i.donation_start_date)))) * 12 +
                EXTRACT(MONTH FROM AGE(DATE_TRUNC('month', CAST(:ref_month AS DATE)), DATE_TRUNC('month', COALESCE(lp.last_paid_month, i.donation_start_date))))
            )::int) AS delay_months,
            TO_CHAR(lf.call_date, 'YYYY-MM-DD') AS last_call_date,
            COALESCE(lf.result_enm, lf.result_nm, 'No Follow-up') AS last_followup_result
        FROM donor_item i
        JOIN donor_master d ON i.donor_no = d.donor_no
        LEFT JOIN lkp_banks b ON i.bank2_cd = b.bank_cd
        LEFT JOIN so_payment_summary lp ON i.so_id = lp.so_id
        LEFT JOIN (
            SELECT DISTINCT ON (f.donor_no) f.donor_no, f.call_date, r.result_nm, r.result_enm
            FROM donor_followup f
            LEFT JOIN lkp_follow_results r ON f.call_result_cd = r.result_cd
            ORDER BY f.donor_no, f.call_date DESC, f.trans_id DESC
        ) lf ON i.donor_no = lf.donor_no
        WHERE i.status_no = 1 AND {di_where}
          AND GREATEST(0, (
                EXTRACT(YEAR FROM AGE(DATE_TRUNC('month', CAST(:ref_month AS DATE)), DATE_TRUNC('month', COALESCE(lp.last_paid_month, i.donation_start_date)))) * 12 +
                EXTRACT(MONTH FROM AGE(DATE_TRUNC('month', CAST(:ref_month AS DATE)), DATE_TRUNC('month', COALESCE(lp.last_paid_month, i.donation_start_date))))
              )::int) >= 2
        ORDER BY i.monthly_pay DESC, delay_months DESC
        LIMIT 25
    """), params)

    high_value_at_risk = [
        {
            "so_id": int(r.so_id),
            "donor_no": int(r.donor_no),
            "donor_name_en": r.donor_name_en,
            "donor_name_ar": r.donor_name_ar,
            "mobile": r.mobile,
            "bank_name": r.bank_name,
            "monthly_pay": round(float(r.monthly_pay or 0), 3),
            "last_paid_month": r.last_paid_month or "Never Paid",
            "delay_months": int(r.delay_months or 0),
            "at_risk_bhd": round(float(r.monthly_pay or 0) * int(r.delay_months or 0), 3),
            "last_call_date": r.last_call_date or "-",
            "last_followup_result": r.last_followup_result
        }
        for r in watchlist_res
    ]

    # 8. Follow-up Outcomes & Delay Reasons Intelligence
    outcomes_res = await db.execute(text("""
        SELECT
            r.result_cd,
            r.result_nm,
            COALESCE(r.result_enm, r.result_nm) AS result_enm,
            COALESCE(df.cnt, 0) + COALESCE(dif.cnt, 0) AS total_calls
        FROM lkp_follow_results r
        LEFT JOIN (SELECT call_result_cd, COUNT(*) AS cnt FROM donor_followup GROUP BY call_result_cd) df ON r.result_cd = df.call_result_cd
        LEFT JOIN (SELECT call_result_cd, COUNT(*) AS cnt FROM donor_item_followup GROUP BY call_result_cd) dif ON r.result_cd = dif.call_result_cd
        ORDER BY total_calls DESC
    """))
    followup_outcomes = [
        {
            "result_cd": int(r.result_cd),
            "result_ar": r.result_nm,
            "result_en": r.result_enm,
            "total_calls": int(r.total_calls or 0)
        }
        for r in outcomes_res
    ]

    reasons_res = await db.execute(text("""
        SELECT
            dr.reason_cd,
            dr.reason_nm,
            COALESCE(dr.reason_enm, dr.reason_nm) AS reason_enm,
            COALESCE(dif.cnt, 0) AS cases_count
        FROM lkp_delay_reasons dr
        LEFT JOIN (SELECT delay_reason_cd, COUNT(*) AS cnt FROM donor_item_followup WHERE delay_reason_cd IS NOT NULL GROUP BY delay_reason_cd) dif ON dr.reason_cd = dif.delay_reason_cd
        ORDER BY cases_count DESC
    """))
    delay_reasons = [
        {
            "reason_cd": int(r.reason_cd),
            "reason_ar": r.reason_nm,
            "reason_en": r.reason_enm,
            "cases_count": int(r.cases_count or 0)
        }
        for r in reasons_res
    ]

    delayed_over_2_count = aging_map["followup_needed"]["count"] + aging_map["critical_risk"]["count"]
    delayed_over_2_bhd = round(aging_map["followup_needed"]["monthly_bhd"] + aging_map["critical_risk"]["monthly_bhd"], 3)

    return {
        "meta": {
            "year": year,
            "prev_year": prev_year,
            "reference_billing_month": str(ref_month)[:7],
            "accepted_delayed_months": accepted_delay,
            "grace_period_months": grace_months,
            "available_years": list(range(2026, 2014, -1)),
            "banks": all_banks,
            "charity_items": all_items
        },
        "kpis": {
            "active_donors": int(d_row.active_donors or 0),
            "inactive_donors": int(d_row.inactive_donors or 0),
            "total_donors": int(d_row.total_donors or 0),
            "active_so_donors": int(p_row.active_so_donors or 0),
            "active_so_count": active_so_count,
            "inactive_so_count": inactive_so_count,
            "expected_monthly_bhd": expected_monthly_bhd,
            "expected_annual_bhd": round(expected_monthly_bhd * 12, 3),
            "avg_so_bhd": avg_so_bhd,
            "ytd_collected_bhd": ytd_collected_bhd,
            "ytd_paid_installments": ytd_paid_installments,
            "ytd_unpaid_bhd": ytd_unpaid_bhd,
            "ytd_unpaid_installments": ytd_unpaid_installments,
            "collection_efficiency_pct": collection_efficiency_pct,
            "prev_year_collected_bhd": cmp_base,
            "yoy_growth_pct": yoy_growth_pct,
            "ytd_general_bank_bhd": ytd_general_bank_bhd,
            "ytd_total_inflow_bhd": round(ytd_collected_bhd + ytd_general_bank_bhd, 3),
            "delayed_over_grace_count": delayed_over_2_count,
            "delayed_over_grace_monthly_bhd": delayed_over_2_bhd,
            "critical_risk_count": aging_map["critical_risk"]["count"],
            "critical_risk_monthly_bhd": aging_map["critical_risk"]["monthly_bhd"],
            "new_so_in_year_count": int(p_row.new_so_count or 0),
            "new_so_in_year_bhd": round(float(p_row.new_so_bhd or 0), 3),
            "deactivated_in_year_count": deact_count,
            "deactivated_in_year_bhd": deact_bhd,
            "net_so_movement_count": int(p_row.new_so_count or 0) - deact_count,
            "net_so_movement_bhd": round(float(p_row.new_so_bhd or 0) - deact_bhd, 3),
            "stmnt_total_rows": stmnt_total_rows,
            "stmnt_matched_rows": stmnt_matched_rows,
            "stmnt_unmatched_rows": stmnt_unmatched_rows,
            "stmnt_match_rate_pct": stmnt_match_rate_pct,
            "latest_stmnt_month": latest_overall_stmnt or "N/A"
        },
        "monthly_trend": monthly_trend,
        "banks_performance": banks_performance,
        "delinquency_aging": aging_map,
        "charity_funds": charity_funds,
        "watchlists": {
            "high_value_at_risk": high_value_at_risk,
            "followup_outcomes": followup_outcomes,
            "delay_reasons": delay_reasons
        }
    }

# ----------------- Data Views & Export Center (/reports-views) -----------------
@app.get("/reports-views", response_class=HTMLResponse)
async def data_views_export_page(request: Request):
    return templates.TemplateResponse("data_views_export.html", {"request": request})

def _paginate_view_response(payload: dict, page: int, page_size: int, export_all: bool) -> dict:
    all_rows = payload.get("rows") or []
    total_rows = len(all_rows)
    eff_page_size = max(1, int(page_size or 100))
    total_pages = max(1, (total_rows + eff_page_size - 1) // eff_page_size)
    cur_page = max(1, min(int(page or 1), total_pages))
    offset = (cur_page - 1) * eff_page_size
    if not export_all:
        payload["rows"] = all_rows[offset : offset + eff_page_size]
    payload["pagination"] = {
        "page": cur_page,
        "page_size": eff_page_size,
        "total_rows": total_rows,
        "total_pages": total_pages,
        "offset": 0 if export_all else offset
    }
    return payload

@app.get("/api/reports/views")
async def get_data_view_export_api(
    view_key: str = "ACTIVE_DON_ADDRESS",
    search_q: Optional[str] = None,
    min_amt: Optional[float] = None,
    status_filter: Optional[str] = "ACTIVE",
    contact_only: Optional[bool] = False,
    page: int = 1,
    page_size: int = 100,
    export_all: bool = False,
    db: AsyncSession = Depends(get_db)
):
    setup_res = await db.execute(text("SELECT so_min_amt FROM sys_donor_setup LIMIT 1"))
    setup_row = setup_res.first()
    default_min_amt = float(setup_row.so_min_amt or 10.0) if setup_row else 10.0

    vk = (view_key or "ACTIVE_DON_ADDRESS").strip().upper()
    params: dict[str, Any] = {}
    q_str = (search_q or "").strip()

    if vk == "ACTIVE_DON_ADDRESS":
        where_parts = ["1=1"]
        if q_str:
            where_parts.append("(CAST(donor_no AS TEXT) ILIKE :q OR donor_name ILIKE :q OR donor_ename ILIKE :q OR address ILIKE :q OR donor_tel2 ILIKE :q)")
            params["q"] = f"%{q_str}%"
        sql = text(f"""
            SELECT donor_no, prefix_name, COALESCE(NULLIF(TRIM(donor_ename), ''), donor_name) AS donor_ename, carenm, address, sumpay, st_no, donor_tel2
            FROM vw_active_don_address
            WHERE {' AND '.join(where_parts)}
            ORDER BY sumpay DESC, donor_no ASC
        """)
        res = await db.execute(sql, params)
        rows = []
        total_amt = 0.0
        for r in res:
            m = dict(r._mapping)
            m["sumpay"] = round(float(m["sumpay"] or 0), 3)
            total_amt = round(total_amt + m["sumpay"], 3)
            rows.append(m)
        return _paginate_view_response({
            "view_key": vk,
            "view_title_en": "Active Donors — Street Address Mailing List (ACTIVE_DON_ADDRESS)",
            "view_title_ar": "Active Donors with Street Addresses & Monthly Standing Orders",
            "db_view_name": "vw_active_don_address",
            "default_min_amt": default_min_amt,
            "columns": ["donor_no", "prefix_name", "donor_ename", "carenm", "address", "sumpay", "st_no", "donor_tel2"],
            "headers": ["Donor No", "Prefix", "Donor Name", "Care / Salutation", "Street Address", "Total Monthly (BHD)", "SO Count", "Mobile / Tel 2"],
            "rows": rows,
            "summary": {"total_rows": len(rows), "total_amount": total_amt}
        }, page, page_size, export_all)

    elif vk == "ACTIVE_DON_PBOX":
        where_parts = ["1=1"]
        if status_filter == "ACTIVE":
            where_parts.append("so_status_group = 1")
        elif status_filter == "INACTIVE":
            where_parts.append("so_status_group = 2")
        if q_str:
            where_parts.append("(CAST(donor_no AS TEXT) ILIKE :q OR donor_name ILIKE :q OR donor_ename ILIKE :q OR p_box ILIKE :q OR donor_tel2 ILIKE :q)")
            params["q"] = f"%{q_str}%"
        sql = text(f"""
            SELECT donor_no, prefix_name, COALESCE(NULLIF(TRIM(donor_ename), ''), donor_name) AS donor_ename, carenm, p_box, sumpay, st_no, donor_tel2,
                   CASE WHEN so_status_group = 1 THEN 'Active' ELSE 'Inactive' END AS status_label
            FROM vw_active_don_pbox
            WHERE {' AND '.join(where_parts)}
            ORDER BY sumpay DESC, donor_no ASC
        """)
        res = await db.execute(sql, params)
        rows = []
        total_amt = 0.0
        for r in res:
            m = dict(r._mapping)
            m["sumpay"] = round(float(m["sumpay"] or 0), 3)
            total_amt = round(total_amt + m["sumpay"], 3)
            rows.append(m)
        return _paginate_view_response({
            "view_key": vk,
            "view_title_en": "Donors — P.O. Box Mailing List (ACTIVE_DON_PBOX)",
            "view_title_ar": "Donors Mailing List with Registered P.O. Box",
            "db_view_name": "vw_active_don_pbox",
            "default_min_amt": default_min_amt,
            "columns": ["donor_no", "prefix_name", "donor_ename", "carenm", "p_box", "sumpay", "st_no", "donor_tel2", "status_label"],
            "headers": ["Donor No", "Prefix", "Donor Name", "Care / Salutation", "P.O. Box", "Total Monthly (BHD)", "SO Count", "Mobile / Tel 2", "SO Status"],
            "rows": rows,
            "summary": {"total_rows": len(rows), "total_amount": total_amt}
        }, page, page_size, export_all)

    elif vk == "SMS_SUBSCRIPTIONS":
        where_parts = ["1=1"]
        if status_filter == "ACTIVE":
            where_parts.append("status_no = 1")
        elif status_filter == "INACTIVE":
            where_parts.append("status_no <> 1")
        if contact_only:
            where_parts.append("donor_contact = 1")
        if q_str:
            where_parts.append("(CAST(donor_no AS TEXT) ILIKE :q OR donor_name ILIKE :q OR donor_ename ILIKE :q OR donor_mobile ILIKE :q OR donor_tel1 ILIKE :q OR donor_tel2 ILIKE :q)")
            params["q"] = f"%{q_str}%"
        sql = text(f"""
            SELECT donor_no, COALESCE(NULLIF(TRIM(donor_ename), ''), donor_name) AS donor_ename, donor_mobile, donor_tel1, donor_tel2,
                   CASE WHEN status_no = 1 THEN 'Active' ELSE 'Inactive' END AS donor_status
            FROM vw_sms_subscriptions
            WHERE {' AND '.join(where_parts)}
            ORDER BY donor_no ASC
        """)
        res = await db.execute(sql, params)
        rows = [dict(r._mapping) for r in res]
        return _paginate_view_response({
            "view_key": vk,
            "view_title_en": "Donor SMS & Phone Subscriptions List (SMS_SUBSCRIPTIONS)",
            "view_title_ar": "Donor Mobile & Telephone Directory for SMS Campaigns",
            "db_view_name": "vw_sms_subscriptions",
            "default_min_amt": default_min_amt,
            "columns": ["donor_no", "donor_ename", "donor_mobile", "donor_tel1", "donor_tel2", "donor_status"],
            "headers": ["Donor No", "Donor Name", "Mobile", "Tel 1 (Home/Office)", "Tel 2 (Mobile 2)", "Status"],
            "rows": rows,
            "summary": {"total_rows": len(rows), "total_amount": None}
        }, page, page_size, export_all)

    elif vk == "UPTO_SPECIFIC_AMT":
        eff_min = float(min_amt) if (min_amt is not None and min_amt >= 0) else default_min_amt
        params["min_amt"] = eff_min
        where_parts = ["a.status_no = 1", "a.monthly_pay >= :min_amt"]
        if contact_only:
            where_parts.append("COALESCE(b.donor_contact, 1) = 1")
        if q_str:
            where_parts.append("(CAST(a.donor_no AS TEXT) ILIKE :q OR CAST(a.so_id AS TEXT) ILIKE :q OR b.donor_name ILIKE :q OR COALESCE(b.donor_ename, '') ILIKE :q OR COALESCE(b.donor_tel2, '') ILIKE :q)")
            params["q"] = f"%{q_str}%"
        sql = text(f"""
            SELECT
                a.donor_no,
                a.so_id,
                a.monthly_pay,
                COALESCE(NULLIF(TRIM(b.donor_ename), ''), b.donor_name) AS donor_ename,
                COALESCE(b.donor_tel2, b.donor_mobile, '') AS mobile,
                CASE WHEN b.donor_p_box IS NOT NULL THEN 'P.BOX: ' || b.donor_p_box::text ELSE '' END AS p_box,
                'FLAT:' || COALESCE(b.donor_flat::text, '') ||
                ' BLD: ' || COALESCE(b.donor_building, '') ||
                ' ROAD: ' || COALESCE(b.donor_road, '') ||
                ' BLOCK: ' || COALESCE(b.donor_block::text, '') AS address
            FROM donor_item a
            JOIN donor_master b ON a.donor_no = b.donor_no
            WHERE {' AND '.join(where_parts)}
            ORDER BY a.monthly_pay DESC, a.donor_no ASC
        """)
        res = await db.execute(sql, params)
        rows = []
        total_amt = 0.0
        for r in res:
            m = dict(r._mapping)
            m["monthly_pay"] = round(float(m["monthly_pay"] or 0), 3)
            total_amt = round(total_amt + m["monthly_pay"], 3)
            rows.append(m)
        return _paginate_view_response({
            "view_key": vk,
            "view_title_en": f"Active Standing Orders >= {eff_min:.3f} BHD (UPTO_SPECIFIC_AMT / UPTO5 / UPTO10 / UPTO25)",
            "view_title_ar": f"Active Standing Orders with Monthly Commitment >= {eff_min:.3f} BHD",
            "db_view_name": "vw_upto_specific_amt",
            "default_min_amt": default_min_amt,
            "applied_min_amt": eff_min,
            "columns": ["donor_no", "so_id", "monthly_pay", "donor_ename", "mobile", "p_box", "address"],
            "headers": ["Donor No", "SO ID", "Monthly Pay (BHD)", "Donor Name", "Mobile / Tel 2", "P.O. Box", "Street Address"],
            "rows": rows,
            "summary": {"total_rows": len(rows), "total_amount": total_amt}
        }, page, page_size, export_all)

    elif vk == "VW_STANDING_ORDERS_SUMMARY":
        where_parts = ["1=1"]
        if status_filter == "ACTIVE":
            where_parts.append("status_no = 1")
        elif status_filter == "INACTIVE":
            where_parts.append("status_no <> 1")
        if q_str:
            where_parts.append("(CAST(so_id AS TEXT) ILIKE :q OR CAST(donor_no AS TEXT) ILIKE :q OR donor_name ILIKE :q OR COALESCE(donor_ename, '') ILIKE :q OR COALESCE(bank_e_desc, '') ILIKE :q OR COALESCE(sort_field, '') ILIKE :q)")
            params["q"] = f"%{q_str}%"
        sql = text(f"""
            SELECT
                so_id, donor_no, COALESCE(NULLIF(TRIM(donor_ename), ''), donor_name) AS donor_ename,
                COALESCE(donor_mobile, donor_tel2, donor_tel1, '') AS mobile,
                COALESCE(bank_e_desc, bank_desc, '') AS bank_name,
                COALESCE(sort_field, '') AS sort_field,
                monthly_pay,
                TO_CHAR(donation_start_date, 'YYYY-MM-DD') AS start_date,
                COALESCE(TO_CHAR(last_paid_month, 'YYYY-MM'), 'Never Paid') AS last_paid_month,
                actual_delay_months,
                CASE WHEN status_no = 1 THEN 'Active' ELSE 'Inactive' END AS so_status,
                last_followup_summary
            FROM vw_standing_orders_summary
            WHERE {' AND '.join(where_parts)}
            ORDER BY monthly_pay DESC, so_id ASC
        """)
        res = await db.execute(sql, params)
        rows = []
        total_amt = 0.0
        for r in res:
            m = dict(r._mapping)
            m["monthly_pay"] = round(float(m["monthly_pay"] or 0), 3)
            total_amt = round(total_amt + m["monthly_pay"], 3)
            rows.append(m)
        return _paginate_view_response({
            "view_key": vk,
            "view_title_en": "Unified Standing Orders & Delay Summary (vw_standing_orders_summary)",
            "view_title_ar": "Unified View of Standing Orders, Delay Months, and Follow-up Summary",
            "db_view_name": "vw_standing_orders_summary",
            "default_min_amt": default_min_amt,
            "columns": ["so_id", "donor_no", "donor_ename", "mobile", "bank_name", "sort_field", "monthly_pay", "start_date", "last_paid_month", "actual_delay_months", "so_status", "last_followup_summary"],
            "headers": ["SO ID", "Donor No", "Donor Name", "Mobile", "Bank", "Bank Code", "Monthly (BHD)", "Start Date", "Last Paid", "Delay (Mo)", "Status", "Last Follow-up"],
            "rows": rows,
            "summary": {"total_rows": len(rows), "total_amount": total_amt}
        }, page, page_size, export_all)

    raise HTTPException(status_code=400, detail=f"Unknown view_key: {view_key}")


