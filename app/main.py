from fastapi import FastAPI, Request, Depends, HTTPException, Form
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

DEFAULT_PAGE_KEYS = ("about", "donors", "audit", "reconcile", "followup", "users")

def normalize_page_permissions(role_code: Optional[str], raw_perms: Any) -> dict:
    if isinstance(raw_perms, str):
        try:
            raw_perms = json.loads(raw_perms)
        except Exception:
            raw_perms = {}
    if not isinstance(raw_perms, dict):
        raw_perms = {}

    # If explicit page keys already exist in raw_perms, honor them
    if any(k in raw_perms for k in DEFAULT_PAGE_KEYS):
        base = {k: raw_perms.get(k, "none") for k in DEFAULT_PAGE_KEYS}
        base["about"] = raw_perms.get("about", "view")
        for k, v in base.items():
            if v not in ("none", "view", "edit"):
                base[k] = "none"
        return base

    # Fallback based on legacy role_code
    code = (role_code or "").upper()
    if code in ("READ_WRITE", "ADMIN"):
        return {k: "edit" for k in DEFAULT_PAGE_KEYS}
    return {
        "about": "view",
        "donors": "view",
        "audit": "view",
        "reconcile": "view",
        "followup": "view",
        "users": "none",
    }

def resolve_page_key(path: str) -> str:
    if path.startswith("/users") or path.startswith("/api/users"):
        return "users"
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

@app.get("/api/init-data")
async def get_initial_screen_data(db: AsyncSession = Depends(get_db)):
    banks_res = await db.execute(text("SELECT bank_cd, bank_desc, bank_e_desc, auto_so_based_code, run_deactivate_delayed_so FROM lkp_banks ORDER BY bank_cd"))
    banks = [dict(r._mapping) for r in banks_res]

    items_lkp_res = await db.execute(text("SELECT item_cd, item_desc FROM lkp_charity_items ORDER BY item_cd"))
    charity_items = [dict(r._mapping) for r in items_lkp_res]

    donors_query = text("""
        SELECT d.*, COALESCE(t.town_nm, '') AS town_name,
               (SELECT COUNT(*) FROM donor_followup f WHERE f.donor_no = d.donor_no) AS donor_followup_count
        FROM donor_master d
        LEFT JOIN lkp_towns t ON d.donor_block = t.block_cd
        ORDER BY d.donor_no ASC
    """)
    donors_res = await db.execute(donors_query)
    donors_list = []

    so_query = text("""
        SELECT *, actual_delay_months AS delay_months
        FROM vw_standing_orders_summary
        ORDER BY so_id ASC
    """)
    # جلب المتابعات القديمة على مستوى الاستقطاع لتجنب أي خطأ
    old_f_res = await db.execute(text("""
        SELECT f.trans_id, f.so_id, f.donor_no, f.item_no,
               TO_CHAR(f.donation_start_date, 'YYYY-MM-DD') AS donation_start_date,
               TO_CHAR(f.call_date, 'YYYY-MM-DD') AS call_date, f.call_time, f.call_by,
               f.call_result_cd, f.delay_reason_cd, f.call_result_notes, f.delayed_months,
               TO_CHAR(f.last_paid_month, 'YYYY-MM-DD') AS last_paid_month,
               r.result_nm, d.reason_nm
        FROM donor_item_followup f
        LEFT JOIN lkp_follow_results r ON f.call_result_cd = r.result_cd
        LEFT JOIN lkp_delay_reasons d ON f.delay_reason_cd = d.reason_cd
    """))
    old_followups_by_so = {}
    for row in old_f_res:
        item_f = dict(row._mapping)
        old_followups_by_so.setdefault(item_f["so_id"], []).append(item_f)

    so_res = await db.execute(so_query)
    so_by_donor = {}
    for row in so_res:
        item = dict(row._mapping)
        item["monthly_pay"] = float(item["monthly_pay"])
        item["donation_start_date"] = item["donation_start_date"].strftime("%Y-%m-%d") if item["donation_start_date"] else ""
        item["donation_expected_edate"] = item["donation_expected_edate"].strftime("%Y-%m-%d") if item["donation_expected_edate"] else ""
        item["through_form"] = (item["through_form"] == 1)
        item["item_followups"] = old_followups_by_so.get(item["so_id"], [])
        
        so_by_donor.setdefault(item["donor_no"], []).append(item)

    for d_row in donors_res:
        d = dict(d_row._mapping)
        for k, v in d.items():
            if v is None and k not in ("donor_flat", "donor_block", "donor_p_box"):
                d[k] = ""
        d["append_date"] = d["append_date"].strftime("%Y-%m-%d") if hasattr(d["append_date"], "strftime") else str(d["append_date"] or "")
        d["last_update"] = d["last_update"].strftime("%Y-%m-%d") if hasattr(d["last_update"], "strftime") else str(d["last_update"] or "")
        d["call_date"] = d["call_date"].strftime("%Y-%m-%d") if hasattr(d["call_date"], "strftime") else str(d["call_date"] or "")
        d["items"] = so_by_donor.get(d["donor_no"], [])
        donors_list.append(d)

    return {"banks": banks, "charity_items": charity_items, "donors": donors_list}

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
               i.status_no, d.donor_name, d.donor_ename,
               (SELECT MAX(m.month_year) FROM money_trans m WHERE m.so_id = i.so_id AND m.status_no = 1) AS last_payment
        FROM donor_item i
        JOIN donor_master d ON i.donor_no = d.donor_no
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
               d.donor_name, d.donor_ename,
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
        SELECT l.*, d.donor_name
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

@app.get("/followup", response_class=HTMLResponse)
async def donor_followup_screen(request: Request):
    return templates.TemplateResponse("donor_followup.html", {"request": request})

@app.get("/api/followup/data")
async def get_followup_screen_data(db: AsyncSession = Depends(get_db)):
    res_lkp = await db.execute(text("SELECT result_cd, result_nm FROM lkp_follow_results ORDER BY result_cd"))
    follow_results = [dict(r._mapping) for r in res_lkp]

    reason_lkp = await db.execute(text("SELECT reason_cd, reason_nm FROM lkp_delay_reasons ORDER BY reason_cd"))
    delay_reasons = [dict(r._mapping) for r in reason_lkp]

    # جلب المتابعات على مستوى المتبرع شاملة سبب التأخير وطريقة التواصل
    f_res = await db.execute(text("""
        SELECT f.*, r.result_nm, COALESCE(dr.reason_nm, 'غير محدد') AS reason_nm,
               CASE f.contact_method
                   WHEN 1 THEN 'اتصال هاتفي'
                   WHEN 2 THEN 'رسالة (SMS/واتساب)'
                   WHEN 3 THEN 'بريد إلكتروني (Email)'
                   ELSE 'اتصال هاتفي'
               END AS contact_method_nm
        FROM donor_followup f
        LEFT JOIN lkp_follow_results r ON f.call_result_cd = r.result_cd
        LEFT JOIN lkp_delay_reasons dr ON f.delay_reason_cd = dr.reason_cd
        ORDER BY f.call_date DESC, f.trans_id DESC
    """))
    followups_by_donor = {}
    for row in f_res:
        item = dict(row._mapping)
        item["call_date"] = item["call_date"].strftime("%Y-%m-%d") if item["call_date"] else ""
        item["append_date"] = item["append_date"].strftime("%Y-%m-%d") if item["append_date"] else ""
        followups_by_donor.setdefault(item["donor_no"], []).append(item)

    # جلب المتابعات القديمة على مستوى الاستقطاع (إن وجدت)
    old_f_res = await db.execute(text("""
        SELECT f.trans_id, f.so_id, f.donor_no, f.item_no, 
               TO_CHAR(f.donation_start_date, 'YYYY-MM-DD') AS donation_start_date,
               TO_CHAR(f.call_date, 'YYYY-MM-DD') AS call_date, f.call_time, f.call_by,
               f.call_result_cd, f.delay_reason_cd, f.call_result_notes, f.delayed_months,
               TO_CHAR(f.last_paid_month, 'YYYY-MM-DD') AS last_paid_month,
               r.result_nm, d.reason_nm
        FROM donor_item_followup f
        LEFT JOIN lkp_follow_results r ON f.call_result_cd = r.result_cd
        LEFT JOIN lkp_delay_reasons d ON f.delay_reason_cd = d.reason_cd
        ORDER BY f.call_date DESC
    """))
    old_followups_by_donor = {}
    old_followups_by_so = {}
    for row in old_f_res:
        item = dict(row._mapping)
        old_followups_by_donor.setdefault(item["donor_no"], []).append(item)
        old_followups_by_so.setdefault(item["so_id"], []).append(item)

    # جلب الاستقطاعات شاملة التأخير الفعلي والافتراضي وملاحظات السداد وآخر متابعة من الـ View الموحد
    so_res = await db.execute(text("""
        SELECT *, actual_delay_months AS delay_months
        FROM vw_standing_orders_summary
        ORDER BY so_id ASC
    """))
    so_by_donor = {}
    for row in so_res:
        item = dict(row._mapping)
        item["monthly_pay"] = float(item["monthly_pay"])
        item["donation_start_date"] = item["donation_start_date"].strftime("%Y-%m-%d") if item["donation_start_date"] else ""
        item["donation_expected_edate"] = item["donation_expected_edate"].strftime("%Y-%m-%d") if item["donation_expected_edate"] else ""
        item["last_paid_month"] = item["last_paid_month"].strftime("%Y-%m-%d") if item["last_paid_month"] else ""
        item["through_form"] = (item["through_form"] == 1)
        
        so_by_donor.setdefault(item["donor_no"], []).append(item)

    donors_res = await db.execute(text("SELECT * FROM donor_master ORDER BY donor_no ASC"))
    donors_list = []
    for d_row in donors_res:
        d = dict(d_row._mapping)
        for k, v in d.items():
            if v is None and k not in ("donor_flat", "donor_block", "donor_p_box"):
                d[k] = ""
            elif hasattr(v, "strftime"):
                d[k] = v.strftime("%Y-%m-%d")
        d["items"] = so_by_donor.get(d["donor_no"], [])
        d["followups"] = followups_by_donor.get(d["donor_no"], [])
        d["old_item_followups"] = old_followups_by_donor.get(d["donor_no"], [])
        d["max_delay"] = max((i["delay_months"] for i in d["items"]), default=0)
        donors_list.append(d)

    # استخراج كافة متابعات الاستقطاعات لترسل دفعة واحدة للواجهة وتتم فلترتها تفاعلياً
    all_item_res = await db.execute(text("""
        SELECT f.trans_id, f.so_id, f.donor_no, f.item_no,
               TO_CHAR(f.donation_start_date, 'YYYY-MM-DD') AS donation_start_date,
               TO_CHAR(f.call_date, 'YYYY-MM-DD') AS call_date, f.call_time, f.call_by,
               f.call_result_cd, f.delay_reason_cd, f.call_result_notes, f.delayed_months,
               TO_CHAR(f.last_paid_month, 'YYYY-MM-DD') AS last_paid_month,
               r.result_nm, d.reason_nm
        FROM donor_item_followup f
        LEFT JOIN lkp_follow_results r ON f.call_result_cd = r.result_cd
        LEFT JOIN lkp_delay_reasons d ON f.delay_reason_cd = d.reason_cd
        ORDER BY f.call_date DESC
    """))
    all_item_followups = [dict(r._mapping) for r in all_item_res]
    for itm in all_item_followups:
        for k, v in itm.items():
            if v is None:
                itm[k] = ""
            elif hasattr(v, "strftime"):
                itm[k] = v.strftime("%Y-%m-%d")

    return {
        "donors": donors_list,
        "all_item_followups": all_item_followups,
        "follow_results": follow_results,
        "delay_reasons": delay_reasons
    }

@app.post("/api/followup/add")
async def add_donor_followup(payload: FollowupCreateSchema, db: AsyncSession = Depends(get_db)):
    # اسم الموظف يؤخذ إجبارياً من جلسة النظام (أو المستخدم النشط) ولا يمكن للمستخدم تعديله أو حذف السجل
    current_logged_in_employee = "HASAN"
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

@app.get("/api/followup/export-csv")
async def export_followup_excel_csv(db: AsyncSession = Depends(get_db)):
    """تصدير تقرير المتابعة الشامل من vw_standing_orders_summary مباشرة بتنسيق CSV متوافق مع Excel"""
    query = text("""
        SELECT donor_no, donor_name, donor_tel1, donor_tel2, donor_mobile,
               so_id, bank_desc, monthly_pay,
               CASE WHEN status_no = 1 THEN 'فعال' ELSE 'غير فعال' END AS so_status,
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
        "كود المتبرع", "اسم المتبرع", "هاتف", "نقال 1", "نقال 2",
        "رقم الاستقطاع SO", "البنك", "المبلغ الشهري", "حالة الاستقطاع",
        "تاريخ آخر سداد", "أشهر التأخير الفعلي", "أشهر التأخير الافتراضي",
        "ملاحظات السداد", "إجمالي استقطاعات المتبرع", "الاستقطاعات الفعالة للمتبرع", "آخر متابعة ونتيجتها"
    ])
    for r in res:
        writer.writerow([
            r.donor_no, r.donor_name, r.donor_tel1 or "", r.donor_tel2 or "", r.donor_mobile or "",
            r.so_id, r.bank_desc or "", float(r.monthly_pay), r.so_status,
            r.last_paid_month.strftime("%Y-%m-%d") if r.last_paid_month else "لا يوجد",
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

class UserRoleUpdateSchema(BaseModel):
    role_id: int

class UserPasswordUpdateSchema(BaseModel):
    password: str

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

    page_perms = normalize_page_permissions(user_data.get("role_code"), user_data.get("permissions"))
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
    res = await db.execute(text("""
        SELECT u.user_id, u.username, u.full_name_ar, u.full_name_en, u.role_id, u.is_active, r.role_code, r.role_name_en, r.permissions
        FROM sys_users u
        JOIN sys_roles r ON u.role_id = r.role_id
        ORDER BY u.user_id ASC
    """))
    rows = []
    for r in res:
        item = dict(r._mapping)
        item["page_permissions"] = normalize_page_permissions(item.get("role_code"), item.get("permissions"))
        item.pop("permissions", None)
        rows.append(item)
    return {"users": rows}

@app.post("/api/users/{user_id}/page-permissions")
async def update_user_page_permissions_api(user_id: int, payload: UserPagePermissionsSchema, db: AsyncSession = Depends(get_db)):
    u_res = await db.execute(text("SELECT role_id FROM sys_users WHERE user_id = :uid"), {"uid": user_id})
    u_row = u_res.first()
    if not u_row:
        raise HTTPException(status_code=404, detail="User not found.")
    cleaned = {}
    for k in DEFAULT_PAGE_KEYS:
        val = payload.page_permissions.get(k, "none")
        cleaned[k] = val if val in ("none", "view", "edit") else "none"
    cleaned["can_edit"] = any(v == "edit" for k, v in cleaned.items() if k != "users")
    await db.execute(
        text("UPDATE sys_roles SET permissions = CAST(:perms AS jsonb) WHERE role_id = :rid"),
        {"perms": json.dumps(cleaned), "rid": u_row.role_id}
    )
    await db.commit()
    return {"status": "updated", "page_permissions": cleaned}

@app.post("/api/users/create")
async def create_user_api(payload: UserCreateSchema, db: AsyncSession = Depends(get_db)):
    uname = payload.username.strip().upper()
    if not uname or not payload.password:
        raise HTTPException(status_code=400, detail="Username and password are required.")
    pwd_hash = hash_password(payload.password.strip())
    try:
        await db.execute(text("""
            INSERT INTO sys_users (username, password_hash, full_name_ar, full_name_en, role_id, is_active)
            VALUES (:u, :p, :fn, :fn, :rid, true)
        """), {"u": uname, "p": pwd_hash, "fn": payload.full_name.strip() or uname, "rid": payload.role_id})
        await db.commit()
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail=f"Could not create user: {str(e)}")
    return {"status": "created"}

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
