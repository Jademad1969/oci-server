from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from pydantic import BaseModel, field_validator
from typing import Optional, Any
from datetime import date
import os

from app.database import get_db

app = FastAPI(title="DIC Standing Orders System - Bahrain")
templates = Jinja2Templates(directory="app/templates")

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
        SELECT i.*, b.bank_desc, c.item_desc,
               COALESCE(
                   (SELECT (EXTRACT(YEAR FROM AGE(DATE_TRUNC('month', CURRENT_DATE), MAX(m.month_year))) * 12 +
                            EXTRACT(MONTH FROM AGE(DATE_TRUNC('month', CURRENT_DATE), MAX(m.month_year))))::int
                    FROM money_trans m WHERE m.so_id = i.so_id AND m.status_no = 1),
                   (EXTRACT(YEAR FROM AGE(DATE_TRUNC('month', CURRENT_DATE), DATE_TRUNC('month', i.donation_start_date))) * 12 +
                    EXTRACT(MONTH FROM AGE(DATE_TRUNC('month', CURRENT_DATE), DATE_TRUNC('month', i.donation_start_date))))::int
               ) AS delay_months,
               (SELECT COUNT(*) FROM donor_followup f WHERE f.donor_no = i.donor_no) AS has_followup
        FROM donor_item i
        LEFT JOIN lkp_banks b ON i.bank2_cd = b.bank_cd
        LEFT JOIN lkp_charity_items c ON i.item_no = c.item_cd
        ORDER BY i.so_id ASC
    """)
    so_res = await db.execute(so_query)
    so_by_donor = {}
    for row in so_res:
        item = dict(row._mapping)
        item["monthly_pay"] = float(item["monthly_pay"])
        item["donation_start_date"] = item["donation_start_date"].strftime("%Y-%m-%d") if item["donation_start_date"] else ""
        item["donation_expected_edate"] = item["donation_expected_edate"].strftime("%Y-%m-%d") if item["donation_expected_edate"] else ""
        item["through_form"] = (item["through_form"] == 1)
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
