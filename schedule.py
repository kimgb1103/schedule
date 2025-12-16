# -*- coding: utf-8 -*-
import base64
import calendar
import datetime as dt
import hashlib
import json
import os
import secrets
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import streamlit as st
try:  # ★
    from streamlit_calendar import calendar as st_calendar  # ★
except Exception:  # ★
    st_calendar = None  # ★

APP_TITLE = "일정 프로그램"
BUILD_TAG = "BUILD_20251215_A"  # ★
print(f"[{BUILD_TAG}] RUNNING: {os.path.abspath(__file__)}")  # ★
DB_DIR = "data"
DB_PATH = os.path.join(DB_DIR, "schedule_app.db")

DEFAULT_OVERTIME = {
    "ot1": {"label": "초과근무(~19:00)", "amount": 0},
    "ot2": {"label": "초과근무(~20:00)", "amount": 0},
    "ot3": {"label": "휴일근무", "amount": 0},
}

DEFAULT_UI = {  # ★
    "show_leave_summary": True,  # ★
    "show_overtime_summary": True,  # ★
}  # ★

calendar.setfirstweekday(calendar.SUNDAY)  # ★


def _now_iso() -> str:
    return dt.datetime.now().isoformat(timespec="seconds")


def _today() -> dt.date:
    return dt.date.today()


def _safe_float(x: Any, default: float = 0.0) -> float:
    try:
        if x is None or x == "":
            return default
        return float(x)
    except Exception:
        return default


def _safe_int(x: Any, default: int = 0) -> int:
    try:
        if x is None or x == "":
            return default
        return int(float(x))
    except Exception:
        return default


def _parse_date(s: str) -> Optional[dt.date]:
    try:
        return dt.date.fromisoformat(s)
    except Exception:
        return None


def _calendar_payload_to_date(x: Any) -> Optional[dt.date]:  # ★
    try:  # ★
        if x is None:  # ★
            return None  # ★
        s = str(x).strip()  # ★
        if not s:  # ★
            return None  # ★
        if len(s) == 10 and s[4] == "-" and s[7] == "-":  # ★
            return dt.date.fromisoformat(s)  # ★
        if len(s) >= 10 and s[4] == "-" and s[7] == "-":  # ★
            if s.endswith("Z"):  # ★
                s2 = s.replace("Z", "+00:00")  # ★
                dtx = dt.datetime.fromisoformat(s2)  # ★
                kst = dt.timezone(dt.timedelta(hours=9))  # ★
                return dtx.astimezone(kst).date()  # ★
            if "+" in s[10:] or ("-" in s[10:] and s[10:].rfind("-") > 0):  # ★
                dtx = dt.datetime.fromisoformat(s)  # ★
                if dtx.tzinfo is not None:  # ★
                    kst = dt.timezone(dt.timedelta(hours=9))  # ★
                    return dtx.astimezone(kst).date()  # ★
                return dtx.date()  # ★
            return dt.date.fromisoformat(s[:10])  # ★
        return None  # ★
    except Exception:  # ★
        return None  # ★


def _pbkdf2_hash(password: str, salt_b64: str) -> str:
    salt = base64.b64decode(salt_b64.encode("utf-8"))
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return base64.b64encode(dk).decode("utf-8")


def hash_password(password: str) -> Tuple[str, str]:
    salt = secrets.token_bytes(16)
    salt_b64 = base64.b64encode(salt).decode("utf-8")
    pw_hash = _pbkdf2_hash(password, salt_b64)
    return pw_hash, salt_b64


def verify_password(password: str, pw_hash: str, salt_b64: str) -> bool:
    try:
        return _pbkdf2_hash(password, salt_b64) == pw_hash
    except Exception:
        return False


@st.cache_resource
def get_conn() -> sqlite3.Connection:
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_settings_columns() -> None:  # ★
    conn = get_conn()  # ★
    cur = conn.cursor()  # ★
    cols = [r[1] for r in cur.execute("PRAGMA table_info(settings)").fetchall()]  # ★
    if "ui_json" not in cols:  # ★
        cur.execute("ALTER TABLE settings ADD COLUMN ui_json TEXT NOT NULL DEFAULT '{}'")  # ★
        conn.commit()  # ★


def init_db() -> None:
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            pw_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS settings (
            user_id TEXT PRIMARY KEY,
            calendar_height INTEGER NOT NULL,
            annual_leave_json TEXT NOT NULL,
            overtime_json TEXT NOT NULL,
            ui_json TEXT NOT NULL DEFAULT '{}',
            updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(user_id)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            date TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            leave_holiday INTEGER NOT NULL DEFAULT 0,
            leave_annual INTEGER NOT NULL DEFAULT 0,
            leave_half REAL NOT NULL DEFAULT 0.0,
            leave_early REAL NOT NULL DEFAULT 0.0,
            ot1 INTEGER NOT NULL DEFAULT 0,
            ot2 INTEGER NOT NULL DEFAULT 0,
            ot3 INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(user_id)
        )
        """
    )

    conn.commit()
    _ensure_settings_columns()  # ★

    admin = get_user("admin")
    if admin is None:
        pw_hash, salt = hash_password("admin")
        cur.execute(
            """
            INSERT INTO users (user_id, name, email, phone, pw_hash, salt, is_admin, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("admin", "관리자", "admin@local", "000-0000-0000", pw_hash, salt, 1, _now_iso()),
        )
        conn.commit()

    ensure_settings("admin")


def get_user(user_id: str) -> Optional[sqlite3.Row]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
    return cur.fetchone()


def create_user(user_id: str, name: str, email: str, phone: str, password: str) -> Tuple[bool, str]:
    if get_user(user_id) is not None:
        return False, "이미 존재하는 ID 입니다."
    if not user_id or not password:
        return False, "ID/PW 는 필수입니다."
    pw_hash, salt = hash_password(password)
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO users (user_id, name, email, phone, pw_hash, salt, is_admin, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 0, ?)
        """,
        (user_id.strip(), name.strip(), email.strip(), phone.strip(), pw_hash, salt, _now_iso()),
    )
    conn.commit()
    ensure_settings(user_id)
    return True, "회원가입 완료"


def update_password_admin(target_user_id: str, new_password: str) -> Tuple[bool, str]:
    if not new_password:
        return False, "새 비밀번호를 입력하세요."
    if get_user(target_user_id) is None:
        return False, "사용자를 찾을 수 없습니다."
    pw_hash, salt = hash_password(new_password)
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET pw_hash = ?, salt = ? WHERE user_id = ?",
        (pw_hash, salt, target_user_id),
    )
    conn.commit()
    return True, "비밀번호 변경 완료"


def delete_user_admin(target_user_id: str) -> Tuple[bool, str]:  # ★
    if not target_user_id:  # ★
        return False, "대상 사용자를 선택하세요."  # ★
    if target_user_id.strip() == "admin":  # ★
        return False, "admin 계정은 삭제할 수 없습니다."  # ★
    if get_user(target_user_id.strip()) is None:  # ★
        return False, "사용자를 찾을 수 없습니다."  # ★
    conn = get_conn()  # ★
    cur = conn.cursor()  # ★
    cur.execute("DELETE FROM events WHERE user_id = ?", (target_user_id.strip(),))  # ★
    cur.execute("DELETE FROM settings WHERE user_id = ?", (target_user_id.strip(),))  # ★
    cur.execute("DELETE FROM users WHERE user_id = ?", (target_user_id.strip(),))  # ★
    conn.commit()  # ★
    return True, "사용자 탈퇴(삭제) 완료"  # ★


def list_users_basic() -> pd.DataFrame:
    conn = get_conn()
    df = pd.read_sql_query(
        "SELECT user_id as ID, name as 이름, email as 메일주소, phone as 핸드폰번호, is_admin as 관리자 FROM users ORDER BY is_admin DESC, user_id ASC",
        conn,
    )
    df["관리자"] = df["관리자"].apply(lambda x: "Y" if int(x) == 1 else "")
    return df


def ensure_settings(user_id: str) -> None:
    _ensure_settings_columns()  # ★
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM settings WHERE user_id = ?", (user_id,))
    if cur.fetchone() is None:
        cur.execute(
            """
            INSERT INTO settings (user_id, calendar_height, annual_leave_json, overtime_json, ui_json, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                680,
                json.dumps({}, ensure_ascii=False),
                json.dumps(DEFAULT_OVERTIME, ensure_ascii=False),
                json.dumps(DEFAULT_UI, ensure_ascii=False),
                _now_iso(),
            ),
        )
        conn.commit()


def get_settings(user_id: str) -> Dict[str, Any]:
    ensure_settings(user_id)
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM settings WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    if row is None:
        return {"calendar_height": 680, "annual_leave": {}, "overtime": DEFAULT_OVERTIME, "ui": dict(DEFAULT_UI)}

    try:
        annual = json.loads(row["annual_leave_json"] or "{}")
    except Exception:
        annual = {}
    try:
        overtime = json.loads(row["overtime_json"] or "{}")
    except Exception:
        overtime = DEFAULT_OVERTIME
    try:  # ★
        ui = json.loads(row["ui_json"] or "{}")  # ★
        if not isinstance(ui, dict):  # ★
            ui = {}  # ★
    except Exception:  # ★
        ui = {}  # ★

    for k in ("ot1", "ot2", "ot3"):
        if k not in overtime:
            overtime[k] = DEFAULT_OVERTIME[k]
        if "label" not in overtime[k]:
            overtime[k]["label"] = DEFAULT_OVERTIME[k]["label"]
        if "amount" not in overtime[k]:
            overtime[k]["amount"] = DEFAULT_OVERTIME[k]["amount"]

    ui.setdefault("show_leave_summary", True)  # ★
    ui.setdefault("show_overtime_summary", True)  # ★

    return {"calendar_height": int(row["calendar_height"]), "annual_leave": annual, "overtime": overtime, "ui": ui}


def save_settings(
    user_id: str,
    calendar_height: int,
    annual_leave: Dict[str, Any],
    overtime: Dict[str, Any],
    ui: Dict[str, Any],  # ★
) -> None:
    ensure_settings(user_id)
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO settings (user_id, calendar_height, annual_leave_json, overtime_json, ui_json, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            calendar_height=excluded.calendar_height,
            annual_leave_json=excluded.annual_leave_json,
            overtime_json=excluded.overtime_json,
            ui_json=excluded.ui_json,
            updated_at=excluded.updated_at
        """,
        (
            user_id,
            int(calendar_height),
            json.dumps(annual_leave, ensure_ascii=False),
            json.dumps(overtime, ensure_ascii=False),
            json.dumps(ui, ensure_ascii=False),
            _now_iso(),
        ),
    )
    conn.commit()


def create_event(
    user_id: str,
    date_iso: str,
    title: str,
    content: str,
    leave_holiday: bool,
    leave_annual: bool,
    leave_half: float,
    leave_early: float,
    ot1: bool,
    ot2: bool,
    ot3: bool,
) -> None:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO events
        (user_id, date, title, content, leave_holiday, leave_annual, leave_half, leave_early, ot1, ot2, ot3, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            date_iso,
            title.strip(),
            content.strip(),
            1 if leave_holiday else 0,
            1 if leave_annual else 0,
            float(leave_half),
            float(leave_early),
            1 if ot1 else 0,
            1 if ot2 else 0,
            1 if ot3 else 0,
            _now_iso(),
            _now_iso(),
        ),
    )
    conn.commit()


def update_event(
    event_id: int,
    user_id: str,
    title: str,
    content: str,
    leave_holiday: bool,
    leave_annual: bool,
    leave_half: float,
    leave_early: float,
    ot1: bool,
    ot2: bool,
    ot3: bool,
) -> None:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE events SET
            title=?,
            content=?,
            leave_holiday=?,
            leave_annual=?,
            leave_half=?,
            leave_early=?,
            ot1=?,
            ot2=?,
            ot3=?,
            updated_at=?
        WHERE id=? AND user_id=?
        """,
        (
            title.strip(),
            content.strip(),
            1 if leave_holiday else 0,
            1 if leave_annual else 0,
            float(leave_half),
            float(leave_early),
            1 if ot1 else 0,
            1 if ot2 else 0,
            1 if ot3 else 0,
            _now_iso(),
            int(event_id),
            user_id,
        ),
    )
    conn.commit()


def delete_event(event_id: int, user_id: str) -> None:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM events WHERE id=? AND user_id=?", (int(event_id), user_id))
    conn.commit()


def list_events_range(user_id: str, start_iso: str, end_iso: str) -> pd.DataFrame:
    conn = get_conn()
    return pd.read_sql_query(
        """
        SELECT * FROM events
        WHERE user_id=? AND date>=? AND date<=?
        ORDER BY date ASC, id ASC
        """,
        conn,
        params=(user_id, start_iso, end_iso),
    )


def list_events_for_date(user_id: str, date_iso: str) -> pd.DataFrame:
    conn = get_conn()
    return pd.read_sql_query(
        "SELECT * FROM events WHERE user_id=? AND date=? ORDER BY id ASC",
        conn,
        params=(user_id, date_iso),
    )


def search_events(user_id: str, keyword: str) -> pd.DataFrame:
    kw = f"%{keyword.strip()}%"
    conn = get_conn()
    return pd.read_sql_query(
        """
        SELECT * FROM events
        WHERE user_id=? AND (title LIKE ? OR content LIKE ?)
        ORDER BY date DESC, id DESC
        """,
        conn,
        params=(user_id, kw, kw),
    )


def leave_used_amount(row: Dict[str, Any]) -> float:
    holiday = float(row.get("leave_holiday", 0) or 0)
    annual = float(row.get("leave_annual", 0) or 0)
    half = float(row.get("leave_half", 0) or 0)
    early = float(row.get("leave_early", 0) or 0)
    return (1.0 if (holiday >= 1 or annual >= 1) else 0.0) + float(half) + float(early)


def has_leave(row: Dict[str, Any]) -> bool:
    return leave_used_amount(row) > 0


def has_overtime(row: Dict[str, Any]) -> bool:
    return int(row.get("ot1", 0) or 0) == 1 or int(row.get("ot2", 0) or 0) == 1 or int(row.get("ot3", 0) or 0) == 1


def compute_year_leave_summary(events_df: pd.DataFrame, annual_total: float) -> Tuple[float, float]:
    used = 0.0
    if not events_df.empty:
        for _, r in events_df.iterrows():
            used += leave_used_amount(r.to_dict())
    remain = float(annual_total) - float(used)
    return used, remain


def compute_month_overtime_summary(events_df: pd.DataFrame, overtime: Dict[str, Any]) -> float:
    if events_df.empty:
        return 0.0
    a1 = _safe_float(overtime.get("ot1", {}).get("amount", 0), 0)
    a2 = _safe_float(overtime.get("ot2", {}).get("amount", 0), 0)
    a3 = _safe_float(overtime.get("ot3", {}).get("amount", 0), 0)
    total = 0.0
    for _, r in events_df.iterrows():
        if int(r["ot1"]) == 1:
            total += a1
        if int(r["ot2"]) == 1:
            total += a2
        if int(r["ot3"]) == 1:
            total += a3
    return total


def _get_query_params() -> Dict[str, str]:
    try:
        qp = st.query_params
        out: Dict[str, str] = {}
        for k in qp:
            v = qp.get(k)
            if isinstance(v, list):
                out[k] = v[0] if v else ""
            else:
                out[k] = str(v) if v is not None else ""
        return out
    except Exception:
        qp2 = st.experimental_get_query_params()
        out2: Dict[str, str] = {}
        for k, v in qp2.items():
            out2[k] = v[0] if isinstance(v, list) and v else (str(v) if v is not None else "")
        return out2


def _set_query_params(**kwargs: str) -> None:
    clean = {k: v for k, v in kwargs.items() if v is not None and v != ""}
    try:
        st.query_params.clear()
        st.query_params.update(clean)
    except Exception:
        st.experimental_set_query_params(**clean)


def _set_pending_nav(year: int, month: int, sel_iso: str) -> None:  # ★
    st.session_state["skip_calendar_callback_once"] = True  # ★
    st.session_state["nav_lock_until"] = dt.datetime.now().timestamp() + 1.5  # ★
    st.session_state["cal_nonce"] = secrets.token_hex(4)  # ★
    st.session_state["selected_date_iso"] = ""  # ★
    st.session_state["view_y"] = int(year)  # ★
    st.session_state["view_m"] = int(month)  # ★
    st.session_state["pending_nav"] = {"y": int(year), "m": int(month), "sel": str(sel_iso or "")}  # ★
    _set_query_params(y=str(int(year)), m=str(int(month)), sel=str(sel_iso or ""))  # ★


def _nav_to(year: int, month: int, sel_iso: str) -> None:  # ★
    _set_pending_nav(year, month, sel_iso)  # ★
    st.rerun()  # ★


def _month_start_end(year: int, month: int) -> Tuple[str, str]:
    first = dt.date(year, month, 1)
    last = dt.date(year, month, calendar.monthrange(year, month)[1])
    return first.isoformat(), last.isoformat()


def _year_start_end(year: int) -> Tuple[str, str]:
    return dt.date(year, 1, 1).isoformat(), dt.date(year, 12, 31).isoformat()


def render_calendar_html(
    year: int,
    month: int,
    selected: Optional[dt.date],
    today: dt.date,
    calendar_height: int,
    events_by_date: Dict[str, List[Dict[str, Any]]],
) -> str:
    weeks = calendar.monthcalendar(year, month)
    while len(weeks) < 6:
        weeks.append([0, 0, 0, 0, 0, 0, 0])

    cell_h = max(80, int(calendar_height / 6))

    css = f"""
    <style>
      .cal-wrap {{
        width: 100%;
        height: {calendar_height}px;
        border: 1px solid rgba(255,255,255,0.12);
        border-radius: 12px;
        overflow: hidden;
      }}
      .cal-head {{
        display: grid;
        grid-template-columns: repeat(7, 1fr);
        border-bottom: 1px solid rgba(255,255,255,0.12);
        background: rgba(255,255,255,0.03);
      }}
      .cal-head div {{
        padding: 10px 8px;
        font-weight: 700;
        text-align: center;
        font-size: 14px;
      }}
      .cal-grid {{
        display: grid;
        grid-template-columns: repeat(7, 1fr);
      }}
      .cal-cell {{
        position: relative;
        height: {cell_h}px;
        padding: 8px 8px 6px 8px;
        border-right: 1px solid rgba(255,255,255,0.08);
        border-bottom: 1px solid rgba(255,255,255,0.08);
        text-decoration: none !important;
        color: inherit !important;
      }}
      .cal-cell:hover {{
        background: rgba(255,255,255,0.04);
      }}
      .cal-cell.outside {{
        opacity: 0.35;
        pointer-events: none;
      }}
      .daynum {{
        font-weight: 700;
        font-size: 14px;
        line-height: 1;
        margin-bottom: 6px;
      }}
      .evt {{
        font-size: 11px;
        opacity: 0.92;
        line-height: 1.25;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        margin-top: 2px;
      }}
      .wk-sat .daynum {{ color: #3aa0ff; font-weight: 800; }}
      .wk-sun .daynum {{ color: #ff5a5a; font-weight: 800; }}

      .b-green {{ box-shadow: inset 0 0 0 3px rgba(0,255,0,0.55); }}
      .b-red {{ box-shadow: inset 0 0 0 3px rgba(255,0,0,0.70); }}
      .b-blue {{ box-shadow: inset 0 0 0 3px rgba(0,120,255,0.75); }}
      .b-redblue {{
        box-shadow:
          inset 0 0 0 3px rgba(255,0,0,0.70),
          inset 0 0 0 6px rgba(0,120,255,0.75);
      }}
      .b-redgreen {{
        box-shadow:
          inset 0 0 0 3px rgba(255,0,0,0.70),
          inset 0 0 0 6px rgba(0,255,0,0.55);
      }}
      .b-bluegreen {{
        box-shadow:
          inset 0 0 0 3px rgba(0,120,255,0.75),
          inset 0 0 0 6px rgba(0,255,0,0.55);
      }}
      .b-redbluegreen {{
        box-shadow:
          inset 0 0 0 3px rgba(255,0,0,0.70),
          inset 0 0 0 6px rgba(0,120,255,0.75),
          inset 0 0 0 9px rgba(0,255,0,0.55);
      }}
    </style>
    """

    weekdays = ["일", "월", "화", "수", "목", "금", "토"]  # ★
    head = '<div class="cal-head">' + "".join([f"<div>{w}</div>" for w in weekdays]) + "</div>"

    cells: List[str] = []
    for week in weeks:
        for wd, day in enumerate(week):
            if day == 0:
                cells.append('<div class="cal-cell outside"></div>')
                continue

            date_obj = dt.date(year, month, day)
            date_iso = date_obj.isoformat()
            evs = events_by_date.get(date_iso, [])

            wk_cls = "wk-sat" if wd == 6 else ("wk-sun" if wd == 0 else "")  # ★

            any_leave = any(has_leave(e) for e in evs)
            any_ot = any(has_overtime(e) for e in evs)

            green = (date_obj == today) or (selected is not None and date_obj == selected)

            border_cls = ""
            if any_leave and any_ot and green:
                border_cls = "b-redbluegreen"
            elif any_leave and any_ot:
                border_cls = "b-redblue"
            elif any_leave and green:
                border_cls = "b-redgreen"
            elif any_ot and green:
                border_cls = "b-bluegreen"
            elif any_leave:
                border_cls = "b-red"
            elif any_ot:
                border_cls = "b-blue"
            elif green:
                border_cls = "b-green"

            href = f"?y={year}&m={month}&sel={date_iso}"

            ev_lines = ""
            for e in evs[:6]:
                title = (e.get("title") or "").replace("<", "&lt;").replace(">", "&gt;")
                ev_lines += f'<div class="evt">{title}</div>'

            cells.append(
                f"""
                <a class="cal-cell {wk_cls} {border_cls}" href="{href}">
                  <div class="daynum">{day}</div>
                  {ev_lines}
                </a>
                """
            )

    grid = '<div class="cal-grid">' + "".join(cells) + "</div>"
    return css + f'<div class="cal-wrap" id="calendar-root">{head}{grid}</div>'


def render_png_calendar(year: int, month: int, events_by_date: Dict[str, List[Dict[str, Any]]]) -> bytes:
    import io
    import matplotlib.pyplot as plt

    weeks = calendar.monthcalendar(year, month)
    while len(weeks) < 6:
        weeks.append([0, 0, 0, 0, 0, 0, 0])

    fig = plt.figure(figsize=(14, 8), dpi=150)
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_axis_off()

    ax.text(0.5, 0.97, f"{year}-{month:02d}", ha="center", va="top", fontsize=18, fontweight="bold")

    weekdays = ["일", "월", "화", "수", "목", "금", "토"]  # ★
    for i, w in enumerate(weekdays):
        ax.text((i + 0.5) / 7, 0.91, w, ha="center", va="center", fontsize=12, fontweight="bold")

    top, bottom, left, right = 0.88, 0.05, 0.02, 0.98
    cell_w = (right - left) / 7
    cell_h = (top - bottom) / 6

    for c in range(8):
        x = left + c * cell_w
        ax.plot([x, x], [bottom, top], linewidth=0.6)
    for r in range(7):
        y = top - r * cell_h
        ax.plot([left, right], [y, y], linewidth=0.6)

    for row_i, week in enumerate(weeks):
        for col_i, day in enumerate(week):
            if day == 0:
                continue
            date_obj = dt.date(year, month, day)
            date_iso = date_obj.isoformat()
            evs = events_by_date.get(date_iso, [])

            x0 = left + col_i * cell_w
            y0 = top - (row_i + 1) * cell_h

            ax.text(x0 + 0.01, y0 + cell_h - 0.02, str(day), ha="left", va="top", fontsize=11, fontweight="bold")
            for idx, e in enumerate(evs[:6]):
                ax.text(x0 + 0.01, y0 + cell_h - 0.06 - idx * 0.03, e.get("title", ""), ha="left", va="top", fontsize=8)

    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight")
    plt.close(fig)
    return buf.getvalue()


def _require_login() -> bool:
    if "auth" not in st.session_state:
        st.session_state["auth"] = {"logged_in": False, "user_id": None, "is_admin": False, "as_user_id": None}
    return bool(st.session_state["auth"]["logged_in"])


def _logout() -> None:
    st.session_state["auth"] = {"logged_in": False, "user_id": None, "is_admin": False, "as_user_id": None}
    st.session_state.pop("pending_nav", None)  # ★
    st.session_state.pop("skip_calendar_callback_once", None)  # ★
    st.session_state.pop("view_y", None)  # ★
    st.session_state.pop("view_m", None)  # ★
    _set_query_params()
    st.rerun()


def login_screen() -> None:
    st.title(APP_TITLE)
    st.caption(f"{BUILD_TAG} | RUNNING: {os.path.abspath(__file__)}")  # ★
    tabs = st.tabs(["로그인", "회원가입"])

    with tabs[0]:
        with st.form("login_form", border=True):
            user_id = st.text_input("ID", value="", autocomplete="username")
            pw = st.text_input("PW", value="", type="password", autocomplete="current-password")
            submit = st.form_submit_button("로그인")
        if submit:
            u = get_user(user_id.strip())
            if u is None:
                st.error("ID/PW 를 확인하세요.")
            else:
                if verify_password(pw, u["pw_hash"], u["salt"]):
                    st.session_state["auth"] = {
                        "logged_in": True,
                        "user_id": u["user_id"],
                        "is_admin": int(u["is_admin"]) == 1,
                        "as_user_id": None,
                    }
                    st.success("로그인 완료")
                    st.rerun()
                else:
                    st.error("ID/PW 를 확인하세요.")

    with tabs[1]:
        with st.form("signup_form", border=True):
            name = st.text_input("이름")
            email = st.text_input("메일주소")
            phone = st.text_input("핸드폰번호")
            new_id = st.text_input("ID")
            new_pw = st.text_input("PW", type="password")
            submit2 = st.form_submit_button("회원가입")
        if submit2:
            ok, msg = create_user(new_id, name, email, phone, new_pw)
            if ok:
                st.success(msg)
            else:
                st.error(msg)


@st.dialog("상세보기", width="large")
def dialog_detail(title: str, df: pd.DataFrame) -> None:
    st.subheader(title)

    if df.empty:
        st.info("데이터 없음")
    else:
        if "구분" in df.columns and "값" in df.columns:
            leave_df = df[df["구분"] == "휴일/연차"].copy()  # ★
            ot_df = df[df["구분"] == "연장근무"].copy()  # ★

            st.markdown("### 휴일/연차")  # ★
            if leave_df.empty:
                st.info("휴일/연차 데이터 없음")  # ★
            else:
                total_leave = float(leave_df["값"].sum())  # ★
                st.markdown(f"**총 사용(합계)**: {total_leave:.1f}")  # ★
                leave_view = leave_df[["일자", "제목", "항목", "값"]].copy()  # ★
                leave_view.rename(columns={"값": "사용"}, inplace=True)  # ★
                leave_view["사용"] = leave_view["사용"].apply(lambda x: f"{float(x):.1f}")  # ★
                st.dataframe(leave_view, use_container_width=True, hide_index=True)  # ★

            st.divider()  # ★
            st.markdown("### 연장근무")  # ★
            if ot_df.empty:
                st.info("연장근무 데이터 없음")  # ★
            else:
                sum_df = ot_df.groupby("항목", as_index=False)["값"].sum()  # ★
                sum_df.rename(columns={"항목": "유형", "값": "금액"}, inplace=True)  # ★
                sum_df["금액"] = sum_df["금액"].apply(lambda x: f"{int(round(float(x))):,}")  # ★
                st.markdown("**집계**")  # ★
                st.dataframe(sum_df, use_container_width=True, hide_index=True)  # ★

                st.markdown("**상세**")  # ★
                ot_view = ot_df[["일자", "제목", "항목", "값"]].copy()  # ★
                ot_view.rename(columns={"항목": "유형", "값": "금액"}, inplace=True)  # ★
                ot_view["금액"] = ot_view["금액"].apply(lambda x: f"{int(round(float(x))):,}")  # ★
                st.dataframe(ot_view, use_container_width=True, hide_index=True)  # ★
        else:
            st.dataframe(df, use_container_width=True, hide_index=True)

    if st.button("닫기"):
        st.rerun()


@st.dialog("검색", width="large")
def dialog_search(user_id: str) -> None:
    st.subheader("키워드 검색 (제목 + 내용)")
    keyword = st.text_input("검색어", value="", placeholder="예: 출장, 회의, 연차 ...")
    if st.button("검색", type="primary", use_container_width=True):
        if not keyword.strip():
            st.warning("검색어를 입력하세요.")
        else:
            df = search_events(user_id, keyword.strip())
            if df.empty:
                st.info("검색 결과 없음")
            else:
                view = df[["date", "title", "content"]].copy()
                view.rename(columns={"date": "일자", "title": "제목", "content": "내용"}, inplace=True)
                st.dataframe(view, use_container_width=True, hide_index=True)
                st.caption("이동할 날짜를 선택 후 [이동] 을 누르세요.")
                jump = st.date_input("이동할 일자", value=_today())
                if st.button("이동"):
                    _nav_to(int(jump.year), int(jump.month), jump.isoformat())  # ★
    if st.button("닫기"):
        st.rerun()


@st.dialog("설정", width="large")
def dialog_settings(user_id: str, settings: Dict[str, Any]) -> None:
    st.subheader("설정")
    cal_h = st.number_input("달력 높이(px)", min_value=360, max_value=1600, value=int(settings["calendar_height"]), step=20)

    st.divider()
    st.markdown("### 상단 요약 표시")  # ★
    ui = dict(settings.get("ui") or {})  # ★
    ui.setdefault("show_leave_summary", True)  # ★
    ui.setdefault("show_overtime_summary", True)  # ★
    ui["show_leave_summary"] = st.checkbox("총 연차(상단) 표시", value=bool(ui.get("show_leave_summary", True)))  # ★
    ui["show_overtime_summary"] = st.checkbox("총 연장근무(상단) 표시", value=bool(ui.get("show_overtime_summary", True)))  # ★

    st.divider()
    st.markdown("### 연도별 연차 갯수")
    annual = dict(settings["annual_leave"] or {})
    col1, col2, col3 = st.columns([1, 1, 1])
    with col1:
        y = st.number_input("연도", min_value=2000, max_value=2100, value=_today().year, step=1)
    with col2:
        cnt = st.number_input("연차 총 갯수", min_value=0.0, max_value=60.0, value=_safe_float(annual.get(str(int(y)), 0), 0), step=0.5)
    with col3:
        if st.button("저장/업데이트", use_container_width=True):
            annual[str(int(y))] = float(cnt)  # ★
            save_settings(user_id, int(cal_h), annual, settings["overtime"], ui)  # ★
            st.success("연도별 연차 저장됨")  # ★
            st.rerun()  # ★

    if annual:
        view = pd.DataFrame([{"연도": k, "연차 총 갯수": v} for k, v in sorted(annual.items(), key=lambda x: x[0])])
        st.dataframe(view, use_container_width=True, hide_index=True)

    st.divider()
    st.markdown("### 연장근무 명칭/금액")
    overtime = dict(settings["overtime"] or DEFAULT_OVERTIME)
    for key in ("ot1", "ot2", "ot3"):
        overtime.setdefault(key, DEFAULT_OVERTIME[key])

    c1, c2, c3 = st.columns(3)
    with c1:
        overtime["ot1"]["label"] = st.text_input("유형 1 명칭", value=overtime["ot1"].get("label", DEFAULT_OVERTIME["ot1"]["label"]))
        overtime["ot1"]["amount"] = st.number_input("유형 1 금액", value=_safe_float(overtime["ot1"].get("amount", 0), 0), step=1000.0, format="%.0f")
    with c2:
        overtime["ot2"]["label"] = st.text_input("유형 2 명칭", value=overtime["ot2"].get("label", DEFAULT_OVERTIME["ot2"]["label"]))
        overtime["ot2"]["amount"] = st.number_input("유형 2 금액", value=_safe_float(overtime["ot2"].get("amount", 0), 0), step=1000.0, format="%.0f")
    with c3:
        overtime["ot3"]["label"] = st.text_input("유형 3 명칭", value=overtime["ot3"].get("label", DEFAULT_OVERTIME["ot3"]["label"]))
        overtime["ot3"]["amount"] = st.number_input("유형 3 금액", value=_safe_float(overtime["ot3"].get("amount", 0), 0), step=1000.0, format="%.0f")

    st.divider()
    if st.button("설정 전체 저장", type="primary", use_container_width=True):
        save_settings(user_id, int(cal_h), annual, overtime, ui)  # ★
        st.success("저장 완료")
        st.rerun()

    if st.button("닫기"):
        st.rerun()


@st.dialog("일정 추가/수정", width="large")
def dialog_event_editor(
    mode: str,
    user_id: str,
    date_iso: str,
    settings: Dict[str, Any],
    event_row: Optional[pd.Series] = None,
) -> None:
    date_obj = _parse_date(date_iso) or _today()

    if mode == "add":  # ★
        edit_date = st.date_input("등록할 날짜", value=date_obj)  # ★
        date_obj = edit_date  # ★

    st.subheader(f"{date_obj.isoformat()} 일정 {'추가' if mode=='add' else '수정'}")

    overtime = settings["overtime"]
    lbl1, lbl2, lbl3 = overtime["ot1"]["label"], overtime["ot2"]["label"], overtime["ot3"]["label"]

    if event_row is None:
        title0, content0 = "", ""
        leave_holiday0, leave_annual0 = False, False
        leave_half0, leave_early0 = 0.0, 0.0
        ot1_0, ot2_0, ot3_0 = False, False, False
    else:
        title0 = str(event_row["title"])
        content0 = str(event_row["content"])
        leave_holiday0 = int(event_row["leave_holiday"]) == 1
        leave_annual0 = int(event_row["leave_annual"]) == 1
        leave_early0 = float(event_row["leave_early"] or 0.0)
        leave_half0 = float(event_row["leave_half"] or 0.0)
        ot1_0 = int(event_row["ot1"]) == 1
        ot2_0 = int(event_row["ot2"]) == 1
        ot3_0 = int(event_row["ot3"]) == 1

    title = st.text_input("제목", value=title0, max_chars=80)
    content = st.text_area("내용", value=content0, height=160)

    st.divider()
    st.markdown("### 휴일/연차")
    c1, c2, c3, c4 = st.columns([1, 1, 1, 1])
    with c1:
        leave_holiday = st.checkbox("휴일", value=leave_holiday0)
    with c2:
        leave_annual = st.checkbox("연차(1)", value=leave_annual0)
    with c3:
        leave_half = st.checkbox("반차(0.5)", value=(leave_half0 > 0))
    with c4:
        leave_early = st.number_input("조퇴(숫자 입력)", min_value=0.0, max_value=8.0, value=float(leave_early0), step=0.5)

    leave_half_val = 0.5 if leave_half else 0.0

    st.divider()
    st.markdown("### 연장근무")
    o1, o2, o3 = st.columns(3)
    with o1:
        ot1 = st.checkbox(lbl1, value=ot1_0)
    with o2:
        ot2 = st.checkbox(lbl2, value=ot2_0)
    with o3:
        ot3 = st.checkbox(lbl3, value=ot3_0)

    st.divider()
    left, right = st.columns([1, 1])
    with left:
        if st.button("저장", type="primary", use_container_width=True):
            if not title.strip():
                st.error("제목은 필수입니다.")
            else:
                if mode == "add":
                    new_date_iso = date_obj.isoformat()  # ★
                    create_event(user_id, new_date_iso, title, content, leave_holiday, leave_annual, leave_half_val, leave_early, ot1, ot2, ot3)  # ★
                    st.session_state["selected_date_iso"] = new_date_iso  # ★
                    st.session_state["view_y"] = int(date_obj.year)  # ★
                    st.session_state["view_m"] = int(date_obj.month)  # ★
                    _set_query_params(y=str(date_obj.year), m=str(date_obj.month), sel=new_date_iso)  # ★
                else:
                    update_event(int(event_row["id"]), user_id, title, content, leave_holiday, leave_annual, leave_half_val, leave_early, ot1, ot2, ot3)
                st.success("저장 완료")
                st.rerun()
    with right:
        if mode == "edit" and event_row is not None:
            if st.button("삭제", type="secondary", use_container_width=True):
                delete_event(int(event_row["id"]), user_id)
                st.success("삭제 완료")
                st.rerun()
        else:
            if st.button("닫기", use_container_width=True):
                st.rerun()


def _build_detail_tables(active_user_id: str, y: int, m: int, settings: Dict[str, Any]) -> pd.DataFrame:
    year_start, year_end = _year_start_end(y)
    month_start, month_end = _month_start_end(y, m)
    year_events = list_events_range(active_user_id, year_start, year_end)
    month_events = list_events_range(active_user_id, month_start, month_end)

    leave_rows = []
    if not year_events.empty:
        for _, r in year_events.iterrows():
            amt = leave_used_amount(r.to_dict())
            if amt > 0:
                leave_rows.append({"구분": "휴일/연차", "일자": r["date"], "제목": r["title"], "항목": "사용", "값": amt})  # ★

    overtime = settings["overtime"]
    ot_rows = []
    if not month_events.empty:
        for _, r in month_events.iterrows():
            if int(r["ot1"]) == 1:
                ot_rows.append({"구분": "연장근무", "일자": r["date"], "제목": r["title"], "항목": overtime["ot1"]["label"], "값": _safe_float(overtime["ot1"]["amount"], 0)})
            if int(r["ot2"]) == 1:
                ot_rows.append({"구분": "연장근무", "일자": r["date"], "제목": r["title"], "항목": overtime["ot2"]["label"], "값": _safe_float(overtime["ot2"]["amount"], 0)})
            if int(r["ot3"]) == 1:
                ot_rows.append({"구분": "연장근무", "일자": r["date"], "제목": r["title"], "항목": overtime["ot3"]["label"], "값": _safe_float(overtime["ot3"]["amount"], 0)})

    df = pd.DataFrame(leave_rows + ot_rows)
    return df


def main_app() -> None:
    auth = st.session_state["auth"]
    user_id = str(auth["user_id"])
    is_admin = bool(auth["is_admin"])
    as_user_id = auth.get("as_user_id")
    active_user_id = as_user_id if (is_admin and as_user_id) else user_id

    settings = get_settings(active_user_id)
    ui = dict(settings.get("ui") or {})  # ★
    ui.setdefault("show_leave_summary", True)  # ★
    ui.setdefault("show_overtime_summary", True)  # ★

    qp = _get_query_params()
    y = _safe_int(qp.get("y"), _today().year)
    m = _safe_int(qp.get("m"), _today().month)
    sel = qp.get("sel", "")

    if "view_y" not in st.session_state:  # ★
        st.session_state["view_y"] = int(y)  # ★
    if "view_m" not in st.session_state:  # ★
        st.session_state["view_m"] = int(m)  # ★

    pend = st.session_state.pop("pending_nav", None)  # ★
    if isinstance(pend, dict):  # ★
        st.session_state["view_y"] = _safe_int(pend.get("y"), int(st.session_state.get("view_y", y)))  # ★
        st.session_state["view_m"] = _safe_int(pend.get("m"), int(st.session_state.get("view_m", m)))  # ★
        sel = str(pend.get("sel") or "")  # ★

    y = int(st.session_state.get("view_y", y))  # ★
    m = int(st.session_state.get("view_m", m))  # ★

    if m < 1:
        m = 1
    if m > 12:
        m = 12

    selected_date = _parse_date(sel) if sel else None
    if selected_date is None:  # ★
        ss_sel = st.session_state.get("selected_date_iso", "")  # ★
        if ss_sel:  # ★
            tmp_d = _parse_date(str(ss_sel))  # ★
            if tmp_d is not None and (tmp_d.year == y and tmp_d.month == m):  # ★
                selected_date = tmp_d  # ★
    if selected_date is not None and (selected_date.year != y or selected_date.month != m):  # ★
        selected_date = None  # ★

    today = _today()

    month_start, month_end = _month_start_end(y, m)
    month_events = list_events_range(active_user_id, month_start, month_end)

    events_by_date: Dict[str, List[Dict[str, Any]]] = {}
    if not month_events.empty:
        for _, r in month_events.iterrows():
            events_by_date.setdefault(str(r["date"]), []).append(r.to_dict())

    annual_cfg = settings["annual_leave"]
    annual_total = _safe_float(annual_cfg.get(str(y), 0), 0)
    year_start, year_end = _year_start_end(y)
    year_events = list_events_range(active_user_id, year_start, year_end)

    leave_used, leave_remain = compute_year_leave_summary(year_events, annual_total)
    ot_month_total = compute_month_overtime_summary(month_events, settings["overtime"])

    st.title(APP_TITLE)
    st.caption(f"{BUILD_TAG} | RUNNING: {os.path.abspath(__file__)}")  # ★

    top_left, top_mid, top_right = st.columns([1.4, 1.2, 1.4])
    with top_left:
        if bool(ui.get("show_leave_summary", True)):  # ★
            st.markdown(f"**{y} 연차**: 총 {annual_total:.1f} / 사용 {leave_used:.1f} / 남음 {leave_remain:.1f}")  # ★
    with top_mid:
        if bool(ui.get("show_overtime_summary", True)):  # ★
            st.markdown(f"**{y}-{m:02d} 연장근무 금액(월)**: {ot_month_total:,.0f}")  # ★
    with top_right:
        urow = get_user(active_user_id)  # ★
        uname = ""  # ★
        if urow is not None:  # ★
            uname = str(urow["name"] or "").strip()  # ★
        if uname:  # ★
            st.markdown(f"**{uname}님**")  # ★
        b1, b2, b3, b4 = st.columns(4)
        with b1:
            if st.button("상세보기", use_container_width=True):
                detail_df = _build_detail_tables(active_user_id, y, m, settings)
                dialog_detail("휴일/연차 · 연장근무 상세", detail_df)  # ★
        with b2:
            if st.button("검색", use_container_width=True):
                dialog_search(active_user_id)
        with b3:
            if st.button("Setting", use_container_width=True):
                dialog_settings(active_user_id, settings)
        with b4:
            if st.button("Logout", use_container_width=True):
                _logout()

    nav_l, nav_c, nav_r = st.columns([1, 2, 1])
    with nav_l:
        if st.button("◀ 이전달", use_container_width=True):
            prev = (dt.date(y, m, 1) - dt.timedelta(days=1)).replace(day=1)
            _nav_to(int(prev.year), int(prev.month), "")  # ★
    with nav_c:
        coly, colm, colgo = st.columns([1, 1, 1])
        with coly:
            yy = st.number_input("연도", min_value=2000, max_value=2100, value=int(y), step=1)
        with colm:
            mm = st.number_input("월", min_value=1, max_value=12, value=int(m), step=1)
        with colgo:
            if st.button("이동", use_container_width=True):
                _nav_to(int(yy), int(mm), "")  # ★
    with nav_r:
        if st.button("다음달 ▶", use_container_width=True):
            last_day = calendar.monthrange(y, m)[1]
            nxt = (dt.date(y, m, last_day) + dt.timedelta(days=1)).replace(day=1)
            _nav_to(int(nxt.year), int(nxt.month), "")  # ★

    if st_calendar is None:  # ★
        st.error("streamlit-calendar 패키지가 설치되지 않아 달력을 표시할 수 없습니다. (pip install streamlit-calendar)")  # ★
    else:  # ★
        leave_dates = set()  # ★
        ot_dates = set()  # ★
        for d_iso, evs in events_by_date.items():  # ★
            if any(has_leave(e) for e in evs):  # ★
                leave_dates.add(d_iso)  # ★
            if any(has_overtime(e) for e in evs):  # ★
                ot_dates.add(d_iso)  # ★

        sel_iso = selected_date.isoformat() if selected_date is not None else ""  # ★
        today_iso = today.isoformat()  # ★

        per_day_css = []  # ★
        for day in range(1, calendar.monthrange(y, m)[1] + 1):  # ★
            d_obj = dt.date(y, m, day)  # ★
            d_iso = d_obj.isoformat()  # ★
            any_leave = d_iso in leave_dates  # ★
            any_ot = d_iso in ot_dates  # ★
            green = (d_iso == today_iso) or (sel_iso != "" and d_iso == sel_iso)  # ★

            if any_leave and any_ot and green:  # ★
                box = "inset 0 0 0 3px rgba(255,0,0,0.70), inset 0 0 0 6px rgba(0,120,255,0.75), inset 0 0 0 9px rgba(0,255,0,0.55)"  # ★
            elif any_leave and any_ot:  # ★
                box = "inset 0 0 0 3px rgba(255,0,0,0.70), inset 0 0 0 6px rgba(0,120,255,0.75)"  # ★
            elif any_leave and green:  # ★
                box = "inset 0 0 0 3px rgba(255,0,0,0.70), inset 0 0 0 6px rgba(0,255,0,0.55)"  # ★
            elif any_ot and green:  # ★
                box = "inset 0 0 0 3px rgba(0,120,255,0.75), inset 0 0 0 6px rgba(0,255,0,0.55)"  # ★
            elif any_leave:  # ★
                box = "inset 0 0 0 3px rgba(255,0,0,0.70)"  # ★
            elif any_ot:  # ★
                box = "inset 0 0 0 3px rgba(0,120,255,0.75)"  # ★
            elif green:  # ★
                box = "inset 0 0 0 3px rgba(0,255,0,0.55)"  # ★
            else:  # ★
                box = ""  # ★

            if box:  # ★
                per_day_css.append(f'.fc-daygrid-day[data-date="{d_iso}"]{{box-shadow:{box};}}')  # ★

        calendar_options = {  # ★
            "initialView": "dayGridMonth",  # ★
            "initialDate": f"{y}-{m:02d}-01",  # ★
            "height": int(settings["calendar_height"]),  # ★
            "firstDay": 0,  # ★
            "fixedWeekCount": True,  # ★
            "dayMaxEventRows": 6,  # ★
            "headerToolbar": {"left": "", "center": "", "right": ""},  # ★
            "locale": "ko",  # ★
            "eventDisplay": "block",  # ★
        }  # ★

        custom_css = (  # ★
            ".fc-day-sat .fc-daygrid-day-number { color: #3aa0ff; font-weight: 800; }"  # ★
            ".fc-day-sun .fc-daygrid-day-number { color: #ff5a5a; font-weight: 800; }"  # ★
            ".fc-event { font-size: 11px; line-height: 1.2; color: #ffffff !important; }"  # ★
            ".fc-daygrid-event, .fc-h-event { background: transparent !important; border: none !important; }"  # ★
            ".fc-event .fc-event-main, .fc-event .fc-event-title { color: #ffffff !important; }"  # ★
            ".fc-event:focus, .fc-event:hover { box-shadow: none !important; }"  # ★
            + "".join(per_day_css)  # ★
        )  # ★

        calendar_events = []  # ★
        if not month_events.empty:  # ★
            for _, r in month_events.iterrows():  # ★
                d0 = str(r["date"])  # ★
                d1 = (dt.date.fromisoformat(d0) + dt.timedelta(days=1)).isoformat()  # ★
                calendar_events.append(  # ★
                    {  # ★
                        "id": str(r["id"]),  # ★
                        "title": str(r["title"]),  # ★
                        "start": d0,  # ★
                        "end": d1,  # ★
                        "allDay": True,  # ★
                    }  # ★
                )  # ★

        cal_state = st_calendar(
            events=calendar_events,
            options=calendar_options,
            custom_css=custom_css,
            key=f"calendar_{y}_{m}_{int(settings['calendar_height'])}_{st.session_state.get('cal_nonce','0')}",
        )  # ★
        current_sel_iso = selected_date.isoformat() if selected_date is not None else ""  # ★
        if isinstance(cal_state, dict):  # ★
            if st.session_state.get("skip_calendar_callback_once"):  # ★
                st.session_state["skip_calendar_callback_once"] = False  # ★
            elif dt.datetime.now().timestamp() < float(st.session_state.get("nav_lock_until", 0) or 0):  # ★
                pass  # ★
            else:  # ★
                cb = cal_state.get("callback")  # ★

                if cb == "dateClick":  # ★
                    dc = (cal_state.get("dateClick", {}) or {})  # ★
                    clicked = dc.get("dateStr") or dc.get("date") or ""  # ★
                    d = _calendar_payload_to_date(clicked)  # ★
                    if d is not None:  # ★
                        sig = f"dateClick|{d.isoformat()}"  # ★
                        if st.session_state.get("last_calendar_action") != sig:  # ★
                            st.session_state["last_calendar_action"] = sig  # ★
                            st.session_state["selected_date_iso"] = d.isoformat()  # ★
                            st.session_state["view_y"] = int(d.year)  # ★
                            st.session_state["view_m"] = int(d.month)  # ★
                            if d.isoformat() != current_sel_iso:  # ★
                                _set_query_params(y=str(d.year), m=str(d.month), sel=d.isoformat())  # ★
                                st.rerun()  # ★

                if cb == "eventClick":  # ★
                    ev = (cal_state.get("eventClick", {}) or {}).get("event", {})  # ★
                    clicked2 = ev.get("startStr") or ev.get("start") or ""  # ★
                    d2 = _calendar_payload_to_date(clicked2)  # ★
                    if d2 is not None:  # ★
                        sig2 = f"eventClick|{str(ev.get('id',''))}|{d2.isoformat()}"  # ★
                        if st.session_state.get("last_calendar_action") != sig2:  # ★
                            st.session_state["last_calendar_action"] = sig2  # ★
                            st.session_state["selected_date_iso"] = d2.isoformat()  # ★
                            st.session_state["view_y"] = int(d2.year)  # ★
                            st.session_state["view_m"] = int(d2.month)  # ★
                            if d2.isoformat() != current_sel_iso:  # ★
                                _set_query_params(y=str(d2.year), m=str(d2.month), sel=d2.isoformat())  # ★
                                st.rerun()  # ★

    img_col1, img_col2 = st.columns([1, 4])
    with img_col1:
        if st.button("이미지", use_container_width=True):
            png = render_png_calendar(y, m, events_by_date)
            st.session_state["last_calendar_png"] = png
            st.session_state["show_image_tools"] = True
    with img_col2:
        if st.session_state.get("show_image_tools"):
            png = st.session_state.get("last_calendar_png", b"")
            if png:
                st.download_button(
                    "PNG 다운로드",
                    data=png,
                    file_name=f"calendar_{y}_{m:02d}.png",
                    mime="image/png",
                    use_container_width=True,
                )
                b64 = base64.b64encode(png).decode("utf-8")
                st.components.v1.html(
                    f"""
                    <div style="padding:10px;border:1px solid rgba(255,255,255,0.12);border-radius:12px;">
                      <button id="copyBtn" style="width:100%;padding:10px;font-weight:700;">클립보드로 복사(시도)</button>
                      <div id="msg" style="margin-top:8px;opacity:0.85;font-size:12px;"></div>
                      <script>
                        const b64 = "{b64}";
                        const btn = document.getElementById("copyBtn");
                        const msg = document.getElementById("msg");
                        function b64ToBlob(b64Data, contentType) {{
                          const byteCharacters = atob(b64Data);
                          const byteArrays = [];
                          for (let offset = 0; offset < byteCharacters.length; offset += 512) {{
                            const slice = byteCharacters.slice(offset, offset + 512);
                            const byteNumbers = new Array(slice.length);
                            for (let i = 0; i < slice.length; i++) {{
                              byteNumbers[i] = slice.charCodeAt(i);
                            }}
                            const byteArray = new Uint8Array(byteNumbers);
                            byteArrays.push(byteArray);
                          }}
                          return new Blob(byteArrays, {{type: contentType}});
                        }}
                        btn.addEventListener("click", async () => {{
                          msg.textContent = "복사 시도 중...";
                          try {{
                            const blob = b64ToBlob(b64, "image/png");
                            if (!navigator.clipboard || !window.ClipboardItem) {{
                              throw new Error("Clipboard API 미지원");
                            }}
                            await navigator.clipboard.write([new ClipboardItem({{"image/png": blob}})]);
                            msg.textContent = "클립보드에 이미지가 복사되었습니다.";
                          }} catch (e) {{
                            msg.textContent = "복사 실패(브라우저/보안정책/Streamlit 제한 가능). PNG 다운로드를 사용하세요.";
                          }}
                        }});
                      </script>
                    </div>
                    """,
                    height=130,
                )

    with st.sidebar:
        st.header("일정 관리")

        if is_admin:
            st.subheader("관리자 모드")
            users_df = list_users_basic()
            user_ids = users_df["ID"].tolist()
            pick = st.selectbox("캘린더 볼 사용자", options=user_ids, index=user_ids.index(active_user_id) if active_user_id in user_ids else 0)
            if pick != active_user_id:
                st.session_state["auth"]["as_user_id"] = pick
                st.rerun()

            st.markdown("### 사용자 목록 (PW 미표시)")
            st.dataframe(users_df[["ID", "이름", "메일주소", "핸드폰번호", "관리자"]], use_container_width=True, hide_index=True)

            st.markdown("### 비밀번호 변경")
            target = st.selectbox("대상 사용자", options=user_ids, index=0, key="admin_pw_target")
            new_pw = st.text_input("새 비밀번호", type="password", key="admin_pw_new")
            if st.button("비밀번호 변경", use_container_width=True, key="admin_pw_btn"):
                ok, msg = update_password_admin(target, new_pw)
                if ok:
                    st.success(msg)
                else:
                    st.error(msg)

            st.markdown("### 사용자 탈퇴(삭제)")  # ★
            candidates = [uid for uid in user_ids if uid != "admin"]  # ★
            if candidates:  # ★
                del_target = st.selectbox("탈퇴 대상 사용자", options=candidates, index=0, key="admin_del_target")  # ★
                del_confirm = st.checkbox("정말 탈퇴(삭제) 하겠습니다.", value=False, key="admin_del_confirm")  # ★
                if st.button("사용자 탈퇴(삭제)", type="secondary", use_container_width=True, key="admin_del_btn"):  # ★
                    if not del_confirm:  # ★
                        st.warning("삭제 확인 체크박스를 먼저 선택하세요.")  # ★
                    else:  # ★
                        ok2, msg2 = delete_user_admin(del_target)  # ★
                        if ok2:  # ★
                            if st.session_state.get("auth", {}).get("as_user_id") == del_target:  # ★
                                st.session_state["auth"]["as_user_id"] = None  # ★
                            st.success(msg2)  # ★
                            st.rerun()  # ★
                        else:  # ★
                            st.error(msg2)  # ★
            else:  # ★
                st.info("삭제할 사용자가 없습니다. (admin 제외)")  # ★

        st.divider()

        if selected_date is None:
            st.info("달력에서 날짜를 클릭하세요.")
        else:
            st.subheader(f"선택: {selected_date.isoformat()}")
            date_iso = selected_date.isoformat()
            day_df = list_events_for_date(active_user_id, date_iso)

            if st.button("일정 추가", type="primary", use_container_width=True):
                dialog_event_editor("add", active_user_id, date_iso, settings)

            if day_df.empty:
                st.caption("등록된 일정 없음")
            else:
                for _, r in day_df.iterrows():
                    st.markdown(f"**{r['title']}**")
                    st.caption((r["content"] or "")[:120])
                    c1, c2 = st.columns(2)
                    with c1:
                        if st.button("수정", key=f"edit_{r['id']}", use_container_width=True):
                            dialog_event_editor("edit", active_user_id, date_iso, settings, r)
                    with c2:
                        if st.button("삭제", key=f"del_{r['id']}", use_container_width=True):
                            delete_event(int(r["id"]), active_user_id)
                            st.success("삭제 완료")
                            st.rerun()


def run() -> None:
    st.set_page_config(page_title=APP_TITLE, layout="wide")
    init_db()
    if not _require_login():
        login_screen()
        return
    main_app()


if __name__ == "__main__":
    run()
