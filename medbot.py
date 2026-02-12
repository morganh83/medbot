import json
import os
import shutil
import asyncio
import datetime as dt
import secrets
from typing import Optional, Dict, Any, List

from aiohttp import web, ClientSession
import aiosqlite
import discord
from discord import app_commands

try:
    import openlocationcode as olc
    HAS_PLUS_CODES = True
except ImportError:
    HAS_PLUS_CODES = False
    print("Warning: openlocationcode not installed. Plus Codes will not be available.")

try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:
    pass


# =========================
# CONFIG (edit these)
# =========================

DISCORD_TOKEN = os.getenv("DISCORD_TOKEN", "PUT_YOUR_TOKEN_HERE")

JOIN_INTAKE_CHANNEL_ID = int(os.getenv("JOIN_INTAKE_CHANNEL_ID", "0"))
BOOKINGS_CHANNEL_ID = int(os.getenv("BOOKINGS_CHANNEL_ID", "0"))

DISPATCH_CHANNEL_ID = int(os.getenv("DISPATCH_CHANNEL_ID", "0"))
DISPATCH_PING_ROLE_ID = int(os.getenv("DISPATCH_PING_ROLE_ID", "0"))

# When /dispatch runs, create a thread automatically and post updates there.
CREATE_INCIDENT_THREAD = os.getenv("CREATE_INCIDENT_THREAD", "true").lower() == "true"

# Public base URL for GPS link, for example:
# https://medbot.yourdomain.com  (Cloudflare Tunnel URL recommended)
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "https://example.com").rstrip("/")

# Bot web server bind settings (internal). Cloudflare Tunnel can point to this.
WEB_BIND_HOST = os.getenv("WEB_BIND_HOST", "0.0.0.0")
WEB_BIND_PORT = int(os.getenv("WEB_BIND_PORT", "8080"))

# Shared secret for inbound website forms (Join and Book Us).
# Your website must send header: X-MedBot-Secret: <secret>
WEBHOOK_SHARED_SECRET = os.getenv("WEBHOOK_SHARED_SECRET", "CHANGE_ME")

# LocationIQ API key for reverse geocoding (free tier available)
LOCATIONIQ_API_KEY = os.getenv("LOCIQ_API_KEY", "")

# Discord role ID required to resolve incidents (optional - if not set, uses manage_messages permission)
DISPATCH_ROLE_ID = int(os.getenv("DISPATCH_ROLE_ID", "0"))

DB_PATH = os.getenv("DB_PATH", "medbot.db")

EXPORT_CSV = os.getenv("EXPORT_CSV", "true").lower() == "true"
CSV_EXPORT_PATH = os.getenv("CSV_EXPORT_PATH", "incidents_export.csv")

SHEETDB_API_URL = os.getenv("SHEETDB_API_URL", "").rstrip("/")
ROLES_CONFIG_PATH = os.getenv("ROLES_CONFIG_PATH", "roles_config.json")

# Optional: set to a guild ID for instant command sync during development
# Leave empty/0 for global sync (production — can take up to 1 hour)
DEV_GUILD_ID = int(os.getenv("DEV_GUILD_ID", "0"))

APPROVAL_CHANNEL_ID = int(os.getenv("APPROVAL_CHANNEL_ID", "0"))

# Module-level role config (populated by load_roles_config)
ROLES: List[Dict[str, Any]] = []
CERTIFICATIONS: List[Dict[str, Any]] = []
ALL_ITEMS: List[Dict[str, Any]] = []
VERIFIED_ROLE_ID: int = 0
UNVERIFIED_ROLE_ID: int = 0
PENDING_APPROVAL_ROLE_ID: int = 0


ROLES_TEMPLATE_PATH = os.path.join(os.path.dirname(ROLES_CONFIG_PATH), "roles_config.template.json")


def load_roles_config():
    """Load and validate roles from the JSON config file.

    If roles_config.json doesn't exist, copies from roles_config.template.json.
    """
    global ROLES, CERTIFICATIONS, ALL_ITEMS, VERIFIED_ROLE_ID, UNVERIFIED_ROLE_ID, PENDING_APPROVAL_ROLE_ID

    if not os.path.exists(ROLES_CONFIG_PATH):
        if os.path.exists(ROLES_TEMPLATE_PATH):
            shutil.copy2(ROLES_TEMPLATE_PATH, ROLES_CONFIG_PATH)
            print(f"Created {ROLES_CONFIG_PATH} from template. Edit it to set your Discord role IDs.")
        else:
            print(f"ERROR: Neither {ROLES_CONFIG_PATH} nor {ROLES_TEMPLATE_PATH} found.")
            return

    with open(ROLES_CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    ROLES = [r for r in cfg.get("roles", []) if r.get("discord_role_id", 0) != 0]
    CERTIFICATIONS = [r for r in cfg.get("certifications", []) if r.get("discord_role_id", 0) != 0]
    ALL_ITEMS = ROLES + CERTIFICATIONS
    VERIFIED_ROLE_ID = cfg.get("verified_role_id", 0)
    UNVERIFIED_ROLE_ID = cfg.get("unverified_role_id", 0)
    PENDING_APPROVAL_ROLE_ID = cfg.get("pending_approval_role_id", 0)

    verify_count = sum(1 for r in ROLES if r.get("requires_verification"))
    approval_count = sum(1 for r in ROLES if r.get("requires_approval"))
    print(f"Roles config loaded: {len(ROLES)} roles ({verify_count} require verification, {approval_count} require approval), {len(CERTIFICATIONS)} certifications")
    if not ALL_ITEMS:
        print("Warning: No roles/certifications with non-zero discord_role_id found in config. "
              "Set discord_role_id values in roles_config.json.")


# =========================
# DB
# =========================

CREATE_TABLES_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at_utc TEXT NOT NULL,
    incident_id TEXT NOT NULL UNIQUE,
    reporter_user_id INTEGER,
    reporter_name TEXT,
    location TEXT,
    severity TEXT,
    patient_count INTEGER,
    patient_desc TEXT,
    reported_injury TEXT,
    notes TEXT,
    status TEXT NOT NULL,
    discord_message_id INTEGER,
    discord_channel_id INTEGER,
    discord_thread_id INTEGER,
    resolved_at_utc TEXT,
    resolved_by_user_id INTEGER,
    resolved_by_name TEXT,
    care_provided TEXT,
    archived INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS incident_responders (
    incident_db_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    user_name TEXT NOT NULL,
    role TEXT NOT NULL,      -- primary, additional
    status TEXT NOT NULL,    -- en_route, on_scene, cleared
    updated_at_utc TEXT NOT NULL,
    PRIMARY KEY (incident_db_id, user_id),
    FOREIGN KEY (incident_db_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS incident_tokens (
    incident_db_id INTEGER PRIMARY KEY,
    gps_token TEXT NOT NULL UNIQUE,
    created_at_utc TEXT NOT NULL,
    FOREIGN KEY (incident_db_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS incident_location_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_db_id INTEGER NOT NULL,
    label TEXT,
    lat REAL NOT NULL,
    lon REAL NOT NULL,
    accuracy_m REAL,
    created_at_utc TEXT NOT NULL,
    FOREIGN KEY (incident_db_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS incident_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_db_id INTEGER NOT NULL,
    message_id INTEGER NOT NULL,
    author_id INTEGER NOT NULL,
    author_name TEXT NOT NULL,
    content TEXT,
    created_at_utc TEXT NOT NULL,
    FOREIGN KEY (incident_db_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS incident_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_db_id INTEGER NOT NULL,
    message_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    url TEXT NOT NULL,
    content_type TEXT,
    size_bytes INTEGER,
    created_at_utc TEXT NOT NULL,
    FOREIGN KEY (incident_db_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS location_share_tokens (
    token TEXT PRIMARY KEY,
    channel_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    user_name TEXT NOT NULL,
    created_at_utc TEXT NOT NULL,
    expires_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS member_profiles (
    user_id INTEGER PRIMARY KEY,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    nickname_set TEXT NOT NULL,
    joined_at_utc TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS member_roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    role_key TEXT NOT NULL,
    role_type TEXT NOT NULL,
    discord_role_id INTEGER NOT NULL,
    cert_number TEXT,
    assigned_at_utc TEXT NOT NULL,
    verified_at_utc TEXT,
    sheetdb_synced INTEGER DEFAULT 0,
    UNIQUE(user_id, role_key)
);

CREATE TABLE IF NOT EXISTS pending_approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    role_key TEXT NOT NULL,
    discord_message_id INTEGER,
    requested_at_utc TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    reviewed_by_user_id INTEGER,
    reviewed_at_utc TEXT,
    UNIQUE(user_id, role_key)
);
"""


async def db_init():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(CREATE_TABLES_SQL)
        await db.commit()


def utc_now_iso() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def generate_plus_code(lat: float, lon: float) -> Optional[str]:
    """
    Generate a Plus Code (Open Location Code) for precise location.
    11-character code provides ~3m x 3m precision.
    """
    if not HAS_PLUS_CODES:
        return None
    try:
        # Generate full code with maximum precision (11 chars = ~3m)
        code = olc.encode(lat, lon, codeLength=11)
        return code
    except Exception as e:
        print(f"Plus Code generation error: {e}")
        return None


def local_now_for_id() -> dt.datetime:
    return dt.datetime.now().replace(microsecond=0)


async def db_create_incident(payload: Dict[str, Any]) -> Dict[str, Any]:
    created_at_utc = utc_now_iso()

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO incidents (
                created_at_utc, incident_id, reporter_user_id, reporter_name,
                location, severity, patient_count, patient_desc, reported_injury, notes,
                status, discord_message_id, discord_channel_id, discord_thread_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                created_at_utc,
                "PENDING",
                payload.get("reporter_user_id"),
                payload.get("reporter_name"),
                payload.get("location"),
                payload.get("severity"),
                payload.get("patient_count"),
                payload.get("patient_desc"),
                payload.get("reported_injury"),
                payload.get("notes"),
                "open",
                None,
                None,
                None,
            ),
        )
        await db.commit()

        db_id = cur.lastrowid
        now_local = local_now_for_id()
        incident_id = f"{now_local.strftime('%Y%m%d-%H%M')}-{db_id:04d}"

        await db.execute(
            "UPDATE incidents SET incident_id = ? WHERE id = ?", (incident_id, db_id)
        )

        gps_token = secrets.token_urlsafe(24)
        await db.execute(
            "INSERT INTO incident_tokens (incident_db_id, gps_token, created_at_utc) VALUES (?, ?, ?)",
            (db_id, gps_token, created_at_utc),
        )

        await db.commit()

        return {
            "db_id": db_id,
            "incident_id": incident_id,
            "created_at_utc": created_at_utc,
            "gps_token": gps_token,
        }


async def db_set_discord_message(db_id: int, channel_id: int, message_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE incidents SET discord_channel_id = ?, discord_message_id = ? WHERE id = ?",
            (channel_id, message_id, db_id),
        )
        await db.commit()


async def db_set_thread(db_id: int, thread_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE incidents SET discord_thread_id = ? WHERE id = ?",
            (thread_id, db_id),
        )
        await db.commit()


async def db_set_status(db_id: int, status: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE incidents SET status = ? WHERE id = ?", (status, db_id)
        )
        await db.commit()


async def db_upsert_responder(
    db_id: int, user_id: int, user_name: str, role: str, status: str
):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO incident_responders (incident_db_id, user_id, user_name, role, status, updated_at_utc)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(incident_db_id, user_id) DO UPDATE SET
                role = excluded.role,
                status = excluded.status,
                user_name = excluded.user_name,
                updated_at_utc = excluded.updated_at_utc
            """,
            (db_id, user_id, user_name, role, status, utc_now_iso()),
        )
        await db.commit()


async def db_get_responders(db_id: int) -> List[Dict[str, Any]]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT user_id, user_name, role, status, updated_at_utc FROM incident_responders WHERE incident_db_id = ?",
            (db_id,),
        )
        rows = await cur.fetchall()
        return [dict(r) for r in rows]


async def db_get_incident_by_incident_id(incident_id: str) -> Optional[Dict[str, Any]]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
        )
        row = await cur.fetchone()
        return dict(row) if row else None


async def db_get_token_for_incident(db_id: int) -> Optional[str]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT gps_token FROM incident_tokens WHERE incident_db_id = ?", (db_id,)
        )
        row = await cur.fetchone()
        return row["gps_token"] if row else None


async def db_validate_gps_token(
    incident_id: str, token: str
) -> Optional[Dict[str, Any]]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            """
            SELECT i.*, t.gps_token
            FROM incidents i
            JOIN incident_tokens t ON t.incident_db_id = i.id
            WHERE i.incident_id = ? AND t.gps_token = ?
            """,
            (incident_id, token),
        )
        row = await cur.fetchone()
        return dict(row) if row else None


async def db_insert_location_report(
    db_id: int, label: str, lat: float, lon: float, accuracy_m: Optional[float]
):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO incident_location_reports (incident_db_id, label, lat, lon, accuracy_m, created_at_utc)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (db_id, label, lat, lon, accuracy_m, utc_now_iso()),
        )
        await db.commit()


async def db_create_location_share_token(
    channel_id: int, user_id: int, user_name: str
) -> str:
    """Create a temporary token for location sharing in any channel."""
    token = secrets.token_urlsafe(24)
    created_at = dt.datetime.utcnow()
    expires_at = created_at + dt.timedelta(hours=24)  # 24 hour expiry

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO location_share_tokens (token, channel_id, user_id, user_name, created_at_utc, expires_at_utc)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                token,
                channel_id,
                user_id,
                user_name,
                created_at.isoformat() + "Z",
                expires_at.isoformat() + "Z",
            ),
        )
        await db.commit()
    return token


async def db_get_location_share_token(token: str) -> Optional[Dict[str, Any]]:
    """Get location share token if valid and not expired."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            """
            SELECT * FROM location_share_tokens
            WHERE token = ? AND datetime(expires_at_utc) > datetime('now')
            """,
            (token,),
        )
        row = await cur.fetchone()
        return dict(row) if row else None


async def db_archive_incident(
    db_id: int,
    resolved_by_user_id: int,
    resolved_by_name: str,
    care_provided: str,
):
    """Mark incident as resolved and archived with care notes."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            UPDATE incidents
            SET status = 'resolved',
                resolved_at_utc = ?,
                resolved_by_user_id = ?,
                resolved_by_name = ?,
                care_provided = ?,
                archived = 1
            WHERE id = ?
            """,
            (utc_now_iso(), resolved_by_user_id, resolved_by_name, care_provided, db_id),
        )
        await db.commit()


async def db_archive_messages(db_id: int, messages: List[Dict[str, Any]]):
    """Archive messages from incident thread."""
    async with aiosqlite.connect(DB_PATH) as db:
        for msg in messages:
            await db.execute(
                """
                INSERT INTO incident_messages
                (incident_db_id, message_id, author_id, author_name, content, created_at_utc)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    db_id,
                    msg["message_id"],
                    msg["author_id"],
                    msg["author_name"],
                    msg["content"],
                    msg["created_at_utc"],
                ),
            )
        await db.commit()


async def db_archive_files(db_id: int, files: List[Dict[str, Any]]):
    """Archive file attachments from incident thread."""
    async with aiosqlite.connect(DB_PATH) as db:
        for file in files:
            await db.execute(
                """
                INSERT INTO incident_files
                (incident_db_id, message_id, filename, url, content_type, size_bytes, created_at_utc)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    db_id,
                    file["message_id"],
                    file["filename"],
                    file["url"],
                    file.get("content_type"),
                    file.get("size_bytes"),
                    file["created_at_utc"],
                ),
            )
        await db.commit()


# ----- Member profile / role DB helpers -----


async def db_upsert_member_profile(user_id: int, first_name: str, last_name: str, nickname: str):
    now = utc_now_iso()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO member_profiles (user_id, first_name, last_name, nickname_set, joined_at_utc, updated_at_utc)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                first_name = excluded.first_name,
                last_name = excluded.last_name,
                nickname_set = excluded.nickname_set,
                updated_at_utc = excluded.updated_at_utc
            """,
            (user_id, first_name, last_name, nickname, now, now),
        )
        await db.commit()


async def db_get_member_profile(user_id: int) -> Optional[Dict[str, Any]]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM member_profiles WHERE user_id = ?", (user_id,))
        row = await cur.fetchone()
        return dict(row) if row else None


async def db_insert_member_role(user_id: int, role_key: str, role_type: str, discord_role_id: int):
    now = utc_now_iso()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO member_roles (user_id, role_key, role_type, discord_role_id, assigned_at_utc)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(user_id, role_key) DO UPDATE SET
                role_type = excluded.role_type,
                discord_role_id = excluded.discord_role_id
            """,
            (user_id, role_key, role_type, discord_role_id, now),
        )
        await db.commit()


async def db_get_member_roles(user_id: int) -> List[Dict[str, Any]]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM member_roles WHERE user_id = ?", (user_id,))
        rows = await cur.fetchall()
        return [dict(r) for r in rows]


async def db_get_pending_certs(user_id: int) -> List[Dict[str, Any]]:
    """Get certification rows that still need a cert number or date submitted."""
    verifiable_keys = {c["key"] for c in CERTIFICATIONS if c.get("verification", "cert_number") != "none"}
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM member_roles WHERE user_id = ? AND cert_number IS NULL",
            (user_id,),
        )
        rows = await cur.fetchall()
        return [dict(r) for r in rows if r["role_key"] in verifiable_keys]


async def db_submit_cert_number(user_id: int, role_key: str, cert_number: str):
    now = utc_now_iso()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            UPDATE member_roles
            SET cert_number = ?, verified_at_utc = ?, sheetdb_synced = 0
            WHERE user_id = ? AND role_key = ?
            """,
            (cert_number, now, user_id, role_key),
        )
        await db.commit()


async def db_has_role(user_id: int, role_key: str) -> bool:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT 1 FROM member_roles WHERE user_id = ? AND role_key = ?",
            (user_id, role_key),
        )
        return await cur.fetchone() is not None


# ----- Pending approval DB helpers -----


async def db_create_pending_approval(user_id: int, role_key: str) -> int:
    now = utc_now_iso()
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO pending_approvals (user_id, role_key, requested_at_utc, status)
            VALUES (?, ?, ?, 'pending')
            ON CONFLICT(user_id, role_key) DO UPDATE SET
                status = 'pending',
                requested_at_utc = excluded.requested_at_utc,
                reviewed_by_user_id = NULL,
                reviewed_at_utc = NULL
            """,
            (user_id, role_key, now),
        )
        await db.commit()
        return cur.lastrowid


async def db_set_approval_message(approval_id: int, message_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE pending_approvals SET discord_message_id = ? WHERE id = ?",
            (message_id, approval_id),
        )
        await db.commit()


async def db_resolve_approval(approval_id: int, status: str, reviewer_id: int):
    now = utc_now_iso()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE pending_approvals SET status = ?, reviewed_by_user_id = ?, reviewed_at_utc = ? WHERE id = ?",
            (status, reviewer_id, now, approval_id),
        )
        await db.commit()


async def db_get_pending_approval(approval_id: int) -> Optional[Dict[str, Any]]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM pending_approvals WHERE id = ?", (approval_id,))
        row = await cur.fetchone()
        return dict(row) if row else None


async def db_count_pending_approvals(user_id: int) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT COUNT(*) FROM pending_approvals WHERE user_id = ? AND status = 'pending'",
            (user_id,),
        )
        row = await cur.fetchone()
        return row[0] if row else 0


async def db_get_all_pending_approvals() -> List[Dict[str, Any]]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM pending_approvals WHERE status = 'pending' AND discord_message_id IS NOT NULL"
        )
        rows = await cur.fetchall()
        return [dict(r) for r in rows]


async def db_mark_sheetdb_synced(role_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE member_roles SET sheetdb_synced = 1 WHERE id = ?", (role_id,)
        )
        await db.commit()


async def db_search_incidents(
    keyword: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    incident_id: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 20,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """Search archived incidents with filters."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        conditions = ["archived = 1"]
        params: List[Any] = []

        if keyword:
            conditions.append(
                "(location LIKE ? OR patient_desc LIKE ? OR reported_injury LIKE ? OR notes LIKE ? OR care_provided LIKE ?)"
            )
            keyword_pattern = f"%{keyword}%"
            params.extend([keyword_pattern] * 5)

        if date_from:
            conditions.append("created_at_utc >= ?")
            params.append(date_from)

        if date_to:
            conditions.append("created_at_utc <= ?")
            params.append(date_to)

        if incident_id:
            conditions.append("incident_id LIKE ?")
            params.append(f"%{incident_id}%")

        if severity:
            conditions.append("severity LIKE ?")
            params.append(f"%{severity}%")

        where_clause = " AND ".join(conditions)
        query = f"""
            SELECT * FROM incidents
            WHERE {where_clause}
            ORDER BY created_at_utc DESC
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        cur = await db.execute(query, tuple(params))
        rows = await cur.fetchall()
        return [dict(r) for r in rows]


async def db_get_incident_archive(db_id: int) -> Optional[Dict[str, Any]]:
    """Get complete archived incident with messages, files, and responders."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        # Get incident details
        cur = await db.execute("SELECT * FROM incidents WHERE id = ?", (db_id,))
        incident = await cur.fetchone()
        if not incident:
            return None

        incident_dict = dict(incident)

        # Get responders
        cur = await db.execute(
            "SELECT * FROM incident_responders WHERE incident_db_id = ?", (db_id,)
        )
        incident_dict["responders"] = [dict(r) for r in await cur.fetchall()]

        # Get messages
        cur = await db.execute(
            "SELECT * FROM incident_messages WHERE incident_db_id = ? ORDER BY created_at_utc",
            (db_id,),
        )
        incident_dict["messages"] = [dict(r) for r in await cur.fetchall()]

        # Get files
        cur = await db.execute(
            "SELECT * FROM incident_files WHERE incident_db_id = ?", (db_id,)
        )
        incident_dict["files"] = [dict(r) for r in await cur.fetchall()]

        # Get location reports
        cur = await db.execute(
            "SELECT * FROM incident_location_reports WHERE incident_db_id = ? ORDER BY created_at_utc",
            (db_id,),
        )
        incident_dict["locations"] = [dict(r) for r in await cur.fetchall()]

        return incident_dict


async def reverse_geocode(lat: float, lon: float) -> Optional[str]:
    """
    Use LocationIQ to convert GPS coordinates to a human-readable address.
    Returns formatted address or None if geocoding fails.
    """
    if not LOCATIONIQ_API_KEY:
        return None

    try:
        url = f"https://us1.locationiq.com/v1/reverse.php"
        params = {
            "key": LOCATIONIQ_API_KEY,
            "lat": lat,
            "lon": lon,
            "format": "json",
            "normalizeaddress": 1,
        }

        async with ClientSession() as session:
            async with session.get(url, params=params, timeout=5) as response:
                if response.status == 200:
                    data = await response.json()
                    # Format a concise address
                    display_name = data.get("display_name", "")
                    # Try to get just the useful parts
                    address = data.get("address", {})
                    parts = []

                    # Add road/place
                    if road := address.get("road"):
                        parts.append(road)
                    elif suburb := address.get("suburb"):
                        parts.append(suburb)

                    # Add city
                    if city := address.get("city") or address.get("town") or address.get("village"):
                        parts.append(city)

                    # Add state if in US
                    if state := address.get("state"):
                        parts.append(state)

                    return ", ".join(parts) if parts else display_name[:100]
                else:
                    print(f"Geocoding failed: HTTP {response.status}")
                    return None
    except Exception as e:
        print(f"Geocoding error: {e}")
        return None


async def export_incidents_to_csv():
    if not EXPORT_CSV:
        return

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            """
            SELECT
                i.id as db_id, i.created_at_utc, i.incident_id, i.reporter_name,
                i.location, i.severity, i.patient_count, i.patient_desc,
                i.reported_injury, i.notes, i.status,
                i.discord_channel_id, i.discord_message_id, i.discord_thread_id
            FROM incidents i
            ORDER BY i.id DESC
            """
        )
        rows = await cur.fetchall()

    headers = [
        "db_id",
        "created_at_utc",
        "incident_id",
        "reporter_name",
        "location",
        "severity",
        "patient_count",
        "patient_desc",
        "reported_injury",
        "notes",
        "status",
        "discord_channel_id",
        "discord_message_id",
        "discord_thread_id",
    ]

    def esc(value: Any) -> str:
        if value is None:
            return ""
        s = str(value).replace('"', '""')
        return f'"{s}"'

    lines = [",".join(headers)]
    for r in rows:
        lines.append(",".join(esc(r[h]) for h in headers))

    with open(CSV_EXPORT_PATH, "w", encoding="utf-8", newline="") as f:
        f.write("\n".join(lines))


# =========================
# SheetDB sync
# =========================


async def sync_member_to_sheetdb(
    user_id: int,
    first_name: str,
    last_name: str,
    join_date: str,
    certs_str: str,
    roles_str: str,
    status: str,
):
    """Sync member data to SheetDB. Failures are silent (local DB is source of truth)."""
    if not SHEETDB_API_URL:
        return

    row = {
        "Discord User ID": str(user_id),
        "First Name": first_name,
        "Last Name": last_name,
        "Join Date": join_date,
        "Certifications": certs_str,
        "Roles": roles_str,
        "Status": status,
    }

    try:
        async with ClientSession() as session:
            # Check if row already exists
            search_url = f"{SHEETDB_API_URL}/search?Discord User ID={user_id}"
            async with session.get(search_url, timeout=10) as resp:
                existing = await resp.json()

            if existing:
                # Update existing row
                patch_url = f"{SHEETDB_API_URL}/Discord User ID/{user_id}"
                async with session.patch(patch_url, json={"data": row}, timeout=10) as resp:
                    await resp.read()
            else:
                # Create new row
                async with session.post(SHEETDB_API_URL, json={"data": [row]}, timeout=10) as resp:
                    await resp.read()

            # Mark all roles as synced
            member_roles = await db_get_member_roles(user_id)
            for mr in member_roles:
                await db_mark_sheetdb_synced(mr["id"])

    except Exception as e:
        print(f"SheetDB sync error for user {user_id}: {e}")


def _get_verifiable_config(role_key: str) -> Optional[Dict[str, Any]]:
    """Look up a certification definition from config by key."""
    for r in CERTIFICATIONS:
        if r["key"] == role_key:
            return r
    return None


def _build_roles_string(member_roles: List[Dict[str, Any]]) -> str:
    """Build comma-separated role labels for SheetDB Roles column."""
    role_keys = {r["key"] for r in ROLES}
    labels = []
    for mr in member_roles:
        if mr["role_key"] in role_keys:
            cfg = next((r for r in ROLES if r["key"] == mr["role_key"]), None)
            labels.append(cfg["label"] if cfg else mr["role_key"])
    return ", ".join(labels)


def _build_certs_string(member_roles: List[Dict[str, Any]]) -> str:
    """Build cert labels with numbers for SheetDB Certifications column."""
    cert_keys = {c["key"] for c in CERTIFICATIONS}
    parts = []
    for mr in member_roles:
        if mr["role_key"] in cert_keys:
            cfg = next((c for c in CERTIFICATIONS if c["key"] == mr["role_key"]), None)
            label = cfg["label"] if cfg else mr["role_key"]
            number = mr.get("cert_number") or "pending"
            parts.append(f"{label}: {number}")
    return ", ".join(parts)


# =========================
# Discord formatting helpers
# =========================


def responder_summary(responders: List[Dict[str, Any]]) -> str:
    if not responders:
        return "None yet."

    primary = [r for r in responders if r["role"] == "primary"]
    additional = [r for r in responders if r["role"] == "additional"]

    parts = []
    if primary:
        parts.append(
            "Primary: "
            + ", ".join(f'{r["user_name"]} ({r["status"]})' for r in primary)
        )
    if additional:
        parts.append(
            "Additional: "
            + ", ".join(f'{r["user_name"]} ({r["status"]})' for r in additional)
        )
    return "\n".join(parts)


def build_dispatch_embed(
    incident_id: str,
    reporter: str,
    location: str,
    severity: str,
    patient_count: int,
    patient_desc: str,
    reported_injury: str,
    notes: str,
    gps_url: str,
    is_training: bool = False,
) -> discord.Embed:
    if is_training:
        embed = discord.Embed(
            title="[TRAINING] Dispatch Alert",
            description="This is a training exercise. Responders, practice claiming and joining below.",
            color=discord.Color.blue(),
        )
    else:
        embed = discord.Embed(
            title="Dispatch Alert",
            description="New incident reported. Responders, please claim or join below.",
            color=discord.Color.red(),
        )
    embed.add_field(name="Incident ID", value=incident_id, inline=True)
    embed.add_field(name="Status", value="open", inline=True)
    embed.add_field(name="Reported by", value=reporter, inline=True)

    embed.add_field(name="Location", value=location or "Not provided", inline=False)
    embed.add_field(name="Severity", value=severity or "Not provided", inline=True)
    embed.add_field(
        name="Patient count",
        value=str(patient_count) if patient_count is not None else "Not provided",
        inline=True,
    )

    if patient_desc:
        embed.add_field(
            name="Patient description (non identifying)",
            value=patient_desc[:1024],
            inline=False,
        )
    if reported_injury:
        embed.add_field(
            name="Reported injury", value=reported_injury[:1024], inline=False
        )
    if notes:
        embed.add_field(name="Notes", value=notes[:1024], inline=False)

    embed.add_field(name="GPS link", value=gps_url, inline=False)
    embed.add_field(name="Responders", value="None yet.", inline=False)
    return embed


# =========================
# Discord UI for dispatch
# =========================


class IncidentSearchView(discord.ui.View):
    """View for incident search results with dropdown to view details."""

    def __init__(self, incidents: List[Dict[str, Any]]):
        super().__init__(timeout=300)  # 5 minute timeout
        self.incidents = incidents

        # Add dropdown with incident options
        options = [
            discord.SelectOption(
                label=inc["incident_id"],
                description=f"{inc['status']} - {inc['location'][:50] if inc['location'] else 'No location'}",
                value=str(inc["id"]),
            )
            for inc in incidents[:25]  # Discord limit
        ]

        select = discord.ui.Select(
            placeholder="Select an incident to view full details...",
            options=options,
            custom_id="incident_select",
        )
        select.callback = self.select_callback
        self.add_item(select)

    async def select_callback(self, interaction: discord.Interaction):
        """Handle incident selection and show full details."""
        selected_id = int(interaction.data["values"][0])

        # Get full archived incident data
        archive = await db_get_incident_archive(selected_id)
        if not archive:
            await interaction.response.send_message(
                "Could not find incident details.", ephemeral=True
            )
            return

        # Build detailed embed
        embed = discord.Embed(
            title=f"Incident {archive['incident_id']}",
            description=f"**Status:** {archive['status']}",
            color=discord.Color.green()
            if archive["status"] == "resolved"
            else discord.Color.red(),
        )

        embed.add_field(
            name="Reporter", value=archive.get("reporter_name") or "Unknown", inline=True
        )
        embed.add_field(
            name="Created", value=archive["created_at_utc"][:16], inline=True
        )
        embed.add_field(
            name="Severity", value=archive.get("severity") or "N/A", inline=True
        )

        if archive.get("location"):
            embed.add_field(
                name="Location", value=archive["location"], inline=False
            )

        if archive.get("patient_desc"):
            embed.add_field(
                name="Patient Description", value=archive["patient_desc"][:1024], inline=False
            )

        if archive.get("reported_injury"):
            embed.add_field(
                name="Reported Injury", value=archive["reported_injury"][:1024], inline=False
            )

        if archive.get("care_provided"):
            embed.add_field(
                name="Care Provided", value=archive["care_provided"][:1024], inline=False
            )

        # Responders
        if archive.get("responders"):
            responders_text = "\n".join(
                f"• {r['user_name']} ({r['role']}) - {r['status']}"
                for r in archive["responders"]
            )
            embed.add_field(
                name="Responders", value=responders_text[:1024], inline=False
            )

        # Location reports
        if archive.get("locations"):
            locations_text = "\n".join(
                f"• {loc['label'] or 'Unknown'}: {loc['lat']:.6f}, {loc['lon']:.6f}"
                for loc in archive["locations"]
            )
            embed.add_field(
                name="GPS Locations", value=locations_text[:1024], inline=False
            )

        # Message count
        if archive.get("messages"):
            embed.add_field(
                name="Messages", value=f"{len(archive['messages'])} messages archived", inline=True
            )

        # File count
        if archive.get("files"):
            embed.add_field(
                name="Files", value=f"{len(archive['files'])} files archived", inline=True
            )

        if archive.get("resolved_at_utc"):
            embed.add_field(
                name="Resolved",
                value=f"{archive['resolved_at_utc'][:16]} by {archive.get('resolved_by_name') or 'Unknown'}",
                inline=False,
            )

        await interaction.response.send_message(embed=embed, ephemeral=True)


class CareNotesModal(discord.ui.Modal, title="Incident Care Summary"):
    """Modal for capturing care provided notes when resolving an incident."""

    care_notes = discord.ui.TextInput(
        label="Care Provided",
        placeholder="Describe the care provided (e.g., bandaged laceration, provided water, monitored vitals)...",
        style=discord.TextStyle.paragraph,
        required=True,
        max_length=2000,
    )

    def __init__(self, db_id: int, incident_id: str, view: "DispatchView"):
        super().__init__()
        self.db_id = db_id
        self.incident_id = incident_id
        self.view = view

    async def on_submit(self, interaction: discord.Interaction):
        care_provided = self.care_notes.value

        # Archive incident with care notes
        await db_archive_incident(
            self.db_id,
            interaction.user.id,
            interaction.user.display_name,
            care_provided,
        )

        # Try to archive messages and files from thread
        try:
            incident = await db_get_incident_by_incident_id(self.incident_id)
            if incident and incident.get("discord_thread_id"):
                thread = interaction.guild.get_thread(
                    int(incident["discord_thread_id"])
                )
                if thread:
                    messages_data = []
                    files_data = []

                    async for message in thread.history(limit=500):
                        messages_data.append(
                            {
                                "message_id": message.id,
                                "author_id": message.author.id,
                                "author_name": message.author.display_name,
                                "content": message.content or "",
                                "created_at_utc": message.created_at.isoformat() + "Z",
                            }
                        )

                        for attachment in message.attachments:
                            files_data.append(
                                {
                                    "message_id": message.id,
                                    "filename": attachment.filename,
                                    "url": attachment.url,
                                    "content_type": attachment.content_type,
                                    "size_bytes": attachment.size,
                                    "created_at_utc": message.created_at.isoformat()
                                    + "Z",
                                }
                            )

                    await db_archive_messages(self.db_id, messages_data)
                    await db_archive_files(self.db_id, files_data)
        except Exception as e:
            print(f"Warning: Could not archive thread history: {e}")

        await interaction.response.send_message(
            f"Incident **{self.incident_id}** marked resolved and archived.",
            ephemeral=True,
        )

        target = await self.view.get_update_target(interaction)
        await target.send(
            f"Incident **{self.incident_id}** marked **resolved** by {interaction.user.mention}.\n"
            f"**Care provided:** {care_provided}"
        )

        # Disable all buttons except GPS link
        for child in self.view.children:
            if isinstance(child, discord.ui.Button):
                if child.style != discord.ButtonStyle.link:
                    child.disabled = True

        await interaction.message.edit(view=self.view)
        await export_incidents_to_csv()


class DispatchView(discord.ui.View):
    def __init__(self, db_id: int, incident_id: str, gps_url: str, is_training: bool = False):
        super().__init__(timeout=None)
        self.db_id = db_id
        self.incident_id = incident_id
        self.gps_url = gps_url
        self.is_training = is_training
        # In-memory responder tracking for training mode (no DB)
        self._training_responders: List[Dict[str, Any]] = []
        # For training cleanup: store the channel message ID so resolve works from the thread too
        self._channel_message_id: Optional[int] = None

    async def get_update_target(
        self, interaction: discord.Interaction
    ) -> discord.abc.Messageable:
        if self.is_training:
            # For training, find the thread created from the channel message
            if self._channel_message_id:
                thread = interaction.guild.get_thread(self._channel_message_id)
                if thread:
                    return thread
            return interaction.channel

        # Prefer incident thread if it exists.
        try:
            incident = await db_get_incident_by_incident_id(self.incident_id)
            if incident and incident.get("discord_thread_id"):
                thread = interaction.guild.get_thread(
                    int(incident["discord_thread_id"])
                )
                if thread:
                    return thread
        except Exception:
            pass
        return interaction.channel

    async def _get_responders(self) -> List[Dict[str, Any]]:
        if self.is_training:
            return self._training_responders
        return await db_get_responders(self.db_id)

    async def _upsert_responder(self, user_id: int, user_name: str, role: str, status: str):
        if self.is_training:
            existing = next((r for r in self._training_responders if r["user_id"] == user_id), None)
            if existing:
                existing["role"] = role
                existing["status"] = status
                existing["user_name"] = user_name
            else:
                self._training_responders.append({
                    "user_id": user_id, "user_name": user_name,
                    "role": role, "status": status, "updated_at_utc": utc_now_iso(),
                })
        else:
            await db_upsert_responder(self.db_id, user_id, user_name, role, status)

    async def refresh_embed(
        self, interaction: discord.Interaction, note: Optional[str] = None
    ):
        responders = await self._get_responders()

        embed = (
            interaction.message.embeds[0]
            if interaction.message.embeds
            else discord.Embed()
        )
        embed.clear_fields()

        embed.add_field(name="Incident ID", value=self.incident_id, inline=True)
        embed.add_field(name="Status", value="open", inline=True)
        embed.add_field(
            name="Responders", value=responder_summary(responders), inline=False
        )

        if note:
            embed.add_field(name="Update", value=note, inline=False)

        await interaction.message.edit(embed=embed, view=self)

    async def ensure_responder_role(
        self, user: discord.Member, preferred_role: str
    ) -> str:
        responders = await self._get_responders()
        existing = next((r for r in responders if int(r["user_id"]) == user.id), None)
        if existing:
            return existing["role"]
        return preferred_role

    # ROW 0: Response buttons
    @discord.ui.button(
        label="Claim (Primary)",
        style=discord.ButtonStyle.danger,
        custom_id="dispatch_claim_primary",
        row=0,
    )
    async def claim_primary(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ):
        responders = await self._get_responders()
        primary_exists = any(r["role"] == "primary" for r in responders)

        if primary_exists:
            await interaction.response.send_message(
                "Primary responder is already claimed. Use Join (Additional), or ask an admin to hand off.",
                ephemeral=True,
            )
            return

        await self._upsert_responder(
            interaction.user.id,
            interaction.user.display_name,
            "primary",
            "en_route",
        )
        await interaction.response.send_message(
            "You claimed primary response and are marked en route.", ephemeral=True
        )

        target = await self.get_update_target(interaction)
        await target.send(
            f"{interaction.user.mention} claimed primary response for **{self.incident_id}** and is en route."
        )

        await self.refresh_embed(
            interaction,
            note=f"{interaction.user.display_name} claimed primary response (en route).",
        )

    @discord.ui.button(
        label="Join (Additional)",
        style=discord.ButtonStyle.primary,
        custom_id="dispatch_join_additional",
        row=0,
    )
    async def join_additional(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ):
        await self._upsert_responder(
            interaction.user.id,
            interaction.user.display_name,
            "additional",
            "en_route",
        )
        await interaction.response.send_message(
            "You joined as an additional responder and are marked en route.",
            ephemeral=True,
        )

        target = await self.get_update_target(interaction)
        await target.send(
            f"{interaction.user.mention} is en route as an additional responder for **{self.incident_id}**."
        )

        await self.refresh_embed(
            interaction,
            note=f"{interaction.user.display_name} joined as additional (en route).",
        )

    # ROW 1: Action/Status buttons
    @discord.ui.button(
        label="On Scene",
        style=discord.ButtonStyle.secondary,
        custom_id="dispatch_on_scene",
        row=1,
    )
    async def on_scene(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ):
        role = await self.ensure_responder_role(interaction.user, "additional")
        await self._upsert_responder(
            interaction.user.id,
            interaction.user.display_name,
            role,
            "on_scene",
        )
        await interaction.response.send_message(
            "You are marked on scene.", ephemeral=True
        )

        target = await self.get_update_target(interaction)
        await target.send(
            f"{interaction.user.mention} is **on scene** for **{self.incident_id}**."
        )

        await self.refresh_embed(
            interaction, note=f"{interaction.user.display_name} marked on scene."
        )

    @discord.ui.button(
        label="Request Backup",
        style=discord.ButtonStyle.secondary,
        custom_id="dispatch_request_backup",
        row=1,
    )
    async def request_backup(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ):
        ping_text = f"<@&{DISPATCH_PING_ROLE_ID}> " if DISPATCH_PING_ROLE_ID else ""

        target = await self.get_update_target(interaction)
        await interaction.response.send_message(
            "Backup request posted.", ephemeral=True
        )
        await target.send(
            f"{ping_text}Backup requested for **{self.incident_id}** by {interaction.user.mention}.",
            allowed_mentions=discord.AllowedMentions(roles=True, users=True),
        )

        await self.refresh_embed(
            interaction, note=f"Backup requested by {interaction.user.display_name}."
        )

    @discord.ui.button(
        label="Share GPS",
        style=discord.ButtonStyle.primary,
        custom_id="dispatch_share_gps",
        row=1,
    )
    async def share_gps_button(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ):
        """Share GPS location button - sends link to GPS page."""
        await interaction.response.send_message(
            f"GPS sharing link: {self.gps_url}\n\nOpen this link on your device to share your precise location.",
            ephemeral=True,
        )

    # ROW 2: Resolution buttons
    @discord.ui.button(
        label="Escalating",
        style=discord.ButtonStyle.danger,
        custom_id="dispatch_escalating",
        row=2,
    )
    async def escalating(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ):
        """Escalating button - indicates advanced medical care needed."""
        if not self.is_training:
            await db_set_status(self.db_id, "escalated")

        await interaction.response.send_message(
            f"Incident **{self.incident_id}** marked as escalating (advanced care needed).",
            ephemeral=True,
        )

        target = await self.get_update_target(interaction)
        await target.send(
            f"⚠️ Incident **{self.incident_id}** escalated by {interaction.user.mention}. Advanced medical care needed."
        )

        await self.refresh_embed(
            interaction,
            note=f"⚠️ Escalated by {interaction.user.display_name} - advanced care needed.",
        )

    @discord.ui.button(
        label="Resolved",
        style=discord.ButtonStyle.success,
        custom_id="dispatch_resolved",
        row=2,
    )
    async def resolved(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ):
        """Resolved button - requires role and prompts for care notes."""
        # Check permissions: either DISPATCH_ROLE_ID or manage_messages
        has_permission = False
        if DISPATCH_ROLE_ID:
            has_permission = any(
                role.id == DISPATCH_ROLE_ID for role in interaction.user.roles
            )
        else:
            has_permission = interaction.user.guild_permissions.manage_messages

        if not has_permission:
            await interaction.response.send_message(
                "You do not have permission to resolve incidents. Contact dispatch.",
                ephemeral=True,
            )
            return

        if self.is_training:
            await interaction.response.defer(ephemeral=True)
            guild = interaction.guild
            channel_msg_id = self._channel_message_id

            # Delete the thread (created from the channel message)
            if channel_msg_id:
                try:
                    thread = guild.get_thread(channel_msg_id)
                    if thread:
                        await thread.delete()
                except Exception as e:
                    print(f"Warning: Could not delete training thread: {e}")

            # Delete the channel dispatch message
            if channel_msg_id:
                try:
                    ch = guild.get_channel(DISPATCH_CHANNEL_ID)
                    if ch:
                        ch_msg = await ch.fetch_message(channel_msg_id)
                        await ch_msg.delete()
                except Exception as e:
                    print(f"Warning: Could not delete training channel message: {e}")

            await interaction.followup.send(
                "Training exercise resolved and cleaned up.", ephemeral=True
            )
            return

        # Show modal for care notes
        modal = CareNotesModal(self.db_id, self.incident_id, self)
        await interaction.response.send_modal(modal)


# =========================
# Onboarding / Certification UI
# =========================

# In-memory store: user_id -> {"roles": [...], "certifications": [...]} (cleared on submit)
_onboarding_selections: Dict[int, Dict[str, List[str]]] = {}


class RoleApprovalView(discord.ui.View):
    """Persistent view with Approve/Deny buttons for role approval requests."""

    def __init__(self, user_id: int, role_key: str, approval_id: int):
        super().__init__(timeout=None)
        self.target_user_id = user_id
        self.role_key = role_key
        self.approval_id = approval_id

        approve_btn = discord.ui.Button(
            label="Approve",
            style=discord.ButtonStyle.success,
            custom_id=f"approval_approve_{approval_id}",
        )
        approve_btn.callback = self.approve_callback
        self.add_item(approve_btn)

        deny_btn = discord.ui.Button(
            label="Deny",
            style=discord.ButtonStyle.danger,
            custom_id=f"approval_deny_{approval_id}",
        )
        deny_btn.callback = self.deny_callback
        self.add_item(deny_btn)

    async def approve_callback(self, interaction: discord.Interaction):
        # Check admin permission
        if not interaction.user.guild_permissions.manage_roles:
            await interaction.response.send_message(
                "You need Manage Roles permission to approve.", ephemeral=True
            )
            return

        await interaction.response.defer(ephemeral=True)

        guild = interaction.guild
        member = guild.get_member(self.target_user_id)
        if not member:
            await interaction.followup.send("Member not found in server.", ephemeral=True)
            return

        # Find the role config
        role_cfg = next((r for r in ROLES if r["key"] == self.role_key), None)
        if not role_cfg:
            await interaction.followup.send("Role config not found.", ephemeral=True)
            return

        # Assign the requested Discord role
        role_obj = guild.get_role(role_cfg["discord_role_id"])
        if role_obj:
            try:
                await member.add_roles(role_obj, reason=f"Approved by {interaction.user.display_name}")
            except discord.Forbidden:
                await interaction.followup.send(
                    f"Cannot assign role — bot role too low in hierarchy.", ephemeral=True
                )
                return

        # Save role to DB
        await db_insert_member_role(member.id, self.role_key, "role", role_cfg["discord_role_id"])

        # Update approval status
        await db_resolve_approval(self.approval_id, "approved", interaction.user.id)

        # Remove pending approval tag if no other pending approvals
        remaining = await db_count_pending_approvals(self.target_user_id)
        if remaining == 0 and PENDING_APPROVAL_ROLE_ID:
            pending_role = guild.get_role(PENDING_APPROVAL_ROLE_ID)
            if pending_role:
                try:
                    await member.remove_roles(pending_role, reason="All approvals resolved")
                except discord.Forbidden:
                    pass

        # Disable buttons and update embed
        for child in self.children:
            child.disabled = True
        embed = interaction.message.embeds[0] if interaction.message.embeds else discord.Embed()
        embed.color = discord.Color.green()
        embed.set_footer(text=f"Approved by {interaction.user.display_name}")
        await interaction.message.edit(embed=embed, view=self)

        # Notify member
        try:
            await member.send(
                f"Your request for **{role_cfg['label']}** has been **approved**!"
            )
        except discord.Forbidden:
            pass

        await interaction.followup.send(
            f"Approved **{role_cfg['label']}** for {member.display_name}.", ephemeral=True
        )

    async def deny_callback(self, interaction: discord.Interaction):
        if not interaction.user.guild_permissions.manage_roles:
            await interaction.response.send_message(
                "You need Manage Roles permission to deny.", ephemeral=True
            )
            return

        await interaction.response.defer(ephemeral=True)

        guild = interaction.guild
        member = guild.get_member(self.target_user_id)

        # Update approval status
        await db_resolve_approval(self.approval_id, "denied", interaction.user.id)

        # Remove pending approval tag if no other pending approvals
        if member:
            remaining = await db_count_pending_approvals(self.target_user_id)
            if remaining == 0 and PENDING_APPROVAL_ROLE_ID:
                pending_role = guild.get_role(PENDING_APPROVAL_ROLE_ID)
                if pending_role:
                    try:
                        await member.remove_roles(pending_role, reason="All approvals resolved")
                    except discord.Forbidden:
                        pass

        # Disable buttons and update embed
        for child in self.children:
            child.disabled = True
        embed = interaction.message.embeds[0] if interaction.message.embeds else discord.Embed()
        embed.color = discord.Color.red()
        embed.set_footer(text=f"Denied by {interaction.user.display_name}")
        await interaction.message.edit(embed=embed, view=self)

        # Notify member
        role_cfg = next((r for r in ROLES if r["key"] == self.role_key), None)
        label = role_cfg["label"] if role_cfg else self.role_key
        if member:
            try:
                await member.send(
                    f"Your request for **{label}** has been **denied**."
                )
            except discord.Forbidden:
                pass

        await interaction.followup.send(
            f"Denied **{label}** for user ID {self.target_user_id}.", ephemeral=True
        )


async def _request_role_approval(
    interaction: discord.Interaction,
    member: discord.Member,
    role_cfg: Dict[str, Any],
    first_name: str,
    last_name: str,
):
    """Create a pending approval and post to the approval channel."""
    guild = interaction.guild

    # Assign pending approval tag role
    if PENDING_APPROVAL_ROLE_ID:
        pending_role = guild.get_role(PENDING_APPROVAL_ROLE_ID)
        if pending_role:
            try:
                await member.add_roles(pending_role, reason="Pending role approval")
            except discord.Forbidden:
                pass

    # Create DB record
    approval_id = await db_create_pending_approval(member.id, role_cfg["key"])

    # Post to approval channel
    approval_channel = guild.get_channel(APPROVAL_CHANNEL_ID)
    if not approval_channel:
        try:
            approval_channel = await client.fetch_channel(APPROVAL_CHANNEL_ID)
        except Exception:
            pass
    if not approval_channel:
        print(f"WARNING: Approval channel {APPROVAL_CHANNEL_ID} not found")
        return

    embed = discord.Embed(
        title="Role Approval Request",
        description=f"**{first_name} {last_name}** ({member.mention}) requested the **{role_cfg['label']}** role.",
        color=discord.Color.gold(),
    )
    embed.add_field(name="User", value=f"{member.display_name} ({member.id})", inline=True)
    embed.add_field(name="Role", value=role_cfg["label"], inline=True)
    embed.add_field(name="Requested", value=utc_now_iso()[:16], inline=True)

    view = RoleApprovalView(user_id=member.id, role_key=role_cfg["key"], approval_id=approval_id)
    msg = await approval_channel.send(embed=embed, view=view)
    await db_set_approval_message(approval_id, msg.id)


async def process_onboarding(
    interaction: discord.Interaction,
    first_name: str,
    last_name: str,
    selected_role_keys: List[str],
    selected_cert_keys: List[str],
):
    """Shared onboarding logic: assign roles, save profile, sync SheetDB."""
    fname = first_name.strip()
    lname = last_name.strip()
    last_initial = lname[0].upper() if lname else ""
    nickname = f"{fname} {last_initial}."[:32]

    member = interaction.user
    guild = interaction.guild

    # Set nickname (may fail if target is server owner)
    try:
        await member.edit(nick=nickname)
    except discord.Forbidden:
        pass

    # Save / update profile
    await db_upsert_member_profile(member.id, fname, lname, nickname)

    # Resolve selected roles and certifications from config
    selected_roles = [r for r in ROLES if r["key"] in selected_role_keys]
    selected_certs = [c for c in CERTIFICATIONS if c["key"] in selected_cert_keys]

    # Assign Discord roles and save to DB
    assigned_labels = []
    failed_labels = []
    pending_approval_labels = []

    for r in selected_roles:
        # Check if this role requires admin approval
        if r.get("requires_approval") and APPROVAL_CHANNEL_ID:
            try:
                await _request_role_approval(interaction, member, r, fname, lname)
                pending_approval_labels.append(r["label"])
                continue
            except Exception as e:
                print(f"WARNING: Role approval request failed for '{r['label']}', falling back to direct assign: {e}")
                # Fall through to normal assignment below

        role_obj = guild.get_role(r["discord_role_id"])
        if role_obj:
            try:
                await member.add_roles(role_obj, reason="Onboarding role claim")
            except discord.Forbidden:
                print(f"WARNING: Cannot assign role '{r['label']}' to {member} — bot role too low in hierarchy?")
                failed_labels.append(r["label"])
        else:
            print(f"WARNING: Role ID {r['discord_role_id']} for '{r['label']}' not found in guild")
            failed_labels.append(r["label"])
        await db_insert_member_role(member.id, r["key"], "role", r["discord_role_id"])
        assigned_labels.append(r["label"])

    for c in selected_certs:
        role_obj = guild.get_role(c["discord_role_id"])
        if role_obj:
            try:
                await member.add_roles(role_obj, reason="Onboarding certification claim")
            except discord.Forbidden:
                print(f"WARNING: Cannot assign cert role '{c['label']}' to {member} — bot role too low in hierarchy?")
                failed_labels.append(c["label"])
        else:
            print(f"WARNING: Role ID {c['discord_role_id']} for '{c['label']}' not found in guild")
            failed_labels.append(c["label"])
        await db_insert_member_role(member.id, c["key"], "certification", c["discord_role_id"])
        # For "none" verification items, mark as self-reported so they don't appear pending
        if c.get("verification") == "none":
            await db_submit_cert_number(member.id, c["key"], "self-reported")
        assigned_labels.append(c["label"])

    # Handle verification status
    verifiable_certs = [c for c in selected_certs if c.get("verification", "cert_number") != "none"]
    needs_verification = (
        any(r.get("requires_verification") for r in selected_roles)
        or len(verifiable_certs) > 0
    )
    already_verified = VERIFIED_ROLE_ID and any(r.id == VERIFIED_ROLE_ID for r in member.roles)
    if needs_verification and not already_verified and UNVERIFIED_ROLE_ID:
        unverified_role = guild.get_role(UNVERIFIED_ROLE_ID)
        if unverified_role:
            try:
                await member.add_roles(unverified_role, reason="Pending verification")
            except discord.Forbidden:
                pass

    # Sync to SheetDB
    all_member_roles = await db_get_member_roles(member.id)
    roles_str = _build_roles_string(all_member_roles)
    certs_str = _build_certs_string(all_member_roles)
    pending = await db_get_pending_certs(member.id)
    status = "Unverified" if (pending or (needs_verification and not already_verified)) else "Verified"
    profile = await db_get_member_profile(member.id)
    join_date = profile["joined_at_utc"][:10] if profile else utc_now_iso()[:10]

    await sync_member_to_sheetdb(
        member.id, fname, lname, join_date, certs_str, roles_str, status
    )

    # Build response
    lines = [f"**Welcome, {nickname}!** Your roles have been assigned:"]
    if assigned_labels:
        lines.append(", ".join(f"**{l}**" for l in assigned_labels))
    if pending_approval_labels:
        lines.append(
            f"\nPending admin approval: {', '.join(f'**{l}**' for l in pending_approval_labels)}"
        )
    if failed_labels:
        lines.append(
            f"\n**Warning:** Could not assign: {', '.join(failed_labels)}. "
            "An admin needs to move the bot's role higher in the server role hierarchy."
        )
    if needs_verification:
        lines.append(
            "\nYou have credentials that require verification. "
            "Use `/submit-certs` to submit your certification numbers or course dates and get verified."
        )
    await interaction.followup.send("\n".join(lines), ephemeral=True)


class OnboardingModal(discord.ui.Modal, title="Welcome — Tell Us Your Name"):
    first_name = discord.ui.TextInput(
        label="First Name",
        placeholder="Your first name",
        style=discord.TextStyle.short,
        required=True,
        max_length=50,
    )
    last_name = discord.ui.TextInput(
        label="Last Name",
        placeholder="Your last name",
        style=discord.TextStyle.short,
        required=True,
        max_length=50,
    )

    def __init__(self, selected_role_keys: List[str], selected_cert_keys: List[str]):
        super().__init__()
        self.selected_role_keys = selected_role_keys
        self.selected_cert_keys = selected_cert_keys

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        await process_onboarding(
            interaction,
            self.first_name.value,
            self.last_name.value,
            self.selected_role_keys,
            self.selected_cert_keys,
        )


class OnboardingRoleSelect(discord.ui.Select):
    """Multi-select dropdown for role selection during onboarding."""

    def __init__(self, options: List[discord.SelectOption]):
        super().__init__(
            placeholder="Select your roles...",
            custom_id="onboarding_role_select",
            min_values=1,
            max_values=len(options) if options else 1,
            options=options or [discord.SelectOption(label="No roles configured", value="_none")],
            row=0,
        )

    async def callback(self, interaction: discord.Interaction):
        uid = interaction.user.id
        if uid not in _onboarding_selections:
            _onboarding_selections[uid] = {"roles": [], "certifications": []}
        _onboarding_selections[uid]["roles"] = self.values
        labels = []
        for key in self.values:
            for r in ROLES:
                if r["key"] == key:
                    labels.append(r["label"])
                    break
        await interaction.response.send_message(
            f"Roles selected: {', '.join(labels)}. Click **Join** when ready.",
            ephemeral=True,
        )


class OnboardingCertSelect(discord.ui.Select):
    """Multi-select dropdown for certification selection during onboarding."""

    def __init__(self, options: List[discord.SelectOption]):
        super().__init__(
            placeholder="Select your certifications...",
            custom_id="onboarding_cert_select",
            min_values=1,
            max_values=len(options) if options else 1,
            options=options or [discord.SelectOption(label="No certifications configured", value="_none")],
            row=1,
        )

    async def callback(self, interaction: discord.Interaction):
        uid = interaction.user.id
        if uid not in _onboarding_selections:
            _onboarding_selections[uid] = {"roles": [], "certifications": []}
        _onboarding_selections[uid]["certifications"] = self.values
        labels = []
        for key in self.values:
            for c in CERTIFICATIONS:
                if c["key"] == key:
                    labels.append(c["label"])
                    break
        await interaction.response.send_message(
            f"Certifications selected: {', '.join(labels)}. Click **Join** when ready.",
            ephemeral=True,
        )


class OnboardingView(discord.ui.View):
    """Persistent view with role select + certification select + Join button."""

    def __init__(
        self,
        role_options: Optional[List[discord.SelectOption]] = None,
        cert_options: Optional[List[discord.SelectOption]] = None,
    ):
        super().__init__(timeout=None)
        if role_options:
            self.add_item(OnboardingRoleSelect(role_options))
        if cert_options:
            self.add_item(OnboardingCertSelect(cert_options))

    @discord.ui.button(
        label="Join",
        style=discord.ButtonStyle.success,
        custom_id="onboarding_join",
        row=2,
    )
    async def join_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        selected = _onboarding_selections.pop(interaction.user.id, None)
        if not selected or (not selected.get("roles") and not selected.get("certifications")):
            await interaction.response.send_message(
                "Please select at least one role or certification from the dropdowns first.",
                ephemeral=True,
            )
            return

        # If user already has a profile, skip the name modal
        profile = await db_get_member_profile(interaction.user.id)
        if profile:
            await interaction.response.defer(ephemeral=True)
            await process_onboarding(
                interaction,
                profile["first_name"],
                profile["last_name"],
                selected.get("roles", []),
                selected.get("certifications", []),
            )
            return

        modal = OnboardingModal(
            selected_role_keys=selected.get("roles", []),
            selected_cert_keys=selected.get("certifications", []),
        )
        await interaction.response.send_modal(modal)


class SubmitCertsModal(discord.ui.Modal, title="Submit Credentials"):
    """Dynamic modal with up to 5 cert number / course date text inputs."""

    def __init__(self, pending: List[Dict[str, Any]]):
        super().__init__()
        self.pending_roles = pending[:5]

        for p in self.pending_roles:
            cfg = _get_verifiable_config(p["role_key"])
            label = cfg["cert_label"] if cfg else f"{p['role_key']} Cert #"
            placeholder = cfg["cert_placeholder"] if cfg else "Enter certification number"
            self.add_item(
                discord.ui.TextInput(
                    label=label[:45],
                    placeholder=placeholder[:100],
                    style=discord.TextStyle.short,
                    required=True,
                    max_length=100,
                    custom_id=f"cert_{p['role_key']}",
                )
            )

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)

        member = interaction.user
        guild = interaction.guild

        submitted = []
        for child in self.children:
            if isinstance(child, discord.ui.TextInput) and child.custom_id.startswith("cert_"):
                role_key = child.custom_id[5:]  # strip "cert_"
                cert_number = child.value.strip()
                if cert_number:
                    await db_submit_cert_number(member.id, role_key, cert_number)
                    submitted.append(role_key)

        # Check remaining pending certs
        remaining = await db_get_pending_certs(member.id)

        if not remaining:
            # All verified — swap Unverified → Verified
            if UNVERIFIED_ROLE_ID:
                unverified = guild.get_role(UNVERIFIED_ROLE_ID)
                if unverified:
                    try:
                        await member.remove_roles(unverified, reason="All certs verified")
                    except discord.Forbidden:
                        pass
            if VERIFIED_ROLE_ID:
                verified = guild.get_role(VERIFIED_ROLE_ID)
                if verified:
                    try:
                        await member.add_roles(verified, reason="All certs verified")
                    except discord.Forbidden:
                        pass

            status_msg = "All credentials submitted! You are now **Verified**."
        else:
            remaining_labels = []
            for r in remaining:
                cfg = _get_verifiable_config(r["role_key"])
                remaining_labels.append(cfg["label"] if cfg else r["role_key"])
            status_msg = (
                f"Credentials submitted for {len(submitted)} item(s). "
                f"Still pending: {', '.join(remaining_labels)}. "
                f"Run `/submit-certs` again to complete."
            )

        # Sync to SheetDB
        all_member_roles = await db_get_member_roles(member.id)
        profile = await db_get_member_profile(member.id)
        if profile:
            roles_str = _build_roles_string(all_member_roles)
            certs_str = _build_certs_string(all_member_roles)
            sync_status = "Verified" if not remaining else "Unverified"
            await sync_member_to_sheetdb(
                member.id,
                profile["first_name"],
                profile["last_name"],
                profile["joined_at_utc"][:10],
                certs_str,
                roles_str,
                sync_status,
            )

        await interaction.followup.send(status_msg, ephemeral=True)


def _build_onboarding_view() -> OnboardingView:
    """Build an OnboardingView with select options from current config."""
    role_options = [
        discord.SelectOption(
            label=r["label"],
            value=r["key"],
            description=r.get("description", "")[:100],
        )
        for r in ROLES
    ] or None
    cert_options = [
        discord.SelectOption(
            label=c["label"],
            value=c["key"],
            description=c.get("description", "")[:100],
        )
        for c in CERTIFICATIONS
    ] or None
    return OnboardingView(role_options=role_options, cert_options=cert_options)


# =========================
# Discord bot
# =========================

intents = discord.Intents.default()
intents.guilds = True
intents.members = True

client = discord.Client(intents=intents)
tree = app_commands.CommandTree(client)


@tree.command(
    name="dispatch", description="Create a dispatch alert for an on site incident."
)
@app_commands.describe(
    location="Where is the incident. Use landmarks, gate numbers, cross streets, etc.",
    severity="Severity level, for example low, medium, high, critical.",
    patient_count="Approximate number of patients.",
    patient_desc="Non identifying description, for example adult, child, clothing color, etc.",
    reported_injury="Reported issue, for example fall, dehydration, laceration.",
    notes="Any other relevant info for responders.",
)
async def dispatch(
    interaction: discord.Interaction,
    location: str,
    severity: str,
    patient_count: Optional[int] = 1,
    patient_desc: Optional[str] = "",
    reported_injury: Optional[str] = "",
    notes: Optional[str] = "",
):
    if not DISPATCH_CHANNEL_ID:
        await interaction.response.send_message(
            "Dispatch channel is not configured.", ephemeral=True
        )
        return

    await interaction.response.defer(ephemeral=True)

    is_training = severity.lower().strip() == "training"

    channel = interaction.guild.get_channel(DISPATCH_CHANNEL_ID)
    if channel is None:
        await interaction.followup.send(
            "Dispatch channel not found. Check the channel ID.", ephemeral=True
        )
        return

    if is_training:
        # Training mode — no DB logging
        now_local = local_now_for_id()
        incident_id = f"TRAIN-{now_local.strftime('%Y%m%d-%H%M')}"
        gps_url = "(training — no GPS)"

        embed = build_dispatch_embed(
            incident_id=incident_id,
            reporter=interaction.user.display_name,
            location=location,
            severity="training",
            patient_count=patient_count if patient_count is not None else 0,
            patient_desc=patient_desc or "",
            reported_injury=reported_injury or "",
            notes=notes or "",
            gps_url=gps_url,
            is_training=True,
        )

        view = DispatchView(db_id=0, incident_id=incident_id, gps_url=gps_url, is_training=True)

        msg = await channel.send(
            content=f"**[TRAINING] Dispatch:** Incident **{incident_id}** reported.",
            embed=embed,
            view=view,
        )

        # Store channel message ID for cleanup
        view._channel_message_id = msg.id

        if CREATE_INCIDENT_THREAD:
            try:
                thread = await msg.create_thread(name=f"[TRAINING] {incident_id}")
                # Send buttons into the thread so responders can interact from there
                thread_view = DispatchView(db_id=0, incident_id=incident_id, gps_url=gps_url, is_training=True)
                thread_view._channel_message_id = msg.id
                thread_view._training_responders = view._training_responders  # Share state
                await thread.send(
                    f"Training thread for **{incident_id}**. Use the buttons below to practice.",
                    embed=embed.copy(),
                    view=thread_view,
                )
            except Exception as e:
                await channel.send(
                    f"Could not create training thread for **{incident_id}**. Reason: {e}"
                )

        await interaction.followup.send(
            f"Training dispatch created: **{incident_id}**", ephemeral=True
        )
        return

    # Normal dispatch flow
    created = await db_create_incident(
        {
            "reporter_user_id": interaction.user.id,
            "reporter_name": interaction.user.display_name,
            "location": location,
            "severity": severity,
            "patient_count": patient_count,
            "patient_desc": patient_desc,
            "reported_injury": reported_injury,
            "notes": notes,
        }
    )

    incident_id = created["incident_id"]
    db_id = created["db_id"]
    gps_token = created["gps_token"]

    gps_url = f"{PUBLIC_BASE_URL}/gps?incident_id={incident_id}&token={gps_token}"

    ping = f"<@&{DISPATCH_PING_ROLE_ID}> " if DISPATCH_PING_ROLE_ID else ""

    embed = build_dispatch_embed(
        incident_id=incident_id,
        reporter=interaction.user.display_name,
        location=location,
        severity=severity,
        patient_count=patient_count if patient_count is not None else 0,
        patient_desc=patient_desc or "",
        reported_injury=reported_injury or "",
        notes=notes or "",
        gps_url=gps_url,
    )

    view = DispatchView(db_id=db_id, incident_id=incident_id, gps_url=gps_url)

    msg = await channel.send(
        content=f"{ping}**Dispatch:** Incident **{incident_id}** reported.",
        embed=embed,
        view=view,
        allowed_mentions=discord.AllowedMentions(roles=True, users=True),
    )

    await db_set_discord_message(db_id, channel.id, msg.id)

    # Create thread for the incident to keep updates centralized.
    if CREATE_INCIDENT_THREAD:
        try:
            thread = await msg.create_thread(name=f"INCIDENT {incident_id}")
            await db_set_thread(db_id, thread.id)
            await thread.send(
                f"Incident thread for **{incident_id}**. Use buttons on the alert, and use the GPS link if needed.\n"
                f"GPS quick link: {gps_url}"
            )
        except Exception as e:
            # Thread creation can fail based on perms, channel type, etc.
            await channel.send(
                f"Could not create incident thread for **{incident_id}**. Reason: {e}"
            )

    await interaction.followup.send(
        f"Dispatch alert created: **{incident_id}**", ephemeral=True
    )


@tree.command(
    name="backup", description="Request additional support for an existing incident."
)
@app_commands.describe(
    incident_id="Incident ID, for example 20260131-2145-0001.",
    reason="Short reason, for example second patient, crowd surge, needs transport coordination.",
)
async def backup(
    interaction: discord.Interaction, incident_id: str, reason: Optional[str] = ""
):
    await interaction.response.defer(ephemeral=True)

    incident = await db_get_incident_by_incident_id(incident_id)
    if not incident:
        await interaction.followup.send("Incident not found.", ephemeral=True)
        return

    ping = f"<@&{DISPATCH_PING_ROLE_ID}> " if DISPATCH_PING_ROLE_ID else ""
    msg = f"{ping}Backup requested for **{incident_id}** by {interaction.user.mention}."
    if reason:
        msg += f" Reason: {reason}"

    # Prefer thread if it exists
    target = None
    if incident.get("discord_thread_id"):
        target = interaction.guild.get_thread(int(incident["discord_thread_id"]))
    if not target:
        target = (
            interaction.guild.get_channel(int(incident["discord_channel_id"]))
            if incident.get("discord_channel_id")
            else None
        )
    if not target:
        await interaction.followup.send(
            "Could not find the incident channel or thread.", ephemeral=True
        )
        return

    await target.send(
        msg, allowed_mentions=discord.AllowedMentions(roles=True, users=True)
    )
    await interaction.followup.send("Backup request posted.", ephemeral=True)


@tree.command(
    name="share-location",
    description="Share your GPS location in this channel (opens web page to capture location).",
)
async def share_location(interaction: discord.Interaction):
    """
    Share GPS location command - generates a temporary GPS link for any channel.
    Works like the incident GPS button but can be used anywhere.
    """
    # Create a temporary token for this location share
    token = await db_create_location_share_token(
        interaction.channel_id, interaction.user.id, interaction.user.display_name
    )
    gps_url = f"{PUBLIC_BASE_URL}/location-share?token={token}"

    await interaction.response.send_message(
        f"Click to share your location: {gps_url}\n\n"
        f"This link will post your precise GPS coordinates to this channel when you open it on your device.\n"
        f"Link expires in 24 hours.",
        ephemeral=True,
    )


@tree.command(
    name="incident-search",
    description="Search archived incidents by keyword, date, or incident ID.",
)
@app_commands.describe(
    keyword="Search in location, injury, notes, or care provided.",
    incident_id="Search by incident ID (partial match).",
    severity="Filter by severity level.",
    date_from="Start date (YYYY-MM-DD).",
    date_to="End date (YYYY-MM-DD).",
)
async def incident_search(
    interaction: discord.Interaction,
    keyword: Optional[str] = None,
    incident_id: Optional[str] = None,
    severity: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
):
    """Search archived incidents with various filters."""
    await interaction.response.defer(ephemeral=True)

    try:
        results = await db_search_incidents(
            keyword=keyword,
            date_from=date_from,
            date_to=date_to,
            incident_id=incident_id,
            severity=severity,
            limit=10,
            offset=0,
        )

        if not results:
            await interaction.followup.send(
                "No incidents found matching your search criteria.", ephemeral=True
            )
            return

        # Build result embed
        embed = discord.Embed(
            title="Incident Search Results",
            description=f"Found {len(results)} incident(s)",
            color=discord.Color.blue(),
        )

        for inc in results[:10]:  # Limit to 10 results
            status_emoji = (
                "✅" if inc["status"] == "resolved" else "⚠️" if inc["status"] == "escalated" else "🔵"
            )
            field_value = (
                f"**Status:** {status_emoji} {inc['status']}\n"
                f"**Location:** {inc['location'] or 'N/A'}\n"
                f"**Severity:** {inc['severity'] or 'N/A'}\n"
                f"**Created:** {inc['created_at_utc'][:16]}\n"
            )
            if inc.get("resolved_at_utc"):
                field_value += f"**Resolved:** {inc['resolved_at_utc'][:16]}\n"

            embed.add_field(
                name=f"📋 {inc['incident_id']}",
                value=field_value,
                inline=False,
            )

        search_params = []
        if keyword:
            search_params.append(f"keyword: {keyword}")
        if incident_id:
            search_params.append(f"ID: {incident_id}")
        if severity:
            search_params.append(f"severity: {severity}")
        if date_from:
            search_params.append(f"from: {date_from}")
        if date_to:
            search_params.append(f"to: {date_to}")

        embed.set_footer(text=f"Search: {', '.join(search_params)}")

        # Add view details button
        view = IncidentSearchView(results)
        await interaction.followup.send(embed=embed, view=view, ephemeral=True)

    except Exception as e:
        await interaction.followup.send(
            f"Error searching incidents: {e}", ephemeral=True
        )


@tree.command(
    name="submit-certs",
    description="Submit certification numbers for your certifications.",
)
async def submit_certs(interaction: discord.Interaction):
    pending = await db_get_pending_certs(interaction.user.id)
    if not pending:
        # Check if user has requires_verification roles but no certification rows at all
        all_member_roles = await db_get_member_roles(interaction.user.id)
        cert_keys = {c["key"] for c in CERTIFICATIONS}
        has_cert_rows = any(mr["role_key"] in cert_keys for mr in all_member_roles)
        verify_role_keys = {r["key"] for r in ROLES if r.get("requires_verification")}
        has_verify_role = any(mr["role_key"] in verify_role_keys for mr in all_member_roles)

        if has_verify_role and not has_cert_rows:
            await interaction.response.send_message(
                "You have roles that require verification but no certifications on file yet. "
                "Go back to the role channel and select your certifications from the dropdown.",
                ephemeral=True,
            )
        else:
            await interaction.response.send_message(
                "All certifications verified! You have no pending cert submissions.",
                ephemeral=True,
            )
        return

    if len(pending) > 5:
        await interaction.response.send_modal(SubmitCertsModal(pending[:5]))
    else:
        await interaction.response.send_modal(SubmitCertsModal(pending))


@tree.command(
    name="reload-roles",
    description="(Admin) Reload roles_config.json without restarting the bot.",
)
@app_commands.default_permissions(manage_guild=True)
async def reload_roles(interaction: discord.Interaction):
    try:
        load_roles_config()
        verify_count = sum(1 for r in ROLES if r.get("requires_verification"))
        await interaction.response.send_message(
            f"Roles config reloaded: {len(ROLES)} roles ({verify_count} require verification), "
            f"{len(CERTIFICATIONS)} certifications.\n"
            "Note: Any existing onboarding embeds still show the old options. "
            "Run `/setup-certifications` again to post an updated one.",
            ephemeral=True,
        )
    except Exception as e:
        await interaction.response.send_message(
            f"Failed to reload config: {e}", ephemeral=True
        )


@tree.command(
    name="setup-certifications",
    description="(Admin) Post the role selection embed in this channel.",
)
@app_commands.default_permissions(manage_guild=True)
async def setup_certifications(interaction: discord.Interaction):
    if not ROLES and not CERTIFICATIONS:
        await interaction.response.send_message(
            "No roles or certifications are configured yet. Edit `roles_config.json` and set `discord_role_id` values, then restart.",
            ephemeral=True,
        )
        return

    embed = discord.Embed(
        title="Role Selection & Certification Verification",
        description=(
            "Welcome! Select the roles and/or certifications that apply to you "
            "from the dropdowns below, then click **Join** to get started.\n\n"
            "Some roles require verification. Certifications require you to "
            "submit your cert numbers with `/submit-certs` to become Verified."
        ),
        color=discord.Color.blurple(),
    )

    general_roles = [r for r in ROLES if not r.get("requires_verification")]
    verify_roles = [r for r in ROLES if r.get("requires_verification")]

    if general_roles:
        general_list = "\n".join(f"• **{r['label']}** — {r.get('description', '')}" for r in general_roles)
        embed.add_field(name="Roles (no verification required)", value=general_list, inline=False)

    if verify_roles:
        verify_list = "\n".join(f"• **{r['label']}** — {r.get('description', '')}" for r in verify_roles)
        embed.add_field(name="Roles (verification required)", value=verify_list, inline=False)

    if CERTIFICATIONS:
        cert_list = "\n".join(f"• **{c['label']}** — {c.get('description', '')}" for c in CERTIFICATIONS)
        embed.add_field(name="Certifications", value=cert_list, inline=False)

    embed.set_footer(text="You can come back and add more roles anytime.")

    view = _build_onboarding_view()
    await interaction.response.defer(ephemeral=True)
    await interaction.channel.send(embed=embed, view=view)
    await interaction.followup.send("Certification embed posted!", ephemeral=True)


@client.event
async def on_ready():
    try:
        load_roles_config()
    except Exception as e:
        print(f"ERROR: Failed to load roles config: {e}")

    await db_init()

    try:
        if DEV_GUILD_ID:
            guild_obj = discord.Object(id=DEV_GUILD_ID)
            tree.copy_global_to(guild=guild_obj)
            await tree.sync(guild=guild_obj)
            print(f"Commands synced to dev guild {DEV_GUILD_ID} (instant)")
        else:
            await tree.sync()
            print("Commands synced globally (may take up to 1 hour)")
    except Exception as e:
        print(f"Command sync failed: {e}")

    # Re-register views for all open incidents so buttons work after restart
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """
                SELECT i.id, i.incident_id, i.discord_message_id, t.gps_token
                FROM incidents i
                LEFT JOIN incident_tokens t ON t.incident_db_id = i.id
                WHERE i.status IN ('open', 'escalated') AND i.discord_message_id IS NOT NULL
                """
            )
            open_incidents = await cur.fetchall()

            for inc in open_incidents:
                gps_url = f"{PUBLIC_BASE_URL}/gps?incident_id={inc['incident_id']}&token={inc['gps_token']}" if inc['gps_token'] else ""
                view = DispatchView(
                    db_id=inc['id'],
                    incident_id=inc['incident_id'],
                    gps_url=gps_url
                )
                # Attach view to the specific message ID so Discord knows which buttons it handles
                client.add_view(view, message_id=inc['discord_message_id'])

        print(f"Re-registered {len(open_incidents)} incident views")
    except Exception as e:
        print(f"Warning: Could not re-register views: {e}")

    # Register persistent onboarding view (handles dropdown + Join from any posted embed)
    if ROLES or CERTIFICATIONS:
        client.add_view(_build_onboarding_view())
        print("Onboarding view registered")

    # Re-register pending approval views
    try:
        pending_approvals = await db_get_all_pending_approvals()
        for pa in pending_approvals:
            view = RoleApprovalView(
                user_id=pa["user_id"],
                role_key=pa["role_key"],
                approval_id=pa["id"],
            )
            client.add_view(view, message_id=pa["discord_message_id"])
        print(f"Re-registered {len(pending_approvals)} approval views")
    except Exception as e:
        print(f"Warning: Could not re-register approval views: {e}")

    print(f"MedBot logged in as {client.user}.")


@client.event
async def on_app_command_completion(interaction: discord.Interaction, command: app_commands.Command):
    guild_name = interaction.guild.name if interaction.guild else "DM"
    print(f"[CMD] /{command.name} used by {interaction.user} ({interaction.user.id}) in #{interaction.channel} [{guild_name}]")


@tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    guild_name = interaction.guild.name if interaction.guild else "DM"
    cmd_name = interaction.command.name if interaction.command else "unknown"
    print(f"[CMD ERROR] /{cmd_name} by {interaction.user} ({interaction.user.id}) in #{interaction.channel} [{guild_name}]: {error}")
    if not interaction.response.is_done():
        await interaction.response.send_message(
            "Something went wrong running that command.", ephemeral=True
        )


# =========================
# Webhook receiver for forms
# =========================


def require_secret(request: web.Request):
    provided = request.headers.get("X-MedBot-Secret", "")
    if not WEBHOOK_SHARED_SECRET or WEBHOOK_SHARED_SECRET == "CHANGE_ME":
        raise web.HTTPUnauthorized(
            text="Server misconfigured. Set WEBHOOK_SHARED_SECRET."
        )
    if provided != WEBHOOK_SHARED_SECRET:
        raise web.HTTPForbidden(text="Forbidden")


def clean(s: Any, max_len: int = 1000) -> str:
    if s is None:
        return ""
    s = str(s).strip()
    if len(s) > max_len:
        s = s[:max_len] + "…"
    return s


async def post_form_to_channel(channel_id: int, title: str, fields: Dict[str, str]):
    channel = client.get_channel(channel_id)
    if channel is None:
        return

    embed = discord.Embed(title=title, color=discord.Color.blurple())
    for k, v in fields.items():
        if v:
            embed.add_field(name=k, value=v, inline=False)

    await channel.send(embed=embed)


async def handle_join(request: web.Request):
    require_secret(request)
    data = await request.json()

    fields = {
        "Name": f'{clean(data.get("first_name"), 80)} {clean(data.get("last_name"), 80)}'.strip(),
        "Email": clean(data.get("email"), 120),
        "Phone": clean(data.get("phone"), 40),
        "Why you want to join": clean(data.get("why"), 1200),
        "Certifications or training": clean(data.get("certs"), 1200),
        "More info": clean(data.get("more_info"), 1500),
    }

    if not JOIN_INTAKE_CHANNEL_ID:
        return web.json_response(
            {"ok": False, "error": "JOIN_INTAKE_CHANNEL_ID not configured"},
            status=500,
            headers={"Access-Control-Allow-Origin": "*"}
        )

    await post_form_to_channel(JOIN_INTAKE_CHANNEL_ID, "New Join Request", fields)
    return web.json_response(
        {"ok": True},
        headers={"Access-Control-Allow-Origin": "*"}
    )


async def handle_book(request: web.Request):
    require_secret(request)
    data = await request.json()

    fields = {
        "Name": clean(data.get("name"), 120),
        "Email": clean(data.get("email"), 120),
        "Phone": clean(data.get("phone"), 40),
        "Event location": clean(data.get("event_location"), 300),
        "Date": clean(data.get("date"), 40),
        "Time": clean(data.get("time"), 40),
        "About the event": clean(data.get("about"), 1500),
    }

    if not BOOKINGS_CHANNEL_ID:
        return web.json_response(
            {"ok": False, "error": "BOOKINGS_CHANNEL_ID not configured"},
            status=500,
            headers={"Access-Control-Allow-Origin": "*"}
        )

    await post_form_to_channel(BOOKINGS_CHANNEL_ID, "New Booking Request", fields)
    return web.json_response(
        {"ok": True},
        headers={"Access-Control-Allow-Origin": "*"}
    )


# =========================
# Health check endpoint
# =========================


async def health_check(request: web.Request):
    """Health check endpoint for Docker and monitoring."""
    return web.json_response({
        "status": "healthy",
        "bot_ready": client.is_ready(),
        "timestamp": utc_now_iso()
    })


# =========================
# GPS quick link web flow
# =========================

GPS_PAGE_HTML = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Share GPS to MedBot</title>
  <style>
    body { font-family: system-ui, Arial, sans-serif; max-width: 680px; margin: 0 auto; padding: 24px; }
    .card { border: 1px solid #ddd; border-radius: 12px; padding: 16px; }
    button { font-size: 16px; padding: 12px 16px; border-radius: 10px; border: 0; cursor: pointer; }
    input { width: 100%; padding: 12px; border: 1px solid #ccc; border-radius: 10px; margin-top: 8px; margin-bottom: 12px; }
    .muted { color: #666; font-size: 14px; }
    .ok { color: #0a7a2f; }
    .err { color: #b00020; }
    code { background: #f6f6f6; padding: 2px 6px; border-radius: 6px; }
  </style>
</head>
<body>
  <h2>Share GPS Location</h2>
  <div class="card">
    <p><b>Incident:</b> <code id="incident"></code></p>
    <p class="muted">This will ask your device for location permission and then send coordinates to the incident thread in Discord.</p>

    <label for="label">Your name or call sign (optional)</label>
    <input id="label" placeholder="Example: Morgan, Medic 2, Team Lead">

    <button id="btn">Share my location</button>

    <p id="status" class="muted"></p>
  </div>

<script>
  const params = new URLSearchParams(window.location.search);
  const incident_id = params.get("incident_id");
  const token = params.get("token");

  // Determine if this is incident-based or general location sharing
  const isIncident = !!incident_id;
  const endpoint = isIncident ? "/gps/report" : "/location-share/report";

  if (isIncident) {
    document.getElementById("incident").textContent = incident_id || "(missing)";
  }

  const statusEl = document.getElementById("status");
  const btn = document.getElementById("btn");

  function setStatus(text, cls) {
    statusEl.textContent = text;
    statusEl.className = cls || "muted";
  }

  btn.addEventListener("click", async () => {
    if (!token) {
      setStatus("Missing token.", "err");
      return;
    }
    if (isIncident && !incident_id) {
      setStatus("Missing incident_id.", "err");
      return;
    }
    if (!navigator.geolocation) {
      setStatus("Geolocation is not supported on this device.", "err");
      return;
    }

    setStatus("Requesting location permission…");

    navigator.geolocation.getCurrentPosition(async (pos) => {
      const payload = {
        token,
        label: document.getElementById("label").value || "",
        lat: pos.coords.latitude,
        lon: pos.coords.longitude,
        accuracy_m: pos.coords.accuracy || null
      };

      if (isIncident) {
        payload.incident_id = incident_id;
      }

      try {
        setStatus("Sending location to MedBot…");
        const res = await fetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.ok) {
          setStatus("Location sent successfully. You can close this tab.", "ok");
        } else {
          setStatus("Error: " + (data.error || "unknown error"), "err");
        }
      } catch (e) {
        setStatus("Failed to send location: " + e, "err");
      }

    }, (err) => {
      setStatus("Location request failed: " + err.message, "err");
    }, {
      enableHighAccuracy: true,
      timeout: 12000,
      maximumAge: 0
    });
  });
</script>
</body>
</html>
"""


async def gps_page(request: web.Request):
    # Basic serving of the page. Token validation happens on POST.
    return web.Response(text=GPS_PAGE_HTML, content_type="text/html")


async def gps_report(request: web.Request):
    data = await request.json()

    incident_id = clean(data.get("incident_id"), 40)
    token = clean(data.get("token"), 200)
    label = clean(data.get("label"), 80)

    try:
        lat = float(data.get("lat"))
        lon = float(data.get("lon"))
    except Exception:
        return web.json_response(
            {"ok": False, "error": "Invalid lat or lon"}, status=400
        )

    accuracy_m = None
    try:
        if data.get("accuracy_m") is not None:
            accuracy_m = float(data.get("accuracy_m"))
    except Exception:
        accuracy_m = None

    incident = await db_validate_gps_token(incident_id, token)
    if not incident:
        return web.json_response(
            {"ok": False, "error": "Invalid token or incident_id"}, status=403
        )

    if incident.get("status") != "open":
        return web.json_response(
            {"ok": False, "error": "Incident is not open"}, status=400
        )

    db_id = int(incident["id"])
    await db_insert_location_report(db_id, label, lat, lon, accuracy_m)

    # Post to incident thread if present, else dispatch channel.
    guilds = client.guilds
    if not guilds:
        return web.json_response({"ok": False, "error": "Bot not ready"}, status=503)

    guild = guilds[0]  # Typical single guild deployment for this bot.
    target = None

    if incident.get("discord_thread_id"):
        target = guild.get_thread(int(incident["discord_thread_id"]))
    if not target and incident.get("discord_channel_id"):
        target = guild.get_channel(int(incident["discord_channel_id"]))

    if target:
        maps_link = f"https://maps.google.com/?q={lat},{lon}"
        who = f" from **{label}**" if label else ""

        # Generate Plus Code for precise location (3m accuracy)
        plus_code = generate_plus_code(lat, lon)
        plus_code_text = f"\n📍 **Plus Code:** `{plus_code}`" if plus_code else ""

        # Format accuracy
        acc_txt = f"±{accuracy_m:.0f}m" if isinstance(accuracy_m, float) else "unknown"

        await target.send(
            f"📍 **GPS Location** for **{incident_id}**{who}\n"
            f"**Coordinates:** `{lat:.6f}, {lon:.6f}` ({acc_txt}){plus_code_text}\n"
            f"[Open in Google Maps]({maps_link})"
        )

    return web.json_response({"ok": True})


# =========================
# Web server
# =========================


async def location_share_page(request: web.Request):
    """Serve GPS page for general location sharing (not tied to incident)."""
    token = request.query.get("token", "")

    # Validate token
    token_data = await db_get_location_share_token(token)
    if not token_data:
        return web.Response(
            text="<h1>Invalid or expired link</h1><p>This location share link is invalid or has expired.</p>",
            content_type="text/html",
            status=403,
        )

    # Use same GPS page but with different context
    html = GPS_PAGE_HTML.replace(
        '<p><b>Incident:</b> <code id="incident"></code></p>',
        f'<p><b>Sharing location to channel</b></p><p class="muted">Requested by: <b>{token_data["user_name"]}</b></p>',
    )
    return web.Response(text=html, content_type="text/html")


async def location_share_report(request: web.Request):
    """Handle location report from general location sharing."""
    data = await request.json()

    token = clean(data.get("token"), 200)
    label = clean(data.get("label"), 80)

    try:
        lat = float(data.get("lat"))
        lon = float(data.get("lon"))
    except Exception:
        return web.json_response(
            {"ok": False, "error": "Invalid lat or lon"}, status=400
        )

    accuracy_m = None
    try:
        if data.get("accuracy_m") is not None:
            accuracy_m = float(data.get("accuracy_m"))
    except Exception:
        accuracy_m = None

    # Validate token
    token_data = await db_get_location_share_token(token)
    if not token_data:
        return web.json_response(
            {"ok": False, "error": "Invalid or expired token"}, status=403
        )

    # Post to the specified channel
    guilds = client.guilds
    if not guilds:
        return web.json_response({"ok": False, "error": "Bot not ready"}, status=503)

    guild = guilds[0]
    channel = guild.get_channel(int(token_data["channel_id"]))

    if channel:
        maps_link = f"https://maps.google.com/?q={lat},{lon}"
        who = f" from **{label}**" if label else f" from **{token_data['user_name']}**"

        # Generate Plus Code for precise location (3m accuracy)
        plus_code = generate_plus_code(lat, lon)
        plus_code_text = f"\n📍 **Plus Code:** `{plus_code}`" if plus_code else ""

        # Format accuracy
        acc_txt = f"±{accuracy_m:.0f}m" if isinstance(accuracy_m, float) else "unknown"

        await channel.send(
            f"📍 **GPS Location**{who}\n"
            f"**Coordinates:** `{lat:.6f}, {lon:.6f}` ({acc_txt}){plus_code_text}\n"
            f"[Open in Google Maps]({maps_link})"
        )

    return web.json_response({"ok": True})


async def handle_cors_preflight(request: web.Request):
    """Handle CORS preflight OPTIONS requests."""
    return web.Response(
        status=204,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, X-MedBot-Secret",
            "Access-Control-Max-Age": "86400",
        }
    )


async def start_web_server():
    app = web.Application()
    app.router.add_get("/health", health_check)

    # Webhook endpoints with CORS preflight
    app.router.add_options("/webhook/join", handle_cors_preflight)
    app.router.add_post("/webhook/join", handle_join)
    app.router.add_options("/webhook/book", handle_cors_preflight)
    app.router.add_post("/webhook/book", handle_book)

    app.router.add_get("/gps", gps_page)
    app.router.add_post("/gps/report", gps_report)

    app.router.add_get("/location-share", location_share_page)
    app.router.add_post("/location-share/report", location_share_report)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, WEB_BIND_HOST, WEB_BIND_PORT)
    await site.start()
    print(f"Webhook server listening on http://{WEB_BIND_HOST}:{WEB_BIND_PORT}")


async def main():
    async with client:
        await start_web_server()
        await client.start(DISCORD_TOKEN)


if __name__ == "__main__":
    if DISCORD_TOKEN == "PUT_YOUR_TOKEN_HERE":
        raise SystemExit("Set DISCORD_TOKEN in env before running.")
    asyncio.run(main())
