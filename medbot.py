import os
import asyncio
import datetime as dt
import secrets
from typing import Optional, Dict, Any, List

from aiohttp import web, ClientSession
import aiosqlite
import discord
from discord import app_commands

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
"""


async def db_init():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(CREATE_TABLES_SQL)
        await db.commit()


def utc_now_iso() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


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
) -> discord.Embed:
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
    def __init__(self, db_id: int, incident_id: str, gps_url: str):
        super().__init__(timeout=None)
        self.db_id = db_id
        self.incident_id = incident_id
        self.gps_url = gps_url

    async def get_update_target(
        self, interaction: discord.Interaction
    ) -> discord.abc.Messageable:
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

    async def refresh_embed(
        self, interaction: discord.Interaction, note: Optional[str] = None
    ):
        responders = await db_get_responders(self.db_id)

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
        responders = await db_get_responders(self.db_id)
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
        responders = await db_get_responders(self.db_id)
        primary_exists = any(r["role"] == "primary" for r in responders)

        if primary_exists:
            await interaction.response.send_message(
                "Primary responder is already claimed. Use Join (Additional), or ask an admin to hand off.",
                ephemeral=True,
            )
            return

        await db_upsert_responder(
            self.db_id,
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
        await db_upsert_responder(
            self.db_id,
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
        await db_upsert_responder(
            self.db_id,
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

        # Show modal for care notes
        modal = CareNotesModal(self.db_id, self.incident_id, self)
        await interaction.response.send_modal(modal)


# =========================
# Discord bot
# =========================

intents = discord.Intents.default()
intents.guilds = True

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

    channel = interaction.guild.get_channel(DISPATCH_CHANNEL_ID)
    if channel is None:
        await interaction.followup.send(
            "Dispatch channel not found. Check the channel ID.", ephemeral=True
        )
        return

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


@client.event
async def on_ready():
    await db_init()
    try:
        await tree.sync()
    except Exception as e:
        print("Command sync failed:", e)
    print(f"MedBot logged in as {client.user}.")


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
        acc_txt = f"{accuracy_m:.0f} m" if isinstance(accuracy_m, float) else "unknown"
        who = f" from **{label}**" if label else ""

        # Try to get human-readable address via reverse geocoding
        address = await reverse_geocode(lat, lon)
        address_text = f"\n📍 **Address:** {address}" if address else ""

        await target.send(
            f"GPS location received for **{incident_id}**{who}: {lat:.6f}, {lon:.6f} (accuracy {acc_txt}){address_text}\n{maps_link}"
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
        acc_txt = f"{accuracy_m:.0f} m" if isinstance(accuracy_m, float) else "unknown"
        who = f" from **{label}**" if label else f" from **{token_data['user_name']}**"

        # Try to get human-readable address via reverse geocoding
        address = await reverse_geocode(lat, lon)
        address_text = f"\n📍 **Address:** {address}" if address else ""

        await channel.send(
            f"📍 GPS location shared{who}: {lat:.6f}, {lon:.6f} (accuracy {acc_txt}){address_text}\n{maps_link}"
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
