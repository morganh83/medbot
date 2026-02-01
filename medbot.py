import os
import asyncio
import datetime as dt
import secrets
from typing import Optional, Dict, Any, List

from aiohttp import web
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
    discord_thread_id INTEGER
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


class DispatchView(discord.ui.View):
    def __init__(self, db_id: int, incident_id: str, gps_url: str):
        super().__init__(timeout=None)
        self.db_id = db_id
        self.incident_id = incident_id

        # Link button for GPS page (works outside Discord).
        self.add_item(
            discord.ui.Button(
                label="Share GPS", style=discord.ButtonStyle.link, url=gps_url
            )
        )

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

    @discord.ui.button(
        label="Claim (Primary)",
        style=discord.ButtonStyle.danger,
        custom_id="dispatch_claim_primary",
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

    @discord.ui.button(
        label="On Scene",
        style=discord.ButtonStyle.secondary,
        custom_id="dispatch_on_scene",
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
        label="Resolved",
        style=discord.ButtonStyle.success,
        custom_id="dispatch_resolved",
    )
    async def resolved(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ):
        if not interaction.user.guild_permissions.manage_messages:
            await interaction.response.send_message(
                "You do not have permission to resolve incidents.", ephemeral=True
            )
            return

        await db_set_status(self.db_id, "resolved")
        await interaction.response.send_message(
            f"Incident **{self.incident_id}** marked resolved.", ephemeral=True
        )

        target = await self.get_update_target(interaction)
        await target.send(
            f"Incident **{self.incident_id}** marked **resolved** by {interaction.user.mention}."
        )

        for child in self.children:
            if isinstance(child, discord.ui.Button):
                # Leave Share GPS link visible if you want, or disable everything.
                if child.style != discord.ButtonStyle.link:
                    child.disabled = True

        await interaction.message.edit(view=self)
        await export_incidents_to_csv()


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
            {"ok": False, "error": "JOIN_INTAKE_CHANNEL_ID not configured"}, status=500
        )

    await post_form_to_channel(JOIN_INTAKE_CHANNEL_ID, "New Join Request", fields)
    return web.json_response({"ok": True})


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
            {"ok": False, "error": "BOOKINGS_CHANNEL_ID not configured"}, status=500
        )

    await post_form_to_channel(BOOKINGS_CHANNEL_ID, "New Booking Request", fields)
    return web.json_response({"ok": True})


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
  document.getElementById("incident").textContent = incident_id || "(missing)";

  const statusEl = document.getElementById("status");
  const btn = document.getElementById("btn");

  function setStatus(text, cls) {
    statusEl.textContent = text;
    statusEl.className = cls || "muted";
  }

  btn.addEventListener("click", async () => {
    if (!incident_id || !token) {
      setStatus("Missing incident_id or token.", "err");
      return;
    }
    if (!navigator.geolocation) {
      setStatus("Geolocation is not supported on this device.", "err");
      return;
    }

    setStatus("Requesting location permission…");

    navigator.geolocation.getCurrentPosition(async (pos) => {
      const payload = {
        incident_id,
        token,
        label: document.getElementById("label").value || "",
        lat: pos.coords.latitude,
        lon: pos.coords.longitude,
        accuracy_m: pos.coords.accuracy || null
      };

      try {
        setStatus("Sending location to MedBot…");
        const res = await fetch("/gps/report", {
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
        await target.send(
            f"GPS location received for **{incident_id}**{who}: {lat:.6f}, {lon:.6f} (accuracy {acc_txt}).\n{maps_link}"
        )

    return web.json_response({"ok": True})


# =========================
# Web server
# =========================


async def start_web_server():
    app = web.Application()
    app.router.add_post("/webhook/join", handle_join)
    app.router.add_post("/webhook/book", handle_book)

    app.router.add_get("/gps", gps_page)
    app.router.add_post("/gps/report", gps_report)

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
