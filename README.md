# MedBot - Discord Street Medic Bot

A Discord bot for street medic organizations to manage incident dispatches, GPS tracking, volunteer applications, and event booking requests.

## Features

- **Incident Management**: Create and track medical incidents with `/dispatch` command
- **GPS Tracking**: Generate shareable GPS links for responders to report locations
- **Volunteer Applications**: Webhook endpoint for processing volunteer join requests
- **Event Bookings**: Webhook endpoint for event coverage requests
- **CSV Export**: Export incident history to CSV
- **Thread Support**: Automatic thread creation for incident coordination

## Prerequisites

- Python 3.11+
- Discord Bot Token ([Discord Developer Portal](https://discord.com/developers/applications))
- Docker and Docker Compose (for containerized deployment)

## Quick Start

### 1. Configuration

Create a `.env` file in the project root:

```bash
# Discord Configuration
DISCORD_TOKEN=your-discord-bot-token-here

# Channel IDs (right-click channel in Discord, Copy ID)
JOIN_INTAKE_CHANNEL_ID=123456789012345678
BOOKINGS_CHANNEL_ID=123456789012345678
DISPATCH_CHANNEL_ID=123456789012345678
DISPATCH_PING_ROLE_ID=123456789012345678

# Web Server Configuration
WEB_BIND_HOST=0.0.0.0
WEB_BIND_PORT=8080
PUBLIC_BASE_URL=https://your-domain.com

# Webhook Security (generate with: openssl rand -base64 32)
WEBHOOK_SHARED_SECRET=your-strong-random-secret-here

# Database
DB_PATH=/app/data/medbot.db

# Optional: CSV Export
EXPORT_CSV=true
CSV_EXPORT_PATH=/app/data/incidents_export.csv

# Optional: Thread Creation
CREATE_INCIDENT_THREAD=true
```

### 2. Deploy with Docker

```bash
# Create data directory for persistence
mkdir -p data

# Build and start the container
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the container
docker-compose down

# Restart the container
docker-compose restart
```

### 3. Verify Deployment

```bash
# Check if container is running
docker ps

# Test health check endpoint
curl http://localhost:8080/health
```

**Expected response:**
```json
{
  "status": "healthy",
  "bot_ready": true,
  "timestamp": "2026-02-04T12:34:56.789Z"
}
```

## API Reference

The bot runs an HTTP server on port 8080 (configurable via `WEB_BIND_PORT`) with the following endpoints:

### Health Check

**Endpoint:** `GET /health`

**Description:** Health check endpoint for monitoring and Docker health checks.

**Response:**
```json
{
  "status": "healthy",
  "bot_ready": true,
  "timestamp": "2026-02-04T12:34:56.789Z"
}
```

**Example:**
```bash
curl http://localhost:8080/health
```

---

### Volunteer Join Request

**Endpoint:** `POST /webhook/join`

**Description:** Submit a volunteer application to join the street medic team.

**Authentication:** Requires `X-MedBot-Secret` header matching `WEBHOOK_SHARED_SECRET`.

**Request Body:**
```json
{
  "first_name": "John",
  "last_name": "Doe",
  "email": "john.doe@example.com",
  "phone": "555-123-4567",
  "why": "I want to help my community and have first aid training",
  "certs": "CPR/AED, First Aid",
  "more_info": "Available weekends"
}
```

**Field Limits:**
- `first_name`: max 80 chars
- `last_name`: max 80 chars
- `email`: max 120 chars
- `phone`: max 40 chars
- `why`: max 1200 chars
- `certs`: max 1200 chars
- `more_info`: max 1500 chars (optional)

**Response:**
```json
{
  "ok": true
}
```

**Example:**
```bash
curl -X POST http://localhost:8080/webhook/join \
  -H "Content-Type: application/json" \
  -H "X-MedBot-Secret: your-secret-here" \
  -d '{
    "first_name": "John",
    "last_name": "Doe",
    "email": "john.doe@example.com",
    "phone": "555-123-4567",
    "why": "I want to help my community",
    "certs": "CPR/AED, First Aid",
    "more_info": "Available weekends"
  }'
```

**Discord Output:** Creates an embed in `JOIN_INTAKE_CHANNEL_ID` with all application details.

---

### Event Booking Request

**Endpoint:** `POST /webhook/book`

**Description:** Submit a request for street medic coverage at an event.

**Authentication:** Requires `X-MedBot-Secret` header matching `WEBHOOK_SHARED_SECRET`.

**Request Body:**
```json
{
  "name": "Jane Smith",
  "email": "jane@example.com",
  "phone": "555-987-6543",
  "event_location": "123 Main St, City, State",
  "date": "2026-03-15",
  "time": "14:00",
  "about": "Community festival with 500 expected attendees"
}
```

**Field Limits:**
- `name`: max 120 chars
- `email`: max 120 chars
- `phone`: max 40 chars
- `event_location`: max 300 chars
- `date`: max 40 chars
- `time`: max 40 chars
- `about`: max 1500 chars

**Response:**
```json
{
  "ok": true
}
```

**Example:**
```bash
curl -X POST http://localhost:8080/webhook/book \
  -H "Content-Type: application/json" \
  -H "X-MedBot-Secret: your-secret-here" \
  -d '{
    "name": "Jane Smith",
    "email": "jane@example.com",
    "phone": "555-987-6543",
    "event_location": "123 Main St, City, State",
    "date": "2026-03-15",
    "time": "14:00",
    "about": "Community festival with 500 expected attendees"
  }'
```

**Discord Output:** Creates an embed in `BOOKINGS_CHANNEL_ID` with all booking details.

---

### GPS Tracking Page

**Endpoint:** `GET /gps?incident_id={id}&token={token}`

**Description:** Web page for responders to share their GPS location for an incident.

**Query Parameters:**
- `incident_id`: The incident ID (e.g., "INC-001")
- `token`: Secret token for this incident (prevents unauthorized location sharing)

**Example:**
```bash
# Open in browser
http://localhost:8080/gps?incident_id=INC-001&token=abc123
```

**Features:**
- Requests geolocation permission from user's device
- Allows responder to add their name/callsign
- Posts location to incident thread in Discord

---

### GPS Location Report

**Endpoint:** `POST /gps/report`

**Description:** Submit GPS coordinates for an incident (called by the GPS tracking page).

**Request Body:**
```json
{
  "incident_id": "INC-001",
  "token": "abc123",
  "label": "Medic 2",
  "lat": 42.3601,
  "lon": -71.0589,
  "accuracy_m": 10
}
```

**Response:**
```json
{
  "ok": true
}
```

**Example:**
```bash
curl -X POST http://localhost:8080/gps/report \
  -H "Content-Type: application/json" \
  -d '{
    "incident_id": "INC-001",
    "token": "abc123",
    "label": "Medic 2",
    "lat": 42.3601,
    "lon": -71.0589,
    "accuracy_m": 10
  }'
```

**Discord Output:** Posts location message in incident thread with Google Maps link and accuracy.

---

## Discord Commands

### `/dispatch`

Creates a new medical incident and generates a GPS tracking link.

**Usage:** `/dispatch description: Medical emergency at park`

**Features:**
- Creates incident in database
- Posts to `DISPATCH_CHANNEL_ID` with role ping
- Generates unique GPS tracking link
- Creates thread for incident (if `CREATE_INCIDENT_THREAD=true`)
- Exports to CSV (if `EXPORT_CSV=true`)

### `/respond`

Claim an incident as a responder.

**Usage:** Click "Respond" button on incident message

**Features:**
- Records responder in database
- Updates incident message
- Exports to CSV

### `/resolve`

Mark an incident as resolved.

**Usage:** Click "Resolve" button on incident message

**Features:**
- Updates incident status
- Records resolution time
- Exports to CSV

---

## Testing

### Test Health Check

```bash
curl http://localhost:8080/health
```

**Expected:** `{"status":"healthy","bot_ready":true,...}`

### Test Join Webhook

```bash
curl -X POST http://localhost:8080/webhook/join \
  -H "Content-Type: application/json" \
  -H "X-MedBot-Secret: your-secret-here" \
  -d '{
    "first_name": "Test",
    "last_name": "User",
    "email": "test@example.com",
    "phone": "555-0000",
    "why": "Testing the webhook integration",
    "certs": "None",
    "more_info": "This is a test"
  }'
```

**Expected:** `{"ok":true}` and message appears in Discord join intake channel.

### Test Book Webhook

```bash
curl -X POST http://localhost:8080/webhook/book \
  -H "Content-Type: application/json" \
  -H "X-MedBot-Secret: your-secret-here" \
  -d '{
    "name": "Test Event",
    "email": "test@example.com",
    "phone": "555-0000",
    "event_location": "Test Location",
    "date": "2026-12-31",
    "time": "18:00",
    "about": "This is a test booking request"
  }'
```

**Expected:** `{"ok":true}` and message appears in Discord bookings channel.

### Test Invalid Secret

```bash
curl -X POST http://localhost:8080/webhook/join \
  -H "Content-Type: application/json" \
  -H "X-MedBot-Secret: wrong-secret" \
  -d '{"first_name":"Test","last_name":"User","email":"test@test.com","phone":"555-0000","why":"test","certs":"none"}'
```

**Expected:** `403 Forbidden` - Authentication failed.

---

## Troubleshooting

### Container won't start

**Check logs:**
```bash
docker-compose logs
```

**Common issues:**
- Missing `DISCORD_TOKEN` in `.env`
- Invalid Discord token
- Port 8080 already in use

**Solution:**
```bash
# Verify .env file exists and has DISCORD_TOKEN
cat .env | grep DISCORD_TOKEN

# Check if port 8080 is in use
netstat -ano | findstr :8080  # Windows
lsof -i :8080                 # Linux/Mac

# Change WEB_BIND_PORT in .env if needed
```

### Health check returns unhealthy

**Check Discord connection:**
```bash
curl http://localhost:8080/health
```

If `bot_ready: false`, the Discord connection failed.

**Check logs:**
```bash
docker-compose logs -f
```

**Common issues:**
- Invalid Discord token
- Network connectivity issues
- Discord API outage

### Webhooks return 403 Forbidden

**Issue:** `X-MedBot-Secret` header doesn't match `WEBHOOK_SHARED_SECRET`.

**Solution:**
```bash
# Verify secret in .env
cat .env | grep WEBHOOK_SHARED_SECRET

# Use the exact same secret in requests
curl -X POST http://localhost:8080/webhook/join \
  -H "X-MedBot-Secret: $(grep WEBHOOK_SHARED_SECRET .env | cut -d'=' -f2)" \
  ...
```

### Forms not appearing in Discord

**Check:**
1. Channel IDs are correct in `.env`
2. Bot has permission to post in those channels
3. Bot is in the Discord server

**Get channel ID:**
- Right-click channel in Discord
- Select "Copy ID" (must have Developer Mode enabled)
- Paste into `.env` file

### Database errors

**Reset database:**
```bash
# Stop bot
docker-compose down

# Remove database
rm data/medbot.db

# Restart bot (will recreate database)
docker-compose up -d
```

### CSV export not working

**Check:**
```bash
# Verify EXPORT_CSV is enabled
cat .env | grep EXPORT_CSV

# Check if CSV file is being created
ls -la data/
```

**View CSV:**
```bash
cat data/incidents_export.csv
```

---

## Docker Commands Reference

```bash
# Build and start
docker-compose up -d

# Stop
docker-compose down

# Restart
docker-compose restart

# View logs (live)
docker-compose logs -f

# View logs (last 100 lines)
docker-compose logs --tail=100

# Rebuild after code changes
docker-compose down
docker-compose up -d --build

# Execute command in container
docker-compose exec medbot python -c "print('Hello')"

# Access container shell
docker-compose exec medbot /bin/bash

# Check container status
docker-compose ps

# View resource usage
docker stats medbot
```

---

## Development

### Run without Docker

```bash
# Install dependencies
pip install -r requirements.txt

# Run bot
python medbot.py
```

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DISCORD_TOKEN` | Yes | - | Discord bot token |
| `JOIN_INTAKE_CHANNEL_ID` | Yes | `0` | Channel for volunteer applications |
| `BOOKINGS_CHANNEL_ID` | Yes | `0` | Channel for event bookings |
| `DISPATCH_CHANNEL_ID` | Yes | `0` | Channel for incident dispatches |
| `DISPATCH_PING_ROLE_ID` | Yes | `0` | Role to ping on new incidents |
| `WEB_BIND_HOST` | No | `0.0.0.0` | HTTP server bind address |
| `WEB_BIND_PORT` | No | `8080` | HTTP server port |
| `PUBLIC_BASE_URL` | No | `https://example.com` | Public URL for GPS links |
| `WEBHOOK_SHARED_SECRET` | Yes | `CHANGE_ME` | Secret for webhook authentication |
| `DB_PATH` | No | `medbot.db` | SQLite database path |
| `EXPORT_CSV` | No | `true` | Enable CSV export |
| `CSV_EXPORT_PATH` | No | `incidents_export.csv` | CSV export file path |
| `CREATE_INCIDENT_THREAD` | No | `true` | Create thread for incidents |

---

## Security Notes

- **Never commit `.env` to version control** - It contains secrets
- **Use strong random secrets** - Generate with `openssl rand -base64 32`
- **Rotate secrets periodically** - Every 6-12 months recommended
- **Restrict Discord permissions** - Bot only needs:
  - Send Messages
  - Embed Links
  - Create Public Threads (if using threads)
  - Mention Roles (for dispatch pings)
- **Use Cloudflare Tunnel** - Keeps bot private while allowing public access
- **Enable Docker health checks** - Automated monitoring and restart

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Discord Bot                           │
│  ┌────────────────────────────────────────────────────┐ │
│  │  Discord.py Client                                 │ │
│  │  - Slash commands (/dispatch, /respond, /resolve) │ │
│  │  - Event handlers                                  │ │
│  │  - Database operations (SQLite)                    │ │
│  └────────────────────────────────────────────────────┘ │
│                                                           │
│  ┌────────────────────────────────────────────────────┐ │
│  │  HTTP Server (aiohttp)                             │ │
│  │  - /health - Health check                          │ │
│  │  - /webhook/join - Volunteer applications          │ │
│  │  - /webhook/book - Event bookings                  │ │
│  │  - /gps - GPS tracking page                        │ │
│  │  - /gps/report - GPS location submission           │ │
│  └────────────────────────────────────────────────────┘ │
│                                                           │
│  Port: 8080 (localhost)                                  │
└─────────────────────────────────────────────────────────┘
                        ↕
        ┌───────────────────────────┐
        │  Cloudflare Tunnel        │
        │  (Optional, Recommended)  │
        └───────────────────────────┘
                        ↕
        ┌───────────────────────────┐
        │  Public Internet          │
        │  (your-domain.com)        │
        └───────────────────────────┘
```

---

## License

MIT License - See LICENSE file for details

---

## Support

For issues, questions, or contributions:
- GitHub Issues: [morganh83/medbot](https://github.com/morganh83/medbot/issues)
- Documentation: See `DEPLOYMENT_GUIDE.md` for full deployment instructions

---

**Built with ❤️ for street medic organizations**
