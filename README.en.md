# Log Anonymizer

**[Русская версия](README.md)** | English version

Data anonymization service that preserves document logic: the same entity is
always replaced by the same pseudonym.

## What gets anonymized

| Type | Example input | Pseudonym (`pseudonym` style) | Realistic (`realistic` style) |
|---|---|---|---|
| IPv4 | `192.168.1.100` | `[IP1]` | `198.18.x.x` |
| IPv6 | `2001:db8::1`, `[::1]:8443` | `[IP2]` | `fd00::x` |
| Ports | `:8080`, `port=443`, `порт 22` | `[PORT1]` | random port >1024 |
| Domains | `api.example.com` | `[HOST1]` | `host-N.example.com` |
| Email | `ivan@mail.ru` | `[LOCAL1]@[HOST2]` | `userN@host-N...` |
| Phones (RU) | `+7 (999) 123-45-67`, `8-999-123-45-67` | `[PHONE1]` | `+7 9xx xxx-xx-xx` |
| Phones (intl) | `+1 212 555 0143` | `[PHONE2]` | — |
| Full names | `Иванов Иван Иванович`, `Петрова А.С.`, `John Smith` | fictional names, same gender & letter case | (always realistic) |
| MAC | `00:1a:2b:3c:4d:5e` | `[MAC1]` | `02:xx:...` |

## File formats

- Text: `.log`, `.txt` (including cp1251 encoding).
- Excel: `.xlsx` (openpyxl) and `.xls` (xlrd/xlwt). All sheets and cells are
  walked; one shared mapping per workbook (same value on different sheets ->
  same pseudonym); sheet names are anonymized too. Numbers, dates and booleans
  are preserved as-is, except 11-digit numbers starting with 7/8 (treated as
  phone numbers stored as numbers). Cell formatting is not preserved
  (library limitation).

## False-positive protection

Never replaced: dates (`2026-01-15`), times (`10:00:01`), UUIDs, software
versions (`1.2.3.4.5`), file names (`app.log`, `main.py` — extension
blacklist), ordinary capitalized words (names are matched only by the
surname+first+patronymic or surname+initials structure).

## Modes

- `session` (default) — counters `[IP1], [IP2]...` scoped to a single file/request.
- `stable` + `salt` — pseudonyms derived via SHA-256 from the salt: identical
  results across runs, files and servers. Different salts -> different results.

## Localization

The web UI supports Russian and English (RU/EN switch in the header, choice
persisted in localStorage, browser language detected on first visit). API
error messages are localized via the `lang` form/JSON field (`ru`/`en`) or the
`Accept-Language` header. Russian name/phone detection works regardless of UI
language.

## Quick start (Docker Compose)

```bash
docker compose up -d --build
# UI:      https://localhost:8082/     (http:// on the same port redirects to https)
# Health:  https://localhost:8082/health
```

### HTTPS / certificates

TLS terminates at nginx using a self-signed certificate from `certs/`
(created with openssl, valid until 2029-01, CN=localhost,
SAN: localhost + 127.0.0.1). The browser will show an untrusted-certificate
warning — this is normal for self-signed certs; for internal use, add
`certs/localhost.crt` to the client's trust store.

Regenerating the certificate:

```bash
cd certs && openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout localhost.key -out localhost.crt -days 825 \
  -subj "/CN=localhost/O=Anonimizator" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  && chmod 600 localhost.key
docker compose restart nginx
```

`certs/` is in .gitignore — the private key must never be committed.

Note: if DNS does not work in the docker build network on your host, the
compose file already sets `build.network: host`.

## CLI (without Docker)

```bash
python app/anonymizer.py -i putty.log                  # -> putty_clean.log
python app/anonymizer.py -i access.log -v              # verbose: pairs to stderr
cat app.log | python app/anonymizer.py -o clean.log
python app/anonymizer.py -i a.log --style realistic
python app/anonymizer.py -i a.log --mode stable --salt SECRET --map-out map.json
python app/anonymizer.py -i a.log --entities ip,port,phone,name
python app/anonymizer.py -i a.log --preserve-common-ports
```

`--map-out` saves the replacement dictionary to JSON; `--map-in` loads it
(e.g. for de-anonymization by a trusted party or consistent processing of a
file series).

## HTTP API

### POST /upload (multipart/form-data)

Field `file` (.log/.txt/.xls/.xlsx, up to 50 MB). Optional form fields:
`entities` (repeated value or CSV: ip,port,host,email,phone,name,mac),
`style` (pseudonym|realistic), `mode` (session|stable), `salt`,
`preserve_common_ports` (1|true), `lang` (ru|en).

Response: attachment; statistics in the `X-Anon-Stats` header (JSON).

```bash
curl -F "file=@access.log" -F "style=realistic" https://localhost:8082/upload -o clean.log --cacert certs/localhost.crt   # or -k
curl -F "file=@report.xlsx" https://localhost:8082/upload -o report_clean.xlsx -k
```

### POST /api/anonymize (JSON)

```bash
curl -X POST https://localhost:8082/api/anonymize -k \
  -H 'Content-Type: application/json' \
  -d '{"text": "Иванов И.И. 10.0.0.1:22", "mode": "stable", "salt": "s3cr3t", "lang": "en"}'
```

Response: `{"text": ..., "mapping": {original: pseudonym}, "stats": {...}}`

### GET /health

```json
{"status": "healthy", "timestamp": "..."}
```

## Large files

`anonymize_stream()` processes input line by line — memory does not grow with
file size. The web service handles files up to 50 MB in memory.

## Privacy

Processing happens **in-process** (no subprocess): uploaded data is never
written to disk and never leaves process memory. No temporary files or
upload/processed directories are used.

## Tests

```bash
python -m venv .venv && .venv/bin/pip install -r app/requirements.txt pytest
.venv/bin/python -m pytest tests/ -q
```

## Structure

```
app/
  anonymizer.py    # core: Anonymizer class + CLI
  excel_anon.py    # Excel (.xls/.xlsx) walker
  app.py           # Flask: /, /health, /upload, /api/anonymize
  static/index.html# web UI (drag&drop, paste area, settings, RU/EN)
  Dockerfile
  requirements.txt
nginx/nginx.conf   # reverse proxy + TLS (host port 8082)
tests/             # pytest: core + excel + web layer
docker-compose.yml
```

## Limitations (honest)

- Name detection is heuristic: full triples and "Surname I.I." validated
  against dictionaries of given names, patronymics and surname endings.
  Exotic surnames without typical endings (e.g. «Жук») are skipped — a
  deliberate trade-off favoring zero false positives.
- Phones are detected by `+7/8` format (10 digits) and international
  `+CC...` (8–15 digits). Numbers without `+` in non-RU formats may be missed.
- With the `realistic` style, generated names may theoretically coincide with
  real people — a property of any name generator.
- English full-name detection only catches "Firstname Lastname" pairs where
  the first name is in the built-in dictionary.
