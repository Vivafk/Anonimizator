# -*- coding: utf-8 -*-
"""
Веб-сервис анонимизации логов.

Эндпоинты:
  GET  /                 - веб-интерфейс
  GET  /health           - health check
  POST /upload           - загрузка файла (multipart), возврат анонимизированного файла
  POST /api/anonymize    - анонимизация текста (JSON), возврат текста + маппинга

Обработка выполняется в процессе (без subprocess и временных файлов на диске):
данные никуда не сохраняются, что критично для сервиса анонимизации.
"""

import io
import json
import logging
import os
import time
from datetime import datetime

from flask import Flask, jsonify, render_template, request, send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from anonymizer import Anonymizer
from excel_anon import SUPPORTED_EXCEL_EXTS, ExcelError, anonymize_excel

try:
    import magic  # python-magic; опционально
except ImportError:  # pragma: no cover
    magic = None

app = Flask(__name__, static_folder="static", template_folder="static")

# Secure cookie settings
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'


@app.after_request
def add_security_headers(response):
    """Defense-in-depth: security headers на уровне Flask."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# Rate limiting: защита от DoS
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per minute"],
    storage_uri="memory://",
)

app.config["MAX_CONTENT_LENGTH"] = int(
    os.environ.get("MAX_UPLOAD_MB", "50")
) * 1024 * 1024
app.config["ALLOWED_EXTENSIONS"] = {"log", "txt", "json", *SUPPORTED_EXCEL_EXTS}
app.config["PROCESS_TIMEOUT_SECONDS"] = int(
    os.environ.get("PROCESS_TIMEOUT", "120")
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Стартовая проверка: модуль ядра жив
Anonymizer().anonymize_text("selftest 10.0.0.1")

# --------------------------------------------------------------------------- #
#  Локализация сообщений (ru по умолчанию, en опционально)                     #
# --------------------------------------------------------------------------- #

MESSAGES = {
    "ru": {
        "no_file": "Файл не передан",
        "no_file_selected": "Файл не выбран",
        "not_allowed": "Недопустимый тип файла. Разрешены: %s",
        "empty_file": "Пустой файл",
        "invalid_binary": "Недопустимый тип файла (бинарное содержимое отклонено)",
        "text_too_large": "Слишком большой текст",
        "file_too_large": "Файл слишком большой",
        "text_required": "Поле 'text' обязательно (строка)",
        "internal_error": "Внутренняя ошибка сервера",
        "bad_xlsx": "Файл не является валидным Excel (.xlsx)",
        "bad_xls": "Файл не является валидным Excel (.xls)",
        "bad_excel_ext": "Неподдерживаемый формат Excel: %s",
    },
    "en": {
        "no_file": "No file provided",
        "no_file_selected": "No file selected",
        "not_allowed": "File type not allowed. Allowed: %s",
        "empty_file": "Empty file",
        "invalid_binary": "Invalid file type (binary content rejected)",
        "text_too_large": "Text too large",
        "file_too_large": "File too large",
        "text_required": "Field 'text' is required (string)",
        "internal_error": "Internal server error",
        "bad_xlsx": "File is not a valid Excel (.xlsx)",
        "bad_xls": "File is not a valid Excel (.xls)",
        "bad_excel_ext": "Unsupported Excel format: %s",
    },
}


def get_lang() -> str:
    """Определяет язык ответа: поле lang в запросе, затем Accept-Language."""
    lang = ""
    if request.form:
        lang = request.form.get("lang", "")
    if not lang and request.is_json:
        data = request.get_json(silent=True) or {}
        lang = data.get("lang", "")
    if not lang:
        lang = request.args.get("lang", "")
    if not lang:
        lang = request.accept_languages.best_match(["ru", "en"]) or "ru"
    lang = str(lang).lower()[:2]
    return lang if lang in MESSAGES else "ru"


def msg(key: str, *args) -> str:
    """Локализованное сообщение текущего запроса."""
    text = MESSAGES[get_lang()].get(key) or MESSAGES["ru"].get(key, key)
    return text % args if args else text


def allowed_file(filename: str) -> bool:
    """Проверка разрешенных расширений."""
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]
    )


# Magic bytes для Excel
_XLSX_MAGIC = b'PK\x03\x04'
_XLS_MAGIC = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'


def validate_excel_magic(raw: bytes, ext: str) -> bool:
    """Проверка magic bytes для Excel-файлов."""
    if ext == "xlsx":
        return raw[:4] == _XLSX_MAGIC
    if ext == "xls":
        return raw[:8] == _XLS_MAGIC
    return True


def file_ext(filename: str) -> str:
    """Нижнерегистровое расширение файла без точки ('' если нет)."""
    return filename.rsplit(".", 1)[1].lower() if "." in filename else ""


def validate_text_content(raw: bytes) -> bool:
    """Проверяет, что содержимое похоже на текст (магия MIME + эвристика)."""
    if magic is not None:
        try:
            mime = magic.Magic(mime=True).from_buffer(raw[:64 * 1024])
            if mime not in ("text/plain", "application/octet-stream",
                            "text/x-log", "inode/x-empty",
                            "application/json", "text/json"):
                return False
        except Exception as e:  # noqa: BLE001
            logger.warning("magic недоступен: %s", e)
    # Эвристика: не более 10% непечатаемых байтов в первом куске
    sample = raw[:64 * 1024]
    if sample:
        bad = sum(1 for b in sample if b < 9 or (13 < b < 32))
        if bad / len(sample) > 0.10:
            return False
    return True


def decode_text(raw: bytes) -> str:
    """Декодирует байты в текст (utf-8 с запасным вариантом cp1251).

    Для JSON-файлов дополнительно нормализует escape-последовательности
    (\\t, \\r, \\n -> реальные символы), чтобы regex-ы в anonymizer
    корректно находили IP-адреса и другие паттерны.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("cp1251", errors="replace")

    # JSON: декодировать unicode-escapes и нормализовать control chars
    if text.lstrip().startswith("{") or text.lstrip().startswith("["):
        try:
            data = json.loads(text)
            # json.dumps c ensure_ascii=False декодирует \uXXXX
            text = json.dumps(data, ensure_ascii=False, indent=None, separators=(",", ":"))
            # Но control characters экранируются обратно: 	 -> \t
            # Возвращаем реальные символы для корректной работы regex
            text = text.replace("\\t", "\t").replace("\\r", "\r").replace("\\n", "\n")
        except (json.JSONDecodeError, ValueError):
            pass

    return text


def build_anonymizer(form) -> Anonymizer:
    """Собирает Anonymizer из параметров запроса (form/query/JSON dict)."""
    if hasattr(form, "getlist"):
        entities = form.getlist("entities") or None
    else:
        raw = form.get("entities")
        if isinstance(raw, str):
            entities = [x.strip() for x in raw.split(",") if x.strip()] or None
        elif isinstance(raw, (list, tuple)):
            entities = list(raw) or None
        else:
            entities = None
    return Anonymizer(
        entities=entities,
        mode=form.get("mode", "session") or "session",
        salt=form.get("salt", "") or "",
        style=form.get("style", "pseudonym") or "pseudonym",
        preserve_common_ports=form.get("preserve_common_ports", "") in ("1", "true", "on"),
    )


@app.route("/")
def index():
    """Веб-интерфейс."""
    return render_template("index.html")


@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy",
                    "timestamp": datetime.utcnow().isoformat()})


@app.route("/upload", methods=["POST"])
@limiter.limit("10 per minute")
def upload_file():
    """Загрузка файла, анонимизация в памяти, возврат результата.

    Поддерживаются текстовые форматы (.log/.txt) и Excel (.xls/.xlsx).
    """
    started = time.monotonic()
    if "file" not in request.files:
        return jsonify({"error": msg("no_file")}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": msg("no_file_selected")}), 400
    if not allowed_file(file.filename):
        allowed = ", ".join("." + e for e in sorted(app.config["ALLOWED_EXTENSIONS"]))
        return jsonify({"error": msg("not_allowed", allowed)}), 400

    raw = file.read()
    if not raw:
        return jsonify({"error": msg("empty_file")}), 400

    try:
        anonymizer = build_anonymizer(request.form)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    ext = file_ext(file.filename)
    if ext in SUPPORTED_EXCEL_EXTS:
        return _handle_excel(file.filename, raw, ext, anonymizer, started)
    if ext == "json":
        return _handle_json(file.filename, raw, anonymizer, started)
    return _handle_text(file.filename, raw, anonymizer, started)


def _handle_text(filename: str, raw: bytes, anonymizer: Anonymizer,
                 started: float):
    """Анонимизация текстового файла (.log/.txt/.json)."""
    if not validate_text_content(raw):
        return jsonify({"error": msg("invalid_binary")}), 400

    text = decode_text(raw)
    result = anonymizer.anonymize_text(text)

    elapsed = time.monotonic() - started
    logger.info(
        "Обработан %s (%d байт, %.1f с): %d замен, %d уникальных",
        filename, len(raw), elapsed,
        result.stats["total_replacements"], len(result.mapping),
    )

    # Санитизация: убрать всё кроме alphanum, dash, underscore, dot
    import re
    safe_base = re.sub(r'[^\w\-.]', '_', os.path.splitext(os.path.basename(filename))[0])
    download_name = safe_base + "_clean.log"
    resp = send_file(
        io.BytesIO(result.text.encode("utf-8")),
        as_attachment=True,
        download_name=download_name,
        mimetype="text/plain",
    )
    resp.headers["X-Anon-Stats"] = json.dumps(result.stats, ensure_ascii=False)
    return resp


def _handle_json(filename: str, raw: bytes, anonymizer: Anonymizer,
                 started: float):
    """Анонимизация JSON-файла: рекурсивная обработка всех строковых значений."""
    if not validate_text_content(raw):
        return jsonify({"error": msg("invalid_binary")}), 400

    try:
        text = decode_text(raw)
        data = json.loads(text)
    except json.JSONDecodeError as e:
        return jsonify({"error": f"Невалидный JSON: {e}"}), 400

    def anonymize_value(obj):
        """Рекурсивно анонимизирует все строковые значения в JSON."""
        if isinstance(obj, str):
            result = anonymizer.anonymize_text(obj)
            return result.text
        elif isinstance(obj, dict):
            return {k: anonymize_value(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [anonymize_value(item) for item in obj]
        else:
            return obj

    anonymized_data = anonymize_value(data)
    output_text = json.dumps(anonymized_data, ensure_ascii=False, indent=2)

    elapsed = time.monotonic() - started
    logger.info(
        "Обработан JSON %s (%d байт, %.1f с)",
        filename, len(raw), elapsed
    )

    import re
    safe_base = re.sub(r'[^\w\-.]', '_', os.path.splitext(os.path.basename(filename))[0])
    download_name = safe_base + "_clean.json"
    resp = send_file(
        io.BytesIO(output_text.encode("utf-8")),
        as_attachment=True,
        download_name=download_name,
        mimetype="application/json",
    )
    resp.headers["X-Anon-Stats"] = json.dumps({"format": "json"}, ensure_ascii=False)
    return resp


def _handle_excel(filename: str, raw: bytes, ext: str, anonymizer: Anonymizer,
                  started: float):
    """Анонимизация книги Excel (.xls/.xlsx)."""
    # Проверка magic bytes
    if not validate_excel_magic(raw, ext):
        return jsonify({"error": msg("bad_" + ext)}), 400
    
    try:
        out_bytes, stats = anonymize_excel(raw, ext, anonymizer)
    except ExcelError as e:
        logger.warning("Отклонён невалидный Excel %s: %s", filename, e)
        return jsonify({"error": msg(e.key, *e.fmt_args)}), 400
    except ValueError as e:
        logger.warning("Отклонён невалидный Excel %s: %s", filename, e)
        return jsonify({"error": str(e)}), 400

    elapsed = time.monotonic() - started
    logger.info(
        "Обработан %s (%d байт, %.1f с): %d листов, %d замен, %d уникальных",
        filename, len(raw), elapsed, stats.get("sheets", 0),
        stats.get("total_replacements", 0), stats.get("unique_entities", 0),
    )

    import re
    safe_base = re.sub(r'[^\w\-.]', '_', os.path.splitext(os.path.basename(filename))[0])
    download_name = safe_base + "_clean." + ext
    mimetype = ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                if ext == "xlsx" else "application/vnd.ms-excel")
    resp = send_file(
        io.BytesIO(out_bytes),
        as_attachment=True,
        download_name=download_name,
        mimetype=mimetype,
    )
    resp.headers["X-Anon-Stats"] = json.dumps(stats, ensure_ascii=False)
    return resp


@app.route("/api/anonymize", methods=["POST"])
@limiter.limit("20 per minute")
def api_anonymize():
    """Анонимизация текста: JSON {text, entities?, style?, mode?, salt?}."""
    data = request.get_json(silent=True) or {}
    text = data.get("text")
    if not isinstance(text, str) or not text:
        return jsonify({"error": msg("text_required")}), 400
    if len(text.encode("utf-8")) > app.config["MAX_CONTENT_LENGTH"]:
        return jsonify({"error": msg("text_too_large")}), 413

    try:
        anonymizer = build_anonymizer(data)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    result = anonymizer.anonymize_text(text)
    return jsonify({
        "text": result.text,
        "stats": result.stats,
    })


@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": msg("file_too_large")}), 413


@app.errorhandler(500)
def server_error(e):
    logger.error("Внутренняя ошибка: %s", e)
    return jsonify({"error": msg("internal_error")}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
