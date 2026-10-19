# -*- coding: utf-8 -*-
"""
Анонимизация Excel-файлов (.xls, .xlsx).

Обходит все листы и ячейки книги, заменяя чувствительные данные тем же
движком Anonymizer, что и для текста. Один анонимизатор на всю книгу:
одинаковые значения в разных ячейках/листах получают одинаковые псевдонимы.

Особенности:
  * числа, даты и булевы значения сохраняются как есть (структура не ломается);
  * исключение: 11-значные числа, начинающиеся с 7/8, считаются телефонами;
  * имена листов тоже анонимизируются (ФИО/IP в названии листа - тоже утечка);
  * недопустимые в именах листов символы ([ ] : * ? / \\) заменяются на '-'.
"""

import datetime
import io
import re
from typing import Dict, Tuple

from anonymizer import Anonymizer, GIVEN_M, GIVEN_F

__all__ = ["anonymize_excel", "is_numeric_phone"]

SUPPORTED_EXCEL_EXTS = ("xls", "xlsx")

_BAD_TITLE_CHARS = re.compile(r"[\[\]:*?/\\]")


class ExcelError(ValueError):
    """Ошибка разбора Excel с ключом для локализации сообщения.

    key - ключ в app.MESSAGES ('bad_xlsx' / 'bad_xls' / 'bad_excel_ext'),
    fmt_args - аргументы подстановки (%s).
    """

    def __init__(self, key: str, *fmt_args):
        self.key = key
        self.fmt_args = fmt_args
        super().__init__("%s %s" % (key, fmt_args))


def is_numeric_phone(value) -> bool:
    """11-значное число, начинающееся с 7 или 8 -> похоже на телефон."""
    try:
        v = int(value)
    except (TypeError, ValueError):
        return False
    if v != float(value):
        return False
    return 10 ** 10 <= abs(v) < 10 ** 11 and str(abs(v))[0] in "78"


def _anonymize_cell_value(an: Anonymizer, value, stats: Dict):
    """Возвращает анонимизированное значение ячейки (тип по возможности сохраняется)."""
    if value is None or isinstance(value, (bool, datetime.datetime, datetime.date,
                                           datetime.time)):
        return value
    if isinstance(value, (int, float)):
        if "phone" in an.entities and is_numeric_phone(value):
            fake = an.anonymize_text(str(int(value)), include_mapping=False)
            _bump(stats, fake.stats)
            return fake.text
        return value
    if isinstance(value, str):
        r = an.anonymize_text(value, include_mapping=False)
        _bump(stats, r.stats)
        return r.text
    return value


def _bump(stats: Dict, cell_stats: Dict) -> None:
    stats["total_replacements"] += cell_stats["total_replacements"]
    for t, n in cell_stats["by_type"].items():
        stats["by_type"][t] = stats["by_type"].get(t, 0) + n


def _new_stats() -> Dict:
    return {"total_replacements": 0, "by_type": {}, "sheets": 0, "cells": 0}


def _anonymize_title(an: Anonymizer, title: str) -> str:
    """Анонимизирует имя листа: сначала общий движок, затем одиночные ФИО-токены."""
    out = an.anonymize_text(title, include_mapping=False).text
    tokens = out.split(" ")
    fixed = []
    for tok in tokens:
        core = tok.strip(".,;:!?()")
        low = core.lower().replace("ё", "е")
        if core and (an._cyr_surname(core) is not None
                     or low in GIVEN_M or low in GIVEN_F):
            kind = ("surname_f" if an._cyr_surname(core) == "f"
                    else "surname_m" if an._cyr_surname(core) == "m"
                    else "given_m")
            fake = an._fake(kind, core.lower())
            tok = tok.replace(core, fake)
        fixed.append(tok)
    out = " ".join(fixed)
    # символы, недопустимые в именах листов (в т.ч. из псевдонимов [IP1])
    out = _BAD_TITLE_CHARS.sub("-", out)
    return (out.strip() or "Sheet")[:31]


def _unique(name: str, used: set) -> str:
    base = name
    i = 2
    while name.lower() in used:
        suffix = "_%d" % i
        name = base[:31 - len(suffix)] + suffix
        i += 1
    used.add(name.lower())
    return name


def anonymize_excel(raw: bytes, ext: str, an: Anonymizer) -> Tuple[bytes, Dict]:
    """
    Анонимизирует книгу Excel.

    Возвращает (bytes результата, stats).
    Бросает ValueError, если файл не является валидным Excel или расширение
    не поддерживается.
    """
    ext = ext.lower().lstrip(".")
    if ext == "xlsx":
        return _anonymize_xlsx(raw, an)
    if ext == "xls":
        return _anonymize_xls(raw, an)
    raise ExcelError("bad_excel_ext", ext)


# --------------------------------------------------------------------- xlsx

def _anonymize_xlsx(raw: bytes, an: Anonymizer) -> Tuple[bytes, Dict]:
    import openpyxl
    import zipfile
    
    # Валидация структуры xlsx (обязательные файлы)
    def _validate_xlsx_structure(zf: zipfile.ZipFile) -> bool:
        names = zf.namelist()
        required = ['[Content_Types].xml', 'xl/workbook.xml']
        return all(r in names for r in required)
    
    # Защита от Zip Bomb: проверка размера распакованного содержимого
    MAX_UNCOMPRESSED_SIZE = 500 * 1024 * 1024  # 500MB
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            # Валидация структуры
            if not _validate_xlsx_structure(zf):
                raise ExcelError("bad_xlsx")
            # Проверка размера
            total_uncompressed = sum(info.file_size for info in zf.infolist())
            if total_uncompressed > MAX_UNCOMPRESSED_SIZE:
                raise ValueError(
                    f"Распакованный размер {total_uncompressed} превышает лимит {MAX_UNCOMPRESSED_SIZE}"
                )
    except zipfile.BadZipFile:
        raise ExcelError("bad_xlsx")
    
    try:
        # data_only=True: не загружать формулы (защита от RCE)
        # keep_links=False: не загружать внешние ссылки (защита от XXE/SSRF)
        wb = openpyxl.load_workbook(
            io.BytesIO(raw),
            data_only=True,
            keep_links=False
        )
    except Exception:  # noqa: BLE001 - openpyxl кидает разные исключения
        raise ExcelError("bad_xlsx")

    stats = _new_stats()

    for ws in wb.worksheets:
        stats["sheets"] += 1
        for row in ws.iter_rows():
            for cell in row:
                stats["cells"] += 1
                cell.value = _anonymize_cell_value(an, cell.value, stats)

    # Имена листов - после ячеек (чтобы маппинг уже содержал псевдонимы)
    used = set()
    for ws in wb.worksheets:
        ws.title = _unique(_anonymize_title(an, ws.title), used)

    buf = io.BytesIO()
    wb.save(buf)
    stats["unique_entities"] = len(an.merged_mapping())
    return buf.getvalue(), stats


# ---------------------------------------------------------------------- xls

def _anonymize_xls(raw: bytes, an: Anonymizer) -> Tuple[bytes, Dict]:
    import xlrd
    import xlwt

    try:
        book = xlrd.open_workbook(file_contents=raw)
    except Exception:  # noqa: BLE001
        raise ExcelError("bad_xls")

    stats = _new_stats()
    out_wb = xlwt.Workbook(encoding="utf-8")

    used = set()
    for sheet in book.sheets():
        stats["sheets"] += 1
        out_ws = out_wb.add_sheet(_unique(_anonymize_title(an, sheet.name), used))
        for r in range(sheet.nrows):
            for c in range(sheet.ncols):
                stats["cells"] += 1
                ctype = sheet.cell_type(r, c)
                value = sheet.cell_value(r, c)

                if ctype == xlrd.XL_CELL_DATE:
                    value = xlrd.xldate.xldate_as_datetime(value, book.datemode)
                    out_ws.write(r, c, value)
                elif ctype == xlrd.XL_CELL_NUMBER:
                    out_ws.write(r, c, _anonymize_cell_value(an, value, stats))
                elif ctype == xlrd.XL_CELL_TEXT:
                    out_ws.write(r, c, _anonymize_cell_value(an, value, stats))
                elif ctype == xlrd.XL_CELL_BOOLEAN:
                    out_ws.write(r, c, bool(value))
                elif ctype == xlrd.XL_CELL_EMPTY or ctype == xlrd.XL_CELL_BLANK:
                    pass  # пустые ячейки не пишем
                else:  # ERROR и прочее
                    out_ws.write(r, c, _anonymize_cell_value(an, str(value), stats))

    stats["unique_entities"] = len(an.merged_mapping())
    buf = io.BytesIO()
    out_wb.save(buf)
    return buf.getvalue(), stats
