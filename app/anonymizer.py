#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Анонимизатор логов и текстов.

Заменяет чувствительные данные на детерминированные псевдонимы,
сохраняя логику документа:
  * IPv4 / IPv6 адреса        -> [IP1] / [IP2] ...   (или правдоподобные фейки)
  * порты (IP:port, port=NNN) -> [PORT1] ...
  * домены и email            -> [HOST1], [LOCAL1]
  * телефоны (RU и междунар.) -> [PHONE1]
  * ФИО (кириллица, латиница, инициалы) -> вымышленные ФИО того же рода/регистра
  * MAC-адреса                -> [MAC1]

Одна и та же сущность всегда получает один и тот же псевдоним:
  * mode="session" - в пределах экземпляра (счётчики);
  * mode="stable"  - криптографически от соли (одинаково между запусками/файлами).

Защищает от ложных срабатываний: даты, время, UUID, версии ПО (1.2.3.4.5),
имена файлов (app.log, main.py), обычные слова с заглавной буквы.
"""

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

__all__ = ["Anonymizer", "AnonymizeResult", "LogAnonymizer", "generate_output_filename"]

# --------------------------------------------------------------------------- #
#  Словари имён                                                                #
# --------------------------------------------------------------------------- #

GIVEN_M = {
    "александр", "алексей", "анатолий", "андрей", "антон", "аркадий", "артём",
    "артем", "борис", "вадим", "валентин", "валерий", "василий", "виктор",
    "виталий", "владимир", "владислав", "вячеслав", "геннадий", "георгий",
    "григорий", "даниил", "данил", "денис", "дмитрий", "евгений", "егор",
    "иван", "игорь", "илья", "кирилл", "константин", "леонид", "максим",
    "матвей", "михаил", "никита", "николай", "олег", "павел",
    "пётр", "петр", "роман", "руслан", "семён", "семен", "сергей",
    "станислав", "степан", "тимур", "фёдор", "федор", "филипп", "эдуард",
    "юрий", "яков",
}

GIVEN_F = {
    "александра", "алёна", "алена", "анастасия", "анна", "валентина",
    "валерия", "вера", "вероника", "виктория", "галина", "дарья", "екатерина",
    "елена", "елизавета", "ирина", "ксения", "людмила", "мария", "надежда",
    "наталия", "наталья", "ольга", "полина", "светлана", "софия", "софья",
    "тамара", "татьяна", "ульяна", "юлия", "яна",
}

SUR_M = [
    "Смирнов", "Иванов", "Кузнецов", "Попов", "Васильев", "Петров", "Соколов",
    "Михайлов", "Новиков", "Фёдоров", "Морозов", "Волков", "Алексеев",
    "Лебедев", "Семёнов", "Егоров", "Павлов", "Козлов", "Степанов",
    "Николаев", "Орлов", "Андреев", "Макаров", "Никитин", "Захаров",
    "Зайцев", "Соловьёв", "Борисов", "Яковлев", "Григорьев", "Романов",
    "Тарасов", "Белов", "Комаров", "Ильин", "Голубев", "Антонов", "Юрьев",
    "Тимофеев", "Ефимов", "Матвеев", "Сергеев", "Крылов", "Титов", "Федотов",
    "Марков", "Шевченко", "Ковалёв", "Гусев", "Достоевский",
]

SUR_F = [
    (s[:-2] + "ая") if s.endswith("ский") else
    (s + "а") for s in SUR_M
]

PATR_M = [
    "Александрович", "Алексеевич", "Андреевич", "Антонович", "Борисович",
    "Валерьевич", "Васильевич", "Викторович", "Витальевич", "Владимирович",
    "Геннадьевич", "Георгиевич", "Григорьевич", "Денисович", "Дмитриевич",
    "Евгеньевич", "Иванович", "Игоревич", "Ильич", "Кириллович",
    "Константинович", "Леонидович", "Максимович", "Михайлович", "Никитич",
    "Николаевич", "Олегович", "Павлович", "Петрович", "Романович",
    "Русланович", "Сергеевич", "Станиславович", "Степанович", "Тимурович",
    "Фёдорович", "Федорович", "Юрьевич", "Яковлевич",
]

PATR_F = [
    "Александровна", "Алексеевна", "Андреевна", "Антоновна", "Борисовна",
    "Валерьевна", "Васильевна", "Викторовна", "Витальевна", "Владимировна",
    "Геннадьевна", "Георгиевна", "Григорьевна", "Денисовна", "Дмитриевна",
    "Евгеньевна", "Ивановна", "Игоревна", "Ильинична", "Кирилловна",
    "Константиновна", "Леонидовна", "Максимовна", "Михайловна", "Никитична",
    "Николаевна", "Олеговна", "Павловна", "Петровна", "Романовна",
    "Руслановна", "Сергеевна", "Станиславовна", "Степановна", "Тимуровна",
    "Фёдоровна", "Федоровна", "Юрьевна", "Яковлевна",
]

EN_FIRST = {
    "john", "james", "robert", "michael", "william", "david", "richard",
    "joseph", "thomas", "charles", "christopher", "daniel", "matthew",
    "anthony", "mark", "donald", "steven", "paul", "andrew", "joshua",
    "kenneth", "kevin", "brian", "george", "timothy", "ronald", "edward",
    "jason", "jeffrey", "ryan", "jacob", "gary", "nicholas", "eric",
    "jonathan", "stephen", "larry", "justin", "scott", "brandon",
    "benjamin", "samuel", "raymond", "gregory", "frank", "alexander",
    "patrick", "jack", "dennis", "jerry", "tyler", "aaron", "peter", "adam",
    "mary", "patricia", "jennifer", "linda", "elizabeth", "barbara",
    "susan", "jessica", "sarah", "karen", "nancy", "lisa", "betty",
    "margaret", "sandra", "ashley", "kim", "emily", "donna", "michelle",
    "dorothy", "julia", "alice", "anna", "emma", "olivia", "sophie",
}

EN_STOP = {
    "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
    "am", "do", "does", "did", "has", "have", "had", "say", "says", "said",
    "told", "asked", "went", "came", "saw", "made", "took", "got", "let",
    "put", "in", "on", "at", "to", "for", "with", "from", "by", "of", "and",
    "or", "but", "if", "then", "than", "that", "this", "these", "those",
    "it", "its", "as", "not", "no", "yes", "will", "would", "can", "could",
    "shall", "should", "may", "might", "must", "also", "very", "just",
    "now", "here", "there", "when", "where", "why", "how", "all", "any",
    "some", "after", "before", "during", "over", "under", "again", "ok",
    "http", "https", "www", "ftp", "ssh", "tcp", "udp", "dns", "get",
    "post", "error", "warning", "info", "debug", "server", "client",
    "user", "host", "port", "file", "line", "time", "date",
}

RU_ALPHA = "АБВГДЕЖЗИКЛМНОПРСТУФХЦЧШЩЭЮЯ"

# --------------------------------------------------------------------------- #
#  Регулярные выражения                                                        #
# --------------------------------------------------------------------------- #

_OCT = r'(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'

RE_UUID = re.compile(
    r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
    r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
)
RE_DATE = re.compile(r'(?<!\d)\d{4}-\d{2}-\d{2}(?!\d)')
RE_TIME = re.compile(
    r'(?<![\d.:])\d{1,2}:\d{2}(?::\d{2})?(?:[.,]\d{1,6})?(?![\d:])'
)

RE_MAC = re.compile(
    r'(?<![\w:])(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}(?![:\w])'
)

_V6_OCT_PART = _OCT + r'\.' + _OCT + r'\.' + _OCT + r'\.' + _OCT
_V6 = (
    r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,7}:'
    r'|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}'
    r'|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}'
    r'|:(?::[0-9a-fA-F]{1,4}){1,7}'
    r'|::(?:[fF]{4}:)?' + _V6_OCT_PART +
    r'|(?:[0-9a-fA-F]{1,4}:){1,6}' + _V6_OCT_PART
)

RE_IPV6 = re.compile(r'(?<![:.\w])(' + _V6 + r')(?![:\w.])')
RE_IPV6_BR = re.compile(
    r'\[(' + _V6 + r')\](?::(\d{1,5})(?!\d))?'
)

RE_IPV4 = re.compile(
    r'(?<![\w.-])(' + _OCT + r'\.' + _OCT + r'\.' + _OCT + r'\.' + _OCT + r')'
    r'(?![\d.])(?::(\d{1,5})(?!\d))?'
)

RE_DOMAIN = re.compile(
    r'(?<![\w.-])'
    r'((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24})'
    r'(?![@\w-]|\.[a-zA-Z0-9])'
)

RE_EMAIL = re.compile(
    r'(?<![\w.-])([A-Za-z0-9._%+-]{1,64})@'
    r'((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24})'
    r'(?![@\w.-])'
)

# Российские номера: +7/8 и 10 цифр (мобильные 9xx, городские 3xx/4xx/8xx)
RE_PHONE_RU = re.compile(
    r'(?<![\w+.:,-])(?:\+7|8)[ (.-]*([3489]\d{2})[ ).-]*(\d{3})[ .-]*(\d{2})[ .-]*(\d{2})(?!\d)'
)
# Международные: +CC и 7..13 цифр следом
RE_PHONE_INTL = re.compile(
    r'(?<![\w+.:,-])(\+\d{1,3}(?:[ .-]?\(?\d{1,6}\)?){2,4})(?![\w.-])'
)

RE_PORT_KW = re.compile(
    r'(?i)\b([sd]?port|порт)(\s*[=:]?\s*)(\d{2,5})(?!\d)'
)

_CYR_W = r'[А-ЯЁ][А-ЯЁа-яё]+'
RE_NAME_CYR = re.compile(
    r'(?<![А-ЯЁа-яё])(' + _CYR_W + r')( )(' + _CYR_W + r')( )(' + _CYR_W + r')(?![А-ЯЁа-яё])'
)
RE_NAME_INIT = re.compile(
    r'(?<![А-ЯЁа-яё\w])(' + _CYR_W + r')[ ]+([А-ЯЁ])\.[ ]?([А-ЯЁ])\.(?![А-ЯЁа-яё\w])'
)
RE_NAME_PAIR = re.compile(
    r'(?<![А-ЯЁа-яё])(' + _CYR_W + r')( )(' + _CYR_W + r')(?![А-ЯЁа-яё])'
)
RE_NAME_LAT = re.compile(
    r'(?<![A-Za-z])([A-Z][a-z]{1,15})( )([A-Z][a-z]{1,20})(?![A-Za-z])'
)

SUR_M_ENDS = (
    "ов", "ев", "ёв", "ин", "ын", "ский", "цкий", "их", "ых", "ко", "ук",
    "юк", "ич", "швили", "дзе", "ян", "оглы", "ер", "ель", "ок", "ёк",
    "ак", "як", "ун", "юр", "ло",
)
SUR_F_ENDS = ("ова", "ева", "ёва", "ина", "ына", "ская", "цкая", "их", "ых", "ко")

# Расширения файлов, которые не должны приниматься за TLD домена
EXT_BLACKLIST = {
    "log", "txt", "py", "pyc", "pyo", "js", "mjs", "ts", "tsx", "jsx", "go",
    "rs", "java", "class", "jar", "war", "ear", "c", "h", "cpp", "hpp",
    "cc", "cs", "sh", "bash", "zsh", "fish", "rb", "php", "pl", "pm", "lua",
    "sql", "yaml", "yml", "json", "xml", "html", "htm", "css", "scss",
    "sass", "less", "md", "markdown", "rst", "cfg", "conf", "ini", "toml",
    "env", "properties", "gradle", "proto", "tf", "tfvars", "pp", "lock",
    "sum", "mod", "service", "socket", "timer", "mount", "target", "swp",
    "bak", "tmp", "temp", "gz", "bz2", "xz", "z", "zip", "tar", "rar",
    "7z", "rpm", "deb", "exe", "dll", "so", "o", "a", "bin", "dat",
    "csv", "db", "sqlite", "sqlite3", "jpg", "jpeg", "png", "gif", "svg",
    "ico", "webp", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "key", "pem", "crt", "cer", "key", "p12", "pfx", "iso", "img", "dmp",
    "out", "err", "orig", "rej", "diff", "patch", "makefile", "cmake",
}

COMMON_PORTS = frozenset(range(1025)) | {
    3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017,
}

TAG_BY_KIND = {
    "ip": "IP", "port": "PORT", "host": "HOST",
    "email": "LOCAL", "phone": "PHONE", "mac": "MAC",
}

NAME_KINDS = (
    "surname_m", "surname_f", "given_m", "given_f",
    "patr_m", "patr_f", "initials", "lat_first", "lat_last",
)
KIND_TO_TYPE = dict(
    [("ip", "ip"), ("port", "port"), ("host", "host"), ("email", "email"),
     ("phone", "phone"), ("mac", "mac")]
    + [(k, "name") for k in NAME_KINDS]
)
ALL_TYPES = ("ip", "port", "host", "email", "phone", "name", "mac")


# --------------------------------------------------------------------------- #
#  Результат                                                                   #
# --------------------------------------------------------------------------- #

@dataclass
class AnonymizeResult:
    """Результат анонимизации текста."""
    text: str
    mapping: Dict[str, str] = field(default_factory=dict)
    stats: Dict = field(default_factory=dict)


# --------------------------------------------------------------------------- #
#  Ядро                                                                        #
# --------------------------------------------------------------------------- #

class Anonymizer:
    """
    Универсальный анонимизатор: IP, порты, домены, email, телефоны, ФИО, MAC.

    Параметры:
      entities   - набор типов сущностей (по умолчанию все):
                   ip, port, host, email, phone, name, mac
      mode       - "session" (счётчики в рамках экземпляра) или
                   "stable" (хэш от соли: результат воспроизводим между запусками)
      salt       - соль для mode="stable"
      style      - "pseudonym" ([IP1]) или "realistic" (правдоподобные значения)
      preserve_common_ports - не трогать общеизвестные порты (80, 443, 22, ...)
      preload_mapping - готовый словарь {оригинал: псевдоним} для переиспользования
    """

    ALL_ENTITIES = ("ip", "port", "host", "email", "phone", "name", "mac")

    def __init__(
        self,
        entities: Optional[Sequence[str]] = None,
        mode: str = "session",
        salt: str = "",
        style: str = "pseudonym",
        preserve_common_ports: bool = False,
        preload_mapping: Optional[Dict[str, str]] = None,
    ):
        if entities is None:
            entities = self.ALL_ENTITIES
        unknown = set(entities) - set(self.ALL_ENTITIES)
        if unknown:
            raise ValueError(
                "Неизвестные типы сущностей: %s (доступны: %s)"
                % (", ".join(sorted(unknown)), ", ".join(self.ALL_ENTITIES))
            )
        if mode not in ("session", "stable"):
            raise ValueError("mode должен быть 'session' или 'stable'")
        if style not in ("pseudonym", "realistic"):
            raise ValueError("style должен быть 'pseudonym' или 'realistic'")

        self.entities = frozenset(entities)
        self.mode = mode
        self.salt = salt
        self.style = style
        self.preserve_common_ports = preserve_common_ports

        self._maps: Dict[str, Dict[str, str]] = {
            k: {} for k in list(TAG_BY_KIND) + list(NAME_KINDS)
        }
        self._counters: Dict[str, int] = {}
        self._preload: Dict[str, str] = dict(preload_mapping or {})

    # ------------------------------------------------------------------ #
    #  Генерация псевдонимов                                             #
    # ------------------------------------------------------------------ #

    def _hash_int(self, kind: str, original: str, mod: int) -> int:
        h = hashlib.sha256(
            ("%s|%s|%s" % (self.salt, kind, original)).encode("utf-8")
        ).hexdigest()
        return int(h[:12], 16) % mod

    def _hash_hex(self, kind: str, original: str, n: int = 8) -> str:
        return hashlib.sha256(
            ("%s|%s|%s" % (self.salt, kind, original)).encode("utf-8")
        ).hexdigest()[:n]

    def _next(self, kind: str) -> int:
        self._counters[kind] = self._counters.get(kind, 0) + 1
        return self._counters[kind]

    def _index(self, kind: str, original: str, attempt: int = 0) -> int:
        if self.mode == "stable":
            key = original if attempt == 0 else "%s#%d" % (original, attempt)
            return self._hash_int(kind, key, 10 ** 9)
        return self._next(kind)

    def _fake_ip(self, original: str, attempt: int = 0) -> str:
        n = self._index("ip", original, attempt)
        if ":" in original:  # IPv6
            return "fd00::%x" % (n % (2 ** 64))
        return "198.18.%d.%d" % (1 + (n // 250) % 250, 1 + n % 250)

    def _generate(self, kind: str, original: str, attempt: int = 0) -> str:
        tag = TAG_BY_KIND.get(kind)
        if tag is not None and self.style == "pseudonym":
            if self.mode == "stable":
                return "[%s-%s]" % (tag, self._hash_hex(kind, original))
            return "[%s%d]" % (tag, self._next(kind))

        # realistic-стиль (и имена, которые всегда реалистичны)
        if kind == "ip":
            return self._fake_ip(original, attempt)
        if kind == "port":
            n = self._index("port", original, attempt)
            return str(1024 + n % 64000)
        if kind == "host":
            n = self._index("host", original, attempt)
            return "host-%d.example.com" % n
        if kind == "email":
            n = self._index("email", original, attempt)
            return "user%d" % n
        if kind == "phone":
            n = self._index("phone", original, attempt)
            d = "%09d" % ((n * 7919) % 10 ** 9)
            return "+7 9%s%s %s%s%s-%s%s-%s%s" % (
                d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8]
            )
        if kind == "mac":
            n = self._index("mac", original, attempt)
            return "02:%02x:%02x:%02x:%02x:%02x" % (
                n & 0xFF, (n >> 4) & 0xFF, (n >> 8) & 0xFF,
                (n >> 12) & 0xFF, (n >> 16) & 0xFF,
            )
        if kind == "surname_m":
            return SUR_M[self._index(kind, original, attempt) % len(SUR_M)]
        if kind == "surname_f":
            return SUR_F[self._index(kind, original, attempt) % len(SUR_F)]
        if kind == "given_m":
            return GIVEN_M_LIST[self._index(kind, original, attempt) % len(GIVEN_M_LIST)]
        if kind == "given_f":
            return GIVEN_F_LIST[self._index(kind, original, attempt) % len(GIVEN_F_LIST)]
        if kind == "patr_m":
            return PATR_M[self._index(kind, original, attempt) % len(PATR_M)]
        if kind == "patr_f":
            return PATR_F[self._index(kind, original, attempt) % len(PATR_F)]
        if kind == "initials":
            n = self._index(kind, original, attempt)
            return "%s.%s." % (RU_ALPHA[n % len(RU_ALPHA)],
                               RU_ALPHA[(n * 7 + 3) % len(RU_ALPHA)])
        if kind == "lat_first":
            return EN_FIRST_LIST[self._index(kind, original, attempt) % len(EN_FIRST_LIST)]
        if kind == "lat_last":
            n = self._index(kind, original, attempt)
            return EN_LAST_STEMS[n % len(EN_LAST_STEMS)]
        raise ValueError("Неизвестный kind: %s" % kind)

    def _fake(self, kind: str, original: str) -> str:
        """Возвращает (и кеширует) псевдоним для оригинала в рамках kind."""
        m = self._maps[kind]
        if original in m:
            return m[original]
        if original in self._preload:
            fake = self._preload[original]
        else:
            # псевдоним не должен совпадать с оригиналом (иначе смысла нет)
            attempt = 0
            fake = self._generate(kind, original, attempt)
            while fake.lower() == original.lower() and attempt < 16:
                attempt += 1
                fake = self._generate(kind, original, attempt)
        m[original] = fake
        return fake

    @staticmethod
    def _match_case(original: str, fake: str) -> str:
        """Сохраняет регистр оригинала (ВСЕ ЗАГЛАВНЫЕ -> фейк ЗАГЛАВНЫМИ)."""
        if original.isupper():
            return fake.upper()
        return fake

    def merged_mapping(self) -> Dict[str, str]:
        """Плоский словарь {оригинал: псевдоним} по всем типам."""
        out: Dict[str, str] = {}
        for m in self._maps.values():
            out.update(m)
        return out

    # ------------------------------------------------------------------ #
    #  Валидаторы                                                        #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _valid_domain(domain: str) -> bool:
        if len(domain) > 253:
            return False
        tld = domain.rsplit(".", 1)[-1].lower()
        if tld in EXT_BLACKLIST or len(tld) < 2:
            return False
        if all(c.isdigit() or c == "." for c in domain):
            return False
        return True

    @staticmethod
    def _valid_port(value: str) -> bool:
        try:
            p = int(value)
        except ValueError:
            return False
        return 0 < p <= 65535

    def _port_replaced(self, value: str) -> bool:
        return (
            "port" in self.entities
            and self._valid_port(value)
            and not (self.preserve_common_ports and int(value) in COMMON_PORTS)
        )

    @staticmethod
    def _cyr_gender(surname_l: str, patr_l: str) -> Optional[str]:
        """Определяет род ФИО по отчеству (приоритет) и фамилии."""
        if patr_l.endswith(("вна", "чна")):
            return "f"
        if patr_l.endswith(("ович", "евич", "вич", "ич")):
            return "m"
        return None

    def _cyr_triple(self, w1: str, w2: str, w3: str) -> Optional[str]:
        """Валидирует тройку (фамилия, имя, отчество). Возвращает 'm'/'f'/None."""
        l1, l2, l3 = (w.lower().replace("ё", "е") for w in (w1, w2, w3))
        if l2 not in GIVEN_M and l2 not in GIVEN_F:
            return None
        gender = None
        if l3.endswith(("вна", "чна")):
            gender = "f"
        elif l3.endswith(("ович", "евич", "вич")) or l3 in ("ильич", "никитич", "фомич", "кузьмич", "лукич"):
            gender = "m"
        if gender is None:
            return None
        s1 = w1.lower()
        if gender == "f":
            if not s1.endswith(SUR_F_ENDS):
                return None
        else:
            if not s1.endswith(SUR_M_ENDS):
                return None
        # имя должно согласовываться с родом
        if gender == "m" and l2 not in GIVEN_M and l2 not in GIVEN_F:
            return None
        if gender == "m" and l2 in GIVEN_F and l2 not in GIVEN_M:
            return None
        if gender == "f" and l2 in GIVEN_M and l2 not in GIVEN_F:
            return None
        return gender

    def _cyr_surname(self, w: str) -> Optional[str]:
        """Проверяет слово на роль фамилии; возвращает 'm'/'f'/None."""
        s = w.lower()
        if s.endswith(SUR_F_ENDS) and s.endswith(("а", "я")):
            return "f"
        if s.endswith(SUR_M_ENDS):
            return "m"
        return None

    # ------------------------------------------------------------------ #
    #  Сбор span-ов                                                      #
    # ------------------------------------------------------------------ #

    def _spans(self, text: str) -> List[Tuple[int, int, int, Callable]]:
        spans: List[Tuple[int, int, int, Callable]] = []

        def add(s: int, e: int, prio: int, fn: Callable) -> None:
            spans.append((s, e, prio, fn))

        # 0. Защищённые зоны: UUID, даты, время (никогда не заменяются)
        for rx in (RE_UUID, RE_DATE, RE_TIME):
            for m in rx.finditer(text):
                add(m.start(), m.end(), 0,
                    lambda g=m.group(0): (g, []))

        # 1. Email (local + домен)
        if "email" in self.entities:
            for m in RE_EMAIL.finditer(text):
                local, domain = m.group(1), m.group(2)
                if not self._valid_domain(domain):
                    continue
                add(m.start(1), m.end(1), 1,
                    lambda lo=local: (self._fake("email", lo), [("email", lo)]))
                add(m.start(2), m.end(2), 1,
                    lambda d=domain: (self._fake("host", d), [("host", d)]))

        # 2. MAC (до IPv6, чтобы не принять за короткий IPv6)
        if "mac" in self.entities:
            for m in RE_MAC.finditer(text):
                mac = m.group(0)
                add(m.start(), m.end(), 2,
                    lambda v=mac: (self._fake("mac", v), [("mac", v)]))

        # 3. IPv6 (в квадратных скобках и обычные)
        if "ip" in self.entities:
            for m in RE_IPV6_BR.finditer(text):
                ip, port = m.group(1), m.group(2)
                repl_port = port if (port and self._port_replaced(port)) else None
                add(m.start(), m.end(), 3, self._mk_v6_br(ip, port, repl_port))
            for m in RE_IPV6.finditer(text):
                ip = m.group(1)
                add(m.start(), m.end(), 3,
                    lambda v=ip: (self._fake("ip", v), [("ip", v)]))

            # 4. IPv4 (с опциональным портом)
            for m in RE_IPV4.finditer(text):
                ip, port = m.group(1), m.group(2)
                end = m.end()
                repl_port = port if (port and self._port_replaced(port)) else None
                if port and repl_port is None:
                    end = m.end(1)  # порт не заменяем - сужаем span до IP
                add(m.start(), end, 4, self._mk_v4(ip, port, repl_port))

        # 5. Домены
        if "host" in self.entities:
            for m in RE_DOMAIN.finditer(text):
                d = m.group(1)
                if not self._valid_domain(d):
                    continue
                add(m.start(), m.end(), 5,
                    lambda v=d: (self._fake("host", v), [("host", v)]))

        # 6/7. Телефоны
        if "phone" in self.entities:
            for m in RE_PHONE_RU.finditer(text):
                full = m.group(0)
                add(m.start(), m.end(), 6,
                    lambda v=full: (self._fake("phone", v), [("phone", v)]))
            for m in RE_PHONE_INTL.finditer(text):
                full = m.group(0)
                digits = sum(c.isdigit() for c in full)
                if not (8 <= digits <= 15):
                    continue
                add(m.start(), m.end(), 7,
                    lambda v=full: (self._fake("phone", v), [("phone", v)]))

        # 8. ФИО: полная кириллическая тройка
        if "name" in self.entities:
            for m in RE_NAME_CYR.finditer(text):
                w1, w2, w3 = m.group(1), m.group(3), m.group(5)
                gender = self._cyr_triple(w1, w2, w3)
                if gender is None:
                    continue
                s_kind = "surname_" + ("f" if w1.lower().endswith(("а", "я"))
                                       and not w1.lower().endswith(("их", "ых"))
                                       else "m")
                g_kind = "given_f" if (gender == "f" and w2.lower().replace("ё", "е") in GIVEN_F
                                       and w2.lower().replace("ё", "е") not in GIVEN_M) else \
                         "given_m" if gender == "m" else "given_f"
                add(m.start(1), m.end(1), 8, self._mk_name(s_kind, w1))
                add(m.start(3), m.end(3), 8, self._mk_name(g_kind, w2))
                add(m.start(5), m.end(5), 8, self._mk_name("patr_" + gender, w3))

            # 9. Фамилия + инициалы
            for m in RE_NAME_INIT.finditer(text):
                surname = m.group(1)
                g = self._cyr_surname(surname)
                if g is None:
                    continue
                i1, i2 = m.group(2), m.group(3)
                key = "%s.%s." % (i1, i2)
                add(m.start(1), m.end(1), 9,
                    self._mk_name("surname_" + g, surname))
                add(m.start(2), m.end(), 9,
                    lambda k=key: (self._fake("initials", k), [("initials", k)]))

            # 9. Фамилия + имя (без отчества)
            for m in RE_NAME_PAIR.finditer(text):
                w1, w2 = m.group(1), m.group(3)
                g1 = self._cyr_surname(w1)
                if g1 is None:
                    continue
                l2 = w2.lower().replace("ё", "е")
                if l2 not in GIVEN_M and l2 not in GIVEN_F:
                    continue
                g_kind = ("given_f" if (l2 in GIVEN_F and l2 not in GIVEN_M)
                          else "given_m")
                add(m.start(1), m.end(1), 9, self._mk_name("surname_" + g1, w1))
                add(m.start(3), m.end(3), 9, self._mk_name(g_kind, w2))

            # 9. Латинские имя+фамилия
            for m in RE_NAME_LAT.finditer(text):
                first, last = m.group(1), m.group(3)
                if first.lower() not in EN_FIRST:
                    continue
                if last.lower() in EN_STOP or len(last) < 2:
                    continue
                add(m.start(1), m.end(1), 9, self._mk_name("lat_first", first))
                add(m.start(3), m.end(3), 9, self._mk_name("lat_last", last))

        # 10. Порты по ключевому слову (port=8080, порт 22, sport:1234)
        if "port" in self.entities:
            for m in RE_PORT_KW.finditer(text):
                value = m.group(3)
                if not self._port_replaced(value):
                    continue
                add(m.start(3), m.end(3), 10,
                    lambda v=value: (self._fake("port", v), [("port", v)]))

        return spans

    def _mk_v4(self, ip: str, port: Optional[str],
               repl_port: Optional[str]) -> Callable:
        def build():
            fake_ip = self._fake("ip", ip)
            if repl_port is not None:
                return ("%s:%s" % (fake_ip, self._fake("port", repl_port)),
                        [("ip", ip), ("port", repl_port)])
            if port is not None:
                return "%s:%s" % (fake_ip, port), [("ip", ip)]
            return fake_ip, [("ip", ip)]
        return build

    def _mk_v6_br(self, ip: str, port: Optional[str],
                  repl_port: Optional[str]) -> Callable:
        def build():
            fake_ip = self._fake("ip", ip)
            if self.style == "pseudonym":
                ip_part = fake_ip  # уже в скобках: [IP1]
            else:
                ip_part = "[%s]" % fake_ip
            if repl_port is not None:
                return ("%s:%s" % (ip_part, self._fake("port", repl_port)),
                        [("ip", ip), ("port", repl_port)])
            if port is not None:
                return "%s:%s" % (ip_part, port), [("ip", ip)]
            return ip_part, [("ip", ip)]
        return build

    def _mk_name(self, kind: str, word: str) -> Callable:
        def build():
            fake = self._fake(kind, word.lower())
            fake = self._match_case(word, fake)
            return fake, [("name", word.lower())]
        return build

    # ------------------------------------------------------------------ #
    #  Основной метод                                                    #
    # ------------------------------------------------------------------ #

    def anonymize_text(self, text: str,
                       include_mapping: bool = True) -> AnonymizeResult:
        """Анонимизирует текст, возвращает AnonymizeResult(text, mapping, stats).

        include_mapping=False - не строить сводный словарь (экономия O(N)
        на вызов; используется при потоковой обработке, где словарь нужен
        один раз в конце).
        """
        spans = self._spans(text)
        spans.sort(key=lambda sp: (sp[0], sp[2], -(sp[1] - sp[0])))

        kept = []
        cur_end = -1
        for s, e, prio, fn in spans:
            if s >= cur_end:
                kept.append((s, e, fn))
                cur_end = e

        out: List[str] = []
        pos = 0
        pairs: List[Tuple[str, str]] = []
        for s, e, fn in kept:
            repl, types = fn()
            out.append(text[pos:s])
            out.append(repl)
            pos = e
            pairs.extend(types)
        out.append(text[pos:])
        result_text = "".join(out)

        by_type = {t: 0 for t in ALL_TYPES}
        distinct: Dict[str, set] = {t: set() for t in ALL_TYPES}
        for t, orig in pairs:
            stat_t = KIND_TO_TYPE.get(t, t)
            by_type[stat_t] += 1
            distinct[stat_t].add(orig)

        orig_lines = text.splitlines(True)
        new_lines = result_text.splitlines(True)
        if len(orig_lines) == len(new_lines):
            changed = sum(1 for a, b in zip(orig_lines, new_lines) if a != b)
        else:
            changed = sum(1 for t_ in ALL_TYPES if by_type[t_])
        stats = {
            "total_lines": len(orig_lines) if text else 0,
            "changed_lines": changed,
            "total_replacements": len(pairs),
            "by_type": by_type,
            "distinct_by_type": {t: len(s) for t, s in distinct.items()},
        }
        return AnonymizeResult(
            text=result_text,
            mapping=self.merged_mapping() if include_mapping else {},
            stats=stats,
        )

    # Потоковая обработка (для больших файлов)
    def anonymize_stream(self, input_stream: Iterable[str],
                         output_stream, verbose: bool = False) -> Dict:
        agg = {"total_lines": 0, "changed_lines": 0, "total_replacements": 0}
        for line in input_stream:
            r = self.anonymize_text(line, include_mapping=False)
            agg["total_lines"] += r.stats["total_lines"] or (1 if line else 0)
            agg["changed_lines"] += r.stats["changed_lines"]
            agg["total_replacements"] += r.stats["total_replacements"]
            if verbose and r.stats["changed_lines"]:
                print("ORIG: %s" % line.rstrip("\r\n"), file=sys.stderr)
                print("ANON: %s" % r.text.rstrip("\r\n"), file=sys.stderr)
                print("-" * 40, file=sys.stderr)
            output_stream.write(r.text)
        return agg


# Списки для генерации (стабильный порядок)
GIVEN_M_LIST = sorted(w.capitalize() for w in GIVEN_M)
GIVEN_F_LIST = sorted(w.capitalize() for w in GIVEN_F)
EN_FIRST_LIST = sorted(w.capitalize() for w in EN_FIRST)
EN_LAST_STEMS = [
    "Anderson", "Baker", "Bennett", "Brooks", "Brown", "Carter", "Clark",
    "Collins", "Cook", "Cooper", "Davis", "Evans", "Fisher", "Foster",
    "Gray", "Green", "Hall", "Harris", "Hayes", "Hill", "Howard", "Hughes",
    "Jenkins", "Kelly", "King", "Lane", "Lewis", "Long", "Marshall",
    "Martin", "Miller", "Morgan", "Morris", "Nelson", "Owen", "Parker",
    "Perry", "Price", "Reed", "Riley", "Roberts", "Robinson", "Rogers",
    "Ross", "Russell", "Scott", "Shaw", "Smith", "Stone", "Taylor",
    "Thomas", "Turner", "Walker", "Ward", "Warren", "Watson", "Webb",
    "Wells", "White", "Williams", "Wilson", "Wood", "Wright", "Young",
]


# --------------------------------------------------------------------------- #
#  Обратная совместимость со старым классом                                    #
# --------------------------------------------------------------------------- #

class LogAnonymizer:
    """Шим совместимости со старым API (anonymize_line/process_log)."""

    def __init__(self, **kwargs):
        self._an = Anonymizer(**kwargs)

    @property
    def ip_mapping(self):
        return self._an._maps["ip"]

    @property
    def host_mapping(self):
        return self._an._maps["host"]

    @property
    def ip_counter(self):
        return len(self._an._maps["ip"])

    @property
    def host_counter(self):
        return len(self._an._maps["host"])

    def anonymize_line(self, line: str) -> Tuple[str, bool]:
        r = self._an.anonymize_text(line)
        return r.text, r.stats["total_replacements"] > 0

    def process_log(self, input_stream, output_stream, verbose=False):
        return self._an.anonymize_stream(input_stream, output_stream, verbose)


def generate_output_filename(input_filename: str) -> str:
    """putty.log -> putty_clean.log"""
    import os
    base, ext = os.path.splitext(input_filename)
    return "%s_clean%s" % (base, ext or ".log")


# --------------------------------------------------------------------------- #
#  CLI                                                                         #
# --------------------------------------------------------------------------- #

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Анонимизация логов: IP, порты, домены, email, телефоны, "
                    "ФИО, MAC -> детерминированные псевдонимы.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  python anonymizer.py -i putty.log
  python anonymizer.py -i access.log -v --style realistic
  python anonymizer.py -i a.log --mode stable --salt MY_SECRET --map-out map.json
  cat app.log | python anonymizer.py -o clean.log --entities ip,port,phone,name
        """,
    )
    parser.add_argument("-i", "--input", help="Входной файл (по умолчанию STDIN)")
    parser.add_argument("-o", "--output",
                        help="Выходной файл (по умолчанию <input>_clean.<ext> или STDOUT")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Печатать пары оригинал->замена в STDERR")
    parser.add_argument("--entities",
                        default=",".join(Anonymizer.ALL_ENTITIES),
                        help="Список сущностей через запятую: %s"
                             % ",".join(Anonymizer.ALL_ENTITIES))
    parser.add_argument("--style", choices=("pseudonym", "realistic"),
                        default="pseudonym",
                        help="pseudonym: [IP1]; realistic: правдоподобные значения")
    parser.add_argument("--mode", choices=("session", "stable"), default="session",
                        help="session: счётчики; stable: хэш от соли (воспроизводимо)")
    parser.add_argument("--salt", default="",
                        help="Соль для mode=stable")
    parser.add_argument("--preserve-common-ports", action="store_true",
                        help="Не заменять общеизвестные порты (80, 443, 22, ...)")
    parser.add_argument("--map-out", help="Сохранить словарь замен в JSON-файл")
    parser.add_argument("--map-in", help="Загрузить словарь замен из JSON-файла")
    args = parser.parse_args(argv)

    preload = None
    if args.map_in:
        try:
            with open(args.map_in, "r", encoding="utf-8") as f:
                preload = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print("Ошибка чтения --map-in: %s" % e, file=sys.stderr)
            return 1

    try:
        anonymizer = Anonymizer(
            entities=[x.strip() for x in args.entities.split(",") if x.strip()],
            mode=args.mode,
            salt=args.salt,
            style=args.style,
            preserve_common_ports=args.preserve_common_ports,
            preload_mapping=preload,
        )
    except ValueError as e:
        print("Ошибка параметров: %s" % e, file=sys.stderr)
        return 1

    output_file = args.output
    if not output_file and args.input:
        output_file = generate_output_filename(args.input)

    input_stream = output_stream = None
    try:
        if args.input:
            input_stream = open(args.input, "r", encoding="utf-8", errors="ignore")
            print("Чтение из файла: %s" % args.input, file=sys.stderr)
        else:
            input_stream = sys.stdin
            print("Чтение из STDIN", file=sys.stderr)

        if output_file:
            output_stream = open(output_file, "w", encoding="utf-8")
            print("Запись в файл: %s" % output_file, file=sys.stderr)
        else:
            output_stream = sys.stdout

        agg = anonymizer.anonymize_stream(input_stream, output_stream, args.verbose)

        mapping = anonymizer.merged_mapping()
        if args.map_out:
            with open(args.map_out, "w", encoding="utf-8") as f:
                json.dump(mapping, f, ensure_ascii=False, indent=2, sort_keys=True)
            print("Словарь замен сохранен в: %s" % args.map_out, file=sys.stderr)

        print("\n%s" % ("=" * 50), file=sys.stderr)
        print("Обработка завершена успешно!", file=sys.stderr)
        print("Всего строк: %d" % agg["total_lines"], file=sys.stderr)
        print("Изменено строк: %d" % agg["changed_lines"], file=sys.stderr)
        print("Всего замен: %d" % agg["total_replacements"], file=sys.stderr)
        print("Уникальных псевдонимов: %d" % len(mapping), file=sys.stderr)
        if output_file:
            print("Результат сохранен в: %s" % output_file, file=sys.stderr)
        print("=" * 50, file=sys.stderr)
        return 0
    except FileNotFoundError:
        print("Ошибка: файл '%s' не найден." % args.input, file=sys.stderr)
        return 1
    except PermissionError:
        print("Ошибка: нет прав на запись в '%s'." % output_file, file=sys.stderr)
        return 1
    finally:
        if input_stream is not None and input_stream is not sys.stdin:
            input_stream.close()
        if output_stream is not None and output_stream is not sys.stdout:
            output_stream.close()


if __name__ == "__main__":
    sys.exit(main())
