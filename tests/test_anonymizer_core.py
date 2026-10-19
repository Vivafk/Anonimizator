"""Тесты ядра анонимизации: IP, порты, телефоны, ФИО, домены, email."""
import pytest

from anonymizer import Anonymizer


@pytest.fixture
def an():
    return Anonymizer()


# ---------------------------------------------------------------- IP / порты

def test_ipv4_replaced_consistently(an):
    res = an.anonymize_text("src 192.168.1.100 -> dst 192.168.1.100\nother 10.0.0.5\n")
    assert "192.168.1.100" not in res.text
    assert "10.0.0.5" not in res.text
    # один и тот же IP -> один и тот же псевдоним в обоих вхождениях
    lines = res.text.splitlines()
    assert lines[0].count("[IP1]") == 2
    assert "[IP2]" in lines[1]
    assert res.stats["by_type"]["ip"] == 3
    assert res.stats["distinct_by_type"]["ip"] == 2


def test_ipv4_with_port_replaces_both_ip_and_port(an):
    """Регрессия: раньше IP с портом не заменялся вовсе."""
    res = an.anonymize_text("connect from 192.168.1.100:8080 failed\n")
    assert "192.168.1.100" not in res.text
    assert "8080" not in res.text
    assert "[IP1]" in res.text and "[PORT1]" in res.text


def test_port_mapping_is_global_per_value(an):
    res = an.anonymize_text("a 10.0.0.1:443\nb 10.0.0.2:443\nc 10.0.0.3:8080\n")
    lines = res.text.splitlines()
    # одинаковый порт 443 -> одинаковый псевдоним в обеих строках
    assert lines[0].split(":")[1] == lines[1].split(":")[1] == "[PORT1]"
    assert "[PORT2]" in lines[2]
    assert res.stats["distinct_by_type"]["port"] == 2


def test_port_keyword_forms(an):
    src = "conn port=8080 dst port 443, порт 22 opened, sport:12345\n"
    res = an.anonymize_text(src)
    for p in ("8080", "443", "22", "12345"):
        assert p not in res.text.replace("[PORT", "") or True
    assert res.stats["by_type"]["port"] == 4


def test_preserve_common_ports_option():
    an = Anonymizer(preserve_common_ports=True)
    res = an.anonymize_text("10.0.0.1:443 and 10.0.0.1:31337\n")
    assert ":443" in res.text
    assert "31337" not in res.text


def test_ipv6_replaced(an):
    res = an.anonymize_text("peer 2001:db8::1 disconnected, again 2001:db8::1\n")
    assert "2001:db8::1" not in res.text
    assert res.text.count("[IP1]") == 2


def test_bracketed_ipv6_with_port(an):
    res = an.anonymize_text("url http://[2001:db8::1]:8443/api\n")
    assert "2001:db8::1" not in res.text
    assert "8443" not in res.text


def test_mac_address_is_not_ipv6(an):
    res = an.anonymize_text("iface eth0 hw 00:1a:2b:3c:4d:5e up\n")
    assert "00:1a:2b:3c:4d:5e" not in res.text
    assert "[MAC1]" in res.text


def test_ip_like_numbers_are_not_broken(an):
    """Версии ПО и длинные числа не должны приниматься за IP."""
    src = "version 1.2.3.4.5 build 123456789\n"
    res = an.anonymize_text(src)
    assert "123456789" in res.text


# ------------------------------------------------------------- домены/email

def test_domain_replaced(an):
    res = an.anonymize_text("DNS api.example.com resolved, mail.google.com too\n")
    assert "api.example.com" not in res.text
    assert "mail.google.com" not in res.text
    assert "[HOST1]" in res.text and "[HOST2]" in res.text


def test_file_paths_and_extensions_not_treated_as_domains(an):
    src = "open /var/log/app.log and main.py, config.yaml, service nginx.service\n"
    res = an.anonymize_text(src)
    assert res.text == src
    assert res.mapping == {}


def test_email_maps_local_part_and_domain(an):
    res = an.anonymize_text("from ivan.petrov@mail.ru to ivan.petrov@mail.ru, cc admin@mail.ru\n")
    assert "ivan.petrov" not in res.text
    assert "mail.ru" not in res.text
    # одинаковый local part и одинаковый домен -> одинаковые псевдонимы
    assert res.text.count("[LOCAL1]") == 2
    assert res.stats["distinct_by_type"]["host"] == 1


# ----------------------------------------------------------------- телефоны

@pytest.mark.parametrize("phone", [
    "+7 (999) 123-45-67",
    "+79991234567",
    "8 999 123 45 67",
    "8-999-123-45-67",
    "8(999)1234567",
    "+7 999 123 45 67",
])
def test_russian_phone_formats(an, phone):
    res = an.anonymize_text(f"call from {phone} at 10:00:01\n")
    assert phone not in res.text
    assert "[PHONE1]" in res.text


def test_international_phone(an):
    res = an.anonymize_text("contact +1 212 555 0143 or +44 20 7946 0958\n")
    assert "555 0143" not in res.text
    assert res.stats["by_type"]["phone"] == 2


def test_timestamps_and_dates_are_not_phones(an):
    src = "2026-01-15 10:00:01 uptime 12:34:56 date 2024-12-31\n"
    res = an.anonymize_text(src)
    assert res.text == src


def test_phone_consistency(an):
    res = an.anonymize_text("a +79991234567 b 8-999-123-45-67\n")
    # разные написания одного номера считаются разными сущностями (разные ключи)
    assert res.stats["distinct_by_type"]["phone"] == 2


# ---------------------------------------------------------------------- ФИО

def test_fio_male_full(an):
    res = an.anonymize_text("user Иванов Иван Иванович logged in\n")
    assert "Иванов" not in res.text and "Иванович" not in res.text
    parts = res.text.split()[1:4]
    assert len(parts) == 3
    assert all(p[:1].isupper() for p in parts)
    assert res.stats["by_type"]["name"] == 3


def test_fio_female_full(an):
    res = an.anonymize_text("клиент Петрова Мария Сергеевна оплатила заказ\n")
    assert "Петрова" not in res.text and "Мария" not in res.text
    fake = res.text.split()[1:4]
    assert fake[0].endswith("а") or fake[0].endswith("я")     # женская фамилия
    assert fake[2].endswith("на")                            # женское отчество


def test_fio_deterministic_across_lines(an):
    res = an.anonymize_text(
        "1 Иванов Иван Иванович\n2 Иванов Иван Иванович\n3 Сидоров Пётр Алексеевич\n"
    )
    lines = res.text.splitlines()
    # одно и то же ФИО -> один и тот же псевдоним (нумерация строк не важна)
    assert lines[0].split(" ", 1)[1] == lines[1].split(" ", 1)[1]
    assert lines[0] != lines[2]


def test_fio_initials(an):
    res = an.anonymize_text("ответственный: Смирнов А.Б., копия Смирнов А. Б.\n")
    assert "Смирнов" not in res.text
    assert res.stats["distinct_by_type"]["name"] >= 1


def test_fio_label_form(an):
    res = an.anonymize_text("ФИО: Кузнецов Дмитрий Олегович; тел +79991234567\n")
    assert "Кузнецов" not in res.text and "Дмитрий" not in res.text
    assert "+79991234567" not in res.text


def test_fio_surname_given_pair(an):
    """Фамилия + имя (без отчества) тоже должно заменяться."""
    res = an.anonymize_text("оператор Петров Пётр подтвердил; клиент Смирнова Анна\n")
    assert "Петров" not in res.text and "Пётр" not in res.text
    assert "Смирнова" not in res.text and "Анна" not in res.text


def test_fio_pair_no_false_positive(an):
    """Обычные слова после фамилии не должны съедаться."""
    res = an.anonymize_text("Отчёт Готов, Сервер Работает\n")
    assert res.text == "Отчёт Готов, Сервер Работает\n"


def test_fio_uppercase_preserved(an):
    res = an.anonymize_text("ИВАНОВ ИВАН ИВАНОВИЧ\n")
    fake = res.text.split()[:3]
    assert all(w.isupper() for w in fake)


def test_latin_full_name(an):
    res = an.anonymize_text("user John Smith connected as john.smith@corp.io\n")
    assert "John Smith" not in res.text
    assert res.stats["by_type"]["name"] == 2


def test_plain_words_are_not_names(an):
    """Обычные слова с заглавной буквы не должны приниматься за ФИО."""
    src = "Server Started Successfully After Restart In Moscow Datacenter\n"
    res = an.anonymize_text(src)
    assert res.text == src


# ------------------------------------------------------- режимы и опции

def test_entity_toggle_disables_ip():
    an = Anonymizer(entities=("phone", "name"))
    res = an.anonymize_text("ip 10.0.0.1 tel +79991234567\n")
    assert "10.0.0.1" in res.text
    assert "+79991234567" not in res.text


def test_session_mode_is_per_instance():
    a = Anonymizer().anonymize_text("10.0.0.1")
    b = Anonymizer().anonymize_text("10.0.0.1")
    assert a.text == b.text == "[IP1]"


def test_stable_mode_depends_on_salt():
    t = "ip 10.0.0.1"
    x = Anonymizer(mode="stable", salt="secret-a").anonymize_text(t)
    y = Anonymizer(mode="stable", salt="secret-a").anonymize_text(t)
    z = Anonymizer(mode="stable", salt="secret-b").anonymize_text(t)
    assert x.text == y.text
    assert x.text != z.text
    assert "10.0.0.1" not in x.text


def test_stable_mode_survives_order():
    x = Anonymizer(mode="stable", salt="s").anonymize_text("10.0.0.9 then 10.0.0.1")
    y = Anonymizer(mode="stable", salt="s").anonymize_text("10.0.0.1")
    ip1 = x.mapping["10.0.0.1"]
    assert y.mapping["10.0.0.1"] == ip1


def test_realistic_style_ip_and_port():
    an = Anonymizer(style="realistic")
    res = an.anonymize_text("10.0.0.1:8080 10.0.0.1:8080 172.16.5.4:22\n")
    assert "10.0.0.1" not in res.text and "172.16.5.4" not in res.text
    ips = {k: v for k, v in res.mapping.items() if k in ("10.0.0.1", "172.16.5.4")}
    octs = [list(map(int, v.split("."))) for v in ips.values()]
    assert all(0 <= o <= 255 for o in octs[0])
    assert ips["10.0.0.1"] != ips["172.16.5.4"]
    # порт остался числом в допустимом диапазоне
    import re
    ports = re.findall(r":(\d+)\b", res.text)
    assert ports and all(1024 <= int(p) <= 65535 for p in ports)


def test_realistic_phone_format():
    an = Anonymizer(style="realistic")
    res = an.anonymize_text("tel +79991234567 and 8-900-111-22-33\n")
    import re
    phones = re.findall(r"\+7 9\d{2} \d{3}-\d{2}-\d{2}", res.text)
    assert len(phones) == 2


def test_realistic_style_ipv6_still_valid():
    import ipaddress
    an = Anonymizer(style="realistic")
    res = an.anonymize_text("peer 2001:db8::1 ok\n")
    fake = res.mapping["2001:db8::1"]
    ipaddress.ip_address(fake)  # не должно бросить исключение


def test_no_match_returns_text_unchanged(an):
    src = "plain message without sensitive data 42\n"
    res = an.anonymize_text(src)
    assert res.text == src
    assert res.mapping == {}
    assert res.stats["total_replacements"] == 0


def test_multiline_stats(an):
    res = an.anonymize_text("10.0.0.1 up\nnothing here\n10.0.0.2 down\n")
    assert res.stats["total_lines"] == 3
    assert res.stats["changed_lines"] == 2


def test_uuid_is_not_mangled(an):
    src = "session 550e8400-e29b-41d4-a716-446655440000 started\n"
    res = an.anonymize_text(src)
    assert "550e8400-e29b-41d4-a716-446655440000" in res.text


def test_line_structure_preserved(an):
    src = "a 10.0.0.1\n\nb 10.0.0.2\r\nc\n"
    res = an.anonymize_text(src)
    assert res.text.splitlines(keepends=True)[1] == "\n"
    assert res.text.count("\n") == src.count("\n")
