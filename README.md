# Анонимайзер логов

**[English version](README.en.md)** | Русская версия

Сервис анонимизации данных с сохранением логики документа.

## Что анонимизируется

| Тип | Пример оригинала | Псевдоним (стиль `pseudonym`) | Реалистичный (стиль `realistic`) |
|---|---|---|---|
| IPv4 | `192.168.1.100` | `[IP1]` | `198.18.x.x` |
| IPv6 | `2001:db8::1`, `[::1]:8443` | `[IP2]` | `fd00::x` |
| Порты | `:8080`, `port=443`, `порт 22` | `[PORT1]` | случайный порт >1024 |
| Домены | `api.example.com` | `[HOST1]` | `host-N.example.com` |
| Email | `ivan@mail.ru` | `[LOCAL1]@[HOST2]` | `userN@host-N...` |
| Телефоны RU | `+7 (999) 123-45-67`, `8-999-123-45-67` | `[PHONE1]` | `+7 9xx xxx-xx-xx` |
| Телефоны межд. | `+1 212 555 0143` | `[PHONE2]` | — |
| ФИО | `Иванов Иван Иванович`, `Петрова А.С.`, `John Smith` | вымышленные ФИО того же рода и регистра | (всегда) |
| MAC | `00:1a:2b:3c:4d:5e` | `[MAC1]` | `02:xx:...` |

## Форматы файлов

- Текстовые: `.log`, `.txt` (в т.ч. cp1251).
- Excel: `.xlsx` (openpyxl) и `.xls` (xlrd/xlwt). Обходятся все листы и все
  ячейки; один общий маппинг на книгу (одинаковые значения в разных листах ->
  одинаковые псевдонимы); имена листов тоже анонимизируются. Числа, даты и
  булевы значения сохраняются как есть, кроме 11-значных чисел, начинающихся
  с 7/8 (считаются телефонами, сохранёнными числом). Форматирование ячеек
  Excel не сохраняется (ограничение библиотек).

## Защита от ложных срабатываний

Не заменяются: даты (`2026-01-15`), время (`10:00:01`), UUID, версии ПО
(`1.2.3.4.5`), имена файлов (`app.log`, `main.py` — чёрный список расширений),
обычные слова с заглавной буквы (ФИО распознаётся только по структуре
фамилия+имя+отчество или фамилия+инициалы).

## Режимы

- `session` (по умолчанию) — счётчики `[IP1], [IP2]...` в рамках одного файла/запроса.
- `stable` + `salt` — псевдонимы через SHA-256 от соли: одинаковый результат
  между запусками, файлами и серверами. Разные соли -> разные результаты.

## Локализация (RU/EN)

- Веб-интерфейс: переключатель RU/EN в шапке; выбор запоминается в
  localStorage; при первом визите определяется язык браузера.
- Сообщения об ошибках API: поле `lang` (ru|en) в форме/JSON или заголовок
  `Accept-Language`; по умолчанию русский.
- Документация: README.md (рус.) и README.en.md (англ.).
- Распознавание русских ФИО/телефонов не зависит от языка интерфейса.

## Быстрый старт (Docker Compose)

```bash
docker compose up -d --build
# UI:      https://localhost:8082/     (http:// на том же порту редиректит на https)
# Health:  https://localhost:8082/health
```

### HTTPS / сертификаты

TLS терминируется на nginx, используется самоподписанный сертификат из
каталога `certs/` (создан openssl, действует до 2029-01, CN=localhost,
SAN: localhost + 127.0.0.1). Браузер покажет предупреждение о недоверенном
центре — это нормально для самоподписанного сертификата; для внутреннего
использования добавьте `certs/localhost.crt` в доверенные на клиенте.

Перевыпуск сертификата:

```bash
cd certs && openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout localhost.key -out localhost.crt -days 825 \
  -subj "/CN=localhost/O=Anonimizator" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  && chmod 600 localhost.key
docker compose restart nginx
```

Каталог `certs/` в .gitignore — приватный ключ не должен попадать в репозиторий.

Примечание: если DNS в build-сети не работает, в compose уже задан
`build.network: host`.

## CLI (без Docker)

```bash
python app/anonymizer.py -i putty.log                  # -> putty_clean.log
python app/anonymizer.py -i access.log -v              # verbose: пары в stderr
cat app.log | python app/anonymizer.py -o clean.log
python app/anonymizer.py -i a.log --style realistic
python app/anonymizer.py -i a.log --mode stable --salt SECRET --map-out map.json
python app/anonymizer.py -i a.log --entities ip,port,phone,name
python app/anonymizer.py -i a.log --preserve-common-ports
```

`--map-out` сохраняет словарь замен в JSON; `--map-in` загружает его
(например, для де-анонимизации доверенным лицом или согласованной обработки
серии файлов).

## HTTP API

### POST /upload (multipart/form-data)

Поле `file` (.log/.txt, до 50 МБ). Необязательные поля формы:
`entities` (повторяющееся значение или CSV: ip,port,host,email,phone,name,mac),
`style` (pseudonym|realistic), `mode` (session|stable), `salt`,
`preserve_common_ports` (1|true).

Ответ: файл-вложение; статистика в заголовке `X-Anon-Stats` (JSON).

```bash
curl -F "file=@access.log" -F "style=realistic" https://localhost:8082/upload -o clean.log --cacert certs/localhost.crt   # или -k
```

### POST /api/anonymize (JSON)

```bash
curl -X POST https://localhost:8082/api/anonymize -k \
  -H 'Content-Type: application/json' \
  -d '{"text": "Иванов И.И. 10.0.0.1:22", "mode": "stable", "salt": "s3cr3t"}'
```

Ответ: `{"text": ..., "mapping": {оригинал: псевдоним}, "stats": {...}}`

### GET /health

```json
{"status": "healthy", "timestamp": "..."}
```

## Обработка больших файлов

`anonymize_stream()` обрабатывает поток построчно — память не растёт с
размером файла. Веб-сервис обрабатывает файлы до 50 МБ в памяти.

## Приватность

Обработка выполняется **в процессе** (без subprocess): загруженные данные
нигде не сохраняются на диске и не покидают память процесса. Временные
файлы и директории uploads/processed не используются.

## Тесты

```bash
python -m venv .venv && .venv/bin/pip install -r app/requirements.txt pytest
.venv/bin/python -m pytest tests/ -q
```

## Структура

```
app/
  anonymizer.py    # ядро: класс Anonymizer + CLI
  app.py           # Flask: /, /health, /upload, /api/anonymize
  static/index.html# веб-интерфейс (drag&drop, вставка текста, настройки)
  Dockerfile
  requirements.txt
nginx/nginx.conf   # reverse proxy (порт 80)
tests/             # pytest: ядро + веб-слой
docker-compose.yml
```

## Ограничения

- Распознавание ФИО эвристическое: полные тройки и «Фамилия И.О.» с
  валидацией по словарям имён/отчеств/окончаний фамилий. Экзотические
  фамилии без типичных окончаний (например, «Жук», «Голова») пропускаются —
  это осознанный выбор в пользу отсутствия ложных срабатываний.
- Телефоны определяются по формату `+7/8` (10 цифр) и международному `+CC...`
  (8–15 цифр). Номера без `+` и не RU-формата могут быть пропущены.
- В стиле `realistic` вымышленные имена могут теоретически совпасть с
  реальными людьми — это свойство любого генератора имён.
