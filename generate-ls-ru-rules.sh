#!/bin/bash
# generate-ls-ru-rules.sh
#
# Генератор Little Snitch правил из списка CIDR. Живёт в этом репозитории
# (app-ru-split). Запускается приложением Steward — его bundled ls-rules-sync.sh
# делает `cd "$REPO" && bash generate-ls-ru-rules.sh "<merged-ru-cidrs.txt>"` —
# либо вручную.
#
# Генерирует .lsrules файлы для Little Snitch:
#   Firefox + Диск-О → только российские IP
#   Safari + Chrome + Charles (прокси) → всё кроме российских IP
#
# CIDR-диапазоны берутся из .txt файла. Целевой каталог или конкретный .txt
# передаётся аргументом $1 либо переменной окружения $RULES_TARGET_DIR. Без
# аргумента — обратно-совместимый дефолт: сканируется папка самого скрипта.
#
# Использование:
#   bash generate-ls-ru-rules.sh                       # дефолт: папка скрипта
#   bash generate-ls-ru-rules.sh /path/to/repo         # каталог с *.txt
#   bash generate-ls-ru-rules.sh /path/to/cidrs.txt    # конкретный .txt
#   RULES_TARGET_DIR=/path/to/repo bash generate-ls-ru-rules.sh
# Результат (рядом с CIDR-файлом / в целевом каталоге):
#   ru-only.lsrules
#   no-ru.lsrules

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# КОРРЕКЦИЯ (docs/06 §7.2): явная цель из $1 или $RULES_TARGET_DIR,
# иначе обратно-совместимый дефолт — папка скрипта.
TARGET="${1:-${RULES_TARGET_DIR:-$SCRIPT_DIR}}"

if [ -d "$TARGET" ]; then
    # Каталог — сканируем первый *.txt в нём, .lsrules кладём туда же.
    OUT_DIR="$(cd "$TARGET" && pwd)"
    CIDRS_FILE=$(find "$OUT_DIR" -maxdepth 1 -name "*.txt" -type f | head -1)
elif [ -f "$TARGET" ]; then
    # Конкретный .txt — используем его, .lsrules рядом с ним.
    CIDRS_FILE="$TARGET"
    OUT_DIR="$(cd "$(dirname "$TARGET")" && pwd)"
else
    echo "Ошибка: цель не найдена: $TARGET"
    exit 1
fi

if [ -z "$CIDRS_FILE" ]; then
    echo "Ошибка: не найден .txt файл с CIDR-диапазонами в $OUT_DIR"
    exit 1
fi

echo "Используется файл: $(basename "$CIDRS_FILE")"
COUNT=$(wc -l < "$CIDRS_FILE" | tr -d ' ')
echo "Диапазонов: $COUNT"

OUTPUT_RU="$OUT_DIR/ru-only.lsrules"
OUTPUT_NORU="$OUT_DIR/no-ru.lsrules"

echo "Генерирую .lsrules файлы..."

python3 - "$CIDRS_FILE" "$OUTPUT_RU" "$OUTPUT_NORU" << 'PYEOF'
import sys, json

cidrs_file = sys.argv[1]
output_ru = sys.argv[2]
output_noru = sys.argv[3]

with open(cidrs_file) as f:
    cidrs = [line.strip() for line in f if line.strip()]

remote_addresses = ", ".join(cidrs)

# NB: правило для local-net (127/8, 10/8, 172.16/12, 192.168/16, 169.254/16)
# больше НЕ включается в подписку — security-by-default (см. README).
# Если нужен доступ к localhost / LAN — добавь private-rule вручную в Little Snitch.

infra_domains = [
    "mozilla.org", "mozilla.net", "mozilla.com",
    "raw.githubusercontent.com",
    "ublockorigin.pages.dev", "ublockorigin.github.io",
    "filters.adtidy.org", "easylist.to",
    "easylist-downloads.adblockplus.org",
    "pgl.yoyo.org", "malware-filter.gitlab.io",
    "secure.fanboy.co.nz"
]

# Приложения: только РФ
ru_only_apps = [
    {
        "name": "Firefox",
        "path": "/Applications/Firefox.app/Contents/MacOS/firefox",
        "infra": True
    },
    {
        "name": "DiskO",
        "path": "/Applications/DiskO.app/Contents/MacOS/DiskO",
        "infra": False
    },
    {
        "name": "DiskO FSE",
        "path": "/Applications/DiskO.app/Contents/PlugIns/Mail.Ru.DiskO.as.FSE.appex/Contents/MacOS/Mail.Ru.DiskO.as.FSE",
        "infra": False
    },
    {
        "name": "DiskO Helper",
        "path": "/Applications/DiskO.app/Contents/Library/LoginItems/Mail.Ru.DiskO.Helper.app/Contents/MacOS/Mail.Ru.DiskO.Helper",
        "infra": False
    }
]

# --- RU-only: Firefox + DiskO ---
ru_rules = {
    "name": "RU-only: Firefox + DiskO",
    "description": "Firefox и Диск-О: разрешить только российские IP (+ Mozilla/uBlock инфраструктура для Firefox). Локалка/loopback НЕ включены — добавь private-rule вручную если нужно. Всё остальное заблокировано.",
    "rules": []
}

for app in ru_only_apps:
    # Российские IP
    ru_rules["rules"].append({
        "action": "allow",
        "process": app["path"],
        "direction": "outgoing",
        "remote-addresses": remote_addresses,
        "notes": f"{app['name']} → российские IP → разрешить"
    })
    # Инфраструктура (только для Firefox)
    if app["infra"]:
        ru_rules["rules"].append({
            "action": "allow",
            "process": app["path"],
            "direction": "outgoing",
            "remote-domains": infra_domains,
            "notes": f"{app['name']} → инфраструктура обновлений и uBlock → разрешить"
        })
    # Deny всё остальное
    ru_rules["rules"].append({
        "action": "deny",
        "process": app["path"],
        "direction": "outgoing",
        "notes": f"{app['name']} → всё остальное → заблокировать"
    })

# --- No-RU: Safari + Chrome + Charles (proxy) ---
# Charles — это HTTP-прокси: когда браузер ходит через него, исходящее соединение
# к сайту открывает ПРОЦЕСС Charles, а не браузер, поэтому deny на бинарник браузера
# его НЕ ловит. Значит сам Charles тоже должен быть в этой группе (deny РФ + allow
# остального), иначе через него РФ-коннекты утекают. NB: это блокирует РФ для ЛЮБОГО
# трафика через Charles (в т.ч. если прогонять через него Firefox/Диск-О).
noru_apps = [
    ("/Applications/Safari.app/Contents/MacOS/Safari", "Safari"),
    ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "Chrome"),
    ("/Applications/Charles.app/Contents/MacOS/Charles", "Charles")
]

noru_rules = {
    "name": "No-RU: Safari + Chrome + Charles",
    "description": "Safari, Chrome и Charles (прокси): заблокировать российские IP, всё остальное — разрешить. Приложения ПОЛНОСТЬЮ определены этой группой (deny РФ + allow остального), поэтому отдельное ручное allow-правило в Little Snitch заводить НЕ нужно. Charles включён, т.к. при проксировании именно его процесс открывает соединение к сайту — иначе РФ-коннекты утекают мимо deny на браузер.",
    "rules": []
}

for path, name in noru_apps:
    # Российские IP → заблокировать. Это правило СПЕЦИФИЧНЕЕ общего allow ниже
    # (ограничивает remote-addresses, тогда как у allow — «Any Server»), а в Little
    # Snitch специфичность сервера решается ДО разбора deny↔allow, так что более
    # специфичный deny выигрывает у общего allow — значит для РФ-адресов срабатывает
    # именно этот deny, даже соседствуя с allow-всё. (deny-бьёт-allow лишь усиливает.)
    noru_rules["rules"].append({
        "action": "deny",
        "process": path,
        "direction": "outgoing",
        "remote-addresses": remote_addresses,
        "notes": f"{name} → российские IP → заблокировать"
    })
    # Всё остальное → разрешить. Делает группу самодостаточной: приложение
    # полностью определено здесь (deny РФ + allow остального), поэтому отдельное
    # ручное allow-правило для Chrome/Safari больше не требуется.
    noru_rules["rules"].append({
        "action": "allow",
        "process": path,
        "direction": "outgoing",
        "notes": f"{name} → всё остальное → разрешить"
    })

# Записать
with open(output_ru, 'w') as f:
    json.dump(ru_rules, f, ensure_ascii=False, indent=2)

with open(output_noru, 'w') as f:
    json.dump(noru_rules, f, ensure_ascii=False, indent=2)

print(f"Записано {len(cidrs)} CIDR-диапазонов")
print(f"  RU-only (Firefox + DiskO): {output_ru}")
print(f"  No-RU (Safari + Chrome + Charles): {output_noru}")
PYEOF

echo ""
echo "Готово!"
echo ""
echo "Файл 1: $OUTPUT_RU"
echo "  Firefox + Диск-О → только РФ (+ Mozilla/uBlock для Firefox)"
echo "  Локалка/loopback НЕ включена — добавь private-rule вручную в Little Snitch если нужно."
echo ""
echo "Файл 2: $OUTPUT_NORU"
echo "  Safari + Chrome + Charles → заблокированы российские IP, всё остальное разрешено (группа самодостаточна)"
echo ""
echo "Установка в Little Snitch (для каждого файла отдельный гист и Remote Rule Group):"
echo "  1. Создать secret gist на gist.github.com"
echo "  2. Вставить содержимое файла"
echo "  3. Little Snitch → Rule Groups → + → Remote Rule Group…"
echo "  4. Вставить raw URL, снять галочку 'Disable new allow rules'"
echo ""
echo "Обновление:"
echo "  Положить новый .txt файл в $OUT_DIR"
echo "  bash $SCRIPT_DIR/generate-ls-ru-rules.sh $OUT_DIR"
echo "  Обновить гисты"
