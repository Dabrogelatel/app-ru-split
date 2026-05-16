#!/bin/bash
# generate-ls-ru-rules.sh
# Генерирует .lsrules файлы для Little Snitch:
#   Firefox + Диск-О → только российские IP
#   Safari + Chrome → всё кроме российских IP
#
# CIDR-диапазоны берутся из .txt файла в папке скрипта
#
# Использование: bash generate-ls-ru-rules.sh
# Результат:
#   ./ru-only.lsrules
#   ./no-ru.lsrules

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Найти .txt файл с CIDR в папке скрипта
CIDRS_FILE=$(find "$SCRIPT_DIR" -maxdepth 1 -name "*.txt" -type f | head -1)

if [ -z "$CIDRS_FILE" ]; then
    echo "Ошибка: не найден .txt файл с CIDR-диапазонами в $SCRIPT_DIR"
    exit 1
fi

echo "Используется файл: $(basename "$CIDRS_FILE")"
COUNT=$(wc -l < "$CIDRS_FILE" | tr -d ' ')
echo "Диапазонов: $COUNT"

OUTPUT_RU="$SCRIPT_DIR/ru-only.lsrules"
OUTPUT_NORU="$SCRIPT_DIR/no-ru.lsrules"

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

# --- No-RU: Safari + Chrome ---
noru_apps = [
    ("/Applications/Safari.app/Contents/MacOS/Safari", "Safari"),
    ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "Chrome")
]

noru_rules = {
    "name": "No-RU: Safari + Chrome",
    "description": "Safari и Chrome: заблокировать российские IP. Всё остальное разрешено.",
    "rules": []
}

for path, name in noru_apps:
    noru_rules["rules"].append({
        "action": "deny",
        "process": path,
        "direction": "outgoing",
        "remote-addresses": remote_addresses,
        "notes": f"{name} → российские IP → заблокировать"
    })

# Записать
with open(output_ru, 'w') as f:
    json.dump(ru_rules, f, ensure_ascii=False, indent=2)

with open(output_noru, 'w') as f:
    json.dump(noru_rules, f, ensure_ascii=False, indent=2)

print(f"Записано {len(cidrs)} CIDR-диапазонов")
print(f"  RU-only (Firefox + DiskO): {output_ru}")
print(f"  No-RU (Safari + Chrome):   {output_noru}")
PYEOF

echo ""
echo "Готово!"
echo ""
echo "Файл 1: $OUTPUT_RU"
echo "  Firefox + Диск-О → только РФ (+ Mozilla/uBlock для Firefox)"
echo "  Локалка/loopback НЕ включена — добавь private-rule вручную в Little Snitch если нужно."
echo ""
echo "Файл 2: $OUTPUT_NORU"
echo "  Safari + Chrome → заблокированы российские IP"
echo ""
echo "Установка в Little Snitch (для каждого файла отдельный гист и Remote Rule Group):"
echo "  1. Создать secret gist на gist.github.com"
echo "  2. Вставить содержимое файла"
echo "  3. Little Snitch → Rule Groups → + → Remote Rule Group…"
echo "  4. Вставить raw URL, снять галочку 'Disable new allow rules'"
echo ""
echo "Обновление:"
echo "  Положить новый .txt файл в $SCRIPT_DIR"
echo "  bash $SCRIPT_DIR/generate-ls-ru-rules.sh"
echo "  Обновить гисты"
