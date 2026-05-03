# Firefox: только российский трафик

**Задача:** Firefox работает параллельно с VPN-клиентом. VPN-клиент маршрутизирует российский трафик напрямую (split-tunneling). Firefox не должен отправлять ни одного запроса за пределы РФ — ни при каких условиях. Внутри российской зоны — обычный браузер: куки, пароли, автозаполнение, уведомления.

**Модель угрозы:** российский сайт содержит сторонние ресурсы (аналитика, CDN, шрифты, антифрод-скрипты) за пределами РФ. Если Firefox отправит запрос на зарубежный IP, удалённый сервер увидит VPN-IP. Это недопустимо. Запрос должен быть заблокирован до установки соединения.

---

# Часть 1. Что делать

---

## 1. Firefox и профиль

Скачать Firefox с `mozilla.org/firefox`. Установить. Закрыть (Cmd+Q).

Создать отдельный профиль:

```bash
/Applications/Firefox.app/Contents/MacOS/firefox --ProfileManager
```

Create Profile → имя `RU-only` → Finish → выбрать → Start Firefox.

Ярлык для запуска (Automator → Application → Run Shell Script):

```bash
/Applications/Firefox.app/Contents/MacOS/firefox -P "RU-only" -no-remote &
```

Сохранить как `Firefox RU.app` в Applications. Положить в Dock.

Визуально отличить от основного: в RU-профиле меню ☰ → More tools → Customize toolbar → Themes → выбрать яркую тему (Red, Alpenglow).

---

## 2. about:config — 13 параметров

Открыть `about:config` → Accept the Risk → найти и изменить каждый:

### Блокировка каналов утечки

```
media.peerconnection.enabled               → false
media.peerconnection.ice.default_address_only → true
network.http.http3.enable                   → false
network.http.http3.enable_0rtt              → false
network.dns.disableIPv6                     → true
```

### Отключить встроенный VPN Firefox (появился в 149)

```
browser.ipProtection.enabled                → false
```

### DNS — только системный резолвер

```
network.trr.mode                            → 5
```

### Запрет упреждающих соединений

```
network.prefetch-next                       → false
network.dns.disablePrefetch                 → true
network.dns.disablePrefetchFromHTTPS        → true
network.predictor.enabled                   → false
network.http.speculative-parallel-limit     → 0
```

### Запрет прямого fallback при отказе прокси

```
network.proxy.failover_direct               → false
```

---

## 3. PAC-файл

PAC — основной механизм блокировки трафика за пределы РФ. Работает на уровне сетевого стека Firefox: решение принимается до установки TCP-соединения.

Создать файл:

```bash
nano ~/ru-whitelist.pac
```

Содержимое:

```javascript
function FindProxyForURL(url, host) {
    host = host.toLowerCase();

    // --- Локальные адреса: всегда DIRECT ---
    if (host === "localhost" ||
        host === "127.0.0.1" ||
        isPlainHostName(host) ||
        isInNet(host, "127.0.0.0", "255.0.0.0") ||
        isInNet(host, "10.0.0.0", "255.0.0.0") ||
        isInNet(host, "172.16.0.0", "255.240.0.0") ||
        isInNet(host, "192.168.0.0", "255.255.0.0")) {
        return "DIRECT";
    }

    // --- Прямой IP в URL (не домен) → блокировать ---
    // Если кто-то обращается по IP напрямую (http://1.2.3.4/),
    // мы не можем определить страну — блокируем.
    // Локальные диапазоны уже пропущены выше.
    var ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    if (ipPattern.test(host)) {
        return "PROXY 127.0.0.1:1";
    }

    // --- Российские TLD ---
    if (dnsDomainIs(host, ".ru") ||
        dnsDomainIs(host, ".su") ||
        dnsDomainIs(host, ".рф")         || dnsDomainIs(host, ".xn--p1ai") ||
        dnsDomainIs(host, ".москва")     || dnsDomainIs(host, ".xn--80adxhks") ||
        dnsDomainIs(host, ".moscow") ||
        dnsDomainIs(host, ".рус")        || dnsDomainIs(host, ".xn--p1acf") ||
        dnsDomainIs(host, ".дети")       || dnsDomainIs(host, ".xn--d1acj3b") ||
        dnsDomainIs(host, ".tatar")) {
        return "DIRECT";
    }

    // --- Российские сервисы на нероссийских TLD ---
    // Добавляйте только домены, которыми реально пользуетесь.
    var ruDomains = [
        // Firefox — обновления и расширения
        "mozilla.org",
        "mozilla.net",
        "mozilla.com",
        // uBlock Origin — загрузка списков фильтров
        "raw.githubusercontent.com",
        "ublockorigin.pages.dev",
        "ublockorigin.github.io",
        "filters.adtidy.org",
        "easylist.to",
        "pgl.yoyo.org",
        "malware-filter.gitlab.io",
        "secure.fanboy.co.nz",
        // uBlock Origin — обновление фильтров
        "raw.githubusercontent.com",
        "ublockorigin.pages.dev",
        "ublockorigin.github.io",
        "easylist.to",
        "easylist-downloads.adblockplus.org",
        "filters.adtidy.org",
        // Банки
        "sberbank.com",
        "tinkoff.com",
        "alfabank.com",
        // Сервисы
        "yandex.com",
        "yandex.net",
        "yastatic.net",
        "mail.ru",
        "vk.com",
        "vk.me",
        "vkuserid.com",
        "userapi.com",
        "ok.ru",
        // Маркетплейсы
        "ozon.com",
        "wildberries.com",
        "wbbasket.ru"
    ];

    for (var i = 0; i < ruDomains.length; i++) {
        if (dnsDomainIs(host, ruDomains[i]) || host === ruDomains[i]) {
            return "DIRECT";
        }
    }

    // --- Всё остальное → заблокировать ---
    return "PROXY 127.0.0.1:1";
}
```

Подключить: Settings → General → **Proxy Settings** → Configure proxy… → **Automatic proxy configuration URL**:

```
file:///Users/ВАШ_ПОЛЬЗОВАТЕЛЬ/ru-whitelist.pac
```

Имя пользователя: `whoami` в Terminal. Нажать OK. Перезапустить Firefox.

---

## 4. Настройки Privacy

Settings (Cmd+,) → Privacy & Security:

- **Enhanced Tracking Protection** → Standard
- **HTTPS-Only Mode** → Enable in all windows
- **DNS over HTTPS** → Off

---

## 5. uBlock Origin

Домены `mozilla.org/net/com` уже добавлены в PAC-whitelist — без них Firefox не может ни устанавливать расширения, ни обновляться.

Установить: `addons.mozilla.org/firefox/addon/ublock-origin/` → Add to Firefox.

Dashboard → Filter lists → в разделе региональных фильтров включить все три:

- RU AdList
- RU AdList (с иконкой 👁)
- RU AdList: Counters

uBlock блокирует трекеры и рекламные скрипты, которые отправляют запросы к зарубежным серверам. PAC заблокирует соединение, uBlock не даст скрипту даже попытаться — два независимых барьера.

---

## 6. Блокировка на уровне IP (Little Snitch)

PAC работает по доменам. Если домен из whitelist резолвится на зарубежный IP — PAC его пропустит. Для полной гарантии «ни одного пакета за пределы РФ» нужна блокировка на уровне IP-адресов.

**Little Snitch** ($59, obdev.at/littlesnitch) — файрволл для macOS с фильтрацией по приложению и по стране. Firefox работает от обычного пользователя — уведомления, буфер обмена, Keychain, всё штатно.

### 6.1. Установить Little Snitch

Скачать с `obdev.at/littlesnitch` → установить → перезагрузить Mac (устанавливает сетевое расширение ядра). Есть бесплатный демо-режим (полная функциональность, сессии по 3 часа).

### 6.2. Сгенерировать и импортировать правила

Little Snitch не имеет встроенного фильтра по стране в правилах. Нужно загрузить российские IP-диапазоны как набор правил.

Скрипт скачивает актуальные российские IP из RIPE и создаёт `.lsrules`-файл:

```bash
bash ~/generate-ls-ru-rules.sh
```

Скрипт создаёт `~/firefox-ru-only.lsrules` с четырьмя правилами:
1. Firefox → Allow → все российские IP (тысячи CIDR-диапазонов)
2. Firefox → Allow → локальная сеть (127.0.0.0/8, 10.0.0.0/8 и т.д.)
3. Firefox → Allow → инфраструктура Mozilla и uBlock (домены обновлений)
4. Firefox → Deny → всё остальное

Импорт в Little Snitch:
1. Положить файл `~/firefox-ru-only.lsrules` на HTTPS-сервер (проще всего — secret gist на gist.github.com)
2. Скопировать raw URL гиста
3. В Little Snitch: Rule Groups → `+` → **Remote Rule Group…** → вставить raw URL
4. Снять галочку «Disable new allow rules»
5. Подтвердить

После импорта в правилах Firefox должно появиться четыре строки:
- allow ~34,7 million IP addresses (российские диапазоны)
- allow ~45,1 million IP addresses (локальные сети)
- allow 11 domains (инфраструктура Mozilla и uBlock)
- deny any outgoing connection

Обновлять раз в месяц: перегенерировать скриптом → обновить содержимое гиста → Little Snitch подхватит по расписанию (или правый клик по группе → Update Now).

### 6.3. Мониторинг

**В реальном времени:** Little Snitch Network Monitor (Cmd+Shift+M) → группировка по Country — сразу видно, куда идёт трафик Firefox. Заблокированные соединения подсвечиваются красным.

**Оповещения при изменении правил:** Little Snitch отслеживает изменения в правилах. Если кто-то или что-то изменит или удалит правила — вы увидите это в интерфейсе. Дополнительно: включите уведомления о заблокированных соединениях (Settings → Notifications), чтобы видеть попытки Firefox выйти за пределы РФ.

**Защита от модификации:** Little Snitch требует пароль администратора для изменения правил. Сетевое расширение ядра защищено SIP (System Integrity Protection) — удалить или подменить его без вашего ведома невозможно.

### 6.4. Скрипт контроля целостности правил (дополнительно)

Для автоматического мониторинга — скрипт, который проверяет контрольную сумму правил Little Snitch и уведомляет при изменении:

```bash
#!/bin/bash
# ~/check-ls-rules.sh
RULES_FILE="$HOME/Library/Group Containers/"*".com.obdev.littlesnitch"/rules.json
HASH_FILE="/tmp/.ls-rules-hash"

CURRENT_HASH=$(shasum -a 256 $RULES_FILE 2>/dev/null | awk '{print $1}')

if [ -f "$HASH_FILE" ]; then
    SAVED_HASH=$(cat "$HASH_FILE")
    if [ "$CURRENT_HASH" != "$SAVED_HASH" ]; then
        osascript -e 'display notification "Правила Little Snitch были изменены!" with title "⚠️ Безопасность"'
    fi
fi

echo "$CURRENT_HASH" > "$HASH_FILE"
```

Автоматизировать через launchd (проверка каждые 5 минут):

```bash
# Сделать скрипт исполняемым
chmod +x ~/check-ls-rules.sh

# Создать launchd-агент
cat > ~/Library/LaunchAgents/com.rufire.checkrules.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.rufire.checkrules</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>HOMEDIR/check-ls-rules.sh</string>
    </array>
    <key>StartInterval</key>
    <integer>300</integer>
</dict>
</plist>
EOF

# Заменить HOMEDIR на реальный путь
sed -i '' "s|HOMEDIR|$HOME|g" ~/Library/LaunchAgents/com.rufire.checkrules.plist

# Запустить
launchctl load ~/Library/LaunchAgents/com.rufire.checkrules.plist
```

---

### Альтернатива: pf-файрволл (бесплатно, но без уведомлений)

Если не хотите платить за Little Snitch — можно использовать встроенный pf. Ограничение: pf не умеет фильтровать по приложению, только по UID. Firefox нужно запускать от отдельного системного пользователя, из-за чего **не будут работать**: уведомления macOS, буфер обмена с основным пользователем, Keychain.

<details>
<summary>Инструкция по настройке pf (нажать, чтобы развернуть)</summary>

**Создать системного пользователя:**

```bash
sudo dscl . -create /Users/rufire
sudo dscl . -create /Users/rufire UserShell /usr/bin/false
sudo dscl . -create /Users/rufire RealName "RU Firefox"
sudo dscl . -create /Users/rufire UniqueID 599
sudo dscl . -create /Users/rufire PrimaryGroupID 20
sudo dscl . -create /Users/rufire NFSHomeDirectory /Users/rufire
sudo mkdir -p /Users/rufire
sudo chown rufire:staff /Users/rufire
sudo dscl . -create /Users/rufire IsHidden 1
```

**Скачать российские IP-диапазоны:**

```bash
curl -s "https://stat.ripe.net/data/country-resource-list/data.json?resource=RU&v4_format=prefix" \
  | python3 -c "
import sys, json
data = json.load(sys.stdin)
for prefix in data['data']['resources']['ipv4']:
    print(prefix)
" > /tmp/ru-nets.txt
sudo cp /tmp/ru-nets.txt /etc/pf.ru-nets
```

**Создать правила:**

```bash
sudo nano /etc/pf.anchors/rufire
```

```
table <ru_nets> persist file "/etc/pf.ru-nets"
table <local_nets> const { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 }
pass out quick proto { tcp udp } user rufire to <local_nets>
pass out quick proto { tcp udp } user rufire to <ru_nets>
block out log quick proto { tcp udp } user rufire
```

**Подключить и запустить:**

```bash
echo 'anchor "rufire"' | sudo tee -a /etc/pf.conf
echo 'load anchor "rufire" from "/etc/pf.anchors/rufire"' | sudo tee -a /etc/pf.conf
sudo pfctl -f /etc/pf.conf
sudo pfctl -e
```

**Ярлык запуска:**

```bash
sudo -u rufire /Applications/Firefox.app/Contents/MacOS/firefox -P "RU-only" -no-remote &
```

Для работы без пароля: `sudo visudo -f /etc/sudoers.d/rufire` → `ВАШ_ПОЛЬЗОВАТЕЛЬ ALL=(rufire) NOPASSWD: /Applications/Firefox.app/Contents/MacOS/firefox`

</details>

---

## Что НЕ делать

- **Не включать встроенный VPN Firefox** (появился в 149.0) — он подменяет IP через собственный прокси Mozilla, что конфликтует со split-tunneling и PAC. Если видите предложение включить — отказаться.
- **Не включать `privacy.resistFingerprinting`** — меняет таймзону на UTC. С российским IP это вызовет антифрод.
- **Не ставить Canvas Blocker, Chameleon, Trace** — делают браузер подозрительнее, а не безопаснее.
- **Не включать DoH (Max Protection)** — ломает split-DNS VPN-клиента.
- **Не использовать этот профиль для зарубежных сайтов.**
- **Не менять User-Agent** — кастомный UA = флаг для антифрода.
- **Не добавлять в PAC домены без необходимости** — каждый лишний домен расширяет поверхность утечки.

---
---

# Часть 2. Чек-лист проверки

Включить VPN. Открыть Firefox RU-only.

---

## Обязательные тесты

| # | Что проверяем | Куда идти | Ожидаемый результат | Если провален |
|---|---|---|---|---|
| 1 | Российский IP | `2ip.ru` | IP вашего российского провайдера | Split-tunneling VPN не работает. Чинить конфиг VPN-клиента. |
| 2 | Блокировка зарубежных сайтов | `google.com` | Ошибка «proxy server refused connection» | PAC не подключен или `failover_direct` = true. |
| 3 | WebRTC | Временно добавить `browserleaks.com` в PAC → открыть `browserleaks.com/webrtc` | «No Leak» / нет публичных IP | `media.peerconnection.enabled` не выключен. Перезапустить Firefox. |
| 4 | IPv6 | Временно добавить `ipv6-test.com` в PAC → открыть | «No IPv6 address detected» | `network.dns.disableIPv6` не выключен, либо IPv6 не отключён в VPN/системе. |
| 5 | DNS-утечка | Временно добавить `dnsleaktest.com` в PAC → Extended test | DNS-серверы российского провайдера или VPN | DoH включён в Firefox, либо `network.trr.mode` ≠ 5. |
| 6 | HTTP/3 | `about:networking` → HTTP → колонка «Protocol» | Нет записей с `h3` | `network.http.http3.enable` не выключен. |

**После тестов 3–5** — убрать тестовые домены из PAC и перезапустить Firefox.

---

## Проверка на реальном сайте

1. Открыть нужный сайт (банк, Госуслуги) в Firefox RU.
2. F12 → вкладка **Network** → обновить страницу (Cmd+R).
3. Смотреть колонку **Domain** — все запросы к нероссийским доменам должны быть красными (заблокированы PAC или uBlock).
4. Если запрос зелёный, но домен зарубежный — проверить, не добавлен ли он в PAC по ошибке. Если нет — значит домен соответствует TLD-правилу и нужно решить, оставить или убрать.
5. `about:networking` → HTTP — список всех установленных соединений и их IP-адресов.

---

## Проверка Little Snitch (если настроен шаг 6)

1. Открыть Little Snitch Network Monitor (Cmd+Shift+M).
2. Группировка по Country.
3. Открыть в Firefox RU любой российский сайт — в мониторе должна появиться только Россия (и Local Network).
4. Попробовать открыть `google.com` — PAC заблокирует на уровне домена. В Little Snitch будет видна попытка DNS-запроса.
5. Если в мониторе видны соединения с другими странами от Firefox — проверить правила, порядок, нет ли лишних Allow.

---

## После каждого обновления Firefox

Проверить что не сбросилось:

- `about:config` → `media.peerconnection.enabled` = false
- `about:config` → `network.http.http3.enable` = false
- `about:config` → `network.proxy.failover_direct` = false
- `about:config` → `network.dns.disableIPv6` = true
- `about:config` → `network.trr.mode` = 5
- `about:config` → `browser.ipProtection.enabled` = false
- Settings → Proxy Settings → PAC-файл на месте

Прогнать тесты 1–2 повторно.

---
---

# Часть 3. Зачем нужен каждый пункт

---

## about:config — подробно

### `media.peerconnection.enabled → false`

WebRTC — протокол для видеозвонков и P2P-соединений в браузере. JavaScript на странице может создать `RTCPeerConnection` и отправить STUN-запрос к зарубежному серверу. STUN-запрос идёт по UDP, **минуя PAC-файл и прокси-настройки Firefox**. Это единственный способ, которым код сайта может напрямую узнать IP-адрес в обход всех сетевых настроек браузера. Отключение WebRTC полностью устраняет этот вектор.

`media.peerconnection.ice.default_address_only → true` — дополнительная страховка: даже если WebRTC почему-то активируется, он не будет перебирать все сетевые интерфейсы.

### `network.http.http3.enable → false`

HTTP/3 (QUIC) работает поверх UDP на порту 443. VPN-клиенты обрабатывают TCP надёжно, но UDP-трафик могут пропустить или обработать некорректно — это зависит от реализации. Кроме того, QUIC использует заголовок `Alt-Svc` для переключения на альтернативный endpoint, который PAC может не проконтролировать. Отключение заставляет Firefox использовать только TCP (HTTP/1.1 и HTTP/2), где поведение предсказуемо.

`enable_0rtt` — быстрое возобновление TLS-сессий, потенциально используется для корреляции между визитами. Отключается заодно.

### `network.dns.disableIPv6 → true`

Если у провайдера есть IPv6, а VPN-клиент его не перехватывает, Firefox может отправить запрос по IPv6 напрямую, минуя VPN-туннель. pf-правила из шага 6 покрывают только IPv4. Отключение IPv6 на уровне Firefox устраняет весь класс IPv6-утечек.

### `browser.ipProtection.enabled → false`

В Firefox 149 появился встроенный бесплатный VPN (IP Protection), который маршрутизирует трафик через прокси-серверы Mozilla. Он конфликтует со всей схемой: подменяет IP-адрес на выходе, обходит split-tunneling внешнего VPN-клиента и может перехватить управление трафиком у PAC-файла. Должен быть явно выключен.

### `network.trr.mode → 5`

Trusted Recursive Resolver (DoH в Firefox). Значение 5 — полностью выключен. DNS-запросы идут через системный резолвер, который контролируется VPN-клиентом через split-DNS. Если оставить DoH включённым, Firefox будет слать DNS-запросы к Cloudflare или Google в обход VPN-логики, и VPN-клиент не сможет разделить трафик по доменам.

### `network.prefetch-next → false`

Firefox предзагружает страницы, на которые пользователь может перейти (на основе `<link rel="prefetch">`). Если на российском сайте есть ссылка на зарубежный ресурс, Firefox может начать загрузку ещё до клика. Это преждевременный запрос к зарубежному серверу.

### `network.dns.disablePrefetch → true` и `network.dns.disablePrefetchFromHTTPS → true`

Firefox предзагружает DNS-записи для ссылок на странице. Первый параметр отключает это для HTTP-страниц, второй — для HTTPS. Поскольку практически все сайты сейчас работают по HTTPS, без второго параметра первый бесполезен. Даже если запрос потом заблокирует PAC, DNS-запрос уже может утечь через системный резолвер к зарубежному DNS-серверу (если VPN не контролирует все DNS-запросы).

### `network.predictor.enabled → false`

Предиктор Firefox анализирует поведение пользователя и заранее устанавливает TCP-соединения с серверами, на которые пользователь предположительно перейдёт. Это может инициировать соединение с зарубежным сервером до того, как PAC его заблокирует.

### `network.http.speculative-parallel-limit → 0`

Отдельный от предиктора механизм: Firefox открывает спекулятивные TCP-соединения при наведении курсора на ссылку. При нуле — ни одного упреждающего соединения. Это дополняет отключение предиктора.

### `network.proxy.failover_direct → false`

**Критически важный параметр.** По умолчанию Firefox, получив от PAC указание `PROXY 127.0.0.1:1` и не сумев подключиться к этому прокси, может откатиться на DIRECT-соединение — то есть отправить запрос напрямую. Это полностью обходит всю защиту PAC. При `false` Firefox покажет ошибку соединения и не будет пытаться обойти прокси.

---

## PAC-файл — подробно

### Принцип работы

PAC (Proxy Auto-Configuration) — встроенный механизм Firefox. Перед каждым сетевым запросом Firefox вызывает функцию `FindProxyForURL(url, host)`. Функция возвращает одно из:

- `"DIRECT"` — соединяться напрямую
- `"PROXY host:port"` — идти через прокси

Возврат `"PROXY 127.0.0.1:1"` отправляет запрос на несуществующий прокси на localhost:1. Соединение не устанавливается, данные не передаются, удалённый сервер ничего не получает. При `failover_direct = false` Firefox не пытается обойти этот отказ.

PAC вызывается на уровне сетевого стека — до TCP-handshake, до TLS, до отправки HTTP-заголовков. Это не фильтрация «после факта», а превентивная блокировка.

### Что PAC блокирует

Типичный сценарий: вы на `sberbank.ru`, код страницы вызывает `fetch("https://api.google-analytics.com/collect")`. Без PAC — Firefox идёт к Google Analytics через VPN, Google получает VPN-IP. С PAC — `google-analytics.com` не в whitelist, запрос заблокирован, утечки нет.

Аналогично блокируются: Google Fonts, Facebook Pixel, Cloudflare Analytics, любые зарубежные CDN, рекламные сети, антифрод-скрипты, обращающиеся к зарубежным серверам.

### Почему mozilla.org и CDN-домены uBlock в whitelist

Firefox не может обновляться и устанавливать расширения без доступа к `addons.mozilla.org`, `aus5.mozilla.org` и другим поддоменам Mozilla. uBlock Origin скачивает фильтр-листы с `raw.githubusercontent.com`, `ublockorigin.pages.dev`, `easylist.to`, `filters.adtidy.org`. Без этих доменов фильтры устаревают и перестают блокировать трекеры — а это один из слоёв защиты. Все эти домены — инфраструктура браузера и расширения, не сторонние трекеры. Они видят VPN-IP, но это контролируемый компромисс: без них защита ослабнет сильнее, чем от самой утечки.

### Что PAC НЕ блокирует

1. **WebRTC.** STUN-запросы идут по UDP через собственную сетевую логику, минуя прокси-механизм. Именно поэтому WebRTC отключается отдельно.

2. **Разрешённые домены с зарубежными IP.** Если `yandex.com` в whitelist, а поддомен резолвится на IP за пределами РФ — PAC пропустит, потому что проверяет домен, а не IP. Для этого нужен Little Snitch (шаг 6).

3. **QUIC (HTTP/3).** Может использовать `Alt-Svc` для переключения на альтернативный endpoint. Отключается в about:config.

4. **Прямые IP-адреса в URL.** Обработаны в улучшенном PAC: все нелокальные IP-адреса блокируются.

### Почему не IP-фильтрация в PAC

PAC поддерживает `dnsResolve(host)` и `isInNet()`, но использование их для проверки каждого запроса по российским IP-диапазонам (тысячи префиксов) превратит PAC в тормоз — `dnsResolve` синхронный и блокирует рендеринг страницы. Доменная фильтрация мгновенна. Для IP-уровня используется Little Snitch.

---

## uBlock Origin — подробно

PAC блокирует соединение, но скрипт на странице уже выполнился и попытался сделать запрос. uBlock работает раньше — он блокирует загрузку самого скрипта (или изображения, или iframe), который мог бы инициировать запрос. Два барьера дополняют друг друга:

- uBlock не даёт загрузить скрипт трекера → скрипт не выполняется → запрос не создаётся
- PAC блокирует запрос на сетевом уровне → даже если скрипт проскочил мимо uBlock, соединение не установится

Русские списки фильтров (RU AdList, AdGuard Russian) содержат правила для российских рекламных сетей и трекеров, которые часто используют зарубежные серверы.

---

## Блокировка на уровне IP — подробно

### Зачем нужен IP-уровень

PAC + about:config + uBlock закрывают 95%+ реальных утечек. Оставшиеся 5% — это:

- Whitelisted домен (например, `yandex.net`) резолвится на CDN-сервер за пределами РФ
- Непредвиденный механизм в Firefox, который обходит PAC (теоретически — баг браузера)
- Расширение Firefox, отправляющее запросы в обход прокси-настроек

### Почему Little Snitch

Little Snitch — файрволл уровня приложения для macOS. Работает через сетевое расширение ядра (Network Extension), перехватывая каждое сетевое соединение до отправки пакета. Ключевые преимущества для этой задачи:

- **Фильтрация по приложению** — правила применяются только к Firefox, остальные приложения не затронуты.
- **Фильтрация по стране** — через импорт российских IP-диапазонов из RIPE в формате `.lsrules`. Скрипт генерации автоматизирует процесс.
- **Firefox работает как обычно** — от вашего пользователя, с уведомлениями, буфером обмена, Keychain.
- **Мониторинг** — Network Monitor показывает все соединения в реальном времени с группировкой по стране. Заблокированные подсвечены красным.
- **Защита правил** — изменение требует пароль администратора, расширение защищено SIP.
- **GeoIP-база обновляется скриптом** — `bash ~/generate-ls-ru-rules.sh` раз в месяц.

### Как работают правила

Little Snitch применяет правила от частного к общему. Порядок для Firefox:

1. Allow → Local Network (localhost, 10.x, 192.168.x)
2. Allow → российские IP-диапазоны (из RIPE, CIDR-формат)
3. Allow → конкретные домены инфраструктуры (mozilla.org, хосты фильтров uBlock)
4. Deny → Any

Когда Firefox пытается установить соединение, Little Snitch проверяет destination IP по списку российских CIDR-диапазонов. Если IP не российский и домен не в исключениях — блокирует пакет. Это происходит до TCP-handshake.

### Альтернатива: pf

Бесплатная альтернатива — встроенный pf (packet filter). Работает на уровне ядра, фильтрует по IP. Но pf не умеет фильтровать по приложению, только по UID — Firefox нужно запускать от отдельного системного пользователя, что ломает уведомления, буфер обмена и Keychain. Инструкция в шаге 6 (свёрнутый блок).

---

## Итог: слои защиты

| Слой | Что блокирует | Уровень |
|---|---|---|
| **VPN split-tunneling** | Маршрутизирует RU-трафик напрямую | Сеть (основа всего) |
| **PAC-файл** | Запросы к нероссийским доменам | Firefox, до TCP-соединения |
| **`failover_direct = false`** | Откат на прямое соединение при отказе прокси | Firefox |
| **WebRTC off** | STUN-запросы по UDP в обход PAC | Firefox |
| **HTTP/3 off** | UDP-соединения, Alt-Svc endpoint'ы | Firefox |
| **IPv6 off** | IPv6-утечки в обход VPN-туннеля | Firefox |
| **DoH off** | DNS-запросы в обход VPN | Firefox |
| **Prefetch/predictor off** | Упреждающие запросы к зарубежным серверам | Firefox |
| **uBlock Origin** | Загрузка трекеров и рекламных скриптов | Firefox, до выполнения JS |
| **Little Snitch** | Любые пакеты к IP за пределами РФ | Сетевое расширение ядра macOS |

Каждый слой закрывает то, что пропускают другие. PAC + about:config + uBlock — надёжный минимум. Little Snitch — гарантия на случай непредвиденного, с мониторингом и уведомлениями.
