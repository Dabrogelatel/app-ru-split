# App RU split — раздельное туннелирование VPN по странам на macOS

Набор правил [Little Snitch](https://www.obdev.at/products/littlesnitch/) (`.lsrules`) и PAC-файла для Firefox, который разделяет сетевой трафик приложений macOS по географии назначения. Цель — **не давать VPN-IP засветиться на российских ресурсах** и одновременно **не выпускать браузер с российским IP за пределы РФ**.

> **Ключевые слова:** VPN split-tunneling macOS · раздельное туннелирование по странам · Little Snitch правила Россия · Firefox только РФ · anti-detect для VPN · утечка VPN-IP · geoip RU для macOS · PAC-файл для Firefox · `.lsrules` Russia bypass · блокировка российских IP в Safari · split по GeoIP · Firefox RU-only профиль · Xray/Happ/v2ray split-tunnel macOS.

---

## Кому это нужно

Типовой сценарий — пользователь живёт в России и использует VPN (Xray, V2Ray, Hiddify, Happ Plus, WireGuard, OpenVPN) для доступа к заблокированным ресурсам. Возникает два противоположных риска:

1. **Утечка VPN-IP на российский сайт.** Вы зашли в Госуслуги / банк / маркетплейс с иностранного IP → триггер «подозрительный вход», блокировка аккаунта, SMS-код, вопросы службе безопасности.
2. **Российский IP уходит на зарубежный ресурс.** Когда сайт отдаёт рекламу, аналитику, шрифты, антифрод-скрипты через зарубежные CDN, эти хвосты идут с вашего российского IP, пока VPN неактивен или настроен на bypass.

Эти правила решают обе задачи **на уровне приложений**, параллельно с VPN-клиентом:

| Приложение | Разрешённые назначения |
|---|---|
| Firefox | Только российские IP + инфраструктура обновлений (Mozilla, uBlock-источники). |
| Диск-О (Mail.ru Cloud) | Только российские IP. |
| Safari | Всё, **кроме** российских IP (всегда через VPN). |
| Chrome | Всё, **кроме** российских IP (всегда через VPN). |

> **Локальная сеть (loopback / RFC1918) специально НЕ включена** — security-by-default.
> Если действительно нужен доступ к `localhost:PORT` (dev-сервер, Native Messaging),
> к роутеру (`192.168.1.1`), NAS или принтеру в LAN — добавь private rule в Little
> Snitch вручную (`Rules → + → New Rule…` → action=allow, process=Firefox/DiskO,
> remote-addresses=127.0.0.0/8 или нужный диапазон). Подписка эти ручные правила
> не перетирает. Подробности — секция «Локальная сеть» ниже.

Защита — двухслойная. Little Snitch фильтрует на уровне IP-пакетов (использует базу российских CIDR-диапазонов). Firefox дополнительно имеет PAC-файл, который режет по TLD и домену ещё до резолвинга. Если какой-то слой пропустит — второй подстрахует.

---

## Как это работает в связке с VPN-клиентом

Правила сами по себе VPN-туннель **не обходят** — они только говорят «можно/нельзя». Чтобы российский трафик Firefox реально шёл напрямую (а не через VPN-сервер, который обычно блокирует исходящие на РФ для анти-детекта), нужно одновременно настроить **split-tunneling в самом VPN-клиенте**:

- **Happ Plus / Hiddify / V2Box / Streisand / FoXray** — routing rules: `geoip:ru` → outbound `direct`.
- **Xray/V2Ray (runtime-конфиг):** `routing.rules = [{ "outboundTag":"direct", "ip":["geoip:ru"] }]` + `domainStrategy:"IPIfNonMatch"`.
- **WireGuard:** исключить RU-CIDR из `AllowedIPs` (либо использовать `PostUp`-скрипты с `route`/`pf`).

Иначе `DIRECT` в PAC означает «без HTTP-прокси», но пакет всё равно уйдёт в `utun0` → к VPN-серверу → получит блок → в Firefox `PR_END_OF_FILE_ERROR`.

Подробная пошаговая инструкция (Firefox-профиль, `about:config`, установка PAC, установка `.lsrules`, проверка утечек): [firefox-ru-only.md](firefox-ru-only.md).

---

## Что лежит в репозитории

| Файл | Назначение |
|---|---|
| [firefox-ru-only.md](firefox-ru-only.md) | Пошаговая инструкция: Firefox-профиль, `about:config` (13 параметров против утечек WebRTC/DoH/QUIC), PAC, Little Snitch, проверка. |
| [generate-ls-ru-rules.sh](generate-ls-ru-rules.sh) | Bash-скрипт: из `merged-ru-cidrs-*.txt` генерирует `ru-only.lsrules` + `no-ru.lsrules`. |
| [ru-only.lsrules](ru-only.lsrules) | Little Snitch Rule Group: Firefox + Диск-О ⇒ только РФ + инфраструктура Firefox/uBlock (локалка/loopback не включены — добавь private-rule вручную если нужно). |
| [no-ru.lsrules](no-ru.lsrules) | Little Snitch Rule Group: Safari + Chrome ⇒ заблокированы российские IP. |
| [ru-whitelist.pac.example](ru-whitelist.pac.example) | Шаблон PAC для Firefox. Российские TLD + явный список RU-доменов на нероссийских TLD (vk.com, timeweb.cloud, mozilla.org и т.п.) → `DIRECT`; всё остальное → блокировка через `PROXY 127.0.0.1:1`. |

Приватная копия `ru-whitelist.pac` (с персональными доменами) и промежуточные `merged-ru-cidrs-*.txt` не коммитятся — см. `.gitignore`.

---

## Установка в Little Snitch (подписка на правила)

Little Snitch → **Rules → + → Subscribe to Rule Group…** — вставить raw-URL:

```
https://raw.githubusercontent.com/Dabrogelatel/app-ru-split/main/ru-only.lsrules
https://raw.githubusercontent.com/Dabrogelatel/app-ru-split/main/no-ru.lsrules
```

**Важно:** снять галочку **Disable new allow rules**, иначе свежеприлетевшие allow-правила окажутся выключенными.

Little Snitch сам периодически подтягивает обновления — как только в репозиторий приедет новый коммит со свежим CIDR-списком, правила у подписчиков обновятся автоматически.

---

## Установка PAC в Firefox

Файл `ru-whitelist.pac` (скопировать из `.example` и дополнить своими доменами):

**Firefox → Settings → Network Settings → Settings…** → **Automatic proxy configuration URL** → указать `file:///полный/путь/к/ru-whitelist.pac`.

Логика PAC:
1. Локальные адреса (`127.0.0.0/8`, `10/8`, `172.16/12`, `192.168/16`) → `DIRECT`.
2. Прямой IPv4 в URL (без домена) → блокировка (нельзя определить страну).
3. Российские TLD (`.ru`, `.su`, `.рф`, `.москва`, `.moscow`, `.рус`, `.дети`, `.tatar`) → `DIRECT`.
4. Список RU-сервисов на нероссийских TLD (`vk.com`, `timeweb.cloud`, `mozilla.org` и т.д.) → `DIRECT`.
5. Всё остальное → `PROXY 127.0.0.1:1` (несуществующий порт = блокировка до установки соединения).

Свои домены добавляйте в локальный `ru-whitelist.pac` (не в `.example`) — локальная копия в `.gitignore`, ваши персональные домены не уйдут в публичный репозиторий.

---

## Локальная сеть (loopback / LAN) — почему не включена и как добавить

Подписка `ru-only.lsrules` **не разрешает** RU-only приложениям ходить в локальные диапазоны `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`. Это сделано осознанно — security-by-default:

- **Расширения через Native Messaging.** Многие browser-расширения общаются с локальными host-приложениями (KeePassXC, 1Password, Plex и т.п.) через WebSocket на `127.0.0.1`. Если расширение скомпрометировано — оно может отправить данные локальному прокси / трояну с C2 на loopback.
- **Локальные прокси.** Если на машине стоит прокси (`mitmproxy`, корпоративный proxy, etc.), Firefox с открытым доступом к loopback может туда попасть и непреднамеренно отдать туда трафик. С правилом «нет local-net» — не попадёт даже если PAC будет криво настроен.
- **CSRF в LAN.** Открытое разрешение `192.168.0.0/16` позволяет любой странице JS-кодом стучаться в админку роутера / NAS / IoT (даже без явного обращения пользователя). С правилом «нет LAN» — не достучится.

**Если действительно нужен localhost / LAN** (запускаешь dev-сервер на `localhost:3000`, ходишь в роутер через `192.168.1.1`, и т.п.) — добавь private rule в Little Snitch:

1. Little Snitch → **Rules → + → New Rule…**
2. Action: **Allow**, Direction: **Outgoing**
3. Process: путь к Firefox / Disk-O / другому приложению
4. Remote: **Address Range** → ввести нужный диапазон (`127.0.0.0/8` или `192.168.1.0/24`, etc.)
5. Save

Private-правила хранятся **отдельно** от подписки и не перетираются при автообновлении. Можешь сделать их прицельными (например, разрешить Firefox только `127.0.0.1:3000` для dev-сервера, не весь `127/8`).

---

## FAQ

**В Firefox ошибка `PR_END_OF_FILE_ERROR` на российском сайте.**
Скорее всего на клиенте VPN нет split-tunneling для `geoip:ru`. Весь трафик уходит в туннель, VPN-сервер блокирует исходящие на РФ (анти-детект) — Firefox видит обрыв TLS. Настройте в VPN-клиенте bypass для `geoip:ru` → `direct`. См. раздел «Как это работает в связке с VPN-клиентом».

**Safari/Chrome не открывают российский сайт, хотя VPN работает.**
Это нормально и запланировано: в `no-ru.lsrules` для них прописан deny на RU-CIDR. Российские сайты открывайте в Firefox (у которого правила наоборот: только РФ).

**Мой домен на не-`.ru` TLD с российским IP заблокирован.**
Если IP домена в RU-CIDR — Little Snitch его пропустит. Если нет (например, хостится на зарубежном VPS, но это российский сервис) — добавьте его в локальный `ru-whitelist.pac` (PAC проверяет по домену) и в локальную Rule Group Little Snitch (allow `remote-domain`).

**Зачем блокировать прямые IP в URL?**
Если кто-то обращается по `http://1.2.3.4/`, PAC не может определить страну — блокируем. Редкий кейс, обычно это трекеры/рекламные пиксели.

---

## Лицензия и поддержка

Правила и скрипт — [MIT](https://opensource.org/licenses/MIT). Issues и PR приветствуются.
