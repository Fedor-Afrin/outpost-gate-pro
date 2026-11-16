"""
Консоль: цвета (как в Ubuntu) и язык подсказок Linux-синтаксиса (en / ru / he).

Цвета — только в живой сессии с терминалом: Ansible, скрипты и ssh host "команда" получают чистый текст.
Язык: по умолчанию английский; sl1 / sl2 / sl3 (или sl en|ru|he) — переключить, выбор запоминается.
Сообщения пишутся по-английски; перевод — по шаблонам ({…} — подставляемые части).
"""
from __future__ import annotations

import re

LANGS = {"1": "en", "2": "ru", "3": "he", "en": "en", "ru": "ru", "he": "he", "eng": "en", "english": "en",
         "rus": "ru", "russian": "ru", "heb": "he", "hebrew": "he", "iw": "he"}
LANG_NAMES = {"en": "English", "ru": "Русский", "he": "עברית"}

# --- цвета ---------------------------------------------------------------------------------------------
RESET = "\x1b[0m"
STYLES = {"bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33", "blue": "34", "magenta": "35",
          "cyan": "36", "bgreen": "1;32", "bblue": "1;34", "bred": "1;31", "byellow": "1;33", "bcyan": "1;36"}
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def paint(on: bool, text: str, *styles: str) -> str:
    if not on or not styles or not text:
        return text
    return "\x1b[" + ";".join(STYLES[s] for s in styles) + "m" + text + RESET


def plain_len(s: str) -> int:
    return len(ANSI_RE.sub("", s))


def ljust(s: str, width: int) -> str:
    return s + " " * max(0, width - plain_len(s))


def prompt(on: bool, user: str, host: str) -> str:
    """Как в Ubuntu: зелёный user@host, синий путь."""
    if not on:
        return f"{user}@{host}:~$ "
    return f"\x1b[01;32m{user}@{host}\x1b[00m:\x1b[01;34m~\x1b[00m$ "


# --- переводы --------------------------------------------------------------------------------------------
# английский текст (шаблон) -> (русский, иврит)
CATALOG: dict[str, tuple[str, str]] = {
    "invalid argument: {a}": ("недопустимый аргумент: {a}", "ארגומנט לא חוקי: {a}"),
    "{cmd}: program not found": ("{cmd}: нет программы", "{cmd}: התוכנית לא נמצאה"),
    "{cmd}: no answer in 15 s": ("{cmd}: нет ответа за 15 с", "{cmd}: אין תשובה תוך 15 שניות"),
    "{cmd}: exit code {code}": ("{cmd}: код {code}", "{cmd}: קוד יציאה {code}"),
    "quotes: {e}": ("кавычки: {e}", "מירכאות: {e}"),
    "{cmd}: command not supported. help — list, /… — RouterOS command, /system shell — real bash":
        ("{cmd}: команда не поддерживается. help — список, /… — команда RouterOS, /system shell — настоящий bash",
         "{cmd}: הפקודה לא נתמכת. help — רשימה, /… — פקודת RouterOS, /system shell — bash אמיתי"),
    "the router name is changed like this: /system identity set name=office":
        ("имя роутера меняется так: /system identity set name=office",
         "שם הנתב משתנה כך: /system identity set name=office"),
    "ip: option {o} is not supported (allowed: {allowed})":
        ("ip: ключ {o} не поддерживается (можно: {allowed})", "ip: האפשרות {o} לא נתמכת (מותר: {allowed})"),
    "ip: specify an object — address, route, link, neigh, rule":
        ("ip: укажите объект — address, route, link, neigh, rule", "ip: ציין אובייקט — address, route, link, neigh, rule"),
    "ip {o}: object not supported (address, route, link, neigh, rule)":
        ("ip {o}: объект не поддерживается (address, route, link, neigh, rule)",
         "ip {o}: האובייקט לא נתמך (address, route, link, neigh, rule)"),
    "ip {obj} {verb}: not supported. {hint}": ("ip {obj} {verb}: так не умею. {hint}", "ip {obj} {verb}: לא נתמך. {hint}"),
    "interfaces: /interface print; ports in segments — nmcli c mod; disable a segment — nmcli c down lan2":
        ("интерфейсы: /interface print; порты в сегментах — nmcli c mod; выключить сегмент — nmcli c down lan2",
         "ממשקים: /interface print; פורטים במקטעים — nmcli c mod; כיבוי מקטע — nmcli c down lan2"),
    "the ARP table is view-only: ip neigh": ("ARP-таблица только для просмотра: ip neigh", "טבלת ARP לצפייה בלבד: ip neigh"),
    "the router manages routing rules itself (two WANs, VPN)":
        ("правила маршрутизации роутер ведёт сам (два WAN, VPN)", "הנתב מנהל את כללי הניתוב בעצמו (שני WAN, VPN)"),
    "a value is required after {w}": ("после {w} нужно значение", "נדרש ערך אחרי {w}"),
    "unexpected parameter: {w}": ("непонятный параметр: {w}", "פרמטר לא צפוי: {w}"),
    "specify a mask: 10.10.0.1/24": ("укажите маску: 10.10.0.1/24", "ציין מסכה: 10.10.0.1/24"),
    "{addr} dev {dev} — added to the configuration (like /ip address add)":
        ("{addr} dev {dev} — добавлен в конфигурацию (как /ip address add)",
         "{addr} dev {dev} — נוסף לתצורה (כמו /ip address add)"),
    "no address {addr}": ("адреса {addr} нет", "אין כתובת {addr}"),
    "{addr} comes from a segment, WAN or VPN setting, not from ip/RouterOS — change it there: "
    "nmcli c mod lan1 ipv4.addresses …, nmcli c mod wan …":
        ("{addr} задан не командой ip/RouterOS, а настройкой сегмента, WAN или VPN — меняйте там: "
         "nmcli c mod lan1 ipv4.addresses …, nmcli c mod wan …",
         "{addr} מוגדר בהגדרות מקטע, WAN או VPN ולא בפקודת ip/RouterOS — שנה שם: "
         "nmcli c mod lan1 ipv4.addresses …, nmcli c mod wan …"),
    "{addr} — removed from the configuration": ("{addr} — удалён из конфигурации", "{addr} — הוסר מהתצורה"),
    "invalid network: {net}": ("неверная сеть: {net}", "רשת לא חוקית: {net}"),
    "metric must be a number": ("metric — число", "metric חייב להיות מספר"),
    "{dst} via {gw} — added to the configuration (like /ip route add)":
        ("{dst} via {gw} — добавлен в конфигурацию (как /ip route add)", "{dst} via {gw} — נוסף לתצורה (כמו /ip route add)"),
    "route {dst} is not in the configuration": ("маршрута {dst} нет в конфигурации", "הנתיב {dst} לא בתצורה"),
    "route {dst} is not in the configuration — it is dynamic (WAN, VPN, OSPF, GRE)":
        ("маршрута {dst} нет в конфигурации — он динамический (WAN, VPN, OSPF, GRE)",
         "הנתיב {dst} לא בתצורה — הוא דינמי (WAN, VPN, OSPF, GRE)"),
    "{dst} — removed from the configuration": ("{dst} — удалён из конфигурации", "{dst} — הוסר מהתצורה"),
    "bridge: view only — bridge link | bridge fdb | bridge vlan":
        ("bridge: только просмотр — bridge link | bridge fdb | bridge vlan", "bridge: צפייה בלבד — bridge link | bridge fdb | bridge vlan"),
    "ss: allowed options -t -u -l -n -p -a -s -4 -6 and filters":
        ("ss: можно ключи -t -u -l -n -p -a -s -4 -6 и фильтры", "ss: מותרות האפשרויות -t -u -l -n -p -a -s -4 -6 ומסננים"),
    "option {a} is not supported (allowed: {allowed})": ("ключ {a} не поддерживается (можно: {allowed})",
                                                         "האפשרות {a} לא נתמכת (מותר: {allowed})"),
    "extra argument: {a}": ("лишний аргумент: {a}", "ארגומנט מיותר: {a}"),
    "specify an address": ("укажите адрес", "ציין כתובת"),
    "-i: at least 0.2 s": ("-i: не меньше 0.2 с", "-i: לפחות 0.2 שניות"),
    "Error: unknown connection '{name}'. List: nmcli c": ("Error: нет соединения '{name}'. Список: nmcli c",
                                                           "Error: אין חיבור '{name}'. רשימה: nmcli c"),
    "nmcli device: view only (status). Ports — nmcli c mod / LAN in the web UI":
        ("nmcli device: только просмотр (status). Порты — nmcli c mod / LAN в вебе",
         "nmcli device: צפייה בלבד (status). פורטים — nmcli c mod / LAN בממשק הווב"),
    "nmcli connection: show | modify | up | down (add/delete — LAN segments in the web UI or /lan)":
        ("nmcli connection: show | modify | up | down (add/delete — сегменты LAN в вебе или /lan)",
         "nmcli connection: show | modify | up | down (add/delete — מקטעי LAN בממשק הווב או /lan)"),
    "nmcli: general | device | connection": ("nmcli: general | device | connection", "nmcli: general | device | connection"),
    "nmcli c {verb} NAME": ("nmcli c {verb} ИМЯ", "nmcli c {verb} שם"),
    "nmcli c mod NAME property value [property value …]": ("nmcli c mod ИМЯ свойство значение [свойство значение …]",
                                                             "nmcli c mod שם מאפיין ערך [מאפיין ערך …]"),
    "ipv4.method: auto | manual | disabled": ("ipv4.method: auto | manual | disabled", "ipv4.method: auto | manual | disabled"),
    "{k}: for WAN use ipv4.method, ipv4.addresses, ipv4.gateway, ipv4.dns":
        ("{k}: для WAN можно ipv4.method, ipv4.addresses, ipv4.gateway, ipv4.dns",
         "{k}: עבור WAN אפשר ipv4.method, ipv4.addresses, ipv4.gateway, ipv4.dns"),
    "ipv4.method for a segment: shared (hand out addresses via DHCP) | manual (no DHCP)":
        ("ipv4.method для сегмента: shared (раздавать адреса по DHCP) | manual (без DHCP)",
         "ipv4.method למקטע: shared (חלוקת כתובות ב-DHCP) | manual (בלי DHCP)"),
    "{k}: for a segment use ipv4.addresses, ipv4.method, ipv4.dns-search, connection.autoconnect":
        ("{k}: для сегмента можно ipv4.addresses, ipv4.method, ipv4.dns-search, connection.autoconnect",
         "{k}: למקטע אפשר ipv4.addresses, ipv4.method, ipv4.dns-search, connection.autoconnect"),
    "{k}: for GRE use ip-tunnel.remote|local|parent|mtu, ipv4.addresses, ipv4.routes":
        ("{k}: для GRE можно ip-tunnel.remote|local|parent|mtu, ipv4.addresses, ipv4.routes",
         "{k}: עבור GRE אפשר ip-tunnel.remote|local|parent|mtu, ipv4.addresses, ipv4.routes"),
    "VPN is configured in the web UI (VPN → import config) or /interface wireguard; here — nmcli c up|down":
        ("VPN настраивается в вебе (VPN → импорт конфига) или /interface wireguard; здесь — nmcli c up|down",
         "VPN מוגדר בממשק הווב (VPN → ייבוא תצורה) או /interface wireguard; כאן — nmcli c up|down"),
    "the main WAN can't be turned off — you would lose access to the router. Mode: nmcli c mod wan ipv4.method disabled":
        ("основной WAN не выключается — иначе пропадёт доступ к роутеру. Режим: nmcli c mod wan ipv4.method disabled",
         "את ה-WAN הראשי אי אפשר לכבות — תאבד גישה לנתב. מצב: nmcli c mod wan ipv4.method disabled"),
    "Connection '{name}' successfully updated.": ("Соединение '{name}' обновлено.", "החיבור '{name}' עודכן בהצלחה."),
    "Connection '{name}' successfully activated.": ("Соединение '{name}' включено.", "החיבור '{name}' הופעל בהצלחה."),
    "Connection '{name}' successfully deactivated.": ("Соединение '{name}' выключено.", "החיבור '{name}' כובה בהצלחה."),
    "Language: {name}. Switch: sl1 English · sl2 Русский · sl3 עברית":
        ("Язык: {name}. Переключить: sl1 English · sl2 Русский · sl3 עברית",
         "שפה: {name}. החלפה: sl1 English · sl2 Русский · sl3 עברית"),
    "sl: language en, ru or he (sl1, sl2, sl3)": ("sl: язык en, ru или he (sl1, sl2, sl3)", "sl: שפה en, ru או he (sl1, sl2, sl3)"),
}

_COMPILED: list[tuple[re.Pattern, str, tuple[str, str]]] = []


def _compile() -> None:
    for en, tr in CATALOG.items():
        names = re.findall(r"\{(\w+)\}", en)
        pat = re.escape(en)
        for n in names:
            pat = pat.replace(re.escape("{" + n + "}"), f"(?P<{n}>.*?)", 1)
        _COMPILED.append((re.compile("^" + pat + "$", re.S), en, tr))


def T(lang: str, en: str, **kw) -> str:
    """Шаблон -> текст на языке lang."""
    tpl = en
    if lang in ("ru", "he") and en in CATALOG:
        tpl = CATALOG[en][0 if lang == "ru" else 1]
    return tpl.format(**kw) if kw else tpl


def tr(lang: str, text: str) -> str:
    """Готовый английский текст (например, из CliError) -> на язык lang, по шаблонам каталога."""
    if lang not in ("ru", "he") or not text:
        return text
    if not _COMPILED:
        _compile()
    for pat, en, (ru, he) in _COMPILED:
        m = pat.match(text)
        if m:
            return (ru if lang == "ru" else he).format(**m.groupdict())
    return text


HELP = {
    "en": [("Switch language", "sl1 English · sl2 Русский · sl3 עברית   (sl — current)"),
           ("View (real utilities)", None),
           ("ip a | ip -br a | ip addr show dev br-lan", "addresses"),
           ("ip r | ip route get 8.8.8.8", "routes"),
           ("ip link | ip -s link | ip neigh | ip rule", "interfaces, ARP, rules"),
           ("bridge link | bridge vlan", "bridges and VLANs"),
           ("ss -tlnp | ss -ulnp", "who listens on which port"),
           ("ping -c 3 samba | traceroute 8.8.8.8", "connectivity (names via the router's DNS)"),
           ("Changes (saved to the router configuration)", None),
           ("ip addr add 10.10.0.1/24 dev br-lan", "address (like /ip address add)"),
           ("ip route add 192.168.20.0/24 via 172.16.0.2", "route (like /ip route add)"),
           ("ip route del 192.168.20.0/24", "remove a route"),
           ("nmcli | nmcli d | nmcli c | nmcli c show lan1", "devices and connections (WAN, LAN, VPN, GRE)"),
           ("nmcli c mod wan ipv4.method manual ipv4.addresses 203.0.113.10/24 ipv4.gateway 203.0.113.1", "static WAN"),
           ("nmcli c mod lan1 ipv4.addresses 192.168.1.1/24", "LAN address"),
           ("nmcli c up amneziawg | nmcli c down lan2", "turn on / off"),
           ("Other", None),
           ("/…", "a RouterOS command (e.g. /ip firewall nat print)"),
           ("routeros", "switch to MikroTik syntax"),
           ("exit", "log out")],
    "ru": [("Переключить язык", "sl1 English · sl2 Русский · sl3 עברית   (sl — текущий)"),
           ("Просмотр (настоящими утилитами)", None),
           ("ip a | ip -br a | ip addr show dev br-lan", "адреса"),
           ("ip r | ip route get 8.8.8.8", "маршруты"),
           ("ip link | ip -s link | ip neigh | ip rule", "интерфейсы, ARP, правила"),
           ("bridge link | bridge vlan", "мосты и VLAN"),
           ("ss -tlnp | ss -ulnp", "кто слушает порты"),
           ("ping -c 3 samba | traceroute 8.8.8.8", "проверка связи (имена — через DNS роутера)"),
           ("Изменения (в конфигурацию роутера)", None),
           ("ip addr add 10.10.0.1/24 dev br-lan", "адрес (как /ip address add)"),
           ("ip route add 192.168.20.0/24 via 172.16.0.2", "маршрут (как /ip route add)"),
           ("ip route del 192.168.20.0/24", "удалить маршрут"),
           ("nmcli | nmcli d | nmcli c | nmcli c show lan1", "устройства и соединения (WAN, LAN, VPN, GRE)"),
           ("nmcli c mod wan ipv4.method manual ipv4.addresses 203.0.113.10/24 ipv4.gateway 203.0.113.1", "статический WAN"),
           ("nmcli c mod lan1 ipv4.addresses 192.168.1.1/24", "адрес LAN"),
           ("nmcli c up amneziawg | nmcli c down lan2", "включить / выключить"),
           ("Прочее", None),
           ("/…", "команда RouterOS (например, /ip firewall nat print)"),
           ("routeros", "синтаксис MikroTik"),
           ("exit", "выход")],
    "he": [("החלפת שפה", "sl1 English · sl2 Русский · sl3 עברית   (sl — הנוכחית)"),
           ("צפייה (כלים אמיתיים)", None),
           ("ip a | ip -br a | ip addr show dev br-lan", "כתובות"),
           ("ip r | ip route get 8.8.8.8", "נתיבים"),
           ("ip link | ip -s link | ip neigh | ip rule", "ממשקים, ARP, כללים"),
           ("bridge link | bridge vlan", "גשרים ו-VLAN"),
           ("ss -tlnp | ss -ulnp", "מי מאזין לאיזה פורט"),
           ("ping -c 3 samba | traceroute 8.8.8.8", "בדיקת קישוריות (שמות דרך ה-DNS של הנתב)"),
           ("שינויים (נשמרים בתצורת הנתב)", None),
           ("ip addr add 10.10.0.1/24 dev br-lan", "כתובת (כמו /ip address add)"),
           ("ip route add 192.168.20.0/24 via 172.16.0.2", "נתיב (כמו /ip route add)"),
           ("ip route del 192.168.20.0/24", "מחיקת נתיב"),
           ("nmcli | nmcli d | nmcli c | nmcli c show lan1", "התקנים וחיבורים (WAN, LAN, VPN, GRE)"),
           ("nmcli c mod wan ipv4.method manual ipv4.addresses 203.0.113.10/24 ipv4.gateway 203.0.113.1", "WAN סטטי"),
           ("nmcli c mod lan1 ipv4.addresses 192.168.1.1/24", "כתובת LAN"),
           ("nmcli c up amneziawg | nmcli c down lan2", "הפעלה / כיבוי"),
           ("אחר", None),
           ("/…", "פקודת RouterOS (למשל /ip firewall nat print)"),
           ("routeros", "מעבר לתחביר MikroTik"),
           ("exit", "יציאה")],
}

BANNER = {
    "en": ("OutpostGate Pro — Linux syntax", "ip a · ip r · nmcli c · ss -tlnp · ping -c 3 samba",
           "help — commands · sl1/sl2/sl3 — language · /… — RouterOS · routeros — MikroTik syntax · exit"),
    "ru": ("OutpostGate Pro — синтаксис Linux", "ip a · ip r · nmcli c · ss -tlnp · ping -c 3 samba",
           "help — команды · sl1/sl2/sl3 — язык · /… — RouterOS · routeros — синтаксис MikroTik · exit"),
    "he": ("OutpostGate Pro — תחביר Linux", "ip a · ip r · nmcli c · ss -tlnp · ping -c 3 samba",
           "help — פקודות · sl1/sl2/sl3 — שפה · /… — RouterOS · routeros — תחביר MikroTik · exit"),
}


def banner(on: bool, lang: str) -> str:
    title, ex, keys = BANNER.get(lang, BANNER["en"])
    return "\n".join(["", "  " + paint(on, title, "bgreen"), "  " + paint(on, ex, "cyan"),
                      "  " + paint(on, keys, "dim"), ""])


def help_lines(on: bool, lang: str) -> list[str]:
    rows = HELP.get(lang, HELP["en"])
    width = max(len(c) for c, d in rows if d) + 2
    width = min(width, 50)
    out = []
    for cmd, desc in rows:
        if desc is None:
            out += ["", paint(on, cmd, "bold")]
        else:
            c = paint(on, cmd, "cyan" if not out else "green")
            out.append("  " + (ljust(c, width) if len(cmd) < width else c + "  ") + desc)
    return out
