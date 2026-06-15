#!/usr/bin/env python3
# ============================================================================
#  dpicheck1.py — простая проверка ОДНОГО хоста/домена на ТСПУ-блокировки
#
#  Проверяет 4 механизма (методики проекта hyperion-cs/dpi-checkers):
#    A) l4-25 / TCP 16-20  — заморозка после ~16-20KB в одном коннекте
#    B) "Сибирская"        — заморозка при нескольких параллельных TLS к SNI
#    D) DNS-spoofing       — подмена DNS-ответов для этого домена
#    E) SNI-whitelist      — пропуск только по «разрешённому» SNI
#
#  Зависимостей нет (stdlib only). Python 3.8+.
# ============================================================================

import os
import re
import socket
import ssl
import struct
import sys
import threading
import time

# --- параметры (можно не трогать) -------------------------------------------
PORT_DEFAULT = 443
THR_BYTES = 64 * 1024
CONNECT_TIMEOUT = 10
HANDSHAKE_TIMEOUT = 10
FREEZE_TIMEOUT = 15
SIB_CONN = 5
SIB_DELAY_MS = 250
SIB_HS_TIMEOUT = 12
ALLOWED_SNI = "ya.ru"            # заведомо whitelisted домен для теста E

DNS_RESOLVERS = {
    "Cloudflare": "1.1.1.1",
    "Google":     "8.8.8.8",
    "Yandex":     "77.88.8.8",
    "система":    None,          # то, что выдаёт провайдер
}


# ---------- цвета ----------
def c(code, s): return f"\033[{code}m{s}\033[0m"
def green(s):  return c("32", s)
def red(s):    return c("31", s)
def yellow(s): return c("33", s)
def dim(s):    return c("90", s)
def bold(s):   return c("1", s)


def is_ip(s):
    try:
        socket.inet_aton(s); return True
    except OSError:
        return False


# ============================================================================
#  A — l4-25 / TCP 16-20
# ============================================================================
def check_l4_25(ip, port, sni):
    r = {"v": None, "d": "", "sent": 0}
    try:
        sock = socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception as e:
        r["v"] = "CONN_ERR"; r["d"] = f"нет TCP-соединения: {e}"; return r
    ctx = ssl._create_unverified_context()
    try:
        sock.settimeout(HANDSHAKE_TIMEOUT)
        tls = ctx.wrap_socket(sock, server_hostname=sni)
    except Exception as e:
        r["v"] = "TLS_ERR"; r["d"] = f"TLS не установился ({type(e).__name__})"
        try: sock.close()
        except Exception: pass
        return r
    body = os.urandom(THR_BYTES)
    req = (f"POST / HTTP/1.1\r\nHost: {sni}\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
    try:
        tls.sendall(req)
        for i in range(0, len(body), 2048):
            tls.sendall(body[i:i + 2048]); r["sent"] += len(body[i:i + 2048])
        tls.settimeout(FREEZE_TIMEOUT)
        data = tls.recv(4096)
        r["v"] = "CLEAN"
        r["d"] = f"поток {r['sent']//1024}KB прошёл, ответ получен"
    except socket.timeout:
        r["v"] = "FROZEN"
        r["d"] = f"коннект завис после {r['sent']//1024}KB (нет ответа {FREEZE_TIMEOUT}с)"
    except (ConnectionResetError, BrokenPipeError) as e:
        r["v"] = "FROZEN"
        r["d"] = f"обрыв ({type(e).__name__}) на {r['sent']//1024}KB"
    except Exception as e:
        r["v"] = "TLS_ERR"; r["d"] = type(e).__name__
    finally:
        try: tls.close()
        except Exception: pass
    return r


# ============================================================================
#  B — Сибирская (N параллельных TLS)
# ============================================================================
def _hs(ip, port, sni, out, idx):
    t0 = time.time()
    try:
        s = socket.create_connection((ip, port), timeout=SIB_HS_TIMEOUT)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        ctx = ssl._create_unverified_context()
        s.settimeout(SIB_HS_TIMEOUT)
        t = ctx.wrap_socket(s, server_hostname=sni)
        out[idx] = "ok"
        try: t.close()
        except Exception: pass
    except socket.timeout:
        out[idx] = "timeout"
    except Exception:
        out[idx] = "err"


def check_siberian(ip, port, sni):
    r = {"v": None, "d": "", "ok": 0, "frozen": 0, "err": 0}
    out = [None] * SIB_CONN
    ths = []
    for i in range(SIB_CONN):
        th = threading.Thread(target=_hs, args=(ip, port, sni, out, i))
        th.start(); ths.append(th)
        time.sleep(SIB_DELAY_MS / 1000.0)
    for th in ths:
        th.join()
    for res in out:
        if res == "ok": r["ok"] += 1
        elif res == "timeout": r["frozen"] += 1
        else: r["err"] += 1
    if r["frozen"] >= 2 and r["ok"] < SIB_CONN:
        r["v"] = "FROZEN"
        r["d"] = f"{r['frozen']} из {SIB_CONN} параллельных коннектов заморожены"
    elif r["ok"] == SIB_CONN:
        r["v"] = "CLEAN"; r["d"] = f"все {SIB_CONN} параллельных коннектов прошли"
    elif r["ok"] == 0 and r["err"] == SIB_CONN:
        r["v"] = "CONN_ERR"; r["d"] = "все коннекты оборвались (сеть/порт)"
    else:
        r["v"] = "PARTIAL"; r["d"] = f"{r['ok']} ok / {r['frozen']} завис / {r['err']} ошибок"
    return r


# ============================================================================
#  E — SNI-whitelist
# ============================================================================
def _reachable(ip, port, sni):
    try:
        s = socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        ctx = ssl._create_unverified_context()
        s.settimeout(HANDSHAKE_TIMEOUT)
        t = ctx.wrap_socket(s, server_hostname=(sni or None))
        blob = os.urandom(20 * 1024)
        req = (f"POST / HTTP/1.1\r\nHost: {sni or ip}\r\n"
               f"Content-Length: {len(blob)}\r\nConnection: close\r\n\r\n").encode()
        t.sendall(req)
        for i in range(0, len(blob), 2048):
            t.sendall(blob[i:i + 2048])
        t.settimeout(FREEZE_TIMEOUT)
        t.recv(1024)
        t.close()
        return True
    except socket.timeout:
        return False
    except Exception:
        return None


def check_sni(ip, port, real_sni):
    r = {"v": None, "d": ""}
    real = _reachable(ip, port, real_sni)
    allowed = _reachable(ip, port, ALLOWED_SNI)
    w = lambda x: {True: "прошёл", False: "завис", None: "ошибка"}[x]
    r["d"] = f"свой SNI={w(real)}, whitelisted({ALLOWED_SNI})={w(allowed)}"
    if real is False and allowed is True:
        r["v"] = "WHITELIST_SNI"
    elif real is True:
        r["v"] = "CLEAN"
    elif real is False and allowed is False:
        r["v"] = "BLOCKED_ALL"
    else:
        r["v"] = "INCON"
    return r


# ============================================================================
#  D — DNS-spoofing (свой UDP-резолвер)
# ============================================================================
def _dns_a(resolver_ip, host, timeout=4):
    if resolver_ip is None:
        try:
            return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_INET)})
        except Exception:
            return None
    tid = os.urandom(2)
    pkt = tid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    pkt += b"".join(bytes([len(p)]) + p.encode() for p in host.split(".")) + b"\x00"
    pkt += b"\x00\x01\x00\x01"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(pkt, (resolver_ip, 53))
        data, _ = s.recvfrom(2048)
        s.close()
    except Exception:
        return None
    if data[3] & 0x0F == 3:
        return "NXDOMAIN"
    ancount = struct.unpack(">H", data[6:8])[0]
    if ancount == 0:
        return []
    idx = 12
    while data[idx] != 0:
        idx += data[idx] + 1
    idx += 5
    ips = []
    for _ in range(ancount):
        if data[idx] & 0xC0 == 0xC0:
            idx += 2
        else:
            while data[idx] != 0:
                idx += data[idx] + 1
            idx += 1
        rtype = struct.unpack(">H", data[idx:idx + 2])[0]
        idx += 8
        rdlen = struct.unpack(">H", data[idx:idx + 2])[0]
        idx += 2
        if rtype == 1 and rdlen == 4:
            ips.append(".".join(str(b) for b in data[idx:idx + 4]))
        idx += rdlen
    return ips


def check_dns(host):
    """Сравниваем ответы разных резолверов между собой. Если системный
       резолвер выдаёт IP, которого нет ни у одного публичного — подозрение
       на подмену провайдером."""
    r = {"v": None, "rows": []}
    answers = {}
    for name, rip in DNS_RESOLVERS.items():
        a = _dns_a(rip, host)
        answers[name] = a
    # эталон — объединение публичных резолверов
    pub = set()
    for name, rip in DNS_RESOLVERS.items():
        if rip is not None and isinstance(answers[name], list):
            pub.update(answers[name])
    spoof = False
    for name, a in answers.items():
        if a is None:
            tag = yellow("ошибка"); val = "—"
        elif a == "NXDOMAIN":
            tag = red("NXDOMAIN"); val = "NXDOMAIN"; spoof = True
        elif not a:
            tag = yellow("пусто"); val = "(пусто)"
        else:
            val = ",".join(a[:2])
            # системный ответ, не пересекающийся с публичными → подозрение
            if name == "система" and pub and not (set(a) & pub):
                tag = red("ПОДМЕНА?"); spoof = True
            else:
                tag = green("ok")
        r["rows"].append((name, val, tag))
    r["v"] = "SPOOFED" if spoof else "CLEAN"
    return r


# ============================================================================
#  Вывод
# ============================================================================
def vt(v):
    return {
        "CLEAN": green("✓ чисто"), "FROZEN": red("✗ ЗАМОРОЗКА"),
        "PARTIAL": yellow("~ частично"), "TLS_ERR": yellow("? ошибка TLS"),
        "CONN_ERR": yellow("? нет связи"), "WHITELIST_SNI": red("✗ пропуск по whitelisted-SNI"),
        "BLOCKED_ALL": red("✗ режется при любом SNI"), "INCON": yellow("? неоднозначно"),
        "SPOOFED": red("✗ ПОДМЕНА DNS"),
    }.get(v, yellow(str(v)))


def run(host, port, sni):
    LABW = 34   # ширина колонки названия проверки
    LINE = "─" * 56

    print()
    try:
        ip = host if is_ip(host) else socket.gethostbyname(host)
    except Exception as e:
        print(red(f"  Не удалось определить IP для {host}: {e}"))
        print(red("  Проверь адрес/домен и подключение к интернету.\n"))
        return

    # шапка
    print(dim("  " + LINE))
    print(f"  {bold('Хост'):<8} {host}")
    if ip != host:
        print(f"  {dim('IP'):<8} {ip}")
    print(dim("  " + LINE))

    def row(label, verdict_str):
        # label дополняем до LABW БЕЗ цвета, потом печатаем вердикт
        print(f"  {label:.<{LABW}} {verdict_str}")

    def detail(text):
        print(f"  {dim('└ ' + text)}")

    print(dim("  [A] l4-25 / TCP 16-20 ..."), flush=True)
    a = check_l4_25(ip, port, sni)
    row("A) Заморозка по объёму (l4-25) ", vt(a["v"]))
    detail(a["d"])

    print(dim("  [B] сибирская (параллельные TLS) ..."), flush=True)
    b = check_siberian(ip, port, sni)
    row("B) Сибирская блокировка ", vt(b["v"]))
    detail(b["d"])

    print(dim("  [E] фильтр по SNI ..."), flush=True)
    e = check_sni(ip, port, sni)
    row("E) Фильтр по SNI ", vt(e["v"]))
    detail(e["d"])

    if not is_ip(host):
        print(dim("  [D] DNS-spoofing ..."), flush=True)
        d = check_dns(host)
        row("D) Подмена DNS ", vt(d["v"]))
        # выровненная таблица резолверов
        for (name, val, tag) in d["rows"]:
            print(f"     {(name + ':'):<12} {val:<32} {tag}")
    else:
        d = {"v": "CLEAN"}
        row("D) Подмена DNS ", dim("пропущено (введён IP)"))

    # итог
    print(dim("  " + LINE))
    blocked = (a["v"] == "FROZEN" or b["v"] == "FROZEN"
               or e["v"] in ("WHITELIST_SNI", "BLOCKED_ALL"))
    clean = (a["v"] == "CLEAN" and b["v"] == "CLEAN" and e["v"] == "CLEAN")

    if blocked:
        print("  " + bold(red("ИТОГ: хост под ограничением ТСПУ")))
        if a["v"] == "FROZEN":
            print(red("   • l4-25: режется крупный трафик → нужен узел в РФ / whitelisted-SNI"))
        if b["v"] == "FROZEN":
            print(red("   • сибирская: смени fingerprint (Chrome→Firefox), включи mux, держи 1 SNI"))
        if e["v"] == "WHITELIST_SNI":
            print(red("   • пропуск только по whitelisted-SNI → используй разрешённый домен"))
        if e["v"] == "BLOCKED_ALL":
            print(red("   • режется при любом SNI → похоже на CIDR-whitelist, нужен другой IP"))
    elif clean:
        print("  " + bold(green("ИТОГ: ограничений не обнаружено — хост доступен")))
    else:
        print("  " + bold(yellow("ИТОГ: неоднозначно — перепроверь хост или сеть")))
    print()


def ask_target():
    W = 58
    print()
    print(dim("  ┌" + "─" * W + "┐"))
    print(dim("  │ ") + bold("Проверка хоста на блокировки ТСПУ (РФ)".ljust(W - 2)) + dim("│"))
    print(dim("  └" + "─" * W + "┘"))
    print()
    print(yellow("   1) Отключите все VPN."))
    print("   2) Введите IP-адрес или домен для проверки.")
    print()
    print(dim("      примеры:  example.com   |   203.0.113.10"))
    print()
    raw = input("   Хост: ").strip()
    if not raw:
        print("\n   Пусто — выход.\n")
        return None
    return raw


def parse(raw):
    host = raw.strip()
    return host, PORT_DEFAULT, host   # порт всегда 443, SNI = сам хост


def main():
    if len(sys.argv) > 1:
        raw = sys.argv[1]
    else:
        raw = ask_target()
        if not raw:
            return
    host, port, sni = parse(raw)
    run(host, port, sni)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nПрервано.")
        sys.exit(130)
