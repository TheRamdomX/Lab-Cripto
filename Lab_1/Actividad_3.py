#!/usr/bin/env python3
import argparse
import string
from scapy.all import sniff, ICMP, get_if_list, conf
from colorama import Fore, Style, init

init(autoreset=True)

DEFAULT_DELIM = "#"
BUFFER_LIMIT = 200  # si no hay delimitador, analiza cuando buffer alcance este tamaño

buffer_mensaje = ""
current_uid = None
processed = set()  # set of (id, seq) ya procesados
CAPTURE_ICMP_TYPE = 0  # escuchamos Echo Reply por defecto

def detect_loopback_iface():
    ifaces = get_if_list()
    for name in ifaces:
        if 'lo' in name.lower() or 'loopback' in name.lower():
            return name
    try:
        route = conf.route.route("127.0.0.1")
        if route and isinstance(route, (list, tuple)):
            iface = route[-1]
            if iface:
                return iface
    except Exception:
        pass
    return ifaces[0] if ifaces else None

def cesar_descifrar(texto, corrimiento):
    resultado = ""
    for char in texto:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            resultado += chr((ord(char) - base - corrimiento) % 26 + base)
        else:
            resultado += char
    return resultado

def puntuar_texto(texto):
    if not texto:
        return 0
    validos = sum(1 for c in texto if c in (string.ascii_letters + " " + ".,;:¡!¿?"))
    return validos / len(texto)

def analizar_mensaje(mensaje):
    """
    Escoge el corrimiento que maximiza la presencia de vocales (y un poco los espacios).
    Devuelve (mejor_corrimiento, texto_descifrado).
    """
    if not mensaje:
        print("No hay mensaje para analizar.")
        return None, ""

    vocales = set("aeiouáéíóúüAEIOUÁÉÍÓÚÜ")
    mejor_score = -1.0
    mejor_texto = ""
    mejor_corr = 0
    resultados = []

    for corr in range(26):
        desc = cesar_descifrar(mensaje, corr)
        score = sum(1 for c in desc if c in vocales) + 0.2 * desc.count(" ")
        resultados.append((corr, desc, score))
        if score > mejor_score:
            mejor_score = score
            mejor_texto = desc
            mejor_corr = corr

    print("\nPosibilidades de descifrado:")
    for corr, desc, score in resultados:
        if corr == mejor_corr:
            print(Fore.GREEN + f"Shift {corr:2d}: {desc}  (score={score:.2f})" + Style.RESET_ALL)
        else:
            print(f"Shift {corr:2d}: {desc}  (score={score:.2f})")
    print("\n✅ Resultado (heurística: mayor #vocales + espacios):")
    print(Fore.GREEN + f"Shift {mejor_corr}: {mejor_texto}  (score={mejor_score:.2f})" + Style.RESET_ALL)
    return mejor_corr, mejor_texto

def extraer_payload_icmp(pkt):
    try:
        raw = bytes(pkt[ICMP].payload)
        if raw:
            return raw
    except Exception:
        pass
    try:
        if pkt.haslayer("Raw"):
            return bytes(pkt["Raw"].load)
    except Exception:
        pass
    try:
        full = bytes(pkt)
        if len(full) > 28:
            return full[28:]
    except Exception:
        pass
    return b""

def es_imprimible(b):
    try:
        s = b.decode('utf-8', errors='ignore')
        return s if s and (s[0].isprintable() or s[0] in '\r\n') else None
    except Exception:
        return None

def capturar_paquete(pkt):
    global buffer_mensaje, current_uid, processed
    try:
        if not pkt.haslayer(ICMP):
            return
        icmp_type = pkt[ICMP].type
    except Exception:
        return

    # sólo procesar el tipo configurado (por defecto 0 = Echo Reply)
    if icmp_type != CAPTURE_ICMP_TYPE:
        return

    # obtener id y seq de ICMP (si no existen, ignorar)
    try:
        icmp_id = int(pkt[ICMP].id)
        icmp_seq = int(pkt[ICMP].seq)
    except Exception:
        return

    # si el receptor fue iniciado con --uid, current_uid ya está fijado.
    # Si no, la primera respuesta que llegue establece current_uid (vinculación automática).
    if current_uid is None:
        # vinculamos al primer id que aparezca
        current_uid = icmp_id
        print(f"[info] Vinculado a ICMP id={current_uid}. Ignorando otros ids.")

    # ignorar respuestas que no pertenezcan al id en uso
    if icmp_id != current_uid:
        return

    # desduplicar por (id,seq)
    marker = (icmp_id, icmp_seq)
    if marker in processed:
        # ya vimos esta secuencia -> duplicado
        # puedes descomentar la línea siguiente si quieres ver cuándo ocurre:
        # print(f"[debug] Ignorado duplicado id={icmp_id} seq={icmp_seq}")
        return
    processed.add(marker)

    # extraer payload
    data = extraer_payload_icmp(pkt)
    if not data:
        return
    first = data[:1]
    char = es_imprimible(first)
    if char:
        buffer_mensaje += char
        print(f"Recibido char={char!r} (id={icmp_id} seq={icmp_seq} buffer_len={len(buffer_mensaje)})")
        if DELIM and DELIM in buffer_mensaje:
            msg, _, resto = buffer_mensaje.partition(DELIM)
            analizar_mensaje(msg)
            buffer_mensaje = resto
        else:
            if len(buffer_mensaje) >= BUFFER_LIMIT:
                analizar_mensaje(buffer_mensaje)
                buffer_mensaje = ""
    else:
        # ignoramos bytes no imprimibles
        pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ICMP receiver that dedups by id/seq")
    parser.add_argument("--iface", help="Interfaz a usar (si no, se detecta la loopback)")
    parser.add_argument("--delim", default=DEFAULT_DELIM, help=f"Delimitador de fin de mensaje (default '{DEFAULT_DELIM}'). Pon '' para desactivar.")
    parser.add_argument("--uid", type=int, help="Si se pasa, sólo se aceptan replies con este ICMP id")
    parser.add_argument("--mode", choices=("reply", "request"), default="reply", help="Capture 'reply' (type=0) o 'request' (type=8). Default: reply")
    args = parser.parse_args()

    iface = args.iface or detect_loopback_iface()
    if not iface:
        print("No pude detectar una interfaz. Pasa --iface.")
        raise SystemExit(1)

    DELIM = args.delim if args.delim != "" else None
    CAPTURE_ICMP_TYPE = 0 if args.mode == "reply" else 8

    if args.uid:
        current_uid = args.uid
        print(f"[info] Receptor forzado a ICMP id={current_uid}")

    print(f"Escuchando ICMP en iface={iface} (capturando {'reply' if CAPTURE_ICMP_TYPE==0 else 'request'})")
    sniff(filter="icmp", prn=capturar_paquete, store=0, iface=iface)
