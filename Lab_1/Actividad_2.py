#!/usr/bin/env python3
import argparse
import random
from scapy.all import IP, ICMP, Raw, send, get_if_list, conf

PAYLOAD_LEN = 40
DEFAULT_DST = "127.0.0.1"

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

def pad_payload(text, length=PAYLOAD_LEN):
    b = text.encode(errors="ignore")
    if len(b) >= length:
        return b[:length]
    return b + b'0' * (length - len(b))

def main():
    parser = argparse.ArgumentParser(description="ICMP sender estilo ping con texto")
    parser.add_argument("texto", help="Texto a enviar en el payload")
    parser.add_argument("--dst", default=DEFAULT_DST, help="IP destino (por defecto 127.0.0.1)")
    parser.add_argument("--iface", help="Interfaz a usar (si no, se detecta loopback)")
    parser.add_argument("--uid", type=int, help="UID (16-bit) a usar; si no se especifica se genera aleatorio")
    parser.add_argument("--count", type=int, default=4, help="Cantidad de paquetes a enviar")
    args = parser.parse_args()

    iface = args.iface or detect_loopback_iface()
    if not iface:
        print("No pude detectar una interfaz. Usa --iface <iface>.")
        return

    uid = args.uid if args.uid is not None else random.randint(1, 0xFFFF)
    print(f"Usando iface={iface}, dst={args.dst}, ICMP id={uid}")

    seq = 0
    for ch in args.texto:
        payload = pad_payload(ch)
        pkt = IP(dst=args.dst, flags='DF')/ICMP(id=uid, seq=seq)/Raw(load=payload)
        send(pkt, iface=iface, verbose=False)
        print(f"Enviado seq={seq} char={repr(ch)} (DF set)")
        seq += 1

if __name__ == "__main__":
    main()
