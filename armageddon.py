from scapy.layers.inet import UDP, TCP, ICMP, IP
from scapy.layers.l2 import ARP, Ether
from scapy.all import sniff, wrpcap
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.packet import Raw
from scapy.utils import hexdump
import datetime
import argparse
import os
import ctypes
import sys
import time
import threading
import psutil
import netifaces
from colorama import init, Fore, Back, Style
from tqdm import tqdm
import numpy as np
import matplotlib.pyplot as plt
from collections import deque

# Initialiser colorama
init()

# Compteurs de statistiques avancés
stats = {
    "TCP": 0, "UDP": 0, "ICMP": 0, "DNS": 0, "ARP": 0, "HTTP": 0, 
    "HTTPS": 0, "SSH": 0, "FTP": 0, "SMTP": 0, "Other": 0
}

# Historique pour graphique temps réel
history = {proto: deque(maxlen=100) for proto in stats.keys()}
packet_sizes = []
connections = {}
ips_seen = set()
live_capture = True
packets_captured = []
capture_start_time = None

def detect_protocol(packet, sport, dport):
    """Détection intelligente des protocoles basée sur les ports"""
    if dport == 80 or sport == 80:
        return "HTTP"
    elif dport == 443 or sport == 443:
        return "HTTPS"
    elif dport == 22 or sport == 22:
        return "SSH"
    elif dport in [20, 21] or sport in [20, 21]:
        return "FTP"
    elif dport == 25 or sport == 25:
        return "SMTP"
    return None

def extract_http_info(packet):
    """Extraire les informations HTTP si disponible"""
    if Raw in packet:
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            if payload.startswith("GET") or payload.startswith("POST"):
                first_line = payload.split("\r\n")[0]
                return f"HTTP: {first_line}"
            elif payload.startswith("HTTP"):
                status = payload.split("\r\n")[0]
                return f"HTTP: {status}"
        except:
            pass
    return None

def packet_callback(packet):
    global stats, packet_sizes, ips_seen, connections, packets_captured
    
    if args.save:
        packets_captured.append(packet)
    
    # Timestamp
    timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    
    # MAC addresses
    src_mac = packet[Ether].src if packet.haslayer(Ether) else "??"
    dst_mac = packet[Ether].dst if packet.haslayer(Ether) else "??"
    
    # IP addresses
    src_ip = packet[IP].src if packet.haslayer(IP) else "??"
    dst_ip = packet[IP].dst if packet.haslayer(IP) else "??"
    
    if packet.haslayer(IP):
        ips_seen.add(src_ip)
        ips_seen.add(dst_ip)
        
        # Tracking connections
        if packet.haslayer(TCP):
            flow_key = f"{src_ip}:{packet[TCP].sport}-{dst_ip}:{packet[TCP].dport}"
            reverse_key = f"{dst_ip}:{packet[TCP].dport}-{src_ip}:{packet[TCP].sport}"
            
            if flow_key in connections:
                connections[flow_key]["packets"] += 1
                connections[flow_key]["bytes"] += len(packet)
                connections[flow_key]["last_seen"] = time.time()
            elif reverse_key in connections:
                connections[reverse_key]["packets"] += 1
                connections[reverse_key]["bytes"] += len(packet)
                connections[reverse_key]["last_seen"] = time.time()
            else:
                connections[flow_key] = {
                    "src": src_ip, 
                    "dst": dst_ip,
                    "sport": packet[TCP].sport,
                    "dport": packet[TCP].dport,
                    "start_time": time.time(),
                    "last_seen": time.time(),
                    "packets": 1,
                    "bytes": len(packet)
                }
    
    # Packet size tracking
    packet_sizes.append(len(packet))
    
    # Protocol determination and special info extraction
    if packet.haslayer(TCP):
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        proto = detect_protocol(packet, sport, dport) or "TCP"
        
        info = f"{sport} → {dport} "
        flags = []
        if packet[TCP].flags.S: flags.append("SYN")
        if packet[TCP].flags.A: flags.append("ACK")
        if packet[TCP].flags.F: flags.append("FIN")
        if packet[TCP].flags.R: flags.append("RST")
        if packet[TCP].flags.P: flags.append("PSH")
        info += " ".join(flags)
        
        # HTTP detection
        http_info = extract_http_info(packet)
        if http_info:
            info += f" | {http_info}"
            proto = "HTTP"
            
        stats[proto] += 1
        color = Fore.BLUE
    
    elif packet.haslayer(UDP):
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        proto = detect_protocol(packet, sport, dport) or "UDP"
        info = f"{sport} → {dport}"
        stats[proto] += 1
        color = Fore.GREEN
    
    elif packet.haslayer(ICMP):
        proto = "ICMP"
        type_icmp = packet[ICMP].type
        code_icmp = packet[ICMP].code
        icmp_type_names = {
            0: "Echo Reply", 8: "Echo Request",
            3: "Destination Unreachable", 5: "Redirect",
            11: "Time Exceeded"
        }
        type_name = icmp_type_names.get(type_icmp, f"Type {type_icmp}")
        info = f"{type_name} (Code: {code_icmp})"
        stats["ICMP"] += 1
        color = Fore.RED
    
    elif packet.haslayer(DNS):
        proto = "DNS"
        info = ""
        if packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname.decode()
            qtype = packet[DNSQR].qtype
            qtypes = {1: "A", 5: "CNAME", 28: "AAAA", 15: "MX", 16: "TXT"}
            qtype_name = qtypes.get(qtype, str(qtype))
            info = f"Query: {qname} ({qtype_name})"
        elif packet.haslayer(DNSRR):
            rrname = packet[DNSRR].rrname.decode()
            rdata = packet[DNSRR].rdata
            if isinstance(rdata, bytes):
                try:
                    rdata = rdata.decode()
                except:
                    rdata = str(rdata)
            info = f"Response: {rrname} → {rdata}"
        stats["DNS"] += 1
        color = Fore.MAGENTA
    
    elif packet.haslayer(ARP):
        proto = "ARP"
        op = "request" if packet[ARP].op == 1 else "reply"
        info = f"{op} {packet[ARP].psrc} → {packet[ARP].pdst}"
        stats["ARP"] += 1
        color = Fore.YELLOW
    
    else:
        proto = "Other"
        info = "Unknown protocol"
        stats["Other"] += 1
        color = Fore.WHITE
    
    # Update history for the chart
    for p in stats:
        if p == proto:
            history[p].append(history[p][-1] + 1 if history[p] else 1)
        else:
            history[p].append(history[p][-1] if history[p] else 0)
    
    # Length of packet
    length = len(packet)
    
    # Enhanced display with protocol-based coloring
    proto_colors = {
        "TCP": Fore.BLUE, "UDP": Fore.GREEN, "ICMP": Fore.RED,
        "DNS": Fore.MAGENTA, "ARP": Fore.YELLOW, "HTTP": Fore.CYAN,
        "HTTPS": Fore.CYAN, "SSH": Fore.LIGHTBLUE_EX, "FTP": Fore.LIGHTGREEN_EX,
        "SMTP": Fore.LIGHTRED_EX, "Other": Fore.WHITE
    }
    
    color = proto_colors.get(proto, Fore.WHITE)
    proto_display = f"{color}{Style.BRIGHT}{proto:6s}{Style.RESET_ALL}"
    
    # Print packet info with improved formatting
    print(f"{Fore.CYAN}{timestamp}{Style.RESET_ALL} {proto_display} | "
          f"{Fore.WHITE}{src_ip:15s} → {dst_ip:15s} | "
          f"{Back.BLACK}{Fore.WHITE}{length:5d} bytes{Style.RESET_ALL} | "
          f"{color}{info}{Style.RESET_ALL}")
    
    # Show hex dump if requested
    if args.hex and packet.haslayer(Raw):
        print(f"{Fore.CYAN}{'─' * 10} Payload {'─' * 10}{Style.RESET_ALL}")
        hexdump(packet[Raw].load)
        print()

    # Show stats periodically
    total_packets = sum(stats.values())
    if total_packets % (args.stats_interval or 20) == 0:
        if not args.quiet_stats:
            show_stats()

def show_stats():
    """Affiche des statistiques détaillées"""
    total = sum(stats.values())
    now = time.time()
    duration = now - capture_start_time if capture_start_time else 0
    
    os.system('cls' if os.name == 'nt' else 'clear')
    print("\n" + "═" * 60)
    print(f"{Style.BRIGHT}{Back.BLUE}{Fore.WHITE} STATISTIQUES AVANCÉES {Style.RESET_ALL}")
    print("═" * 60)
    
    # Statistiques globales
    pps = total / duration if duration > 0 else 0
    avg_size = np.mean(packet_sizes) if packet_sizes else 0
    
    print(f"{Fore.CYAN}Paquets: {Fore.WHITE}{total} {Fore.CYAN}| "
          f"Durée: {Fore.WHITE}{duration:.1f}s {Fore.CYAN}| "
          f"Débit: {Fore.WHITE}{pps:.1f} pkt/s {Fore.CYAN}| "
          f"Taille moyenne: {Fore.WHITE}{avg_size:.1f} octets")
    print(f"{Fore.CYAN}Adresses IP uniques: {Fore.WHITE}{len(ips_seen)} {Fore.CYAN}| "
          f"Connexions actives: {Fore.WHITE}{len(connections)}")
    
    print("─" * 60)
    print(f"{Style.BRIGHT}DISTRIBUTION PAR PROTOCOLE{Style.RESET_ALL}")
    
    # Distribution par protocole avec barre de progression
    proto_colors = {
        "TCP": Fore.BLUE, "UDP": Fore.GREEN, "ICMP": Fore.RED,
        "DNS": Fore.MAGENTA, "ARP": Fore.YELLOW, "HTTP": Fore.CYAN,
        "HTTPS": Fore.CYAN, "SSH": Fore.LIGHTBLUE_EX, "FTP": Fore.LIGHTGREEN_EX,
        "SMTP": Fore.LIGHTRED_EX, "Other": Fore.WHITE
    }
    
    for proto, count in sorted(stats.items(), key=lambda x: x[1], reverse=True):
        if count == 0:
            continue
            
        color = proto_colors.get(proto, Fore.WHITE)
        percentage = (count / total) * 100 if total > 0 else 0
        bar_length = int(percentage / 2)
        bar = "█" * bar_length
        
        print(f"{color}{proto:6s}{Style.RESET_ALL}: {count:5d} ({percentage:5.1f}%) {color}{bar}{Style.RESET_ALL}")
    
    if args.advanced_stats and len(connections) > 0:
        print("─" * 60)
        print(f"{Style.BRIGHT}TOP 5 CONNEXIONS{Style.RESET_ALL}")
        
        # Trier les connexions par nombre de paquets
        sorted_conns = sorted(connections.items(), 
                             key=lambda x: x[1]["packets"], 
                             reverse=True)[:5]
        
        for key, conn in sorted_conns:
            src = f"{conn['src']}:{conn['sport']}"
            dst = f"{conn['dst']}:{conn['dport']}"
            duration = conn['last_seen'] - conn['start_time']
            print(f"{Fore.WHITE}{src:21s} → {dst:21s} | "
                  f"{Fore.CYAN}Paquets: {Fore.WHITE}{conn['packets']:5d} | "
                  f"{Fore.CYAN}Octets: {Fore.WHITE}{conn['bytes']:7d} | "
                  f"{Fore.CYAN}Durée: {Fore.WHITE}{duration:.1f}s")
    
    print("═" * 60)

def show_live_chart():
    """Affiche un graphique en temps réel des protocoles"""
    plt.figure(figsize=(10, 6))
    plt.ion()  # Mode interactif
    
    x = range(100)
    lines = {}
    colors = {'TCP': 'blue', 'UDP': 'green', 'ICMP': 'red', 
              'DNS': 'magenta', 'ARP': 'yellow', 'HTTP': 'cyan',
              'HTTPS': 'teal', 'SSH': 'darkblue', 'FTP': 'lime',
              'SMTP': 'orange', 'Other': 'gray'}
    
    for proto in stats.keys():
        if len(history[proto]) > 0:
            lines[proto], = plt.plot(x[:len(history[proto])], 
                                     list(history[proto]), 
                                     label=proto, 
                                     color=colors.get(proto, 'gray'))
    
    plt.legend(loc='upper left')
    plt.title('Trafic réseau en temps réel')
    plt.xlabel('Paquets')
    plt.ylabel('Cumul')
    plt.grid(True)
    
    while live_capture:
        for proto in stats.keys():
            if proto in lines and len(history[proto]) > 0:
                data = list(history[proto])
                xdata = range(len(data))
                lines[proto].set_data(xdata, data)
        
        plt.xlim(0, max(1, max(len(h) for h in history.values())))
        plt.ylim(0, max(1, max([max(h) if h else 0 for h in history.values()])))
        plt.draw()
        plt.pause(0.5)
        
    plt.ioff()
    plt.close()

def network_usage_monitor():
    """Moniteur d'utilisation réseau en temps réel"""
    if_stats = {}
    
    while live_capture:
        net_io = psutil.net_io_counters(pernic=True)
        
        for interface, stats in net_io.items():
            if interface not in if_stats:
                if_stats[interface] = {
                    'bytes_sent': stats.bytes_sent,
                    'bytes_recv': stats.bytes_recv,
                    'time': time.time()
                }
                continue
            
            # Calculer la bande passante
            now = time.time()
            time_delta = now - if_stats[interface]['time']
            
            if time_delta > 0:
                bytes_sent_delta = stats.bytes_sent - if_stats[interface]['bytes_sent']
                bytes_recv_delta = stats.bytes_recv - if_stats[interface]['bytes_recv']
                
                send_rate = bytes_sent_delta / time_delta
                recv_rate = bytes_recv_delta / time_delta
                
                if (send_rate > 0 or recv_rate > 0) and (args.interface is None or args.interface == interface):
                    print(f"\r{Fore.YELLOW}Interface {interface}: "
                          f"{Fore.GREEN}↓ {recv_rate/1024:.1f} KB/s "
                          f"{Fore.RED}↑ {send_rate/1024:.1f} KB/s{Style.RESET_ALL}", end="")
            
            # Mettre à jour les statistiques
            if_stats[interface] = {
                'bytes_sent': stats.bytes_sent,
                'bytes_recv': stats.bytes_recv,
                'time': now
            }
            
        time.sleep(1)

def capture_packets():
    global live_capture, capture_start_time
    
    capture_start_time = time.time()
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{Back.BLUE}{Fore.WHITE}{Style.BRIGHT} WIRESHARK PYTHON ADVANCED {Style.RESET_ALL}")
    
    # Afficher les interfaces disponibles
    if args.list_interfaces:
        print(f"\n{Fore.CYAN}Interfaces réseau disponibles:{Style.RESET_ALL}")
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            ip = addrs.get(netifaces.AF_INET, [{'addr': 'Pas d\'IP'}])[0]['addr']
            print(f"  {Fore.GREEN}{iface}{Style.RESET_ALL}: {ip}")
        return
    
    print(f"{Fore.CYAN}Interface: {Fore.WHITE}{args.interface or 'Toutes'}")
    print(f"{Fore.CYAN}Filtre: {Fore.WHITE}{args.filter or 'Aucun'}")
    print(f"{Fore.CYAN}Mode: {Fore.WHITE}{'Hexadécimal activé' if args.hex else 'Normal'}")
    print(f"{Fore.YELLOW}Appuyez sur Ctrl+C pour arrêter.{Style.RESET_ALL}")
    print("\n")
    
    # Démarrer les threads pour les fonctionnalités avancées
    if args.chart:
        chart_thread = threading.Thread(target=show_live_chart)
        chart_thread.daemon = True
        chart_thread.start()
    
    if args.monitor:
        monitor_thread = threading.Thread(target=network_usage_monitor)
        monitor_thread.daemon = True
        monitor_thread.start()
    
    try:
        sniff(iface=args.interface, prn=packet_callback, store=0, 
              filter=args.filter, count=args.count)
    except KeyboardInterrupt:
        pass
    finally:
        live_capture = False
        print(f"\n{Back.RED}{Fore.WHITE} Capture terminée {Style.RESET_ALL}")
        
        # Enregistrer la capture si demandé
        if args.save and packets_captured:
            save_file = args.save if isinstance(args.save, str) else f"capture_{int(time.time())}.pcap"
            print(f"{Fore.GREEN}Enregistrement de {len(packets_captured)} paquets dans {save_file}...{Style.RESET_ALL}")
            wrpcap(save_file, packets_captured)
        
        show_stats()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f"{Back.BLUE}{Fore.WHITE} Sniffer de paquets avancé en Python {Style.RESET_ALL}")
    parser.add_argument("-i", "--interface", default=None, help="Interface réseau")
    parser.add_argument("-f", "--filter", default="", help="Filtre BPF (ex: 'port 80' ou 'host 192.168.1.1')")
    parser.add_argument("--hex", action="store_true", help="Afficher le contenu en hexadécimal")
    parser.add_argument("-c", "--count", type=int, default=0, help="Nombre de paquets à capturer (0=infini)")
    parser.add_argument("-s", "--save", nargs='?', const=True, help="Enregistrer la capture (optionnel: nom de fichier)")
    parser.add_argument("--chart", action="store_true", help="Afficher un graphique en temps réel")
    parser.add_argument("--monitor", action="store_true", help="Moniteur d'utilisation de la bande passante")
    parser.add_argument("--advanced-stats", action="store_true", help="Afficher des statistiques avancées")
    parser.add_argument("--stats-interval", type=int, default=20, help="Intervalle d'affichage des statistiques (paquets)")
    parser.add_argument("--quiet-stats", action="store_true", help="Ne pas afficher les statistiques automatiquement")
    parser.add_argument("--list-interfaces", action="store_true", help="Lister les interfaces réseau disponibles")
    args = parser.parse_args()
    
    # Vérification des droits administrateur
    if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
        print(f"{Back.RED}{Fore.WHITE}{Style.BRIGHT} Ce programme nécessite des droits administrateur {Style.RESET_ALL}")
        print("Veuillez exécuter le script en tant qu'administrateur.")
        sys.exit(1)
    
    capture_packets()