import socket
import threading
import ipaddress
import subprocess
import time

def ping_host(ip, results):
    """Ping un hôte pour vérifier s'il est en ligne"""
    try:
        # Utiliser ping intégré au système
        response = subprocess.run(
            ["ping", "-n", "1", "-w", "200", str(ip)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        if "TTL=" in response.stdout:
            try:
                hostname = socket.gethostbyaddr(str(ip))[0]
            except socket.herror:
                hostname = "Inconnu"
            results.append((str(ip), hostname))
            print(f"Appareil trouvé: {ip} ({hostname})")
    except:
        pass

def scan_network(ip_range):
    """Scan un réseau complet"""
    print(f"Scan du réseau {ip_range}...")
    network = ipaddress.ip_network(ip_range)
    
    results = []
    threads = []
    
    # Créer des threads pour scanner en parallèle
    for ip in network.hosts():
        thread = threading.Thread(target=ping_host, args=(ip, results))
        thread.daemon = True
        threads.append(thread)
        thread.start()
        
        # Limiter le nombre de threads actifs
        while sum(thread.is_alive() for thread in threads) > 50:
            time.sleep(0.1)
    
    # Attendre que tous les threads se terminent
    for thread in threads:
        thread.join()
    
    return results

def get_default_gateway():
    """Obtenir l'adresse IP de la passerelle par défaut"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connecter à une adresse externe pour obtenir la route par défaut
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        
        # Détecter le réseau basé sur l'IP locale
        ip_parts = ip.split('.')
        network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        gateway = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"
        return network, gateway, ip
    except:
        s.close()
        return "127.0.0.0/24", "127.0.0.1", "127.0.0.1"

# Obtenir le réseau local automatiquement
network, gateway, local_ip = get_default_gateway()
print(f"Adresse IP locale: {local_ip}")
print(f"Passerelle par défaut (probable): {gateway}")
print(f"Réseau à scanner: {network}")

# Scanner le réseau
devices = scan_network(network)

# Afficher les résultats
print("\nRésultats du scan:")
print("IP\t\tNom d'hôte")
print("-" * 40)
for ip, hostname in sorted(devices, key=lambda x: [int(i) for i in x[0].split('.')]):
    print(f"{ip}\t{hostname}")

# Tentative d'obtenir des informations DNS
print("\nTentative d'obtention des serveurs DNS...")
try:
    # Approche Windows
    dns_output = subprocess.check_output("ipconfig /all", shell=True, text=True)
    dns_servers = []
    for line in dns_output.split('\n'):
        if "DNS Servers" in line or "Serveurs DNS" in line:
            # Extraire l'adresse IP
            parts = line.split(':')
            if len(parts) > 1:
                dns_ip = parts[1].strip()
                if dns_ip and dns_ip not in dns_servers:
                    dns_servers.append(dns_ip)
    
    if dns_servers:
        print("Serveurs DNS trouvés:")
        for dns in dns_servers:
            print(f"- {dns}")
    else:
        print("Aucun serveur DNS trouvé")
except:
    print("Impossible d'obtenir les informations DNS")