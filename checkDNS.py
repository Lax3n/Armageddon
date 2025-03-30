import socket
import subprocess
import threading
import re
import time

def get_local_ip():
    """Obtenir l'adresse IP locale"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))  # Adresse Google DNS
        local_ip = s.getsockname()[0]
    except:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    return local_ip

def get_network_prefix(ip):
    """Obtenir le préfixe réseau à partir de l'IP locale"""
    parts = ip.split('.')
    return f"{parts[0]}.{parts[1]}.{parts[2]}"

def ping_host(ip, results, lock):
    """Ping un hôte pour vérifier s'il est en ligne"""
    try:
        # Utiliser ping intégré au système
        ping_cmd = ["ping", "-n", "1", "-w", "500", ip]
        response = subprocess.run(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if "TTL=" in response.stdout:
            hostname = "Inconnu"
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                pass
                
            with lock:
                results.append((ip, hostname))
                print(f"Trouvé: {ip} ({hostname})")
    except:
        pass

def get_dns_servers():
    """Obtenir les serveurs DNS configurés sur Windows"""
    dns_servers = []
    try:
        output = subprocess.check_output("ipconfig /all", shell=True, text=True)
        for line in output.split('\n'):
            if "DNS Servers" in line or "Serveurs DNS" in line:
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if ip_match:
                    dns_servers.append(ip_match.group(1))
    except:
        pass
        
    return dns_servers

# Programme principal
def main():
    print("📡 Scanner de réseau local 📡")
    
    # Obtenir l'IP locale
    local_ip = get_local_ip()
    network_prefix = get_network_prefix(local_ip)
    print(f"IP locale: {local_ip}")
    print(f"Préfixe réseau: {network_prefix}")
    
    # Obtenir l'adresse de la passerelle (généralement .1 ou .254)
    gateway = f"{network_prefix}.1"
    print(f"Passerelle probable: {gateway}")
    
    # Obtenir les serveurs DNS
    dns_servers = get_dns_servers()
    if dns_servers:
        print("Serveurs DNS:")
        for dns in dns_servers:
            print(f"- {dns}")
    else:
        print("Aucun serveur DNS trouvé")
    
    # Scanner le réseau
    print(f"\nScan du réseau {network_prefix}.0/24...")
    results = []
    lock = threading.Lock()
    threads = []
    
    for i in range(1, 255):
        ip = f"{network_prefix}.{i}"
        thread = threading.Thread(target=ping_host, args=(ip, results, lock))
        thread.daemon = True
        threads.append(thread)
        thread.start()
        
        # Limiter le nombre de threads simultanés
        while sum(t.is_alive() for t in threads) > 50:
            time.sleep(0.1)
    
    # Attendre la fin de tous les threads
    for thread in threads:
        thread.join()
    
    # Afficher les résultats
    print(f"\n🔍 Résultats du scan ({len(results)} appareils trouvés):")
    print("IP\t\tNom d'hôte")
    print("-" * 50)
    
    for ip, hostname in sorted(results, key=lambda x: [int(i) for i in x[0].split('.')]):
        print(f"{ip}\t{hostname}")

if __name__ == "__main__":
    main()