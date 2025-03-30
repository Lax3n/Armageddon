import socket
import threading
from queue import Queue

target = "8.8.8.8"  
queue = Queue()
open_ports = []


def port_scan(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    except:
        pass

def threader():
    while not queue.empty():
        port = queue.get()
        port_scan(port)
        queue.task_done()


print(f"🔍 Démarrage du scan sur {target}...")
def main():
    for port in range(0, 65535): 
        if port % 10000 == 0:
            print(f"🔄 Scan des ports {port} à {port + 9999}")
        queue.put(port)

    # Créez et lancez les threads
    thread_list = []
    for t in range(1000):  # Nombre de threads
        thread = threading.Thread(target=threader)
        thread_list.append(thread)
        thread.daemon = True
        thread.start()

    queue.join()

    # Affichez les résultats
    if open_ports:
        print(f"✅ Scan terminé ! {len(open_ports)} ports ouverts trouvés:")
        for port in sorted(open_ports):
            try:
                service = socket.getservbyport(port)
                print(f"🔓 Port {port}: {service}")
            except:
                print(f"🔓 Port {port}: service inconnu")
    else:
        print("🔒 Aucun port ouvert trouvé")
    print("🏁 Scan terminé !")

if __name__ == "__main__":
    main()