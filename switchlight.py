import requests

ip = "192.168.1.29"

try:
    # Tentative d'envoi d'une commande directe
    response = requests.post(f"http://{ip}/app/commands", 
                            json={"system": {"set_relay_state": {"state": 0}}})
    print(f"Réponse: {response.status_code}")
    print(f"Contenu: {response.text}")
except Exception as e:
    print(f"Erreur: {e}")