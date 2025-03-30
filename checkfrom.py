import requests

def get_ip_info(ip_address):
    response = requests.get(f"http://ip-api.com/json/{ip_address}")
    data = response.json()
    
    if data["status"] == "success":
        print(f"🔍 Informations pour l'IP {ip_address}:")
        print(f"📍 Localisation: {data.get('city', 'Inconnue')}, {data.get('regionName', 'Inconnu')}, {data.get('country', 'Inconnu')}")
        print(f"🌐 FAI: {data.get('isp', 'Inconnu')}")

        if 'org' in data and data['org']:
            print(f"🏢 Organisation: {data['org']}")
        
        if 'timezone' in data:
            print(f"⏰ Fuseau horaire: {data['timezone']}")
            
        # Coordonnées si disponibles
        if 'lat' in data and 'lon' in data:
            print(f"🗺️ Coordonnées: {data['lat']}, {data['lon']}")
    else:
        print("❌ Impossible de trouver des informations pour cette IP")


ip = "8.8.8.8" 
get_ip_info(ip)