import discord
import re
import os
from dotenv import load_dotenv

# Chargez votre token depuis un fichier .env pour la sécurité
load_dotenv()
TOKEN = os.getenv("discord")

# Créez le client Discord
intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)

# Regex pour trouver les adresses IP
ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
found_ips = set()  # Ensemble pour stocker les IPs uniques trouvées

ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
found_ips = set()  # Ensemble pour stocker les IPs uniques trouvées

@client.event
async def on_ready():
    print(f'{client.user} est connecté à Discord!')
    
    # Sélectionnez le serveur et le canal où vous voulez chercher
    guild = client.guilds[0]  # Prend le premier serveur (modifiez si nécessaire)
    
    # Patterns pour détecter différents formats d'IP
    ip_patterns = [
        re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),  # IPv4 standard (192.168.1.1)
        re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}:\d+\b'),  # IP avec port (192.168.1.1:25565)
        re.compile(r'mc\.[\w\-]+\.[\w\-\.]+'),  # Domaines Minecraft (mc.example.com)
        re.compile(r'play\.[\w\-]+\.[\w\-\.]+'),  # Domaines courants (play.example.com)
        re.compile(r'\b[\w\-]+\.aternos\.me\b'),  # Domaines Aternos
        re.compile(r'\b[\w\-]+\.minehut\.gg\b'),  # Domaines Minehut
        re.compile(r'\bserver\.[\w\-]+\.[\w\-\.]+\b'),  # Serveurs génériques
        re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
        re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?'),
    ]
    
    for channel in guild.text_channels:
        try:
            print(f'Recherche d\'adresses IP dans #{channel.name}...')
            
            # Parcourir les messages
            async for message in channel.history(limit=5000):
                # Capture le message complet, peu importe sa longueur
                full_content = message.content
                
                # Traitement des longs messages en les découpant si nécessaire
                for pattern in ip_patterns:
                    ip_matches = pattern.findall(full_content)
                    for ip in ip_matches:
                        found_ips.add(ip)
                        
                        # Extrait un contexte autour de l'IP pour faciliter la vérification
                        start_idx = max(0, full_content.find(ip) - 50)
                        end_idx = min(len(full_content), full_content.find(ip) + len(ip) + 50)
                        context = full_content[start_idx:end_idx]
                        
                        print(f"IP trouvée dans #{channel.name}: {ip}")
                        print(f"Contexte: ...{context}...")
                
                # Vérifier les embeds
                for embed in message.embeds:
                    if embed.description:
                        for pattern in ip_patterns:
                            ip_matches = pattern.findall(embed.description)
                            for ip in ip_matches:
                                found_ips.add(ip)
                                print(f"IP trouvée dans embed #{channel.name}: {ip}")
                    
                    # Vérifier les champs de l'embed aussi
                    for field in embed.fields:
                        for pattern in ip_patterns:
                            if field.value:
                                ip_matches = pattern.findall(field.value)
                                for ip in ip_matches:
                                    found_ips.add(ip)
                                    print(f"IP trouvée dans embed (champ) #{channel.name}: {ip}")
                
                # Vérifier les liens dans les attachements
                for attachment in message.attachments:
                    if attachment.url:
                        for pattern in ip_patterns:
                            ip_matches = pattern.findall(attachment.url)
                            for ip in ip_matches:
                                found_ips.add(ip)
                                print(f"IP trouvée dans attachment #{channel.name}: {ip}")
        
        except Exception as e:
            print(f"Impossible d'accéder au canal #{channel.name}: {str(e)}")
    
    # Afficher les résultats finaux
    print(f"\nAdresses IP trouvées ({len(found_ips)}):")
    for ip in sorted(found_ips):
        print(f"- {ip}")
    
    await client.close()

# Lancez le client
client.run(TOKEN)