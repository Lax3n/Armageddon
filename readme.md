# ARMAGEDDON

A collection of Python network reconnaissance and analysis tools.

## Tools

* `scanlocal.py` - Scans local network to discover active devices
* `checkDNS.py` - Identifies DNS servers and active hosts on your network
* `checkfrom.py` - Retrieves geolocation and organization info for IP addresses
* `checkport.py` - Port scanner with service identification
* `checkforIP.py` - Discord bot that detects IP addresses in messages
* `switchlight.py` - Example for controlling network-connected devices

## Setup

1. Clone the repository
2. Create a `.env` file in the root directory
3. For Discord functionality, add your token: `discord=YOUR_DISCORD_TOKEN`

## Usage

Run each tool individually:

<pre><div class="relative flex flex-col rounded-lg"><div class="text-text-300 absolute pl-3 pt-2.5 text-xs"></div><div class="pointer-events-none sticky my-0.5 ml-0.5 flex items-center justify-end px-1.5 py-1 mix-blend-luminosity top-0"><div class="from-bg-300/90 to-bg-300/70 pointer-events-auto rounded-md bg-gradient-to-b p-0.5 backdrop-blur-md"><button class="flex flex-row items-center gap-1 rounded-md p-1 py-0.5 text-xs transition-opacity delay-100 text-text-300 active:scale-95 select-none hover:bg-bg-200 opacity-60 hover:opacity-100" data-state="closed"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 256 256" class="text-text-500 mr-px -translate-y-[0.5px]"><path d="M200,32H163.74a47.92,47.92,0,0,0-71.48,0H56A16,16,0,0,0,40,48V216a16,16,0,0,0,16,16H200a16,16,0,0,0,16-16V48A16,16,0,0,0,200,32Zm-72,0a32,32,0,0,1,32,32H96A32,32,0,0,1,128,32Zm72,184H56V48H82.75A47.93,47.93,0,0,0,80,64v8a8,8,0,0,0,8,8h80a8,8,0,0,0,8-8V64a47.93,47.93,0,0,0-2.75-16H200Z"></path></svg><span class="text-text-200 pr-0.5">Copier</span></button></div></div><div><div class="prismjs code-block__code !my-0 !rounded-lg !text-sm !leading-relaxed"><code><span class=""><span class="">python scanlocal.py
</span></span><span class="">python checkport.py
</span><span class="">python checkDNS.py</span></code></div></div></div></pre>

**Note:** For educational and authorized network administration purposes only.

Réessayer

[Claude peut faire des erreurs. Assurez-vous de vérifier ses réponses.](https://support.anthropic.com/en/articles/8525154-claude-is-providing-incorrect-or-misleading-responses-what-s-going-on)
