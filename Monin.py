#!/usr/bin/env python3

# Gemaakt door: Jonas Willems
# Stage: Monin NV - (SEP-DEC-2023)


# BEGIN IMPORTS
# STANDAARD
import os
import re
import json
import time
import signal
import ipaddress
import subprocess
from datetime import datetime
# EXTERN
from tabulate import tabulate
from tqdm import tqdm
from ping3 import ping
import nmapthon2 as nm2
# EINDE IMPORTS


# BEGIN KLEURCODES
groen = "\033[38;2;50;205;50m"
vet_groen = "\033[1;38;2;50;205;50m"
geel = "\033[38;2;255;255;0m"
rood = "\033[38;2;255;0;0m"
vet_rood = "\033[1;38;2;255;0;0m"
blauw = "\033[34m"
reset = "\033[0m"
# EINDE KLEURCODES


# FUNCTIES
def afsluit_signaal(sig, frame):
    herstel_scherm()
    print(f"\n{blauw}Gesloten. Tot de volgende keer!{reset}")
    exit(0)

def herstel_scherm():
    os.system("clear")
    toon_logo()

def tel_aantal_hosts():
    try:
        with open(f'Scans/{filename}', 'r') as json_file:
            data = json.load(json_file)
            return len(data.get('Hosts', []))
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        return 0

def haal_host_lijst_op():
    host_list = []
    try:
        with open(f'Scans/{filename}', 'r') as json_file:
            data = json.load(json_file)
            host_list = data.get('Hosts', [])
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        pass

    return host_list

def toon_logo():
    print(f"""
    {vet_rood}
    __  ___            _      _          ____  ____       ____                           __            
   /  |/  /___  ____  (_)___ ( )_____   / __ \/ __ )     /  _/___  _________  ___  _____/ /_____  _____
  / /|_/ / __ \/ __ \/ / __ \|// ___/  / / / / __  |     / // __ \/ ___/ __ \/ _ \/ ___/ __/ __ \/ ___/
 / /  / / /_/ / / / / / / / / (__  )  / /_/ / /_/ /    _/ // / / (__  ) /_/ /  __/ /__/ /_/ /_/ / /    
/_/  /_/\____/_/ /_/_/_/ /_/ /____/  /_____/_____(_)  /___/_/ /_/____/ .___/\___/\___/\__/\____/_/     
                                                                    /_/                            {reset}
                                  {geel} Monin's Security Tool\n{reset}
                                        {blauw}Versie:{vet_groen} 1.0{reset}
                               {blauw}Ontwikkeld door: {vet_groen}Jonas Willems{reset}""")

def toon_scantekst():
    print(f"\n{groen}Even geduld...{reset} {geel}De scan is bezig,{reset} {geel}neem een kopje koffie{reset} {geel}en ontspan.{reset}\n")

def toon_menu_opties(num_db_systems):
    print(f"""\n{blauw}1. Zoeken naar databasesystemen. Gevonden{reset}: {num_db_systems}{blauw}\n2. Security assessments\n3. Afsluiten{reset}\n""")

def toon_scan_menu():
    print(f"\n{blauw}1. Nieuwe scan\n2. Scan laden\n{reset}")

def laad_scan():
    scan_files = [f for f in os.listdir("Scans") if f.endswith(".json")]
    if not scan_files:

        input(f"\n{rood}Geen scanbestanden gevonden. Druk op enter om door te gaan.{reset}")
        return None
    
    while True:
        print(f"\n{blauw}Beschikbare scans:{reset}")
        for i, file in enumerate(scan_files, start=1):
            print(f"  {i}. {file}")

        selection = input(f"\n{blauw}Selecteer een scan (1-{len(scan_files)}): {reset}")

        try:
            selected_index = int(selection) - 1
            selected_file = scan_files[selected_index]
            return selected_file
        except (ValueError, IndexError):
            input(f"\n{rood}Ongeldige selectie. Druk op enter om het opnieuw te proberen.{reset}")
            herstel_scherm()

def bewaar_scanresultaten(scan_data, start, end):
    max_id = 0
    if os.path.exists(filename):
        with open('Scans/' + filename, 'r') as json_file:
            try:
                existing_data = json.load(json_file)
                if existing_data:
                    max_id = max(entry['ID'] for entry in existing_data)
            except json.decoder.JSONDecodeError:
                existing_data = []

    id_counter = max_id
    results = {}

    for result in scan_data:
        for host in result:
            id_counter += 1
            ip_address = str(host.ip)
            if ip_address not in results:
                results[ip_address] = {'ID': id_counter, 'IP': ip_address, 'Services': []}
            for port in host:
                service = port.service
                if service is not None and port.state == "open":
                    entry = {
                        'Poort': int(service.port),
                        'Service': service.name,
                        'Product': service.product,
                        'Versie': service.version,
                    }

                    if service.name == "oracle" or service.name == "oracle-tns" and service.version == "0.0.0.0.0":
                        del entry['Versie']

                    if service.name == "ftp":
                        
                        anonymous_login_found = False
                        for name, output in port.service.all_scripts():
                            if name == "ftp-anon":
                                lines = output.split("\n")
                                for line in lines:
                                    if "Anonymous FTP login allowed" in line:
                                        entry['Anonymous_Login'] = True
                                        anonymous_login_found = True
                                        break
                        if not anonymous_login_found:
                                entry['Anonymous_Login'] = False  

                    if service.name == "mysql":
                        for name, output in port.service.all_scripts():
                            if name == "mysql-info" or name == "fingerprint-strings":
                                lines = output.split("\n")
                                for line in lines:
                                    if "MariaDB" in line:
                                        product_version_match = re.search(r"Version: (\d+\.\d+\.\d+)-MariaDB", line)
                                        if product_version_match:
                                            entry['Product'] = "MariaDB"
                                            entry['Versie'] = product_version_match.group(1)
                            else:
                                entry['Product'] = service.product
                                entry['Versie'] = service.version

                    if service.product == "MySQL":
                        entry['Product'] = "MySQL"

                    if service.name == "ms-sql-s":
                        for name, output in port.service.all_scripts():
                            if name == "ms-sql-ntlm-info" or name == "ms-sql-info":
                                lines = output.split("\n")
                                for line in lines:
                                    if "Target_Name:" in line:
                                        target_name_match = re.search(r"Target_Name: (\w+[-\w]+)", line)
                                        if target_name_match:
                                            entry['Naam'] = target_name_match.group(1)
                                    # if "Instance name:" in line:
                                    #     instance_name_match = re.search(r"Instance name: (\w+[-\w]+)", line)
                                    #     if instance_name_match:
                                    #         entry['Instance'] = instance_name_match.group(1)

                    results[ip_address]['Services'].append(entry)

    # Lees de bestaande gegevens in als het bestand al bestaat
    existing_data = []
    if os.path.exists(filename):
        with open('Scans/' + filename, 'r') as json_file:
            try:
                existing_data = json.load(json_file)
            except json.decoder.JSONDecodeError:
                existing_data = []
    # Voeg de nieuwe resultaten toe aan de bestaande gegevens
    if results:
        existing_data.extend(results.values())

        # Voeg start- en eindtimestamps toe aan de hele JSON-structuur
    json_structure = {
        "StartTime": start,
        "EndTime": end,
        "Hosts": existing_data
    }

    # Schrijf de gecombineerde gegevens naar het bestand
    # with open('Scans/' + filename, 'w') as json_file:
    #     json.dump(existing_data, json_file, indent=4)
    with open('Scans/' + filename, 'w') as json_file:
        json.dump(json_structure, json_file, indent=4)

def vind_actieve_hosts(target, timeout=3):
    if isinstance(target, list):
        target_ips = target
    else:
        target_ips = [target]

    active_hosts = []
    total_hosts = len(target_ips)
    print((f"{blauw}Zoeken naar live hosts{reset}:"))

    with tqdm(total=total_hosts, ncols=95, bar_format="{l_bar}{bar}{r_bar}", position=0, leave=False, colour='green') as pbar:
        for ip in target_ips:
            pbar.set_description(f"{blauw}Pinging IP{reset}: {ip}")
            response_time = ping(ip, timeout=timeout)
            if response_time is not None and response_time > 0:
                active_hosts.append(ip)
            pbar.update(1)

    return active_hosts

def toon_scanresultaten():
    try:
        with open('Scans/' + filename, 'r') as json_file:
            data = json.load(json_file)

        # Extract timestamps
        start_time = data.get("StartTime", "")
        # end_time = data.get("EndTime", "")

        print(f"\n{blauw}Gevonden op: {groen}{start_time}{reset}")
        # print(f"Scan ended at: {end_time}")

        # Group services by database technology
        grouped_services = {
            'oracle-tns': [],
            'ms-sql-s': [],
            'postgresql': [],
            'mysql': [],
        }

        if 'Hosts' in data:
            hosts = data['Hosts']
            # Populate grouped_services
            for entry in hosts:
                ip = entry.get("IP", "")
                services = entry.get("Services", [])

                for service in services:
                    service_type = service.get("Service", "")

                    if service_type in grouped_services:
                        entry_data = {
                            'ID': entry.get("ID", ""),
                            'IP': ip,
                            'Poort': service.get("Poort", ""),
                            'Product': service.get("Product", ""),
                            'Versie': service.get("Versie", ""),
                            'Naam': service.get("Naam", "") if service_type == 'ms-sql-s' else "",
                            # 'Instance': service.get("Instance", "") if service_type == 'ms-sql-s' else "",
                        }

                        grouped_services[service_type].append(entry_data)

            # Display database technology distribution
            for service_type, services in grouped_services.items():
                if len(services) > 0:
                    if service_type == "oracle-tns":
                        tech_title = f"\n{blauw}Oracle Database(s):{reset}\n"
                    elif service_type == "ms-sql-s":
                        tech_title = f"{blauw}Microsoft SQL Server Database(s):{reset}\n"
                    elif service_type == "postgresql":
                        tech_title = f"{blauw}PostgreSQL Database(s):{reset}\n"
                    elif service_type == "mysql":
                        tech_title = f"{blauw}MySQL Database(s):{reset}\n"
                    else:
                        tech_title = service_type.capitalize()

                    print(tech_title)

                    # table_headers = ['ID', 'IP', 'Poort', 'Product', 'Versie', 'Naam', 'Instance']
                    table_headers = ['ID', 'IP', 'Poort', 'Product', 'Versie', 'Naam']

                    # Add 'Naam' and 'Instance' headers only for MS SQL servers
                    if service_type != 'ms-sql-s':
                        table_headers.remove('Naam')
                        # table_headers.remove('Instance')

                    table_data = [
                        [entry.get(field, "") for field in table_headers] for entry in services
                    ]

                    # Use 'plain' format to remove lines
                    table_format = "plain"
                    colored_table = [[f'{groen}{str(cell)}{reset}' for cell in row] for row in table_data]
                    print(tabulate(colored_table, headers=table_headers, tablefmt=table_format))
                    print("\n")


    except FileNotFoundError:
        print("Het JSON-bestand met db-systemen is niet gevonden.")

def toon_host_details(host_info):
    print(f"\n{blauw}IP Address:{reset} {host_info['IP']}")
    services = host_info.get("Services", [])
    ms_sql_present = any(service.get("Service") == "ms-sql-s" for service in services)
    
    if services:
        # Bouw de tabelheaders op basis van de aanwezige velden in de services
        table_headers = ['Poort', 'Service', 'Product', 'Versie']
        if ms_sql_present:
            table_headers += ['Naam']
            # table_headers += ['Naam', 'Instance']

        table_data = [
            [
                service.get(field, "") if field in service else ""
                for field in table_headers
            ]
            for service in services
        ]

        # Gebruik 'pretty' formaat voor een mooi opgemaakte tabel
        table_format = "plain"
        colored_table = [[f'{groen}{str(cell)}{reset}' for cell in row] for row in table_data]
        print(tabulate(colored_table, headers=table_headers, tablefmt=table_format))
        # print("\n")
    else:
        print("No services found for this host.")

def detecteer_databases(host_list):

    if isinstance(host_list, str):
        host_list = [host_list]

    already_scanned_ips = []
    ips_with_db = []
    resultaten = []

    for target_ip in host_list:
        herstel_scherm()
        toon_scantekst()
        print(f"{blauw}Zoeken naar databases over{reset} {len(host_list)} {blauw}host(s){reset}: {blauw}Gevonden{reset}: {len(ips_with_db)}\n")
        # show ip table
        num_columns = 5
        if len(host_list) > 1:
            num_columns = min(num_columns, len(host_list)) 
            data = [[] for _ in range(len(host_list) // num_columns)]
        else:
            data = [[]]
        for i, ip in enumerate(host_list):
            if ip == target_ip:
                ip = f"{geel}{ip}{reset}"
            elif ip in ips_with_db:
                ip = f"{groen}{ip}{reset}"
            elif ip in already_scanned_ips:
                ip = f"{rood}{ip}{reset}"
            else:
                ip = f"{ip}" 
            if data:
                data[i % len(data)].append(ip)
        table = tabulate(data, tablefmt='plain')
        print(table + "\n")
        already_scanned_ips.append(target_ip)
        # end show ip table

        try:
            scanner = nm2.NmapAsyncScanner()
            scanner.scan(target_ip, arguments='', ports='3306,5432,1521,1433', with_status=True, output='normal', status_interval='2s')
            pbar = tqdm(total=100, ncols=95, bar_format="{l_bar}{bar}{r_bar}", position=0, leave=False, colour='green')
            pbar.set_description(f"{blauw}Scanning host{reset}: " + target_ip)

            while not scanner.finished():
                status = scanner.get_status()
                if status:
                    pbar.n = status.percent
                    pbar.refresh()
                time.sleep(0.2)
            
            pbar.n = 100
            pbar.refresh()
            pbar.close()
            
            result = scanner.get_result()
            # scan_data = result.get_output("normal")

        except nm2.exceptions.NmapScanError as e:
            print(f"Error scanning {target_ip}: {e}")
            time.sleep(0.5)
            continue


        db_system_names = ['mysql', 'ms-sql-s', 'postgresql', 'oracle', 'oracle-tns']
        for host in result:
            for port in host:
                service = port.service
                if service is not None and port.state == "open":
                    if service.name in db_system_names:
                        ips_with_db.append(target_ip)
                        resultaten.append(result)


    # NA DE SCAN
    if not resultaten:
        herstel_scherm()
        print(f"{rood}Geen database gevonden.{reset}")
        input(f"\n{blauw}Druk op Enter om door te gaan.{reset}")
    else:
        herstel_scherm()
        print(f"\n{len(resultaten)}{blauw} database(s) gevonden.{reset}")
        # input(f"\n{blauw}Druk op Enter om door te gaan.{reset}")
        detecteer_services(resultaten)

def detecteer_services(list):
    start_timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")  
    resultaten = []

    already_scanned_ips = []
    host_list = []

    for result in list:
        for host in result:
            host_list.append(host.ip)

    for result in list:
        for host in result:
            herstel_scherm()
            toon_scantekst()
            print(f"{blauw}Zoeken naar services op {reset}{len(list)}{blauw} database(s){reset}.\n")

            # show ip table
            num_columns = 5
            if len(host_list) > 1:
                num_columns = min(num_columns, len(host_list)) 
                data = [[] for _ in range(len(host_list) // num_columns)]
            else:
                data = [[]]
            for i, ip in enumerate(host_list):
                if ip == host.ip:
                    ip = f"{geel}{ip}{reset}"
                elif ip in already_scanned_ips:
                    ip = f"{groen}{ip}{reset}"
                # elif ip in already_scanned_ips:
                #     ip = f"{groen}{ip}{reset}"
                else:
                    ip = f"{ip}" 
                if data:
                    data[i % len(data)].append(ip)
            table = tabulate(data, tablefmt='plain')
            print(table + "\n")
            already_scanned_ips.append(host.ip)
            # end show ip table

            try:
                scanner = nm2.NmapAsyncScanner()
                # --host-timeout  <- argument eventueel nog toevoegen
                # scanner.scan(host.ip, arguments='-sV -sC', ports='', with_status=True, output='all', status_interval='2s')
                scanner.scan(host.ip, arguments='-sV -sC', ports='21,22,3306,5432,1521,1433', with_status=True, output='all', status_interval='2s')
                pbar = tqdm(total=100, ncols=95, bar_format="{l_bar}{bar}{r_bar}", position=0, leave=False, colour='green')
                pbar.set_description(f"{blauw}Scanning host{reset}: " + host.ip)

                while not scanner.finished():
                    status = scanner.get_status()
                    if status:
                        pbar.n = status.percent
                        pbar.refresh()
                    time.sleep(0.2)
                
                pbar.n = 100
                pbar.refresh()
                pbar.close()

                result = scanner.get_result()

                # INFO
                # output = result.get_output("normal")
                # print(output)
                # time.sleep(10)

                resultaten.append(result)

            except nm2.exceptions.NmapScanError as e:
                print(f"Error scanning {host.ip}: {e}")
                time.sleep(0.5)
                continue
        
    end_timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    bewaar_scanresultaten(resultaten, start_timestamp, end_timestamp)

def detecteer_beschikbare_testen(host):
    print(f"\n{blauw}Beschikbare modules:{reset}")
    services_list = host.get("Services", [])
    ssh_present = any(service.get("Service", "") == "ssh" for service in services_list)
    ftp_present = any(service.get("Service", "") == "ftp" for service in services_list)

    if ssh_present:
        print("  1. SSH - Credentials Test")
    if ftp_present:
        print("  2. FTP - Credentials Test")

    if not (ssh_present or ftp_present):
        print(f"{rood}  GEEN{reset}")
        input(f"\n{blauw}Druk op Enter om terug te gaan: {reset}")
        security_beoordelingen()
        return

    while True:
        module_choice = input(f"\n{blauw}Kies een module (1/2) Enter om terug te gaan: {reset}").strip()

        if not module_choice:
            security_beoordelingen()
            break

        if module_choice in ["1", "2"]:
            ip_address = host.get("IP")

            if module_choice == "1" and ssh_present:
                while True:
                    found_pass = ssh_creds(ip_address)
                    if found_pass:
                        input(f"\n{blauw}Enter om door te gaan.{reset}")
                        herstel_scherm()
                        toon_menu_opties(tel_aantal_hosts())
                        break
                    else:
                        choice = input(f"\n{blauw}Wil je opnieuw proberen met een ander username? y/n: {reset}").lower()
                        if choice != 'y':
                            herstel_scherm()
                            toon_menu_opties(tel_aantal_hosts())
                            break
                break

            elif module_choice == "2" and ftp_present:
                while True:
                    ftp_service = next((service for service in services_list if service.get("Service") == "ftp"), None)
                    anonymous = ftp_service.get("Anonymous_Login") if ftp_service else None
                    found_pass = ftp_creds(ip_address, anonymous)
                    if found_pass:
                        input(f"\n{blauw}Enter om door te gaan.{reset}")
                        break
                    else:
                        choice = input(f"\n{blauw}Wil je opnieuw proberen met een ander username? y/n: {reset}").lower()
                        if choice != 'y':
                            break
                break

        else:
            input(f"{rood}Ongeldige keuze. Druk op Enter om opnieuw te proberen.{reset}")
            herstel_scherm()
            toon_host_details(host)

def ftp_creds(ip, anonymous):
    password_list = "Wordlist/Wordlist"
    xservice = "ftp"

    if anonymous == True:
        herstel_scherm()
        print(f"\n{blauw}FTP - Credentials Test: {reset}{groen}Anonymous login mogelijk {reset}")
        xusername = input(f"{blauw}Enter een username: {reset}")
    else:
        herstel_scherm()
        print(f"\n{blauw}FTP - Credentials Test: {reset}{rood}Anonymous login niet mogelijk {reset}")
        xusername = input(f"{blauw}Enter een username: {reset}")

    herstel_scherm()
    print(f"\n{groen}Starting Hydra...{reset}")
    foundpass = start_thc_hydra(ip, xusername, password_list, xservice)
    if foundpass == None:
        return False
    else:
        return True
    
def ssh_creds(ip):
    password_list = "Wordlist/Wordlist"
    xservice = "ssh"
    herstel_scherm()
    print(f"\n{blauw}SSH - Credentials Test{reset}")
    xusername = input(f"{blauw}Enter een username: {reset}")
    herstel_scherm()
    print(f"\n{groen}Starting Hydra...{reset}")
    foundpass = start_thc_hydra(ip, xusername, password_list, xservice)
    if foundpass == None:
        return False
    else:
        return True

def start_thc_hydra(target, username, password_list, service):
    try:
        command = f"hydra -d -l {username} -P {password_list} {target} {service} -I -T 5"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=0, universal_newlines=True)      
        foundpass = None
        start_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        passmatch_pattern = re.compile(r"cpass (\S+), tlogin (\S+), tpass (\S+), redo \d+")
        finalmatch_pattern = re.compile(r"password: (\S+)")

        while True:
            output = process.stdout.readline()
            if not output and process.poll() is not None:
                break  # Uit de lus als er geen uitvoer meer is en het subprocess is voltooid

            if username == "anonymous":
                foundpass = "anypass5"
                reason = f"{groen}anonymous login mogelijk{reset}"
                break
            
            reason = ""
            if "[ERROR]" in output:
                if "kex error" in output:
                    reason = f"{rood}Fout in het Key Exchange-algoritme.{reset}"
                elif "Connection refused" in output:
                    reason = f"{rood}Connection refused.{reset}"
                elif "Connection reset by peer" in output:
                    reason = f"{rood}Connection reset by peer.{reset}"
                elif "disconnected" in output:
                    reason = f"{rood}Disconnected.{reset}"

            if "[DEBUG] send_next_pair_mid done" in output:
                passmatch = passmatch_pattern.search(output)
                if passmatch:
                    tested_password = passmatch.group(1)
                    herstel_scherm()
                    print(f"\n{blauw}{service.upper()} - Credentials Test{reset}: {geel}Testing passwords...{reset}\n")
                    print(f"{blauw}Started{reset}: {start_timestamp}")
                    print(f"\n{blauw}Gebruikersnaam{reset}: {rood}{username}{reset}")
                    print(f"{blauw}Database IPv4{reset}: {target}")
                    print(f"{blauw}Password file{reset}: {password_list}")
                    print(f"{blauw}Testing password{reset}: {rood}{tested_password}{reset}")
                    time.sleep(0.1)

            if "[22][ssh] host" in output or "[21][ftp] host" in output:
                finalmatch = finalmatch_pattern.search(output)
                if finalmatch:
                    foundpass = finalmatch.group(1)


        end_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        herstel_scherm()
        

        if foundpass != None:
            reason = (f"{groen}Password gevonden.{reset}")
            print(f"\n{blauw}{service.upper()} - Credentials Test{reset}: {groen}Credentials found.{reset}\n")
            print(f"{blauw}Started{reset}: {start_timestamp}")
            print(f"{blauw}Ended{reset}: {end_timestamp}\n")
            print(f"\n{blauw}Gebruikersnaam{reset}: {groen}{username}{reset}")
            print(f"{blauw}Database IPv4{reset}: {target}")
            print(f"{blauw}Password file{reset}: {password_list}")
            print(f"{blauw}Gevonden password{reset}: {groen}{foundpass}{reset}")
            print(f"{blauw}Reden{reset}: {reason if reason else 'N/A'}")
        else:
            if reason == "":
                reason = f"{rood}Password not in list.{reset}"
            print(f"\n{blauw}{service.upper()} - Credentials Test{reset}: {rood}Credentials not found.{reset}\n")
            print(f"{blauw}Started{reset}: {start_timestamp}")
            print(f"{blauw}Ended{reset}: {end_timestamp}\n")
            print(f"\n{blauw}Gebruikersnaam{reset}: {rood}{username}{reset}")
            print(f"{blauw}Database IPv4{reset}: {target}")
            print(f"{blauw}Password file{reset}: {password_list}")
            print(f"{blauw}Gevonden password{reset}: {rood}GEEN{reset}")
            print(f"{blauw}Reden{reset}: {reason if reason else 'N/A'}")

    except subprocess.CalledProcessError as e:
        print(f"Command failed with return code {e.returncode}. Output: {e.output}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    return foundpass

# HOOFDOPTIES
def zoek_database_systemen():
    while True:
        herstel_scherm()
        print(f"\n{blauw}Opties voor het zoeken:{reset}\n")
        print(f"{blauw}1. Heel netwerk (CIDR-notatie bv. 192.168.1.0/24){reset}")
        print(f"{blauw}2. Meerdere IP's (gescheiden met komma's (,) bv. 192.168.1.1,192.168.1.5){reset}")
        print(f"{blauw}3. IP-bereik (gescheiden met streepje (-) bv. 192.168.1.0-192.168.1.5{reset}")
        print(f"{blauw}4. Enkele host (bv. 192.168.1.5){reset}")
        choice = input(f"\n{blauw}Selecteer een optie (1/2/3/4): Enter om terug te gaan: {reset}")
        if choice == '1':
            while True:
                herstel_scherm()
                # target_ip_network = "172.24.250.128/25"
                target_ip_network = input(f"\n\n{blauw}Voer het CIDR-blok in (bv. 192.168.1.0/24):{reset} ")
                try:
                    target_ip_list = [str(ip) for ip in ipaddress.IPv4Network(target_ip_network, strict=False)]
                    # Verwijder het laatste IP-adres (broadcast-adres)
                    target_ip_list = target_ip_list[:-1]
                    herstel_scherm()
                    print(f"\n{blauw}Target netwerk{reset}:\n" + target_ip_network + "\n")

                    host_list = vind_actieve_hosts(target_ip_list)
                    
                    if host_list:
                        detecteer_databases(host_list)
                        break
                    else:
                        herstel_scherm()
                        input(f"{rood}Geen hosts gevonden.{reset}") 
                        break 
                except (ValueError,ipaddress.AddressValueError):
                    herstel_scherm()
                    print(f"\n{rood}Ongeldige CIDR-notatie. Voer een geldige CIDR-notatie in (bijv. 192.168.1.0/24).{reset}")
                    input(f"{rood}Druk op enter om het opnieuw te proberen.{reset}")
        elif choice == '2':
            while True:
                herstel_scherm()
                ips_input = input(f"\n\n{blauw}Voer meerdere IP-adressen in, gescheiden door komma's: {reset}")
                # ips_input = "172.24.250.193,172.24.250.198,172.24.250.199,172.24.250.216,172.24.250.217,172.24.250.218"
                # ips_input = "172.24.250.216,172.24.250.218"
                herstel_scherm()
                try:
                    ips = [ip.strip() for ip in ips_input.split(",")]
                    if all(ipaddress.ip_address(ip).version == 4 for ip in ips):
                        print("")
                        host_list = vind_actieve_hosts(ips)
                        if host_list:
                            detecteer_databases(host_list)
                            break
                except (ValueError,ipaddress.AddressValueError):
                    herstel_scherm()
                    print(f"\n{rood}Ongeldige IPv4-adressen. Voer geldige IPv4-adressen in, gescheiden door komma's.{reset}")
                    input(f"{rood}Druk op enter om het opnieuw te proberen.{reset}")
       
        elif choice == '3':
            while True:
                herstel_scherm()
                # ip_range = "172.24.250.150-172.24.250.220"
                ip_range = input(f"\n\n{blauw}Voer het IP-bereik in met een streepje (-). Bv. 192.168.1.1-192.168.1.10:{reset} ")
                try:
                    herstel_scherm()
                    start_ip, end_ip = ip_range.split("-")
                    start_ip = ipaddress.IPv4Address(start_ip.strip())
                    end_ip = ipaddress.IPv4Address(end_ip.strip())
                    host_list = []
                    current_ip = start_ip
                    while current_ip <= end_ip:
                        host_list.append(str(current_ip))
                        current_ip = ipaddress.IPv4Address(int(current_ip) + 1)
                    print("")
                    host_list = vind_actieve_hosts(host_list)
                    if host_list:
                        detecteer_databases(host_list)
                        break
                except (ValueError, ipaddress.AddressValueError):
                    herstel_scherm()
                    print(f"\n{rood}Ongeldige IP-bereiknotatie. Voer een geldig IP-bereik in met een streepje (-).{reset}")
                    input(f"{rood}Druk op enter om het opnieuw te proberen.{reset}")

        elif choice == '4':
            while True:
                herstel_scherm()
                target_ip = input(f"\n\n{blauw}Voer het IPv4 in (bv. 192.168.1.5):{reset} ")
                # target_ip = "172.24.250.218"
                try:
                    herstel_scherm()
                    ipaddress.IPv4Address(target_ip)
                    print("")
                    host = vind_actieve_hosts(target_ip)
                    if host:
                        detecteer_databases(target_ip)
                        break
                    else:
                        herstel_scherm()
                        input(f"\n{rood}Host niet actief. Enter om door te gaan.{reset}")
                        break
                except (ValueError,ipaddress.AddressValueError):
                    herstel_scherm()
                    print(f"\n{rood}Ongeldig IPv4. Voer een geldig IP in. (bv. 192.168.1.5).{reset}")
                    input(f"{rood}Druk op enter om het opnieuw te proberen.{reset}")
        elif not choice.strip():
                    break
        else:
            input(f"{rood}Ongeldige keuze. Druk op Enter om verder te gaan.{reset}")
            continue

        break

def security_beoordelingen():
    herstel_scherm()
    toon_scanresultaten()
    host_list = haal_host_lijst_op()
    while True:
        choice = input(f"{blauw}ID om een host te selecteren, enter om terug te gaan: {reset}")
        if not choice.strip():
            break
        try:
            choice = int(choice)
        except ValueError:
            herstel_scherm()
            toon_scanresultaten()
            print(f"{rood}Ongeldige invoer. Voer een getal in.{reset}")
            continue
        # Zoek naar het item met het overeenkomstige ID
        selected_host = None
        for host in host_list:
            if host['ID'] == choice:
                selected_host = host
                break
        if selected_host:
            herstel_scherm()
            toon_host_details(selected_host)
            detecteer_beschikbare_testen(host)
            break
        else:
            herstel_scherm()
            toon_scanresultaten()
            print(f"{rood}Geen host gevonden met dat ID. Probeer opnieuw.{reset}")

def Main():
    signal.signal(signal.SIGINT, afsluit_signaal)
    while True:
        global filename
        herstel_scherm()
        toon_scan_menu()
        choice = input(f"{blauw}Selecteer een optie (1/2): {reset}")
        while choice not in ["1", "2"]:
            herstel_scherm()
            input(f"\n{rood}Ongeldige keuze. Druk op Enter om verder te gaan.{reset}")
            herstel_scherm()
            toon_scan_menu()
            choice = input(f"{blauw}Selecteer een optie (1/2): {reset}")
        if choice == "1":
            while True:
                # global filename
                filename = input(f"\n{blauw}Voer een naam in voor de scan: {reset}")
                if filename.strip():
                    filename += ".json"
                    if os.path.exists("Scans/" + filename):
                        herstel_scherm()
                        input(f"\n{rood}'{filename}' bestaat al. Druk op enter en kies een andere naam.{reset}")
                    else:
                        break

        elif choice == "2":
                herstel_scherm()
                loaded_data = laad_scan()
                if loaded_data is not None:
                    filename = loaded_data
                else:
                    filename = ""
                    herstel_scherm()
                    continue

        herstel_scherm()
        toon_menu_opties(tel_aantal_hosts())
        while True:
            choice = input(f"{blauw}Selecteer een optie (1/2/3): {reset}")
            if choice == '1':
                zoek_database_systemen()
                herstel_scherm()
                toon_menu_opties(tel_aantal_hosts())

            elif choice == '2':
                security_beoordelingen()
                herstel_scherm()
                toon_menu_opties(tel_aantal_hosts())

            elif choice == '3':
                herstel_scherm()
                print(f"\n{blauw}Gesloten. Tot de volgende keer!{reset}")
                exit(0)
            else:
                input(f"{rood}Ongeldige keuze. Druk op Enter om verder te gaan.{reset}")
                herstel_scherm()
                toon_menu_opties(tel_aantal_hosts())
# EINDE FUNCTIES

Main()