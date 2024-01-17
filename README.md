# Monin's DB. Inspector

![GIF](https://github.com/jonaswillems/Monin-s-DB.-Inspector/assets/57659437/4e6eb32c-1358-432b-b116-761dcdcf92be)

Welkom bij Monin's DB. Inspector, een tool ontwikkeld om databases in netwerken te detecteren en te beoordelen vanuit beveiligingsperspectief.

## Overzicht
Monin's DB. Inspector is een Python-script dat specifiek is ontworpen voor het efficiënt identificeren en beoordelen van databases binnen een netwerkomgeving. Met deze tool kun je niet alleen de achterliggende database services en versies detecteren, maar biedt het ook de mogelijkheid om beveiligingstests uit te voeren op diverse protocollen, zoals SSH en FTP. De beveiligingstests worden uitgevoerd met behulp van de bekende tool thc-hydra en een wordlist, waarmee het script probeert toegang te verkrijgen tot de beveiligde services door verschillende combinaties van gebruikersnamen en wachtwoorden te testen. Bovendien maakt Monin's DB. Inspector gebruik van Nmap om uitgebreide informatie over hosts en services binnen het netwerk te verzamelen, waardoor het een allesomvattende tool is voor database-identificatie en beveiligingsbeoordelingen.

## Kenmerken
- **Netwerkscanning:** Detecteer actieve hosts en zoek naar databases op verschillende poorten.
- **Beveiligingstests:** Voer beveiligingstests uit op SSH- en FTP-services om zwakke wachtwoorden te identificeren.

## Structuur van het project
- `Monin.py`: Het hoofdscript.
- `Wordlist/`: Bevat lijsten met wachtwoorden die worden gebruikt voor beveiligingstests.
- `Scans/`: Map waarin scanresultaten worden opgeslagen.
- `requirements.txt`: Bevat de vereiste Python-bibliotheken voor het script.

## Instructies
### Compatibiliteit: 
Besturingssystemen:
- Kali Linux 2023.4

### Installatie
Om Monin's DB. Inspector te gebruiken, moet je aan de volgende vereisten voldoen:
- Python3
- Nmap
- thc-hydra


1. Update systeem & installeer vereisten:
    ```bash
   sudo apt update && sudo apt upgrade -y && sudo apt install python3 nmap hydra -y
    ```
2. Clone de repository:
    ```bash
    git clone https://github.com/Sm3ll1w/Monin-s-DB.-Inspector.git
    cd Monin-s-DB.-Inspector/
    ```
3. Installeer de vereiste bibliotheken:
    ```bash
    pip install -r requirements.txt
    ```
### Gebruik
1. Start het script:
    ```bash
    python Monin.py
    ```
    
Volg de instructies op het scherm:
- Maak een nieuwe scan aan of laad een bestaande scan.
- Kies de gewenste opties in het hoofdmenu, om databasesystemen te vinden of beveiligingstests te doen.
- Volg de aanwijzingen voor het invoeren van CIDR-notatie, IP-bereiken, lijsten met IP-adressen, enz.
- Bekijk de scanresultaten en voer beveiligingstests uit op geselecteerde hosts.

## TO-DO
- Gevonden credentials opslaan in de JSON-file.
- MSDAT en OSDAT integratie.
- Het ondersteunen van meerdere protocollen.
- Het genereren van een HTLM-rapport.


## Contact
Heb je vragen of feedback? Aarzel niet om contact met me op te nemen.
- **E-mail:** Jonas.Willems@monin-it.be

