# alertBot
Tailer, parser og sender notifikasjoner på Snort og Suricata alarmer.
### Install
Krever python 3.7.x og pip/pipenv. pipenv er anbefalt
```bash
pip install pipenv
cd alertBotV2
# Install dependencies using a virtual enviorment
pipenv install
# Activate virtual enviorment and run
pipenv shell
python alertBot.py
```
> Hvis man ikke vil bruke pipenv, sjekk [packages] i Pipfile -> 'pip install <package>'


Kopier eksemple konfig og filter 
```bash
cp example_config.json config.json
cp example_filter.json filter.json
```
Editer config.json og filter.json  
Aktivere virtual enviorment(kun ved bruk av pipenv) `pipenv shell`  
Start boten `python alertBot.py`  

Følgende argumenter er støttet og overstyrer config.json    
* Overstyr log level `python alertBot.py info|warn|critical|error|debug`
### config.json
Nice2Know
* Config må finnes og ligge i 'root' feks -> alertBotV2/
    - congfig path er hardkodet i src/__init__py
* Logging
    - level: info|warn|critical|error|debug
    - logSize: 3MB er default
    - backupCount: 3 er default. Dvs max antall ved rotering
* Sensors
    - Suricata
        - logType: eve|full|fast - Sett hva en du bruker
    - Snort
        - logType: full|fast - Sett hva en du bruker.
* Notify
    - startUpAlert: true|false - Sender en notifikasjon ved oppstart
    - blackListedFields: [] - Liste med felter som ikke blir tatt med ved en notifikasjon
    - webhook: experimental
* PcapParser
    - Er kun laget for Snort i et Pfsense setup
### fileState.json
Nice2Know
* Blir generert automatisk
* Path er hardkodet i alertBot.py
### filters.json
Nice2Know
* Må finnes og ligge i 'root' feks -> alertBotV2/
* filters.json kan inneholde mange filtere.
* Et filter kan inneholder mange regler. 
* Et filter kan inneholder flere regler med samme felter.
* Filter "logic" er implicit AND med implicit OR.
    - Dette betyr at hvis filtret har to regler må begge reglene treffe (implicit AND).
    - Man kan også bruke flere forskjellie regler på samme felet. Minst en som bruker feltet må treffe (implicit OR).
* Siden det er json må escape chars escaped ved bruk av regex etc.
    - Eks '\d+' bør være '\\d+'
* Filtere blir validert under oppstart og evt feil blir logget(fil og console) og programmet stopper..
* Støtter for øyeblikket alle felter en alarm måtte genererer.
* Støtter for øyeblikket følgende regler:
    - contains
    - not contains
    - regex -> Same as 'exactly' just with regex
    - exactly
    - not exactly
    - ip in cidr
    - ip not in cidr
    - startswith
    - endswith

### Eksemple på felter i en Suricata alarm:
```
{'action': 'allowed',
 'dest': '192.168.1.1',
 'dest_port': 53,
 'name': 'ET DNS Query to a *.top domain - Likely Hostile',
 'payload': 'AAQBAAABAAAAAAAADnNkZnpzamZqaHNpdWZlA3RvcAAAAQAB',
 'proto': 'UDP',
 'src': '192.168.1.145',
 'src_port': 52244,
 'time': '2018-10-11 14:10:37'}
```
Payload er alltid i b64.  
Snort har de samme feltene foruten 'action' og 'payload'.  
Suricata kan også ha følgende felter hvis tilgjengelig:
 * hostname
 * url
 * http_refer
 * http_method
 * http_user_agent
 

        