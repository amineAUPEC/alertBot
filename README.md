# alertBot
Tailer, parser og sender notifikasjoner på Snort og Suricata alarmer.
### Install
Krever python 3.7.x og pip/pipenv. pipenv er anbefalt
```bash
git clone https://github.com/nockstarr/alertBotV2.git  # Or download zip
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
* General
    - reverseDns: true|false - Legger til reverseDNS til src/dest felter
    - restartOnChange: true|false - Restarter programmet når endringer i 'watchedFiles' blir oppdaget
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
    - notifyOnStartUp: true|false - Sender en notifikasjon ved oppstart
    - blackListedFields: [] - Liste med felter som ikke blir tatt med ved en notifikasjon
    - agents
        - webhook: Ikke fungerendes
        - discord: har støtte for embed (se eksemple)
* PcapParser
    - Experimental. Er kun laget for Snort i et Pfsense setup
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

### Eksemple på felter i en Suricata fast_log alarm(ufiltrert):
```
{'classtype': 'Detection of a Network Scan',
 'dest': '192.168.4.10',
 'dest_port': '80',
 'gid': '1',
 'name': 'MALWARE-CNC URI - known scanner tool muieblackcat',
 'priority': '3',
 'protocol': 'TCP',
 'revision': '4',
 'sid': '21257',
 'src': '157.230.128.187',
 'src_port': '35242',
 'time': '2019-01-25 17:58:03.598388'}
```
Snort skal ha de samme feltene.
### Eksemple på felter i en Suricata eve.json alarm(ufiltrert)
```
{'action': 'allowed',
 'dest': '192.168.1.1',
 'dest_port': 53,
 'name': 'INDICATOR-COMPROMISE Suspicious .pw dns query',
 'payload': 'AAQBAAABAAAAAAAABGFsZXgCcHcAAAEAAQ==',
 'proto': 'UDP',
 'src': '192.168.1.50',
 'src_port': 51331,
 'time': '2019-01-25 01:02:23.579419'}
```
Payload burde være b64.  
Suricata kan også ha følgende felter hvis tilgjengelig i eve.json:
 * hostname
 * url
 * http_refer
 * http_method
 * http_user_agent
 

        