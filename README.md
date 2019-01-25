## alertBot
Krever python 3.7 og pip/pipenv(anbefalt)
```
pip install pipenv
cd alertBot
# install dependencies in venv
pipenv install
# activate venv and run
pipenv shell
python alertBot.py
```
Hvis man ikke vil bruke pipenv, sjekk [packages] i Pipfile -> 'pip install <package>'

* Dette er i utgangspunktet gammel dirty kode som er fikset opp i. Litt rot enda.
* Husker siste leste logglinje og gjennopptar derifra ved terminering. 
* Snort(full log) og Suricata(eve.json) parser
* Logging til DB er fjernet
* Kan kun parse/lese en snort/suricata loggfill omgangen. Egentlig ment for å kjøre med threading og parse/lese x antall loggfilter samtidig. Dette er fjernet.
* Kan sende notifikasjoner til Discord og Telegram - config.json må fylles ut.
Kan forekomme POST errors mot Discord hvis payload er stor(max len 2000). Payload kan fjernest i parser 
* Bra funksjonalitet for filtrering av alarmer


#config.json
    - må finnes og ligge i alertBot/
    - congfig path er hardkodet i src/__init__py
#fileState.json:
    - Må finnes - skal bli laget automatisk om den ikke gjør det..
    - Path er hardkodet i alertBot.py
    - Må minimum inneholde {"<interface>": 0}
#filters.json
    - Må finnes og ligge i alertBot/
    - filters.json kan inneholde mange filtere.
        Et filter kan inneholder mange regler. 
        Et filter kan kan inneholder flere regler med samme felter.
        (Et) Filter "logic" er implicit AND med implicit OR
    - Siden det er json må escape chars escaped ved bruk av regex.
        Eks '\d+' bør være '\\d+'
    - Filtere blir validert under oppstart, evt feil blir logget(fil og console) og programmet stopper..
    - Støtter for øyeblikket alle felter en alarm genererer
    - Støtter for øyeblikket reglene:
        contains
        not contains
        regex
        exactly
        not exactly
        ip in cidr
        ip not in cidr
        startswith
        endswith

# Eksemple på felter i en Suricata alarm:
```
{'action': 'allowed',
 'dst': '192.168.1.1',
 'dst_port': 53,
 'name': 'ET DNS Query to a *.top domain - Likely Hostile',
 'payload': 'AAQBAAABAAAAAAAADnNkZnpzamZqaHNpdWZlA3RvcAAAAQAB',
 'proto': 'UDP',
 'src': '192.168.1.145',
 'src_port': 52244,
 'time': '2018-10-11 14:10:37'}
```
Payload er alltid i b64.
Snort har de samme feltene foruten 'action' og 'payload'.

        