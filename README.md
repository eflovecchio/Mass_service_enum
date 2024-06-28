Este script de python sirve para poder enumerar de manera masiva ciertos puertos dando como output una lista de equipos con esos servicios especificados abiertos, pudiendo hacer un recon masivo sobre ciertas tecnologias de manera facil y rapido, este script está pensado para ejecuciones masivas.


Requisitos
pip install python-nmap
pip install concurrent.futures

Ejemplo de ejecucion:
python script.py lista_ips.txt 21,22,80
python script.py lista_ips.txt puertos.txt
python script.py lista_ips.txt 445
