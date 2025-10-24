# Programa de Python que recibe parámetros
# Instalar nmap: apt-get install nmap
# Ejemplo argumentos: python3 davidt.py -t www.jesusninoc.com -p 80 21 22 -v 2 --open
import argparse
import socket
import subprocess
import nmap

def comprobar_ip(ip):
    try:
        subprocess.run(['ping', '-c', '1', ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def ping(target, puertos, verbosidad, show_open):
    for p in puertos:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result=s.connect_ex((target,p))
        if result == 0:
       	    print(f"Puerto {p} abierto")
        else:
            if not show_open or verbosidad > 1:
                print(f"Puerto {p} cerrado")
        s.close()
    
def encontrar_hosts(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-sn')

    hosts_encendidos = []
    for host in nm.all_hosts():
        if nm[host]['status']['state'] == 'up':
            hosts_encendidos.append(host)

    return hosts_encendidos
    
def main():

# Argumentos
    parser = argparse.ArgumentParser(description='Escaneo de puertos')
#    parser.add_argument('-h', action='help', help='Ayuda')
    parser.add_argument('-t', '--target', required=True, help='IP del target')
    parser.add_argument('-p', '--port', nargs='+', type=int, default=[80], help='Puertos a escanear, por defecto 80')
    parser.add_argument('-v', '--verbosity', type=int, default=1, choices=[0, 1, 2], help='Nivel de verbosidad')
    parser.add_argument('--open', action='store_true', help='Muestra solo los puertos abiertos')
    args = parser.parse_args()

    target = args.target
    puertos = args.port
    verbosidad = args.verbosity
    show_open = args.open

#Comprobar ip válida
    if not comprobar_ip(target):
        print("Error: Dirección IP inválida o target no alcanzable.")
        return

    print(f"Target de escaneo: {target}")
    print(f"Puertos: {', '.join(str(p) for p in puertos)}")
    print(f"Nivel de verbosidad: {verbosidad}")

#Ping
    ping(target, puertos, verbosidad, show_open)
        
#Máquinas encendidas
    hosts_encendidos = encontrar_hosts(target)
    if len(hosts_encendidos) == 0:
        print("No se han encontrado máquinas encendidas en la red.")
    else:
        print("Se han encontrado máquinas encendidas en la red:")
        for host in hosts_encendidos:
            print(host)

if __name__ == "__main__":
    main()
