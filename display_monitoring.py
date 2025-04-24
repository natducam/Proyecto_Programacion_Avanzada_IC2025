# Construir la interfaz grafica
import tkinter as tk 
from tkinter import ttk, scrolledtext 
# Correr en hilos para no congelar la interfaz
import threading
import queue
# Capturar y analizar paquetes de red
from scapy.all import sniff, get_if_list
# Detecion de trafico HTTP
from scapy.layers.http import HTTPRequest
# Expresiones regulares, para verificar patrones
import re
# Diccionario para contar fallos de login
from collections import defaultdict
# Escaneo de puertos
import nmap


# Compilación de patrones para detectar posibles amenazas de SQLi y XSS
sql_injection_pattern = re.compile(r"(?i)(union select|or 1=1|--|drop table|insert into|xp_cmdshell)")
xss_pattern = re.compile(r"(?i)(<script>|onerror=|<img src=|<svg|alert\(|document\.cookie)")
login_failures = defaultdict(int)  # Diccionario para contar intentos de login fallidos por IP

# Clase principal para la aplicación de detección de amenazas de red
class ThreatDetectorApp:
    # Constructor de la clase
    # root: ventana principal de Tkinter
    def __init__(self, root):
        # Inicializa la ventana principal
        self.root = root
        self.root.title("Detector de Amenazas de Red")

        # Variables y configuración de la interfaz
        self.interface_var = tk.StringVar()
        interfaces = get_if_list() # Lista de interfazces de red
        if interfaces:
            self.interface_var.set(interfaces[0])
        ttk.Label(root, text="Selecciona la Interfaz de Red:").pack(pady=(10, 0))
        self.interface_menu = ttk.Combobox(root, textvariable=self.interface_var, values=interfaces, width=60)
        self.interface_menu.pack()

        # Botones de control
        self.button_frame = ttk.Frame(root)
        self.button_frame.pack(pady=10)

        self.start_button = ttk.Button(self.button_frame, text="Iniciar Detección", command=self.start_detection)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(self.button_frame, text="Detener Detección", command=self.stop_detection, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Estadísticas en vivo
        self.stats_frame = ttk.Frame(root)
        self.stats_frame.pack(pady=10)

        self.pkt_count_label = ttk.Label(self.stats_frame, text="Paquetes Capturados: 0")
        self.pkt_count_label.grid(row=0, column=0, padx=10)

        self.http_count_label = ttk.Label(self.stats_frame, text="Paquetes HTTP: 0")
        self.http_count_label.grid(row=0, column=1, padx=10)

        self.sqli_count_label = ttk.Label(self.stats_frame, text="SQLi Detectado: 0")
        self.sqli_count_label.grid(row=1, column=0, padx=10)

        self.xss_count_label = ttk.Label(self.stats_frame, text="XSS Detectado: 0")
        self.xss_count_label.grid(row=1, column=1, padx=10)

        # Área de logs
        self.log_area = scrolledtext.ScrolledText(root, height=20, width=80)
        self.log_area.pack(padx=10, pady=10)

        # Botón para escaneo de puertos
        self.scan_button = ttk.Button(root, text="Escanear Puertos Abiertos", command=self.scan_ports)
        self.scan_button.pack(pady=10)

        # Área de salida de escaneo de puertos
        self.port_output = scrolledtext.ScrolledText(root, height=10, width=80)
        self.port_output.pack(padx=10, pady=10)

        # Variables de control de captura
        self.sniffing = False
        self.sniff_thread = None
        self.packet_count = 0
        self.http_packet_count = 0
        self.sqli_count = 0
        self.xss_count = 0
        self.packet_queue = queue.Queue()

        self.log("Inicializado. Listo para iniciar la detección.")

    # Función para registrar mensajes en el área de logs y archivo
    def log(self, message):
        self.log_area.insert(tk.END, message + "\n") # Escribe en el area de logs
        self.log_area.see(tk.END)
        with open("log_monitoreo.txt", "a") as file: # Escribe en el archivo
            file.write("> "+ message + "\n")

    # Función para iniciar la captura de paquetes
    def start_detection(self):
        iface = self.interface_var.get()
        if iface:
            # Reinicia estadisticas antes de empezar
            self.packet_count = 0
            self.http_packet_count = 0
            self.sqli_count = 0
            self.xss_count = 0
            self.pkt_count_label.config(text="Paquetes Capturados: 0")
            self.http_count_label.config(text="Paquetes HTTP: 0")
            self.sqli_count_label.config(text="SQLi Detectado: 0")
            self.xss_count_label.config(text="XSS Detectado: 0")
            # Cambia el estado de los botones
            self.sniffing = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            # Mensaje al log
            self.log(f"Iniciando captura de paquetes en {iface}...")

            # Inicia la captura en un hilo separado
            self.sniff_thread = threading.Thread(target=self.process_traffic, args=(iface,), daemon=True)
            self.sniff_thread.start()

            # Inicia la actualización de estadisticas
            self.update_stats_thread()
        else:
            self.log("Por favor, selecciona una interfaz de red.")

    # Función para detener la captura de paquetes
    def stop_detection(self):
        # Cambia el estado y reinicia los botones
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

        # Mensaje al log
        self.log("Captura de paquetes detenida.")

    # Función para analizar solicitudes HTTP buscando amenazas
    def analyze_request(self, payload):
        threats = []
        # Check si coincide con SQLi y lo agrega a la lista
        if sql_injection_pattern.search(payload):
            threats.append("Inyección SQL")
        # Check si coincide con XSS y lo agrega a la lista
        if xss_pattern.search(payload):
            threats.append("XSS")
        # Si alguna amenaza aparece positiva lo retorna
        return threats

    # Función para registrar intentos de login fallidos
    def log_failed_login(self, ip):
        # Agrega al diccionario de fallos
        login_failures[ip] += 1
        # SI el numero de fallos excede 5 muestra una alerta
        if login_failures[ip] > 5:
            # Mensaje al log
            self.log(f"[!] Posible ataque de fuerza bruta desde {ip}")

    # Función principal para capturar tráfico en la interfaz especificada
    def process_traffic(self, interface):
        sniff(iface=interface, prn=self.handle_packet, store=False, stop_filter=lambda x: not self.sniffing)

    # Función para procesar cada paquete capturado
    def handle_packet(self, pkt):
        if not self.sniffing:
            return False
        self.packet_count += 1
        try:
            # Extracción de información del paquete
            src_ip = pkt[0][1].src # IP de origen
            dst_ip = pkt[0][1].dst # IP de destino
            proto = pkt[0][1].proto # # Protocolo
            # Crea un mensaje con la informacion para agregarlo al log
            info = f"Paquete capturado - Origen: {src_ip}, Destino: {dst_ip}, Protocolo: {proto}"
            self.log(info)

            # Detección de paquetes HTTP
            if pkt.haslayer(HTTPRequest):
                # Aumenta contador HTTP
                self.http_packet_count += 1
                # Extrae host, ruta, y metodo
                http_layer = pkt.getlayer(HTTPRequest)
                host = http_layer.Host.decode() if http_layer.Host else ''
                path = http_layer.Path.decode() if http_layer.Path else ''
                method = http_layer.Method.decode() if http_layer.Method else ''
                full_url = f"http://{host}{path}"
                self.log(f"Solicitud HTTP: {method} {full_url}")

                raw = pkt.sprintf("%Raw.load%")
                # Analiza patrones de amenazas y modifica contadores
                if raw:
                    # Recibe el contenido (payload), aplica patrones, devuelve lsita de amenazas
                    threats = self.analyze_request(raw) 
                    # Basandose en la lista de amenazas devuelve los mensajes nesesarios al log
                    for threat in threats:
                        self.log(f"[!] {threat} detectado desde {src_ip} en {full_url} — Payload: {raw}")
                    if "login failed" in raw.lower():
                        self.log_failed_login(src_ip)
                    if "union select" in raw.lower():
                        self.sqli_count += 1
                    if "<script>" in raw.lower():
                        self.xss_count += 1

            # Actualización de estadísticas
            self.packet_queue.put((self.packet_count, self.http_packet_count, self.sqli_count, self.xss_count))

        except Exception as e:
            self.log(f"[!] Error al procesar el paquete: {e}")

    # Función para actualizar las estadísticas en la interfaz
    def update_stats_thread(self):
        if not self.packet_queue.empty():
            pkt_count, http_count, sqli_count, xss_count = self.packet_queue.get()
            self.pkt_count_label.config(text=f"Paquetes Capturados: {pkt_count}")
            self.http_count_label.config(text=f"Paquetes HTTP: {http_count}")
            self.sqli_count_label.config(text=f"SQLi Detectado: {sqli_count}")
            self.xss_count_label.config(text=f"XSS Detectado: {xss_count}")

        if self.sniffing: # se ejecuta 10 veces por segundo (cada 0.100 milisegundos)
            self.root.after(100, self.update_stats_thread)

    # Función para escanear los puertos abiertos de una IP
    def scan_ports(self):
        ip = "127.0.0.1" # Host local
        if ip:
            self.log(f"Escaneando puertos abiertos para la IP {ip}...")
            nmap_path = [r"C:\\Program Files (x86)\\Nmap\\nmap.exe",] # Direcion de nmap en el dispositivo
            nm = nmap.PortScanner(nmap_search_path=nmap_path)
            try:
                nm.scan(ip, '1-1024') # escanea la ip dada en el rango de puertos 1 al 1024
                # Obtiene los puertos abiertos (puede tardar varios segundos)
                open_ports = [port for port in nm[ip]['tcp'] if nm[ip]['tcp'][port]['state'] == 'open']
                self.port_output.delete(1.0, tk.END) # Remueve el contenido de la pantalla para hacer espacio

                # esta secion escribe los resultados en la interfaz y el archivo de log simultaneamente
                with open("log_escaneo_puertos.txt", "a") as scan_log:
                    scan_log.write(f"Escaneo de puertos para {ip}:\n")

                    if open_ports:
                        self.port_output.insert(tk.END, f"Puertos abiertos para {ip}:\n")
                        scan_log.write(f"Puertos abiertos para {ip}:\n")
                        for port in open_ports:
                            resultado = f"Puerto {port} está abierto\n"
                            self.port_output.insert(tk.END, resultado)
                            scan_log.write(resultado)
                    else:
                        mensaje = "No se detectaron puertos abiertos.\n"
                        self.port_output.insert(tk.END, mensaje)
                        scan_log.write(mensaje)

                    scan_log.write("\n")

            except Exception as e:
                error_msg = f"Error: {e}\n"
                self.port_output.insert(tk.END, error_msg)
                with open("log_escaneo_puertos.txt", "a") as scan_log:
                    scan_log.write(error_msg)
        else:
            mensaje = "Dirección IP no válida.\n"
            self.port_output.insert(tk.END, mensaje)
            with open("log_escaneo_puertos.txt", "a") as scan_log:
                scan_log.write(mensaje)


# Función para ejecutar la aplicación principal
# parent_root = la raiz Tk(), si no existe la crea y trabaja sobre la que creo
def run(parent_root=None):
    # Si se ejecuta localmente
    if parent_root is None: 
        root = tk.Tk()
        app = ThreatDetectorApp(root)
        root.mainloop()
    # Si se integra a otra ventana
    else: 
        window = tk.Toplevel(parent_root)
        app = ThreatDetectorApp(window)

# Si se ejecuta localmente
if __name__ == "__main__": 
    run()