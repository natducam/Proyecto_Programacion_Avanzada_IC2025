import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
from scapy.all import sniff, get_if_list
from scapy.layers.http import HTTPRequest
import re
from collections import defaultdict
import nmap
import queue

sql_injection_pattern = re.compile(r"(?i)(union select|or 1=1|--|drop table|insert into|xp_cmdshell)")
xss_pattern = re.compile(r"(?i)(<script>|onerror=|<img src=|<svg|alert\(|document\.cookie)")
login_failures = defaultdict(int)

class ThreatDetectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Detector de Amenazas de Red")

        self.interface_var = tk.StringVar()
        interfaces = get_if_list()
        if interfaces:
            self.interface_var.set(interfaces[0])
        ttk.Label(root, text="Selecciona la Interfaz de Red:").pack(pady=(10, 0))
        self.interface_menu = ttk.Combobox(root, textvariable=self.interface_var, values=interfaces)
        self.interface_menu.pack()

        self.button_frame = ttk.Frame(root)
        self.button_frame.pack(pady=10)

        self.start_button = ttk.Button(self.button_frame, text="Iniciar Detección", command=self.start_detection)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(self.button_frame, text="Detener Detección", command=self.stop_detection, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Live stats labels
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

        self.log_area = scrolledtext.ScrolledText(root, height=20, width=80)
        self.log_area.pack(padx=10, pady=10)

        self.scan_button = ttk.Button(root, text="Escanear Puertos Abiertos", command=self.scan_ports)
        self.scan_button.pack(pady=10)

        self.port_output = scrolledtext.ScrolledText(root, height=10, width=80)
        self.port_output.pack(padx=10, pady=10)

        self.sniffing = False
        self.sniff_thread = None
        self.packet_count = 0
        self.http_packet_count = 0
        self.sqli_count = 0
        self.xss_count = 0
        self.packet_queue = queue.Queue()  # Queue to pass data to the main thread
        self.log("Inicializado. Listo para iniciar la detección.")

    def log(self, message):
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)

    def start_detection(self):
        iface = self.interface_var.get()
        if iface:
            # Reset stats before starting the detection
            self.packet_count = 0
            self.http_packet_count = 0
            self.sqli_count = 0
            self.xss_count = 0
            self.pkt_count_label.config(text="Paquetes Capturados: 0")
            self.http_count_label.config(text="Paquetes HTTP: 0")
            self.sqli_count_label.config(text="SQLi Detectado: 0")
            self.xss_count_label.config(text="XSS Detectado: 0")
            
            self.sniffing = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.log(f"Iniciando captura de paquetes en {iface}...")
            
            # Start sniffing in a new thread
            self.sniff_thread = threading.Thread(target=self.process_traffic, args=(iface,), daemon=True)
            self.sniff_thread.start()
            
            # Start updating stats in the main thread
            self.update_stats_thread()
        else:
            self.log("Por favor, selecciona una interfaz de red.")

    def stop_detection(self):
        # Stop sniffing and reset buttons
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.log("Captura de paquetes detenida.")

    def analyze_request(self, payload):
        threats = []
        if sql_injection_pattern.search(payload):
            threats.append("Inyección SQL")
        if xss_pattern.search(payload):
            threats.append("XSS")
        return threats

    def log_failed_login(self, ip):
        login_failures[ip] += 1
        if login_failures[ip] > 5:
            self.log(f"[!] Posible ataque de fuerza bruta desde {ip}")

    def process_traffic(self, interface):
        sniff(iface=interface, prn=self.handle_packet, store=False, stop_filter=lambda x: not self.sniffing)

    def handle_packet(self, pkt):
        if not self.sniffing:
            return False
        self.packet_count += 1
        if pkt.haslayer(HTTPRequest):
            self.http_packet_count += 1
            ip = pkt["IP"].src
            try:
                raw = pkt.sprintf("%Raw.load%")
                if raw:
                    threats = self.analyze_request(raw)
                    for threat in threats:
                        self.log(f"[!] {threat} desde {ip} — Payload: {raw}")
                    if "login failed" in raw.lower():
                        self.log_failed_login(ip)
                    if "union select" in raw.lower():
                        self.sqli_count += 1
                    if "<script>" in raw.lower():
                        self.xss_count += 1
            except Exception as e:
                self.log(f"[!] Error al procesar el paquete: {e}")

        # Put updated stats in the queue
        self.packet_queue.put((self.packet_count, self.http_packet_count, self.sqli_count, self.xss_count))

    def update_stats_thread(self):
        # Check for new stats in the queue
        if not self.packet_queue.empty():
            pkt_count, http_count, sqli_count, xss_count = self.packet_queue.get()
            self.pkt_count_label.config(text=f"Paquetes Capturados: {pkt_count}")
            self.http_count_label.config(text=f"Paquetes HTTP: {http_count}")
            self.sqli_count_label.config(text=f"SQLi Detectado: {sqli_count}")
            self.xss_count_label.config(text=f"XSS Detectado: {xss_count}")
        
        if self.sniffing:
            # Re-run the update stats every second
            self.root.after(1000, self.update_stats_thread)

    def scan_ports(self):
        ip = "127.0.0.1"
        if ip:
            self.log(f"Escaneando puertos abiertos para la IP {ip}...")
            nmap_path = [r"C:\Program Files (x86)\Nmap\nmap.exe",]
            nm = nmap.PortScanner(nmap_search_path=nmap_path)
            #nm = nmap.PortScanner()
            try:
                nm.scan(ip, '1-1024')  # Scan ports 1-1024
                open_ports = [port for port in nm[ip]['tcp'] if nm[ip]['tcp'][port]['state'] == 'open']
                self.port_output.delete(1.0, tk.END)  # Clear previous results
                if open_ports:
                    self.port_output.insert(tk.END, f"Puertos abiertos para {ip}:\n")
                    for port in open_ports:
                        self.port_output.insert(tk.END, f"Puerto {port} está abierto\n")
                else:
                    self.port_output.insert(tk.END, "No se detectaron puertos abiertos.")
            except Exception as e:
                self.port_output.insert(tk.END, f"Error: {e}")
        else:
            self.port_output.insert(tk.END, "Dirección IP no válida.")

def run(parent_root=None):
    if parent_root is None:
        root = tk.Tk()
        app = ThreatDetectorApp(root)
        root.mainloop()
    else:
        window = tk.Toplevel(parent_root)
        app = ThreatDetectorApp(window)

if __name__ == "__main__":
    run()