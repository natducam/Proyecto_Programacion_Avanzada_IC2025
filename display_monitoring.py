import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
from scapy.all import sniff, get_if_list
from scapy.layers.http import HTTPRequest
import re
from collections import defaultdict

sql_injection_pattern = re.compile(r"(?i)(union select|or 1=1|--|drop table|insert into|xp_cmdshell)")
xss_pattern = re.compile(r"(?i)(<script>|onerror=|<img src=|<svg|alert\(|document\.cookie)")
login_failures = defaultdict(int)

class ThreatDetectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("App de Monitoreo")

        self.interface_var = tk.StringVar()
        interfaces = get_if_list()
        ttk.Label(root, text="Seleciona Interfaz de Red:").pack(pady=(10, 0))
        self.interface_menu = ttk.Combobox(root, textvariable=self.interface_var, values=interfaces)
        self.interface_menu.pack()

        self.button_frame = ttk.Frame(root)
        self.button_frame.pack(pady=10)

        self.start_button = ttk.Button(self.button_frame, text="Iniciar", command=self.start_detection)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(self.button_frame, text="Detener", command=self.stop_detection, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.log_area = scrolledtext.ScrolledText(root, height=20, width=80)
        self.log_area.pack(padx=10, pady=10)

        self.sniffing = False
        self.sniff_thread = None

        self.log("Inicio GUI correctamente.")

    def log(self, message):
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)

    def start_detection(self):
        iface = self.interface_var.get()
        if iface:
            self.sniffing = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.log(f"Iniciando captura de paquetes en {iface}...")
            self.sniff_thread = threading.Thread(target=self.process_traffic, args=(iface,), daemon=True)
            self.sniff_thread.start()
        else:
            self.log("Por favor selecione una interfaz de red.")

    def stop_detection(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.log("Deteniendo...")

    def analyze_request(self, payload):
        threats = []
        if sql_injection_pattern.search(payload):
            threats.append("SQL Injection")
        if xss_pattern.search(payload):
            threats.append("XSS")
        return threats

    def log_failed_login(self, ip):
        login_failures[ip] += 1
        if login_failures[ip] > 5:
            self.log(f"[ALERTA] Possible ataque de fuerza bruta desde {ip}")

    def process_traffic(self, interface):
        sniff(iface=interface, prn=self.handle_packet, store=False, stop_filter=lambda x: not self.sniffing)

    def handle_packet(self, pkt):
        if not self.sniffing:
            return False
        if pkt.haslayer(HTTPRequest):
            ip = pkt["IP"].src
            try:
                raw = pkt.sprintf("%Raw.load%")
                if raw:
                    threats = self.analyze_request(raw)
                    for threat in threats:
                        self.log(f"[ALERTA] {threat} desde {ip} : {raw}")
                    if "login failed" in raw.lower():
                        self.log_failed_login(ip)
            except Exception as e:
                self.log(f"[ERROR] Error de parsing: {e}")

def run():
    root = tk.Tk()
    app = ThreatDetectorApp(root)
    root.mainloop()

if __name__ == "__main__":
    run()
