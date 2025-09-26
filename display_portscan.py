import tkinter as tk
from tkinter import ttk, scrolledtext
import nmap
from datetime import datetime

class PortScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Escáner de Puertos")

        # IP
        ttk.Label(root, text="Dirección IP a escanear:").pack(pady=(10, 0))
        self.ip_entry = ttk.Entry(root, width=30)
        self.ip_entry.pack(pady=5)
        self.ip_entry.insert(0, "127.0.0.1")

        # Boton de escaneo
        self.scan_button = ttk.Button(root, text="Escanear Puertos", command=self.scan_ports)
        self.scan_button.pack(pady=10)

        # Boton Guardar
        self.save_button = ttk.Button(root, text="Guardar el último escaneo en archivo .txt", command=self.save_scan_to_file)
        self.save_button.pack(pady=5)


        # Area de Output
        self.output_area = scrolledtext.ScrolledText(root, height=15, width=80)
        self.output_area.pack(padx=10, pady=10)

    def scan_ports(self):
        ip = self.ip_entry.get().strip()
        self.output_area.delete(1.0, tk.END)

        if not ip:
            self.output_area.insert(tk.END, "Por favor, ingresa una dirección IP válida.\n")
            return

        self.output_area.insert(tk.END, f"Escaneando puertos abiertos para {ip}...\n")

        try:
            nmap_path = [r"C:\Program Files (x86)\Nmap\nmap.exe"]
            nm = nmap.PortScanner(nmap_search_path=nmap_path)
            nm.scan(ip, '1-1024')

            if ip not in nm.all_hosts():
                self.output_area.insert(tk.END, "No se pudo escanear la IP. Verifica la dirección.\n")
                return

            open_ports = [port for port in nm[ip]['tcp'] if nm[ip]['tcp'][port]['state'] == 'open']
            if open_ports:
                for port in open_ports:
                    service = nm[ip]['tcp'][port].get('name', 'desconocido')
                    self.output_area.insert(tk.END, f"Puerto {port} abierto — Servicio: {service}\n")
            else:
                self.output_area.insert(tk.END, "No se detectaron puertos abiertos.\n")

        except Exception as e:
            self.output_area.insert(tk.END, f"Error durante el escaneo: {e}\n")
    
    def save_scan_to_file(self):
        content = self.output_area.get(1.0, tk.END).strip()
        if not content:
            self.output_area.insert(tk.END, "No hay resultados para guardar.\n")
            return

        timestamp = datetime.now().strftime("%d-%m-%Y-%H-%M-%S")
        filename = f"RESULTS/{timestamp}-SCAN.txt"

        try:
            with open(filename, "w", encoding="utf-8") as file:
                file.write(content)
            self.output_area.insert(tk.END, f"Escaneo guardado en archivo: {filename}\n")
        except Exception as e:
            self.output_area.insert(tk.END, f"Error al guardar el archivo: {e}\n")


def run(parent_root=None):
    if parent_root is None:
        root = tk.Tk()
        app = PortScannerApp(root)
        root.mainloop()
    else:
        window = tk.Toplevel(parent_root)
        app = PortScannerApp(window)

if __name__ == "__main__":
    run()
