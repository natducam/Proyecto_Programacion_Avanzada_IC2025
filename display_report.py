import tkinter as tk
from tkinter import ttk
import os
from datetime import datetime
import csv

class ReportApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Generador de Reportes")

        self.button_frame = ttk.Frame(root)
        self.button_frame.pack(pady=10)

        self.start_button = ttk.Button(self.button_frame, text="Generar Reporte CSV", command=self.generate_csv)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.info = {}

    def compile_info(self):
        try:
            with open("log_monitoreo.txt","r") as file:
                lines = [line.rstrip('\n') for line in file]
                self.info["LOG MONITOREO"] = lines
        except Exception as e:
            self.info["LOG MONITOREO"] = [f"[!] ERROR: {e}"]
        try:
            with open("log_escaneo_puertos.txt","r") as file:
                lines = [line.rstrip('\n') for line in file]
                self.info["LOG ESCANEO DE PUERTOS"] = lines
        except Exception as e:
            self.info["LOG ESCANEO DE PUERTOS"] = [f"[!] ERROR: {e}"]
        try:
            with open("log_autenticacion.txt","r") as file:
                lines = [line.rstrip('\n') for line in file]
                self.info["LOG AUTENTICACION"] = lines
        except Exception as e:
            self.info["LOG AUTENTICACION"] = [f"[!] ERROR: {e}"]
        try:
            with open("logs_windows.txt","r") as file:
                lines = [line.rstrip('\n') for line in file]
                self.info["LOGS WINDOWS"] = lines
        except Exception as e:
            self.info["LOGS WINDOWS"] = [f"[!] ERROR: {e}"]
        try:
            with open("simulacion_logs.txt","r") as file:
                lines = [line.rstrip('\n') for line in file]
                self.info["LOG SIMULACION"] = lines
        except Exception as e:
            self.info["LOG SIMULACION"] = [f"[!] ERROR: {e}"]
        try:
            with open("incidentes.csv","r") as file:
                lines = [line.rstrip('\n') for line in file]
                self.info["LOG INCIDENTES"] = lines
        except Exception as e:
            self.info["LOG INCIDENTES"] = [f"[!] ERROR: {e}"]
        try:
            with open("ips_bloqueadas.txt","r") as file:
                lines = [line.rstrip('\n') for line in file]
                self.info["IPS BLOQUEADAS"] = lines
        except Exception as e:
            self.info["IPS BLOQUEADAS"] = [f"[!] ERROR: {e}"]

    
    def generate_csv(self):
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        directory = "Reportes"
        if not os.path.exists(directory):
            os.mkdir(directory)
        file_name = f"{directory}/Reporte_{timestamp}.csv"
        self.compile_info()
        with open(file_name,mode="a+",newline='') as file:
            writer = csv.writer(file)
            for key,value in self.info.items():
                writer.writerow([f">>> {key} <<<"])
                for item in value:
                    writer.writerow([item])
                writer.writerow([])


def run(parent_root=None):
    if parent_root is None:
        root = tk.Tk()
        app = ReportApp(root)
        root.mainloop()
    else:
        window = tk.Toplevel(parent_root)
        app = ReportApp(window)

if __name__ == "__main__":
    run()