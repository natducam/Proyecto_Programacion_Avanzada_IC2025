import os
import re
from tkinter import *
from tkinter import ttk, filedialog, scrolledtext
from collections import defaultdict

# Patrones de análisis
patron_fallo_login = re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)")
patron_root_login = re.compile(r"session opened for user root", re.IGNORECASE)
patron_keylogger = re.compile(r"(keylogger|logkeys|xinput|keyboard|recording keystrokes|hook)", re.IGNORECASE)

def analizar_logs(ruta_log):
    resultados = []
    intentos_por_ip = defaultdict(int)

    if not os.path.isfile(ruta_log):
        return [f"[!] El archivo {ruta_log} no existe."]

    try:
        with open(ruta_log, 'r', encoding='utf-8', errors='ignore') as file:
            for linea in file:
                if match := patron_fallo_login.search(linea):
                    ip = match.group(1)
                    intentos_por_ip[ip] += 1
                    if intentos_por_ip[ip] >= 5:
                        resultados.append(f"[!] Múltiples intentos fallidos desde {ip}")

                if patron_root_login.search(linea):
                    resultados.append("[!] Se detectó inicio de sesión como root")

                if patron_keylogger.search(linea):
                    resultados.append(f"[!] Posible actividad de keylogger detectada: {linea.strip()}")

    except Exception as e:
        resultados.append(f"[!] Error leyendo el archivo: {e}")

    if not resultados:
        resultados.append("No se detectaron eventos sospechosos.")
    return resultados

def run(parent_root=None):
    window = Toplevel(parent_root) if parent_root else Tk()
    window.title("Detección de Servicios en la Red")

    frm = ttk.Frame(window, padding=10)
    frm.grid()

    ttk.Label(frm, text="Análisis de Logs del Sistema", font=("Arial", 14, "bold")).grid(column=0, row=0, columnspan=2, pady=5)

    output = scrolledtext.ScrolledText(frm, width=90, height=25)
    output.grid(column=0, row=1, columnspan=2, pady=10)

    ruta_log = StringVar(value="/var/log/auth.log")  # Por defecto

    def seleccionar_archivo():
        archivo = filedialog.askopenfilename(title="Seleccionar archivo de log")
        if archivo:
            ruta_log.set(archivo)

    def analizar():
        output.delete("1.0", END)
        ruta = ruta_log.get()
        resultados = analizar_logs(ruta)
        for r in resultados:
            output.insert(END, r + "\n")

    # Entradas y botones
    ttk.Entry(frm, textvariable=ruta_log, width=70).grid(column=0, row=2, padx=5, sticky="w")
    ttk.Button(frm, text="📁 Buscar Log", command=seleccionar_archivo).grid(column=1, row=2, sticky="e")

    ttk.Button(frm, text="🔍 Analizar", command=analizar).grid(column=0, row=3, columnspan=2, pady=5)

    ttk.Button(frm, text="Regresar", command=lambda: [window.destroy(), parent_root.deiconify() if parent_root else None]).grid(column=0, row=4, columnspan=2, pady=10)

    window.mainloop()

# Para pruebas independientes
if __name__ == "__main__":
    run()

