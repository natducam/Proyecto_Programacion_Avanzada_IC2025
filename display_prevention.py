import tkinter as tk
from tkinter import ttk
import re
import os

# === Funciones de análisis ===

def extraer_ip(linea):
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", linea)
    return match.group(0) if match else None

def bloquear_ip(ip):
    with open("ips_bloqueadas.txt", "a") as f:
        f.write(ip + "\n")

def detectar_ips_sospechosas():
    sospechosas = {}
    bloqueadas = []

    try:
        with open("logs_windows.txt", "r") as f:
            for linea in f:
                if "Failed" in linea or "Denied" in linea:
                    ip = extraer_ip(linea)
                    if ip:
                        sospechosas[ip] = sospechosas.get(ip, 0) + 1

        for ip, intentos in sospechosas.items():
            if intentos >= 3:
                bloquear_ip(ip)
                bloqueadas.append(ip)

        return bloqueadas if bloqueadas else ["No se detectaron IPs sospechosas."]
    
    except FileNotFoundError:
        return ["[ERROR] No se encontró el archivo de logs: logs_windows.txt"]

def mostrar_ips_bloqueadas(text_area):
    text_area.delete(1.0, "end")
    if os.path.exists("ips_bloqueadas.txt"):
        with open("ips_bloqueadas.txt", "r") as f:
            ips = f.readlines()
            if ips:
                text_area.insert("end", "IPs bloqueadas:\n\n")
                for ip in ips:
                    text_area.insert("end", ip)
            else:
                text_area.insert("end", "No hay IPs bloqueadas.")
    else:
        text_area.insert("end", "No se ha creado el archivo de IPs bloqueadas aún.")

def bloquear_ip_manual(entry, text_area):
    ip = entry.get().strip()
    if re.match(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", ip):
        bloquear_ip(ip)
        text_area.insert("end", f"IP bloqueada manualmente: {ip}\n")
        entry.delete(0, tk.END)
    else:
        text_area.insert("end", "IP inválida. Introduce una dirección válida.\n")

# === Interfaz gráfica ===

def crear_ventana():
    root = tk.Tk()
    root.title("Prevención de Ataques")

    frm = ttk.Frame(root, padding=10)
    frm.grid()

    label = ttk.Label(frm, text="Prevención de Ataques", font=("Helvetica", 14, "bold"))
    label.grid(row=0, column=0, columnspan=3, pady=10)

    text_area = tk.Text(frm, width=80, height=20)
    text_area.grid(row=1, column=0, columnspan=3, padx=5, pady=5)

    boton_detectar = ttk.Button(frm, text="Detectar y Bloquear IPs Sospechosas",
                                command=lambda: ejecutar_bloqueo_automatico(text_area))
    boton_detectar.grid(row=2, column=0, pady=10)

    boton_ver_ips = ttk.Button(frm, text="Ver IPs Bloqueadas",
                               command=lambda: mostrar_ips_bloqueadas(text_area))
    boton_ver_ips.grid(row=2, column=1, pady=10)

    boton_salir = ttk.Button(frm, text="Salir", command=root.destroy)
    boton_salir.grid(row=2, column=2, pady=10)

    # Entrada de IP manual
    ip_entry = ttk.Entry(frm, width=20)
    ip_entry.grid(row=3, column=0, pady=5)

    boton_bloquear_manual = ttk.Button(frm, text="Bloquear IP Manualmente",
                                       command=lambda: bloquear_ip_manual(ip_entry, text_area))
    boton_bloquear_manual.grid(row=3, column=1, pady=5)

    root.mainloop()

def ejecutar_bloqueo_automatico(text_area):
    text_area.delete(1.0, "end")
    text_area.insert("end", "Ejecutando análisis de IPs sospechosas...\n\n")

    resultados = detectar_ips_sospechosas()
    for linea in resultados:
        text_area.insert("end", f"{linea}\n")

crear_ventana()
