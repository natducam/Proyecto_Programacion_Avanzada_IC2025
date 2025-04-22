import os
import csv
from tkinter import *
from tkinter import ttk, scrolledtext
from datetime import datetime

ARCHIVO_INCIDENTES = "incidentes.csv"
ARCHIVO_LOG = "incidentes.log"

def inicializar_registro():
    if not os.path.exists(ARCHIVO_INCIDENTES):
        with open(ARCHIVO_INCIDENTES, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Fecha", "IP", "Tipo de Ataque", "Acción Tomada"])

def registrar_log(fecha, ip, tipo_ataque, accion):
    with open(ARCHIVO_LOG, mode='a', encoding='utf-8') as f:
        f.write(f"{fecha} - IP: {ip} - Tipo de Ataque: {tipo_ataque} - Acción: {accion}\n")

def registrar_incidente(ip, tipo_ataque, accion, fecha=None):
    inicializar_registro()
    if not fecha:
        fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Registrar en CSV
    with open(ARCHIVO_INCIDENTES, mode='a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([fecha, ip, tipo_ataque, accion])
    
    # Registrar en Log
    registrar_log(fecha, ip, tipo_ataque, accion)

def leer_incidentes():
    if not os.path.exists(ARCHIVO_INCIDENTES):
        return ["No se han registrado incidentes."]
    
    with open(ARCHIVO_INCIDENTES, mode='r', encoding='utf-8') as f:
        reader = csv.reader(f)
        next(reader, None)  # Saltar encabezado
        return [f"{row[0]} - IP: {row[1]} - Tipo: {row[2]} - Acción: {row[3]}" for row in reader]

def run(parent_root=None):
    window = Toplevel(parent_root) if parent_root else Tk()
    window.title("Registro de Incidentes")

    frm = ttk.Frame(window, padding=10)
    frm.grid()

    ttk.Label(frm, text="Registro de Incidentes Detectados", font=("Arial", 14, "bold")).grid(column=0, row=0, columnspan=2, pady=5)

    output = scrolledtext.ScrolledText(frm, width=100, height=20)
    output.grid(column=0, row=1, columnspan=2, pady=10)

    def actualizar_lista():
        output.delete("1.0", END)
        incidentes = leer_incidentes()
        for linea in incidentes:
            output.insert(END, linea + "\n")

    actualizar_lista()

    # Entradas para registrar manualmente
    ttk.Label(frm, text="IP:").grid(column=0, row=2, sticky="e")
    ip_entry = ttk.Entry(frm, width=25)
    ip_entry.grid(column=1, row=2, sticky="w")

    ttk.Label(frm, text="Tipo de Ataque:").grid(column=0, row=3, sticky="e")
    ataque_entry = ttk.Entry(frm, width=25)
    ataque_entry.grid(column=1, row=3, sticky="w")

    ttk.Label(frm, text="Acción Tomada:").grid(column=0, row=4, sticky="e")
    accion_entry = ttk.Entry(frm, width=25)
    accion_entry.grid(column=1, row=4, sticky="w")

    def agregar_manual():
        ip = ip_entry.get().strip()
        tipo = ataque_entry.get().strip()
        accion = accion_entry.get().strip()

        if ip and tipo and accion:
            registrar_incidente(ip, tipo, accion)
            actualizar_lista()
            ip_entry.delete(0, END)
            ataque_entry.delete(0, END)
            accion_entry.delete(0, END)

    ttk.Button(frm, text="➕ Agregar Incidente Manual", command=agregar_manual).grid(column=0, row=5, columnspan=2, pady=5)

    ttk.Button(frm, text="Regresar", command=lambda: [window.destroy(), parent_root.deiconify() if parent_root else None]).grid(column=0, row=6, columnspan=2, pady=10)

    window.mainloop()

# Para pruebas independientes
if __name__ == "__main__":
    run()
