from tkinter import Toplevel, ttk, scrolledtext
import os
import re

def buscar_eventos_sospechosos(log_path):
    eventos = []
    patrones_sospechosos = [
         r"contraseña fallida",
    r"fallo de autenticación",
    r"usuario inválido",
    r"sesión iniciada para el usuario root",
    r"conexión cerrada por .* puerto",
    ]

    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8", errors="ignore") as log_file:
            for linea in log_file:
                for patron in patrones_sospechosos:
                    if re.search(patron, linea, re.IGNORECASE):
                        eventos.append(linea.strip())
                        break
    else:
        eventos.append(f"No se encontró el archivo: {log_path}")
    
    return eventos

def run(root):
    root.destroy()
    ventana = Toplevel()
    ventana.title("Detección de Servicios en la Red")
    frm = ttk.Frame(ventana, padding=10)
    frm.grid()

    ttk.Label(frm, text="Análisis de registros del sistema (ej: /var/log/auth.log)").grid(column=0, row=0)

    text_area = scrolledtext.ScrolledText(frm, width=100, height=30)
    text_area.grid(column=0, row=1)

    log_path = "/var/log/auth.log"  # Ruta por defecto en Linux

    eventos = buscar_eventos_sospechosos(log_path)

    if eventos:
        text_area.insert("1.0", "\n".join(eventos))
    else:
        text_area.insert("1.0", "No se encontraron eventos sospechosos.")

    btn_back = ttk.Button(frm, text="Regresar", command=lambda:[ventana.destroy(), main_menu()])
    btn_back.grid(column=0, row=2)

def main_menu():
    from main import main
    main()
