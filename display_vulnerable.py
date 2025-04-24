import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import platform
import psutil
import os
from packaging import version

def check_vulnerabilities():
    vulnerabilities = []

    # Comprobación de versiones obsoletas de software
    outdated_software = check_outdated_software()
    if outdated_software:
        vulnerabilities.append("++++++++ Software obsoleto ++++++++\n" + "\n".join(outdated_software))

    # Comprobación de configuraciones inseguras
    insecure_configs = check_insecure_configurations()
    if insecure_configs:
        vulnerabilities.append("++++++++ Configuraciones inseguras ++++++++\n" + "\n".join(insecure_configs))

    # Comprobación de fallos autenticación
    weak_auth = check_fail_authentication()
    if weak_auth:
        vulnerabilities.append("++++++++ Fallos en autenticación ++++++++\n" + "\n".join(weak_auth))

    return vulnerabilities

def check_outdated_software():
    outdated = []

    # Verificación de Firefox (al ser una versión vieja esta en otro path)
    firefox_path = r"C:\Program Files\Mozilla Firefox\firefox.exe"
    if os.path.exists(firefox_path):
        try:
            result = subprocess.run([firefox_path, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output = result.stdout.strip()
            if "Firefox" in output:
                version_num = output.split("Firefox")[-1].strip()
                if version.parse(version_num) < version.parse("134"):
                    outdated.append(f"Firefox versión {version_num} -> Se recomienda actualizar a 137 o superior.")
                else:
                    outdated.append(f"Firefox versión {version_num} está dentro del soporte.")
            else:
                outdated.append("No se pudo determinar la versión de Firefox.")
        except Exception as e:
            outdated.append(f"No se pudo verificar la versión de Firefox: {e}")
    else:
        outdated.append("Firefox no está instalado en este sistema.")

    # Verificación de versión de Python
    python_version = platform.python_version()
    if version.parse(python_version) < version.parse('3.8'):
        outdated.append(f"Python {python_version} -> Se recomienda actualizar a 3.10 o superior.")
    else:
        outdated.append(f"Python {python_version} está dentro del soporte.")

    # Verificación de versión de Windows
    if platform.system() == 'Windows':
        windows_version = platform.system() + " " + platform.release()
        release = platform.release()
        supported_versions = ['10', '11']
        if release not in supported_versions:
            outdated.append(f"{windows_version} -> Se recomienda actualizar a Windows 10 o superior.")
        else:
            outdated.append(f"{windows_version} está dentro del soporte.")

    return outdated

def check_insecure_configurations():
    insecure = []
    open_ports = check_open_ports()
    if open_ports:
        insecure.append("Puertos abiertos y sin monitorear:")
        insecure.extend(open_ports)
    return insecure

def check_open_ports():
    open_ports = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'LISTEN':
            try:
                port = conn.laddr.port
                open_ports.append(f"Puerto {port}")
            except Exception:
                continue
    return open_ports

def check_fail_authentication():
    fallos = []
    path_log = "log_autenticacion.txt"

    if os.path.exists(path_log):
        try:
            with open(path_log, 'r', encoding='utf-8', errors='ignore') as archivo:
                lineas = archivo.readlines()
                if lineas:
                    for linea in lineas:
                        fallos.append(linea.strip())
                else:
                    fallos.append("No hay fallos de autenticación.")
        except Exception as e:
            fallos.append(f"No se pudo leer el archivo de log: {e}")
    else:
        fallos.append("No se encontraron fallos de autenticación porque no se encontró el log.")

    return fallos

def show_vulnerabilities():
    vulnerabilities = check_vulnerabilities()
    if vulnerabilities:
        messagebox.showwarning("Vulnerabilidades encontradas", "\n\n".join(vulnerabilities))

def open_window(parent_root):
    window = tk.Toplevel(parent_root)
    window.title("Monitoreo de Vulnerabilidades")

    label = tk.Label(window, text="Verificación de vulnerabilidades del sistema")
    label.pack(pady=10)

    check_button = ttk.Button(window, text="Verificar Vulnerabilidades", command=show_vulnerabilities)
    check_button.pack(pady=20)

    back_button = ttk.Button(window, text="Regresar al menú", command=lambda: back_to_menu(parent_root, window))
    back_button.pack(pady=10)

def back_to_menu(parent_root, window):
    window.destroy()
    parent_root.deiconify()

def run(parent_root=None):
    if parent_root is None:
        root = tk.Tk()
        root.withdraw()
        open_window(root)
    else:
        open_window(parent_root)

if __name__ == "__main__":
    run()




