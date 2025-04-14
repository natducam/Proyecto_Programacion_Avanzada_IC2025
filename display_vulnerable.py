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
        vulnerabilities.append(f"Software obsoleto: {outdated_software}")
    
    # Comprobación de configuraciones inseguras
    insecure_configs = check_insecure_configurations()
    if insecure_configs:
        vulnerabilities.append(f"Configuraciones inseguras: {insecure_configs}")
    
    # Comprobación de autenticación débil
    weak_auth = check_weak_authentication()
    if weak_auth:
        vulnerabilities.append(f"Fallos en autenticación: {weak_auth}")
    else:
        vulnerabilities.append("No se encontraron fallos en autenticación.")
    
    return vulnerabilities

def check_outdated_software():
    outdated = []
    
    # Verificación de versión de Python
    python_version = platform.python_version()
    if version.parse(python_version) < version.parse('3.8'):
        outdated.append(f"Python {python_version} -> Se recomienda actualizar a 3.10 o superior.")
    else:
        outdated.insert(0, "++ No hay versiones obsoletas.")
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
    
    # Verificación de puertos abiertos
    open_ports = check_open_ports()
    if open_ports:
        insecure.append(f"Puertos abiertos y sin monitorear: {open_ports}")
    
    return insecure

def check_open_ports():
    open_ports = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'LISTEN':
            open_ports.append(f"Puerto {conn.laddr.port}")
    return open_ports

def check_weak_authentication():
    weak = []
    try:
        result = subprocess.run(["net", "user"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
        if result.returncode == 0:
            output = result.stdout
            users = []
            capture = False
            for line in output.splitlines():
                if "-------" in line:
                    capture = not capture
                    continue
                if capture:
                    users.extend(line.split())
            for user in users:
                if user.lower() in ['admin', 'administrator', 'test']:
                    weak.append(f"Cuenta potencialmente débil: {user}")
        else:
            weak.append("No se pudo obtener la lista de usuarios.")
    except Exception:
        weak.append("Error al verificar usuarios.")
    
    return weak

def show_vulnerabilities():
    vulnerabilities = check_vulnerabilities()
    
    if vulnerabilities:
        messagebox.showwarning("Vulnerabilidades encontradas", "\n".join(vulnerabilities))

def open_window(parent_root):
    # Ventana principal del módulo de vulnerabilidades
    window = tk.Toplevel(parent_root)
    window.title("Monitoreo de Vulnerabilidades")
    
    # Etiqueta
    label = tk.Label(window, text="Verificación de vulnerabilidades del sistema")
    label.pack(pady=10)
    
    # Botón para ejecutar el chequeo de vulnerabilidades
    check_button = ttk.Button(window, text="Verificar Vulnerabilidades", command=show_vulnerabilities)
    check_button.pack(pady=20)

    # Botón para regresar al menú
    back_button = ttk.Button(window, text="Regresar al menú", command=lambda: close_window_and_back(parent_root, window))
    back_button.pack(pady=10)

def close_window_and_back(parent_root, window):
    window.destroy()
    parent_root.deiconify()  # Mostrar la ventana principal nuevamente

def run(parent_root=None):
    if parent_root is None:
        root = tk.Tk()
        root.withdraw()  # Ocultamos la ventana principal
        open_window(root)  # Abrimos la ventana de vulnerabilidades
    else:
        open_window(parent_root)

if __name__ == "__main__":
    run()
