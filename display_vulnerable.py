import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import platform
import psutil
import os

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
    
    return vulnerabilities

def check_outdated_software():
    outdated = []
    python_version = platform.python_version()
    if python_version < '3.8':
        outdated.append(f"Python {python_version} (se recomienda actualizar a 3.8 o superior)")
    
    try:
        result = subprocess.run(['openssl', 'version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        openssl_version = result.stdout.strip().split()[-1]
        if openssl_version < '1.1':
            outdated.append(f"OpenSSL {openssl_version} (se recomienda actualizar a 1.1 o superior)")
    except FileNotFoundError:
        outdated.append("OpenSSL no encontrado")
    
    return outdated

def check_insecure_configurations():
    insecure = []
    if os.access('/etc/passwd', os.W_OK):
        insecure.append("/etc/passwd tiene permisos de escritura para todos")
    
    open_ports = check_open_ports()
    if open_ports:
        insecure.append(f"Puertos abiertos sin necesidad: {open_ports}")
    
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
        with open('/etc/passwd', 'r') as f:
            lines = f.readlines()
            for line in lines:
                if ':' not in line:
                    continue
                username = line.split(':')[0]
                if username in ['root', 'admin']:
                    weak.append(f"Cuenta potencialmente débil: {username}")
    except FileNotFoundError:
        weak.append("No se puede acceder a /etc/passwd para verificar cuentas.")
    
    return weak

def show_vulnerabilities():
    vulnerabilities = check_vulnerabilities()
    
    if vulnerabilities:
        messagebox.showwarning("Vulnerabilidades encontradas", "\n".join(vulnerabilities))
    else:
        messagebox.showinfo("No se encontraron vulnerabilidades", "El sistema está libre de vulnerabilidades conocidas.")

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

def run(parent_root=None):
    if parent_root is None:
        root = tk.Tk()
        root.withdraw()  # Ocultamos la ventana principal
        open_window(root)  # Abrimos la ventana de vulnerabilidades
    else:
        open_window(parent_root)

if __name__ == "__main__":
    run()
