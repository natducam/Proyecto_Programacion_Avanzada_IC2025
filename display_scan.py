import tkinter as tk
from tkinter import ttk
import threading
from scapy.all import sniff, IP, TCP

# Variable global para el estado de monitoreo
monitoring = False

# Variable para contar los intentos de SYN en diferentes puertos
syn_attempts = {}

# Función que simula el monitoreo de tráfico de red
def monitor_network(log_text):
    def packet_callback(packet):
        if not monitoring:
            return
        if packet.haslayer(IP) and packet.haslayer(TCP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = packet[TCP].flags

            log_text.insert(tk.END, f"IP origen: {ip_src} IP destino: {ip_dst} Puerto origen: {sport} Puerto destino: {dport} Banderas: {flags}.\n")
            log_text.yview(tk.END)

            # Detectar escaneo SYN (muchos intentos a diferentes puertos sin completar la conexión)
            if flags == "S":  # Paquete SYN
                if ip_src not in syn_attempts:
                    syn_attempts[ip_src] = set()
                syn_attempts[ip_src].add(dport)
                
                # Si se detecta demasiados puertos diferentes en un corto período, es un escaneo SYN
                if len(syn_attempts[ip_src]) > 5:
                    log_text.insert(tk.END, f"Mensaje SYN sospechoso detectado desde {ip_src} hacia {ip_dst} en puerto {dport}.\n")
                    log_text.yview(tk.END)

            # Detectar intentos de acceso no autorizado 
            if dport == 22:  # Puerto 22 para SSH
                log_text.insert(tk.END, f"Intento de acceso a SSH detectado desde {ip_src} hacia {ip_dst} en puerto 22.\n")
                log_text.yview(tk.END)

            # Detectar comunicaciones maliciosas a puertos no comunes fuera del rango establecido
            if dport > 1024 and dport < 49152:  
                log_text.insert(tk.END, f"Tráfico sospechoso detectado desde {ip_src} hacia {ip_dst} en puerto {dport}.\n")
                log_text.yview(tk.END)

    # Captura los paquetes de red
    sniff(prn=packet_callback, store=0, count=0)  # count=0 significa que captura indefinidamente hasta que se detenga

# Función para iniciar el monitoreo en un hilo separado
def start_monitoring(log_text):
    global monitoring
    monitoring = True
    monitor_thread = threading.Thread(target=monitor_network, args=(log_text,))
    monitor_thread.daemon = True  # El hilo se cierra cuando se cierra la ventana
    monitor_thread.start()

# Función para detener el monitoreo
def stop_monitoring():
    global monitoring
    monitoring = False

# Función para crear la ventana de monitoreo
def open_window(root):
    global monitoring
    monitoring = False  # Inicia con monitoreo detenido

    # Ventana para monitoreo
    monitoring_window = tk.Toplevel(root)
    monitoring_window.title("Monitoreo de Tráfico de Red")
    
    # Crear frame
    frame = ttk.Frame(monitoring_window, padding=10)
    frame.grid()

    # Crear widget para mostrar el log
    log_text = tk.Text(frame, height=20, width=80)
    log_text.grid(row=0, column=0, padx=10, pady=10)

    # Función para iniciar el monitoreo
    def start_button_pressed():
        start_monitoring(log_text)
        start_button.config(state=tk.DISABLED)
        stop_button.config(state=tk.NORMAL)

    # Función para detener el monitoreo
    def stop_button_pressed():
        stop_monitoring()
        log_text.insert(tk.END, "Monitoreo detenido.\n")
        log_text.yview(tk.END)
        start_button.config(state=tk.NORMAL)
        stop_button.config(state=tk.DISABLED)

    # Función para regresar al menú principal
    def back_button_pressed():
        monitoring_window.destroy()

    start_button = ttk.Button(frame, text="Iniciar Monitoreo", command=start_button_pressed)
    start_button.grid(row=1, column=0, padx=10, pady=10)

    stop_button = ttk.Button(frame, text="Detener Monitoreo", command=stop_button_pressed, state=tk.DISABLED)
    stop_button.grid(row=2, column=0, padx=10, pady=10)

    back_button = ttk.Button(frame, text="Regresar al menú principal", command=back_button_pressed)
    back_button.grid(row=3, column=0, padx=10, pady=10)

    monitoring_window.mainloop()


def run(parent_root=None):
    if parent_root is None:
        root = tk.Tk()
        root.withdraw()
        open_window(root)
    else:
        open_window(parent_root)

if __name__ == "__main__":
    run()
