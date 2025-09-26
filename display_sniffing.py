import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
from scapy.all import sniff, get_if_list
from scapy.layers.http import HTTPRequest
import queue

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Sniffer de Paquetes")

        # Interface selection
        self.interface_var = tk.StringVar()
        interfaces = get_if_list()
        if interfaces:
            self.interface_var.set(interfaces[0])
        ttk.Label(root, text="Selecciona la Interfaz de Red:").pack(pady=(10, 0))
        self.interface_menu = ttk.Combobox(root, textvariable=self.interface_var, values=interfaces)
        self.interface_menu.pack()

        # Buttons
        self.button_frame = ttk.Frame(root)
        self.button_frame.pack(pady=10)

        self.start_button = ttk.Button(self.button_frame, text="Iniciar Sniffing", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(self.button_frame, text="Detener Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.reset_button = ttk.Button(self.button_frame, text="Reiniciar", command=self.reset_sniffer)
        self.reset_button.pack(side=tk.LEFT, padx=5)

        # Status and packet count
        self.status_label = ttk.Label(root, text="Estado: Inactivo")
        self.status_label.pack()

        self.packet_count_label = ttk.Label(root, text="Paquetes Capturados: 0")
        self.packet_count_label.pack(pady=(5, 10))

        # Packet display area
        self.packet_display = scrolledtext.ScrolledText(root, height=20, width=80)
        self.packet_display.pack(padx=10, pady=10)

        self.sniffing = False
        self.packet_count = 0
        self.packet_queue = queue.Queue()
        self.update_display_loop()

    def start_sniffing(self):
        iface = self.interface_var.get()
        if iface:
            self.sniffing = True
            self.packet_count = 0
            self.packet_display.delete(1.0, tk.END)
            self.packet_count_label.config(text="Paquetes Capturados: 0")
            self.status_label.config(text="Estado: Activo")
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)

            self.sniff_thread = threading.Thread(target=self.sniff_packets, args=(iface,), daemon=True)
            self.sniff_thread.start()
        else:
            self.packet_display.insert(tk.END, "Por favor, selecciona una interfaz de red.\n")

    def stop_sniffing(self):
        self.sniffing = False
        self.status_label.config(text="Estado: Inactivo")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

        if self.packet_count == 0:
            self.packet_display.insert(tk.END, "No se detectaron paquetes en esta interfaz.\n")

    def reset_sniffer(self):
        self.sniffing = False
        self.packet_count = 0
        self.packet_display.delete(1.0, tk.END)
        self.packet_count_label.config(text="Paquetes Capturados: 0")
        self.status_label.config(text="Estado: Inactivo")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self, iface):
        sniff(iface=iface, prn=self.handle_packet, store=False, stop_filter=lambda x: not self.sniffing)

    def handle_packet(self, pkt):
        if not self.sniffing:
            return False
        self.packet_count += 1
        summary = pkt.summary()
        self.packet_queue.put((self.packet_count, summary))

    def update_display_loop(self):
        try:
            while not self.packet_queue.empty():
                count, summary = self.packet_queue.get_nowait()
                self.packet_count_label.config(text=f"Paquetes Capturados: {count}")
                self.packet_display.insert(tk.END, summary + "\n")
                self.packet_display.see(tk.END)
        except Exception:
            pass
        finally:
            self.root.after(500, self.update_display_loop)

def run(parent_root):
    if parent_root is None:
        root = tk.Tk()
        app = PacketSnifferApp(root)
        root.mainloop()
    else:
        window = tk.Toplevel(parent_root)
        app = PacketSnifferApp(window)

if __name__ == "__main__":
    run()
