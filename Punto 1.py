import tkinter as tk
from tkinter import scrolledtext, messagebox
import nmap
 
def scan_target():
    target = entry_target.get()
    ports = entry_ports.get()
 
    if not target:
        messagebox.showerror("Error", "Por favor, introduce una IP o dominio.")
        return
 
    scanner = nmap.PortScanner()
    output_text.config(state=tk.NORMAL)
    output_text.delete(1.0, tk.END)
   
    output_text.insert(tk.END, f" Escaneando {target} en puertos {ports}...\n\n")
   
    try:
        scanner.scan(target, ports, arguments="-sS -Pn -T4 -A")
       
        for host in scanner.all_hosts():
            output_text.insert(tk.END, f" Host: {host} ({scanner[host].hostname()})\n")
            output_text.insert(tk.END, f" Estado: {scanner[host].state()}\n\n")
 
            for proto in scanner[host].all_protocols():
                output_text.insert(tk.END, f" Protocolo: {proto.upper()}\n")
                ports = scanner[host][proto].keys()
               
                for port in sorted(ports):
                    state = scanner[host][proto][port]['state']
                    service = scanner[host][proto][port]['name']
                    output_text.insert(tk.END, f"   - Puerto {port}: {state} ({service})\n")
           
            output_text.insert(tk.END, "\n" + "="*40 + "\n")
       
    except Exception as e:
        output_text.insert(tk.END, f" Error: {str(e)}\n")
   
    output_text.config(state=tk.DISABLED)
 
 
root = tk.Tk()
root.title("Escáner de Puertos")
root.geometry("600x400")
 
 
tk.Label(root, text=" IP o Dominio:").pack(pady=5)
entry_target = tk.Entry(root, width=40)
entry_target.pack()
 
 
tk.Label(root, text=" Puertos (ej: 1-1000 o 22,80,443):").pack(pady=5)
entry_ports = tk.Entry(root, width=40)
entry_ports.pack()
entry_ports.insert(0, "1-1024")  
 
 
btn_scan = tk.Button(root, text="Iniciar Escaneo", command=scan_target, bg="green", fg="white")
btn_scan.pack(pady=10)
 
 
output_text = scrolledtext.ScrolledText(root, width=70, height=15, state=tk.DISABLED)
output_text.pack()
 
 
root.mainloop()