from tkinter import Tk
from tkinter import ttk
import display_alerts
import display_sniffing
import display_portscan
import display_vulnerable

def main():
    
    root = Tk()
    root.title("Sistema de Seguridad")
    
    frm = ttk.Frame(root, padding=10)
    frm.grid()
    
    ttk.Label(frm, text="Opciones").grid(column=0, row=0) 
    
    button1 = ttk.Button(frm, text="1. Identificacion de Vulnerabilidades ", command=lambda:display_vulnerable.run(root))
    button1.grid(column=0, row=1)  
    
    button2 = ttk.Button(frm, text="2. Packet Sniffing", command=lambda:display_sniffing.run(root))
    button2.grid(column=0, row=2)  

    button3 = ttk.Button(frm, text="3. Escaneo de Puertos (nmap)", command=lambda:display_portscan.run(root))
    button3.grid(column=0, row=3)  


    button4 = ttk.Button(frm, text="4. Alertas y Notificaciones", command=lambda:display_alerts.run(root))
    button4.grid(column=0, row=4) 

    root.mainloop()

main()