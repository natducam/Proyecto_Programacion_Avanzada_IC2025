from tkinter import Tk
from tkinter import ttk
import display_alerts
import display_prevention
import display_monitoring
import display_scan
import display_vulnerable
import display_services
import display_report
import display_incidents

def boton_presionado():
    print("¡Botón presionado!")

def main():
    
    root = Tk()
    root.title("Sistema de Seguridad")
    
    frm = ttk.Frame(root, padding=10)
    frm.grid()
    
    ttk.Label(frm, text="Opciones").grid(column=0, row=0) 
    
    button1 = ttk.Button(frm, text="1. Escaneo de Puertos y Servicios", command=lambda:display_scan.run(root))
    button1.grid(column=0, row=1) 

    button2 = ttk.Button(frm, text="2. Detecion de Servicios en la Red", command=lambda:display_services.run(root))
    button2.grid(column=0, row=2)  

    button3 = ttk.Button(frm, text="3. Identificacion de Vulnerabilidades ", command=lambda:display_vulnerable.run(root))
    button3.grid(column=0, row=3)  
    
    button4 = ttk.Button(frm, text="4. Mecanismos de Prevencion de Ataque", command=lambda:display_prevention.run(root))
    button4.grid(column=0, row=4)  
    
    button5 = ttk.Button(frm, text="5. Monitoreo", command=lambda:display_monitoring.run(root))
    button5.grid(column=0, row=5)  

    button6 = ttk.Button(frm, text="6. Alertas y Notificaciones", command=lambda:display_alerts.run(root))
    button6.grid(column=0, row=6) 

    button7 = ttk.Button(frm, text="7. Registro de Incidentes", command=lambda:display_incidents.run(root))
    button7.grid(column=0, row=7) 

    button8 = ttk.Button(frm, text="8. Informes", command=lambda:display_report.run())
    button8.grid(column=0, row=8) 
    
    button9 = ttk.Button(frm, text="9. Salir", command=root.destroy)
    button9.grid(column=0, row=9)

    root.mainloop()

main()