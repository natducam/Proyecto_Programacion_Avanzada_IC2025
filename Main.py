from tkinter import Tk
from tkinter import ttk
import display_alerts
import display_monitoring
import display_scan
import display_vulnerable

def boton_presionado():
    print("¡Botón presionado!")

def display_services():
    window_services = Tk()

    frm = ttk.Frame(window_services,padding=10)
    frm.grid()

    go_back = ttk.Button(frm, text="Regresar", command=lambda:[window_services.destroy(),main()])
    go_back.grid(column=0, row=1) 

    window_services.mainloop()

def display_prevention():
    window_prevention = Tk()

    frm = ttk.Frame(window_prevention,padding=10)
    frm.grid()

    go_back = ttk.Button(frm, text="Regresar", command=lambda:[window_prevention.destroy(),main()])
    go_back.grid(column=0, row=1) 

    window_prevention.mainloop()

def display_incidents():
    window_incidents = Tk()

    frm = ttk.Frame(window_incidents,padding=10)
    frm.grid()

    go_back = ttk.Button(frm, text="Regresar", command=lambda:[window_incidents.destroy(),main()])
    go_back.grid(column=0, row=1) 

    window_incidents.mainloop()

def display_report():
    window_report = Tk()

    frm = ttk.Frame(window_report,padding=10)
    frm.grid()

    go_back = ttk.Button(frm, text="Regresar", command=lambda:[window_report.destroy(),main()])
    go_back.grid(column=0, row=1) 

    window_report.mainloop()

def main():
    
    root = Tk()
    root.title("Sistema de Seguridad")
    
    frm = ttk.Frame(root, padding=10)
    frm.grid()
    
    ttk.Label(frm, text="Opciones").grid(column=0, row=0) 
    
    button1 = ttk.Button(frm, text="1. Escaneo de Puertos y Servicios", command=lambda: display_scan.run(root))
    button1.grid(column=0, row=1) 

    button2 = ttk.Button(frm, text="2. Detecion de Servicios en la Red", command=lambda:[root.destroy(),display_services()])
    button2.grid(column=0, row=2)  

    button3 = ttk.Button(frm, text="3. Identificacion de Vulnerabilidades ", command=lambda:display_vulnerable.run(root))
    button3.grid(column=0, row=3)  
    
    button4 = ttk.Button(frm, text="4. Mecanismos de Prevencion de Ataque", command=lambda:[root.destroy(),display_prevention()])
    button4.grid(column=0, row=4)  
    
    button5 = ttk.Button(frm, text="5. Monitoreo", command=lambda:display_monitoring.run(root))
    button5.grid(column=0, row=5)  

    button6 = ttk.Button(frm, text="6. Alertas y Notificaciones", command=lambda:display_alerts.run(root))
    button6.grid(column=0, row=6) 

    button7 = ttk.Button(frm, text="7. Registro de Incidentes", command=lambda:[root.destroy(),display_incidents()])
    button7.grid(column=0, row=7) 

    button8 = ttk.Button(frm, text="8. Informes", command=lambda:[root.destroy(),display_report()])
    button8.grid(column=0, row=8) 

    root.mainloop()

main()