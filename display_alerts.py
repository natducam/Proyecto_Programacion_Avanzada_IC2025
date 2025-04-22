# Cosntruir la interfaz grafica
import tkinter as tk
from tkinter import ttk
# Manejo de sistema de correo
import smtplib
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email import encoders
# Verificar patrones (si un email tiene la estructura de un email)
import re
# Obtener fecha y hora para el asunto del email
from datetime import datetime
# Manejo de directorio de reportes
import os

# Envia un email desde una direcion predeterminada
# recipient_email = el email de destino
# subject = asunto del email, file = archivo de reporte
def send_email(recipient_email,subject,file_path):
    # Servidor y puerto de gmail
    smtp_server = 'smtp.gmail.com' 
    smtp_port = 587

    # Email predeterminado y su clave 
    source_email = 'test02152326@gmail.com'
    password = 'iqtw akxa avxt wwva'

    # Definiendo los detalles
    message = MIMEMultipart()
    message['From'] = source_email
    message['To'] = recipient_email
    message['Subject'] = subject

    message.attach(MIMEText('', 'plain'))

    with open(file_path,"rb") as file: # Adjunta el archivo
        part = MIMEBase("application","octet-stream")
        part.set_payload(file.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition","attachment",filename=os.path.basename(file_path))
        message.attach(part)

    with smtplib.SMTP(smtp_server, smtp_port) as server: # Envia el correo
        server.starttls()
        server.login(source_email, password) 
        server.sendmail(message['From'], message['To'], message.as_string()) 


def get_reports_list():
    directory = "Reportes"
    # Crea la carpeta "Reportes" si no existe
    if not os.path.exists(directory):
        return
    reports = os.listdir(directory)
    return reports


# Clase principal, aplicacion para enviar notificaciones
class NotificationsApp():
    def __init__(self, root):
        self.root = root
        self.root.title("Alertas y Notificaciones")

        # Espacio para escribir el email de destino
        tk.Label(root, text="Correo del destinatario:").pack(anchor='w', padx=10)
        self.recipient_entry = tk.Entry(root, width=50)
        self.recipient_entry.pack(padx=10, pady=(0, 10))

        self.selected_report = tk.StringVar()
        reports = get_reports_list()
        if reports:
            self.selected_report.set(reports[0])
        self.interface_menu = ttk.Combobox(root, textvariable=self.selected_report, values=reports, width=35)
        self.interface_menu.pack()

        # Buton para enviar correo
        self.send_button = tk.Button(root, text="Enviar Alerta", command=self.send_alert)
        self.send_button.pack(pady=(0, 10))

        # Mensaje de estado
        self.status_label = tk.Label(root, text="Sistema listo para enviar reporte.", fg="green")
        self.status_label.pack(pady=(0, 10))

        # Cambia el estado inicial segun disponibilidad de reportes:
        if not reports:
            self.send_button.config(state=tk.DISABLED)
            self.status_label.config(text="[!] No hay reportes disponibles.", fg="red")


    def send_alert(self):
        report_name = self.selected_report.get()
        subject = report_name
        report_path = f"Reportes/{report_name}"

        recipient = self.recipient_entry.get().strip()

        # Validation
        if not recipient:
            self.status_label.config(text="[!] Falta el correo del destinatario.", fg="red")
            return
        else:
            pattern = re.compile(r"[-A-Za-z0-9!#$%&'*+/=?^_`{|}~]+(?:\.[-A-Za-z0-9!#$%&'*+/=?^_`{|}~]+)*@(?:[A-Za-z0-9](?:[-A-Za-z0-9]*[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[-A-Za-z0-9]*[A-Za-z0-9])?", re.IGNORECASE)
            if not pattern.match(recipient):
                self.status_label.config(text="[!] El correo ingresado no es valido.", fg="red")
                return
        try:
            send_email(recipient,subject,report_path)
            self.status_label.config(text="Reporte enviado correctamente.", fg="green")
        except Exception as e:
            self.status_label.config(text=f"[!] ERROR: {e}", fg="red")

def run(parent_root=None):
    if parent_root is None:
        root = tk.Tk()
        app = NotificationsApp(root)
        root.mainloop()
    else:
        window = tk.Toplevel(parent_root)
        app = NotificationsApp(window)

if __name__ == "__main__":
    run()
