import tkinter as tk
from tkinter import ttk
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import os
import re

def send_email(recipient_email, subject, content, attachment_path=None):
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587

    source_email = 'test02152326@gmail.com'
    password = 'iqtw akxa avxt wwva'

    message = MIMEMultipart()
    message['From'] = source_email
    message['To'] = recipient_email
    message['Subject'] = subject

    message.attach(MIMEText(content, 'plain'))

    if attachment_path:
        try:
            with open(attachment_path, 'rb') as file:
                part = MIMEApplication(file.read(), Name=os.path.basename(attachment_path))
                part['Content-Disposition'] = f'attachment; filename="{os.path.basename(attachment_path)}"'
                message.attach(part)
        except Exception as e:
            raise Exception(f"No se pudo adjuntar el archivo: {e}")

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(source_email, password)
        server.sendmail(message['From'], message['To'], message.as_string())

class NotificationsApp():
    def __init__(self, root):
        self.root = root
        self.root.title("Alertas y Notificaciones")

        # Email recipient
        tk.Label(root, text="Correo del destinatario:").pack(anchor='w', padx=10)
        self.recipient_entry = tk.Entry(root, width=50)
        self.recipient_entry.pack(padx=10, pady=(0, 10))

        # Email subject
        tk.Label(root, text="Asunto del correo:").pack(anchor='w', padx=10)
        self.subject_entry = tk.Entry(root, width=50)
        self.subject_entry.pack(padx=10, pady=(0, 10))

        # Email content
        tk.Label(root, text="Contenido del mensaje:").pack(anchor='w', padx=10)
        self.content_text = tk.Text(root, height=10, width=60)
        self.content_text.pack(padx=10, pady=(0, 10))

        # File attachment
        tk.Label(root, text="Selecciona un archivo de RESULTS para adjuntar:").pack(anchor='w', padx=10)
        self.file_var = tk.StringVar()
        self.file_menu = ttk.Combobox(root, textvariable=self.file_var, width=50)
        self.file_menu.pack(padx=10, pady=(0, 10))
        self.load_results_files()

        # Send button
        send_button = tk.Button(root, text="Enviar Alerta", command=self.send_alert)
        send_button.pack(pady=(0, 10))

        # Status label
        self.status_label = tk.Label(root, text="", fg="green")
        self.status_label.pack(pady=(0, 10))

    def load_results_files(self):
        results_folder = "RESULTS"
        if not os.path.exists(results_folder):
            os.makedirs(results_folder)
        files = [f for f in os.listdir(results_folder) if f.endswith(".txt")]
        self.file_menu['values'] = files
        if files:
            self.file_var.set(files[0])
        else:
            self.file_var.set("")

    def send_alert(self):
        recipient = self.recipient_entry.get().strip()
        subject = self.subject_entry.get().strip()
        content = self.content_text.get("1.0", tk.END).strip()
        selected_file = self.file_var.get().strip()
        attachment_path = os.path.join("RESULTS", selected_file) if selected_file else None

        # Validation
        if not recipient:
            self.status_label.config(text="Falta el correo del destinatario.", fg="red")
            return
        else:
            pattern = re.compile(r"[-A-Za-z0-9!#$%&'*+/=?^_`{|}~]+(?:\.[-A-Za-z0-9!#$%&'*+/=?^_`{|}~]+)*@(?:[A-Za-z0-9](?:[-A-Za-z0-9]*[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[-A-Za-z0-9]*[A-Za-z0-9])?", re.IGNORECASE)
            if not pattern.match(recipient):
                self.status_label.config(text="El correo ingresado no es válido.", fg="red")
                return
        if not subject:
            self.status_label.config(text="Falta el asunto del mensaje.", fg="red")
            return
        if not content:
            self.status_label.config(text="Falta el contenido del mensaje.", fg="red")
            return

        try:
            send_email(recipient, subject, content, attachment_path)
            self.status_label.config(text="Alerta enviada correctamente.", fg="green")
        except Exception as e:
            self.status_label.config(text=f"Error al enviar alerta: {e}", fg="red")

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