import tkinter as tk
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import re

def send_email(recipient_email, subject, content):
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587

    source_email = 'test02152326@gmail.com'
    password = 'iqtw akxa avxt wwva'

    message = MIMEMultipart()
    message['From'] = source_email
    message['To'] = recipient_email
    message['Subject'] = subject

    message.attach(MIMEText(content, 'plain'))

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

        # Send button
        send_button = tk.Button(root, text="Enviar Alerta", command=self.send_alert)
        send_button.pack(pady=(0, 10))

        # Status label
        self.status_label = tk.Label(root, text="", fg="green")
        self.status_label.pack(pady=(0, 10))

    def send_alert(self):
        recipient = self.recipient_entry.get().strip()
        subject = self.subject_entry.get().strip()
        content = self.content_text.get("1.0", tk.END).strip()

        # Validation
        if not recipient:
            self.status_label.config(text="Falta el correo del destinatario.", fg="red")
            return
        else:
            pattern = re.compile(r"[-A-Za-z0-9!#$%&'*+/=?^_`{|}~]+(?:\.[-A-Za-z0-9!#$%&'*+/=?^_`{|}~]+)*@(?:[A-Za-z0-9](?:[-A-Za-z0-9]*[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[-A-Za-z0-9]*[A-Za-z0-9])?", re.IGNORECASE)
            if not pattern.match(recipient):
                self.status_label.config(text="El correo ingresado no es valido.", fg="red")
                return
        if not subject:
            self.status_label.config(text="Falta el asunto del mensaje.", fg="red")
            return
        if not content:
            self.status_label.config(text="Falta el contenido del mensaje.", fg="red")
            return

        try:
            send_email(recipient, subject, content)
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
