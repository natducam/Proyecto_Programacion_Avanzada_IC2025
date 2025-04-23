# Construir la interfaz grafica
import tkinter as tk
from tkinter import ttk
# Manejar el directorio donde se guardan los reportes
import os
# Obtener la fecha y hora para el nombre de archivos de reporte
from datetime import datetime
# Trabajar con documentos tipo CSV
import csv

# Clase principal de la aplicación de generación de reportes
class ReportApp:
    # Constructor de la clase
    # root: ventana principal de Tkinter
    def __init__(self, root):
        self.root = root
        self.root.title("Generador de Reportes")

        # Frame para contener los botones
        self.button_frame = ttk.Frame(root)
        self.button_frame.pack(pady=10)

        # Botón para iniciar la generación del reporte CSV
        self.start_button = ttk.Button(self.button_frame, text="Generar Reporte CSV", command=self.generate_csv)
        self.start_button.pack(side=tk.LEFT, padx=5)

        # Mensaje de estado
        self.status_label = tk.Label(root, text="Sistema esta listo para generar reportes", fg="grey")
        self.status_label.pack(pady=(0, 10))

        # Diccionario para almacenar la información recolectada de los logs
        self.info = {}

    # Función para compilar la información de los diferentes archivos de logs
    def compile_info(self):
        try:
            # Intenta abrir el archivo de monitoreo
            with open("log_monitoreo.txt", "r") as file:
                lines = [line.rstrip('\n') for line in file]
                self.info["LOG MONITOREO"] = lines
        except Exception as e:
            # Si ocurre un error, lo registra
            self.info["LOG MONITOREO"] = [f"[!] ERROR: {e}"]

        try:
            # Intenta abrir el archivo de escaneo de puertos
            with open("log_escaneo_puertos.txt", "r") as file:
                lines = [line.rstrip('\n') for line in file]
                self.info["LOG ESCANEO DE PUERTOS"] = lines
        except Exception as e:
            self.info["LOG ESCANEO DE PUERTOS"] = [f"[!] ERROR: {e}"]

        try:
            # Intenta abrir el archivo de incidentes
            with open("incidentes.csv", "r") as file:
                lines = [line.rstrip('\n') for line in file]
                self.info["LOG INCIDENTES"] = lines
        except Exception as e:
            self.info["LOG INCIDENTES"] = [f"[!] ERROR: {e}"]


    # Función para generar el archivo CSV con la información recolectada
    def generate_csv(self):
        try:
            # Crea un timestamp para el nombre del archivo
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            directory = "Reportes"

            # Crea la carpeta "Reportes" si no existe
            if not os.path.exists(directory):
                os.mkdir(directory)

            # Nombre completo del archivo CSV
            file_name = f"{directory}/Reporte_{timestamp}.csv"

            # Compila la información de los archivos de logs
            self.compile_info()

            # Abre el archivo CSV en modo de escritura
            with open(file_name, mode="a+", newline='') as file:
                writer = csv.writer(file)

                # Escribe cada sección de logs en el CSV
                for key, value in self.info.items():
                    writer.writerow([f">>> {key} <<<"]) # Título de la sección
                    for item in value:
                        writer.writerow([item]) # Cada línea del log
                    writer.writerow([])  # Línea en blanco para separar secciones
            self.status_label.config(text="Reporte generado exitosamente.", fg="green")
        except Exception as e:
            self.status_label.config(text=f"[!] ERROR: {e}", fg="red")

# Función para ejecutar la aplicación principal
# parent_root = ventana Tk() existente, o crea una nueva si no existe
def run(parent_root=None):
    if parent_root is None:
        # Si se ejecuta directamente
        root = tk.Tk()
        app = ReportApp(root)
        root.mainloop()
    else:
        # Si se integra a otra ventana
        window = tk.Toplevel(parent_root)
        app = ReportApp(window)

# Punto de entrada del programa
if __name__ == "__main__":
    run()