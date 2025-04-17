import tkinter as tk
from tkinter import messagebox
import datetime
import os

# Datos correctos
USUARIO_CORRECTO = "admin"
CONTRASENA_CORRECTA = "12345"

# Ruta del archivo de log en tu sistema
LOG_FILE_PATH = r"C:\Users\Usuario\GitHub\Proyecto_Programacion_Avanzada_IC2025\log_autenticacion.txt"

# Función para registrar fallos en el log
def registrar_fallo(usuario_intentado):
    fecha_hora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        # Abre el archivo en modo 'a' para agregar texto al final del archivo
        with open(LOG_FILE_PATH, "a") as log:
            log.write(f"Fallo de autenticación con el usuario '{usuario_intentado}' el día {fecha_hora}\n")
        print(f"Log registrado en {LOG_FILE_PATH}")  
    except Exception as e:
        print(f"Error al escribir en el log: {e}")

# Función que valida las credenciales
def validar():
    usuario = entrada_usuario.get()
    contrasena = entrada_contrasena.get()

    if usuario == USUARIO_CORRECTO and contrasena == CONTRASENA_CORRECTA:
        messagebox.showinfo("Acceso concedido", "Inicio de sesión exitoso.")
        ventana.quit()  # Cerrar ventana al ingresar correctamente
    else:
        registrar_fallo(usuario)
        messagebox.showerror("Error", "Usuario o contraseña incorrectos.")

# Crear ventana
ventana = tk.Tk()
ventana.title("Inicio de Sesión")
ventana.geometry("300x200")

# Etiquetas y campos de entrada
tk.Label(ventana, text="Usuario:").pack(pady=5)
entrada_usuario = tk.Entry(ventana)
entrada_usuario.pack()

tk.Label(ventana, text="Contraseña:").pack(pady=5)
entrada_contrasena = tk.Entry(ventana, show="*")
entrada_contrasena.pack()

# Botón para iniciar sesión
tk.Button(ventana, text="Iniciar sesión", command=validar).pack(pady=20)

# Ejecutar la ventana
ventana.mainloop()

