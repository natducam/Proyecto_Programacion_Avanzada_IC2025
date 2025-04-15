def display_prevention():
    window_prevention = Tk()
    window_prevention.title("Mecanismos de Prevención de Ataques")

    frm = ttk.Frame(window_prevention, padding=10)
    frm.grid()

    ttk.Label(frm, text="Mecanismos Disponibles:").grid(column=0, row=0, columnspan=2)

    # Simulación: Bloqueo de IPs
    def bloquear_ip():
        print("IP sospechosa bloqueada (simulado)")

    btn_bloquear_ip = ttk.Button(frm, text="Bloquear IP Sospechosa", command=bloquear_ip)
    btn_bloquear_ip.grid(column=0, row=1, sticky="w", pady=5)

    # Simulación: Filtrado de paquetes
    def filtrar_paquetes():
        print("Filtrado de paquetes activado (simulado)")

    btn_filtrar = ttk.Button(frm, text="Activar Filtrado de Paquetes", command=filtrar_paquetes)
    btn_filtrar.grid(column=0, row=2, sticky="w", pady=5)

    # Simulación: Reglas de acceso
    def aplicar_reglas():
        print("Restricciones de acceso aplicadas (simulado)")

    btn_reglas = ttk.Button(frm, text="Aplicar Reglas de Acceso", command=aplicar_reglas)
    btn_reglas.grid(column=0, row=3, sticky="w", pady=5)

    # Botón para regresar
    go_back = ttk.Button(frm, text="Regresar", command=lambda:[window_prevention.destroy(), main()])
    go_back.grid(column=0, row=4, pady=10)

    window_prevention.mainloop()

