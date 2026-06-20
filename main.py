"""
main.py — Point d'entrée de l'application CyberShield
"""
import customtkinter as ctk
from gui.main_window import MainApp

if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    app = MainApp()
    app.mainloop()