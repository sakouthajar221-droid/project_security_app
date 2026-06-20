"""
main_window.py — Édition Professionnelle "Cryptos"
Interface moderne avec Sidebar, cartes interactives et typographie soignée.
"""

import customtkinter as ctk
import tkinter as tk

# ═══════════════════════ PALETTE PREMIUM ═══════════════════════
BG_MAIN      = "#0f172a"  # Bleu nuit très sombre (Slate 950)
BG_SIDEBAR   = "#1e293b"  # Slate 800
CARD         = "#1e293b"
CARD_HOVER   = "#334155"  # Slate 700
BORDER       = "#334155"
ACCENT       = "#3b82f6"  # Blue (Confidentialité)
GREEN        = "#10b981"  # Emerald (Intégrité)
ORANGE       = "#f59e0b"  # Amber (Authenticité)
PURPLE       = "#8b5cf6"  # Violet (Certificats)
TEXT_PRIMARY = "#f8fafc"
TEXT_MUTED   = "#94a3b8"

# ═══════════════════════ COMPOSANT : CARTE MODULE ═══════════════════════
class ModuleCard(ctk.CTkFrame):
    def __init__(self, parent, icon, title, subtitle, color, command, **kwargs):
        super().__init__(
            parent,
            fg_color=CARD,
            corner_radius=12,
            border_width=1,
            border_color=BORDER,
            cursor="hand2",
            **kwargs
        )
        self._color = color
        self._command = command

        # Layout interne
        self.grid_columnconfigure(0, weight=1)
        
        # Conteneur d'icône avec fond discret
        self.icon_bg = ctk.CTkFrame(self, fg_color=BG_MAIN, width=44, height=44, corner_radius=10)
        self.icon_bg.pack(anchor="w", padx=20, pady=(20, 10))
        self.icon_bg.pack_propagate(False)

        self.icon_lbl = ctk.CTkLabel(self.icon_bg, text=icon, font=ctk.CTkFont(size=22), text_color=color)
        self.icon_lbl.place(relx=0.5, rely=0.5, anchor="center")

        # Titre
        self.title_lbl = ctk.CTkLabel(
            self, text=title, 
            font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold"),
            text_color=TEXT_PRIMARY, anchor="w"
        )
        self.title_lbl.pack(fill="x", padx=20)

        # Description
        self.sub_lbl = ctk.CTkLabel(
            self, text=subtitle,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED, anchor="w", justify="left", wraplength=250
        )
        self.sub_lbl.pack(fill="x", padx=20, pady=(5, 20))

        # Gestion des événements Hover sur tous les éléments de la carte
        for w in [self, self.title_lbl, self.sub_lbl, self.icon_bg, self.icon_lbl]:
            w.bind("<Enter>", self._on_enter)
            w.bind("<Leave>", self._on_leave)
            w.bind("<Button-1>", lambda e: self._command())

    def _on_enter(self, e):
        self.configure(fg_color=CARD_HOVER, border_color=self._color)

    def _on_leave(self, e):
        self.configure(fg_color=CARD, border_color=BORDER)

# ═══════════════════════ FENÊTRE PRINCIPALE ═══════════════════════
class MainApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Configuration de la fenêtre
        self.title("Cryptos — Cryptographic Security Suite")
        self.geometry("1200x800")
        self.minsize(1000, 700)
        self.configure(fg_color=BG_MAIN)

        # Grille principale (Sidebar à gauche, Contenu à droite)
        self.grid_columnconfigure(0, weight=0) # Sidebar largeur fixe
        self.grid_columnconfigure(1, weight=1) # Contenu extensible
        self.grid_rowconfigure(0, weight=1)

        # Initialisation de la Sidebar
        self._setup_sidebar()
        
        # Zone de contenu dynamique
        self.content_area = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        self.content_area.grid(row=0, column=1, sticky="nsew")

        # Affichage de la page d'accueil par défaut
        self.show_home()

    def _setup_sidebar(self):
        """Crée la barre latérale de navigation"""
        self.sidebar = ctk.CTkFrame(self, fg_color=BG_SIDEBAR, width=260, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        # Header Logo
        logo_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        logo_frame.pack(pady=(40, 50), padx=20, fill="x")

        ctk.CTkLabel(
            logo_frame, text="🔐 Cryptos", 
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"), 
            text_color=ACCENT
        ).pack(side="left")

        # Menu de navigation
        self.nav_buttons = []
        menu_items = [
            ("🏠  Tableau de bord", self.show_home),
            ("🔐  Confidentialité", self.open_confidentiality),
            ("✅  Intégrité", self.open_integrity),
            ("✍  Signatures", self.open_signature),
            ("🔏  Certificats X.509", self.open_certificate),
        ]

        for text, cmd in menu_items:
            btn = ctk.CTkButton(
                self.sidebar, text=text, command=cmd,
                fg_color="transparent", text_color=TEXT_PRIMARY,
                anchor="w", font=ctk.CTkFont(family="Segoe UI", size=14),
                hover_color=CARD_HOVER, height=45, corner_radius=10
            )
            btn.pack(fill="x", padx=15, pady=4)
            self.nav_buttons.append(btn)

        # Footer Sidebar
        footer_sb = ctk.CTkLabel(
            self.sidebar, text="v2.4.0-Stable\n© 2026 Cryptos Project", 
            font=("Segoe UI", 11), text_color=TEXT_MUTED, justify="center"
        )
        footer_sb.pack(side="bottom", pady=30)

    def _clear_content(self):
        """Nettoie la zone de contenu avant de charger une nouvelle page"""
        for widget in self.content_area.winfo_children():
            widget.destroy()

    def show_home(self):
        """Affiche le tableau de bord principal"""
        self._clear_content()
        
        # Scrollable Frame pour l'accueil
        scroll = ctk.CTkScrollableFrame(self.content_area, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=40, pady=20)

        # Hero Section (Titre + Sous-titre)
        hero_box = ctk.CTkFrame(scroll, fg_color="transparent")
        hero_box.pack(fill="x", pady=(30, 40))
        
        ctk.CTkLabel(
            hero_box, text="Système Cryptos Opérationnel", 
            font=ctk.CTkFont(size=34, weight="bold"), text_color=TEXT_PRIMARY
        ).pack(anchor="w")
        
        ctk.CTkLabel(
            hero_box, 
            text="Plateforme d'audit et de démonstration des protocoles de sécurité informatique.", 
            font=ctk.CTkFont(size=15), text_color=TEXT_MUTED
        ).pack(anchor="w", pady=(8, 0))

        # Grille des Modules
        grid = ctk.CTkFrame(scroll, fg_color="transparent")
        grid.pack(fill="x")
        grid.columnconfigure((0, 1), weight=1)

        modules = [
            ("🔐", "Confidentialité", "Chiffrement AES-256 et RSA-4096. Protection des données sensibles.", ACCENT, self.open_confidentiality, 0, 0),
            ("✅", "Intégrité", "Vérification SHA-256. Détection instantanée des altérations de données.", GREEN, self.open_integrity, 0, 1),
            ("✍", "Signatures RSA", "Preuve d'authenticité via RSA-PSS. Garantie de non-répudiation.", ORANGE, self.open_signature, 1, 0),
            ("🔏", "Certificats X.509", "Gestion de la PKI, génération de certificats et exportations PEM.", PURPLE, self.open_certificate, 1, 1),
        ]

        for icon, t, st, col, cmd, r, c in modules:
            card = ModuleCard(grid, icon, t, st, col, cmd)
            card.grid(row=r, column=c, padx=12, pady=12, sticky="nsew")

    # ── Logique de Navigation vers les fichiers externes ────────────────

    def open_confidentiality(self):
        self._clear_content()
        from gui.confidentiality_page import ConfidentialityPage
        # On passe self.content_area comme parent pour que la page s'affiche dans la zone de droite
        ConfidentialityPage(self.content_area).pack(fill="both", expand=True)

    def open_integrity(self):
        self._clear_content()
        from gui.integrity_page import IntegrityPage
        IntegrityPage(self.content_area).pack(fill="both", expand=True)

    def open_signature(self):
        self._clear_content()
        from gui.signature_page import SignaturePage
        SignaturePage(self.content_area).pack(fill="both", expand=True)

    def open_certificate(self):
        self._clear_content()
        from gui.certificate_page import CertificatePage
        CertificatePage(self.content_area).pack(fill="both", expand=True)

if __name__ == "__main__":
    app = MainApp()
    app.mainloop()