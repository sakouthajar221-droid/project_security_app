"""
signature_page.py — Signature Numérique RSA-PSS (adaptée en CTkFrame)
"""
import customtkinter as ctk
from tkinter import messagebox, filedialog
import base64
import time
from datetime import datetime

from core.signature import DigitalSignature
from core.asymmetric import AsymmetricCipher
from core.hashing import HashManager

# ── Palette ──────────────────────────────────────────────────────────────────
C_BG       = "#1e2130"
C_CARD     = "#252a3d"
C_CARD2    = "#2e3450"
C_ACCENT   = "#6c8ebf"
C_SUCCESS  = "#4caf82"
C_DANGER   = "#e05c6a"
C_WARN     = "#d4935a"
C_PIRATE   = "#9b4f6e"
C_TEXT     = "#dce3f0"
C_MUTED    = "#7a8499"
C_BORDER   = "#3a4060"
C_STEP_OK  = "#4caf82"
C_STEP_ACT = "#6c8ebf"
C_STEP_OFF = "#3a4060"
C_LOG_BG   = "#1a1e2e"


def _darken(h: str) -> str:
    c = h.lstrip("#")
    rgb = [max(0, int(c[i:i+2], 16) - 20) for i in (0, 2, 4)]
    return "#{:02x}{:02x}{:02x}".format(*rgb)


def make_card(parent, title, icon="", accent=C_ACCENT):
    frame = ctk.CTkFrame(parent, fg_color=C_CARD, corner_radius=12,
                          border_width=1, border_color=C_BORDER)
    frame.pack(fill="x", padx=18, pady=5)
    header = ctk.CTkFrame(frame, fg_color=accent, corner_radius=0, height=34)
    header.pack(fill="x")
    header.pack_propagate(False)
    text = f"  {icon}   {title}" if icon else f"  {title}"
    ctk.CTkLabel(header, text=text,
                 font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                 text_color="#ffffff", anchor="w").pack(side="left", padx=10, fill="y")
    return frame


def make_btn(parent, text, cmd, color=C_ACCENT, width=190):
    return ctk.CTkButton(parent, text=text, command=cmd,
                          fg_color=color, hover_color=_darken(color),
                          text_color="#ffffff", corner_radius=7,
                          font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                          height=34, width=width)


def make_label(parent, text, size=11, color=C_MUTED, bold=False):
    return ctk.CTkLabel(parent, text=text, anchor="w",
                         font=ctk.CTkFont(family="Segoe UI", size=size,
                                          weight="bold" if bold else "normal"),
                         text_color=color)


def make_textbox(parent, height=55, mono=True):
    tb = ctk.CTkTextbox(parent, height=height, corner_radius=7,
                         fg_color=C_CARD2, border_color=C_BORDER, border_width=1,
                         text_color=C_TEXT,
                         font=ctk.CTkFont(family="Courier New" if mono else "Segoe UI", size=11))
    tb.pack(fill="x", padx=14, pady=(2, 8))
    return tb


def tb_set(tb, text):
    tb.configure(state="normal")
    tb.delete("1.0", "end")
    tb.insert("1.0", text)


class SignaturePage(ctk.CTkFrame):
    STEPS = ["Clés RSA", "Message", "Hash SHA-256", "Signature", "Vérification", "Attaque"]

    def __init__(self, parent):
        super().__init__(parent, fg_color=C_BG)

        self.sig_engine    = DigitalSignature()
        self.asym          = AsymmetricCipher()
        self.hasher        = HashManager()

        self.private_key       = None
        self.public_key        = None
        self.attacker_asym     = None
        self.attacker_priv     = None
        self.attacker_pub      = None
        self.current_signature = None
        self.original_hash     = None
        self.attack_signature  = None

        self._step_state  = [0] * len(self.STEPS)
        self._step_labels = []
        self._step_dots   = []

        self._build_ui()

    def _build_ui(self):
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=20, pady=(16, 4))

        ctk.CTkLabel(top, text="✍   Signature Numérique RSA-PSS",
                     font=ctk.CTkFont(family="Segoe UI", size=21, weight="bold"),
                     text_color=C_ACCENT, anchor="w").pack(side="left")

        make_btn(top, "▶  Démonstration auto", self._run_demo,
                 color="#4a5a7a", width=195).pack(side="right", pady=(2, 0))

        banner = ctk.CTkFrame(self, fg_color="#232840", corner_radius=10,
                               border_width=1, border_color=C_ACCENT)
        banner.pack(fill="x", padx=18, pady=(0, 4))
        ctk.CTkLabel(banner,
                     text=("  Principe :  SHA-256(message)  →  chiffrer le hash avec la clé PRIVÉE  →  signature.\n"
                           "  Vérification :  déchiffrer la signature avec la clé PUBLIQUE  →  comparer les hash.\n"
                           "  Attaque :  si un pirate signe avec SA clé privée, "
                           "la vérification avec votre clé publique échoue."),
                     font=ctk.CTkFont(family="Segoe UI", size=11),
                     text_color="#8aacda", justify="left", anchor="w", wraplength=740
                     ).pack(padx=14, pady=8)

        self._build_progress_bar()

        self.scroll = ctk.CTkScrollableFrame(self, fg_color="transparent",
                                              scrollbar_button_color=C_BORDER,
                                              scrollbar_button_hover_color=C_ACCENT)
        self.scroll.pack(fill="both", expand=True)

        self._section_keys()
        self._section_message()
        self._section_hash()
        self._section_sign()
        self._section_verify()
        self._section_attack()
        self._section_compare_keys()
        self._section_log()
        self._bottom_bar()

    def _build_progress_bar(self):
        bar = ctk.CTkFrame(self, fg_color="#1a1e2e", corner_radius=10,
                            border_width=1, border_color=C_BORDER)
        bar.pack(fill="x", padx=18, pady=(0, 6))
        inner = ctk.CTkFrame(bar, fg_color="transparent")
        inner.pack(pady=10, padx=10)

        for i, step in enumerate(self.STEPS):
            col = ctk.CTkFrame(inner, fg_color="transparent")
            col.pack(side="left", padx=6)
            dot = ctk.CTkLabel(col, text=str(i + 1), width=28, height=28, corner_radius=14,
                               fg_color=C_STEP_OFF,
                               font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
                               text_color="#ffffff")
            dot.pack()
            self._step_dots.append(dot)
            lbl = ctk.CTkLabel(col, text=step,
                               font=ctk.CTkFont(family="Segoe UI", size=10), text_color=C_MUTED)
            lbl.pack(pady=(2, 0))
            self._step_labels.append(lbl)
            if i < len(self.STEPS) - 1:
                ctk.CTkFrame(inner, width=30, height=2, fg_color=C_BORDER).pack(side="left", pady=(0, 16))

    def _update_step(self, idx, state):
        self._step_state[idx] = state
        colors      = {0: C_STEP_OFF, 1: C_STEP_ACT, 2: C_STEP_OK}
        text_colors = {0: C_MUTED,    1: C_TEXT,      2: C_SUCCESS}
        self._step_dots[idx].configure(fg_color=colors[state])
        self._step_labels[idx].configure(text_color=text_colors[state])

    def _section_keys(self):
        card = make_card(self.scroll, "Étape 1 — Générer la paire de clés RSA-2048", "🔑")
        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.pack(fill="x", padx=14, pady=(10, 6))
        make_btn(btn_row, "Générer paire RSA", self._generate_keys, C_ACCENT).pack(side="left", padx=(0, 8))
        make_btn(btn_row, "Exporter (.pem)", self._export_keys, "#4a5a8a", width=150).pack(side="left")
        self.key_status = make_label(card, "  Aucune clé générée", 11, C_MUTED)
        self.key_status.pack(fill="x", padx=14, pady=(0, 4))
        make_label(card, "  Clé publique — partageable :", 11, C_SUCCESS, bold=True).pack(fill="x", padx=14)
        self.pub_key_box = make_textbox(card, 80)
        self._add_copy_btn(card, lambda: self.pub_key_box.get("1.0", "end"))
        make_label(card, "  Clé privée — confidentielle, ne jamais partager :", 11, C_DANGER, bold=True).pack(fill="x", padx=14)
        self.priv_key_box = make_textbox(card, 80)
        self._add_copy_btn(card, lambda: self.priv_key_box.get("1.0", "end"))

    def _section_message(self):
        card = make_card(self.scroll, "Étape 2 — Saisir le message", "✉")
        make_label(card, "  Message à signer :", 11, C_MUTED).pack(fill="x", padx=14, pady=(10, 2))
        self.message_entry = ctk.CTkTextbox(card, height=65, corner_radius=7,
                                             fg_color=C_CARD2, border_color=C_BORDER, border_width=1,
                                             text_color=C_TEXT, font=ctk.CTkFont(family="Segoe UI", size=13))
        self.message_entry.pack(fill="x", padx=14, pady=(0, 6))
        self.message_entry.insert("1.0", "Votre message confidentiel ici…")
        file_row = ctk.CTkFrame(card, fg_color="transparent")
        file_row.pack(fill="x", padx=14, pady=(0, 10))
        make_btn(file_row, "📂  Charger un fichier", self._load_file, "#4a5a8a", width=180).pack(side="left", padx=(0, 8))
        self.file_label = make_label(file_row, "Aucun fichier sélectionné", 11, C_MUTED)
        self.file_label.pack(side="left")

    def _section_hash(self):
        card = make_card(self.scroll, "Étape 3 — Calculer le condensé SHA-256", "🔢")
        make_btn(card, "Calculer hash SHA-256", self._compute_hash, "#2e7d60").pack(anchor="w", padx=14, pady=(10, 6))
        make_label(card, "  Condensé SHA-256 (hex) :", 11, C_MUTED).pack(fill="x", padx=14)
        self.hash_box = make_textbox(card, 40)
        self._add_copy_btn(card, lambda: self.hash_box.get("1.0", "end"))

    def _section_sign(self):
        card = make_card(self.scroll, "Étape 4 — Signer avec la clé privée", "🔐")
        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.pack(fill="x", padx=14, pady=(10, 6))
        make_btn(btn_row, "Signer le message", self._sign_message, C_ACCENT).pack(side="left", padx=(0, 8))
        make_btn(btn_row, "📂  Signer un fichier", self._sign_file, "#4a5a8a", width=170).pack(side="left")
        make_label(card, "  Signature RSA-PSS (base64) :", 11, C_MUTED).pack(fill="x", padx=14)
        self.signature_box = make_textbox(card, 65)
        self._add_copy_btn(card, lambda: self.signature_box.get("1.0", "end"))
        self.perf_sign_lbl = make_label(card, "", 10, C_MUTED)
        self.perf_sign_lbl.pack(fill="x", padx=14, pady=(0, 8))

    def _section_verify(self):
        card = make_card(self.scroll, "Étape 5 — Vérifier la signature", "✅", accent=C_SUCCESS)
        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.pack(fill="x", padx=14, pady=(10, 6))
        make_btn(btn_row, "Vérifier la signature", self._verify_signature, C_SUCCESS).pack(side="left", padx=(0, 8))
        make_btn(btn_row, "⚠  Simuler falsification", self._tamper_message, C_WARN, width=190).pack(side="left")
        self.perf_verify_lbl = make_label(card, "", 10, C_MUTED)
        self.perf_verify_lbl.pack(fill="x", padx=14)
        result_box = ctk.CTkFrame(card, fg_color=C_CARD2, corner_radius=8, border_width=1, border_color=C_BORDER)
        result_box.pack(fill="x", padx=14, pady=(4, 12))
        self.verify_result = ctk.CTkLabel(result_box, text="  En attente de vérification…",
                                          font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
                                          text_color=C_MUTED, anchor="w", wraplength=670)
        self.verify_result.pack(fill="x", padx=12, pady=(8, 2))
        self.verify_detail = ctk.CTkLabel(result_box, text="",
                                          font=ctk.CTkFont(family="Courier New", size=11),
                                          text_color=C_MUTED, anchor="w", wraplength=670, justify="left")
        self.verify_detail.pack(fill="x", padx=12, pady=(0, 8))

    def _section_attack(self):
        card = make_card(self.scroll, "Étape 6 — Simulation d'attaque par usurpation de clé", "⚠", accent=C_PIRATE)
        ctk.CTkLabel(card,
                     text=("  Scénario :  un attaquant intercepte le message et le signe\n"
                           "  avec SA propre clé privée en espérant de se faire passer pour l'expéditeur légitime.\n"
                           "  La vérification avec la clé publique originale révèle immédiatement la fraude."),
                     font=ctk.CTkFont(family="Segoe UI", size=15),
                     text_color="#c47fa0", justify="left", anchor="w").pack(fill="x", padx=14, pady=(10, 8))
        ctk.CTkFrame(card, height=1, fg_color=C_BORDER).pack(fill="x", padx=14, pady=(0, 8))

        sub_a = ctk.CTkFrame(card, fg_color="#2a1f2e", corner_radius=8, border_width=1, border_color="#6e3060")
        sub_a.pack(fill="x", padx=14, pady=(0, 8))
        ctk.CTkLabel(sub_a, text="  A — Générer la paire de clés du pirate",
                     font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                     text_color="#d4a0c0", anchor="w").pack(fill="x", padx=10, pady=(8, 4))
        make_btn(sub_a, "Générer clé pirate RSA", self._generate_attacker_key, C_PIRATE, width=210).pack(anchor="w", padx=10, pady=(0, 6))
        self.attacker_status = make_label(sub_a, "  Aucune clé pirate générée", 11, C_MUTED)
        self.attacker_status.pack(fill="x", padx=10)
        make_label(sub_a, "  Clé publique pirate :", 11, "#c47fa0", bold=True).pack(fill="x", padx=10, pady=(6, 2))
        self.attacker_pub_box = make_textbox(sub_a, 75)
        make_label(sub_a, "  Clé privée pirate (utilisée frauduleusement) :", 11, "#c47fa0", bold=True).pack(fill="x", padx=10, pady=(0, 2))
        self.attacker_priv_box = make_textbox(sub_a, 75)

        sub_b = ctk.CTkFrame(card, fg_color="#2a2215", corner_radius=8, border_width=1, border_color="#7a5530")
        sub_b.pack(fill="x", padx=14, pady=(0, 8))
        ctk.CTkLabel(sub_b, text="  B — Le pirate signe le message avec SA clé privée",
                     font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                     text_color="#d4935a", anchor="w").pack(fill="x", padx=10, pady=(8, 4))
        make_btn(sub_b, "Signer (clé pirate)", self._attacker_sign, C_WARN, width=200).pack(anchor="w", padx=10, pady=(0, 6))
        make_label(sub_b, "  Fausse signature produite par le pirate :", 11, "#d4935a", bold=True).pack(fill="x", padx=10, pady=(0, 2))
        self.attack_sig_box = make_textbox(sub_b, 60)
        self.attack_sign_status = make_label(sub_b, "", 11, C_MUTED)
        self.attack_sign_status.pack(fill="x", padx=10, pady=(0, 8))

        sub_c = ctk.CTkFrame(card, fg_color="#1a2a22", corner_radius=8, border_width=1, border_color="#2e6045")
        sub_c.pack(fill="x", padx=14, pady=(0, 12))
        ctk.CTkLabel(sub_c, text="  C — Vérification avec votre clé publique légitime",
                     font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                     text_color="#4caf82", anchor="w").pack(fill="x", padx=10, pady=(8, 4))
        make_btn(sub_c, "Détecter l'attaque", self._verify_attack, C_SUCCESS, width=200).pack(anchor="w", padx=10, pady=(0, 6))
        result_c = ctk.CTkFrame(sub_c, fg_color=C_CARD2, corner_radius=7, border_width=1, border_color=C_BORDER)
        result_c.pack(fill="x", padx=10, pady=(0, 10))
        self.attack_result = ctk.CTkLabel(result_c, text="  En attente…",
                                          font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
                                          text_color=C_MUTED, anchor="w", wraplength=660)
        self.attack_result.pack(fill="x", padx=12, pady=(8, 2))
        self.attack_detail = ctk.CTkLabel(result_c, text="",
                                          font=ctk.CTkFont(family="Courier New", size=11),
                                          text_color=C_MUTED, anchor="w", wraplength=660, justify="left")
        self.attack_detail.pack(fill="x", padx=12, pady=(0, 8))

    def _section_compare_keys(self):
        card = make_card(self.scroll, "Comparaison des clés publiques", "🔍", accent="#4a5a7a")
        ctk.CTkLabel(card,
                     text=("  Visualisation côte à côte : votre clé publique légitime vs la clé publique du pirate.\n"
                           "  Elles sont différentes — c'est pourquoi la vérification détecte la fraude."),
                     font=ctk.CTkFont(family="Segoe UI", size=13),
                     text_color=C_MUTED, anchor="w", justify="left").pack(fill="x", padx=14, pady=(10, 6))
        compare_frame = ctk.CTkFrame(card, fg_color="transparent")
        compare_frame.pack(fill="x", padx=14, pady=(0, 12))
        compare_frame.grid_columnconfigure((0, 1), weight=1)
        left = ctk.CTkFrame(compare_frame, fg_color="#1e2a3a", corner_radius=8, border_width=1, border_color=C_SUCCESS)
        left.grid(row=0, column=0, padx=(0, 6), sticky="nsew")
        ctk.CTkLabel(left, text="  Votre clé publique légitime",
                     font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
                     text_color=C_SUCCESS, anchor="w").pack(fill="x", padx=8, pady=(6, 2))
        self.compare_legit_box = ctk.CTkTextbox(left, height=100, corner_radius=6,
                                                 fg_color=C_CARD2, border_width=0, text_color="#a0d8b0",
                                                 font=ctk.CTkFont(family="Courier New", size=10))
        self.compare_legit_box.pack(fill="x", padx=8, pady=(0, 8))
        right = ctk.CTkFrame(compare_frame, fg_color="#2a1e2a", corner_radius=8, border_width=1, border_color=C_PIRATE)
        right.grid(row=0, column=1, padx=(6, 0), sticky="nsew")
        ctk.CTkLabel(right, text="  Clé publique du pirate",
                     font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
                     text_color="#c47fa0", anchor="w").pack(fill="x", padx=8, pady=(6, 2))
        self.compare_pirate_box = ctk.CTkTextbox(right, height=100, corner_radius=6,
                                                  fg_color=C_CARD2, border_width=0, text_color="#d4a0c0",
                                                  font=ctk.CTkFont(family="Courier New", size=10))
        self.compare_pirate_box.pack(fill="x", padx=8, pady=(0, 8))
        self.compare_verdict = ctk.CTkLabel(card, text="",
                                            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                                            text_color=C_MUTED, anchor="center")
        self.compare_verdict.pack(pady=(0, 8))

    def _section_log(self):
        card = make_card(self.scroll, "Journal d'événements", "📋", accent="#3a4a6a")
        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.pack(fill="x", padx=14, pady=(8, 4))
        make_btn(btn_row, "Effacer le journal", self._clear_log, "#3a4060", width=160).pack(side="left")
        self.log_box = ctk.CTkTextbox(card, height=130, corner_radius=7,
                                      fg_color=C_LOG_BG, border_color=C_BORDER, border_width=1,
                                      text_color="#7ab0e0",
                                      font=ctk.CTkFont(family="Courier New", size=11), state="disabled")
        self.log_box.pack(fill="x", padx=14, pady=(2, 12))

    def _bottom_bar(self):
        bar = ctk.CTkFrame(self.scroll, fg_color="transparent")
        bar.pack(fill="x", padx=18, pady=(4, 18))
        make_btn(bar, "Effacer tout", self._clear_all, "#3a4060", width=120).pack(side="left")
        self.global_status = ctk.CTkLabel(bar, text="",
                                          font=ctk.CTkFont(family="Segoe UI", size=11),
                                          text_color=C_MUTED, anchor="e")
        self.global_status.pack(side="right")

    # ── Utilitaires ──────────────────────────────────────────────────────────

    def _add_copy_btn(self, parent, getter):
        def _copy():
            text = getter().strip()
            parent.clipboard_clear()
            parent.clipboard_append(text)
            self._log("Contenu copié dans le presse-papier.")
        make_btn(parent, "Copier", _copy, "#3a4060", width=90).pack(anchor="e", padx=14, pady=(0, 6))

    def _log(self, message):
        now = datetime.now().strftime("%H:%M:%S")
        entry = f"[{now}]  {message}\n"
        self.log_box.configure(state="normal")
        self.log_box.insert("end", entry)
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _clear_log(self):
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")

    def _status(self, text, color=C_MUTED):
        self.global_status.configure(text=text, text_color=color)

    def _msg(self):
        return self.message_entry.get("1.0", "end").strip()

    def _perf(self, start):
        ms = (time.perf_counter() - start) * 1000
        return f"  ⏱  Durée : {ms:.2f} ms"

    # ── Logique métier ───────────────────────────────────────────────────────

    def _generate_keys(self):
        try:
            self._update_step(0, 1)
            t0 = time.perf_counter()
            self.private_key, self.public_key = self.asym.generate_keypair()
            elapsed = self._perf(t0)
            pub  = self.asym.export_public_key()
            priv = self.asym.export_private_key()
            tb_set(self.pub_key_box, pub)
            tb_set(self.priv_key_box, priv)
            tb_set(self.compare_legit_box, pub)
            self.key_status.configure(text=f"  ✔  Paire RSA-2048 générée  {elapsed}", text_color=C_SUCCESS)
            self._update_step(0, 2)
            self._status("Clés générées", C_SUCCESS)
            self._log(f"Paire RSA-2048 générée.{elapsed}")
            self._refresh_compare()
        except Exception as e:
            messagebox.showerror("Erreur", str(e))
            self._update_step(0, 0)

    def _export_keys(self):
        if not self.private_key:
            messagebox.showwarning("Clés manquantes", "Générez d'abord une paire RSA.")
            return
        try:
            for name, getter in [("private_key.pem", self.asym.export_private_key),
                                  ("public_key.pem", self.asym.export_public_key)]:
                p = filedialog.asksaveasfilename(title=f"Sauvegarder {name}",
                                                  defaultextension=".pem", initialfile=name,
                                                  filetypes=[("PEM", "*.pem"), ("Tous", "*")])
                if p:
                    with open(p, "w") as f:
                        f.write(getter())
                    self._log(f"Clé exportée → {p}")
            messagebox.showinfo("Export réussi", "Clés sauvegardées.")
        except Exception as e:
            messagebox.showerror("Erreur export", str(e))

    def _load_file(self):
        path = filedialog.askopenfilename(title="Sélectionner un fichier",
                                          filetypes=[("Texte", "*.txt"), ("Tous", "*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(4096)
            self.message_entry.delete("1.0", "end")
            self.message_entry.insert("1.0", content)
            name = path.split("/")[-1].split("\\")[-1]
            self.file_label.configure(text=f"  {name}", text_color=C_ACCENT)
            self._log(f"Fichier chargé : {name}")
            self._update_step(1, 2)
        except Exception as e:
            messagebox.showerror("Erreur lecture", str(e))

    def _compute_hash(self):
        msg = self._msg()
        if not msg:
            messagebox.showwarning("Vide", "Saisissez un message.")
            return
        try:
            self._update_step(2, 1)
            t0 = time.perf_counter()
            h  = self.hasher.hash_text(msg, "sha256")
            elapsed = self._perf(t0)
            self.original_hash = h
            tb_set(self.hash_box, h)
            self._update_step(1, 2)
            self._update_step(2, 2)
            self._status("Hash calculé", C_SUCCESS)
            self._log(f"SHA-256 calculé.{elapsed}  →  {h[:24]}…")
        except Exception as e:
            messagebox.showerror("Erreur hash", str(e))

    def _sign_message(self):
        if not self.private_key:
            messagebox.showwarning("Clé manquante", "Générez d'abord la paire RSA.")
            return
        msg = self._msg()
        if not msg:
            messagebox.showwarning("Vide", "Saisissez un message.")
            return
        try:
            self._update_step(3, 1)
            if not self.original_hash:
                self.original_hash = self.hasher.hash_text(msg, "sha256")
                tb_set(self.hash_box, self.original_hash)
                self._update_step(2, 2)
            t0 = time.perf_counter()
            self.current_signature = self.sig_engine.sign(msg, self.private_key)
            elapsed = self._perf(t0)
            tb_set(self.signature_box, self.current_signature)
            self.perf_sign_lbl.configure(text=elapsed, text_color=C_MUTED)
            self._update_step(3, 2)
            self._status("Message signé", C_SUCCESS)
            self._log(f"Message signé avec la clé privée RSA-PSS.{elapsed}")
            self.verify_result.configure(text="  Message signé — cliquez 'Vérifier' pour confirmer.", text_color=C_MUTED)
            self.verify_detail.configure(text="")
        except Exception as e:
            messagebox.showerror("Erreur signature", str(e))
            self._update_step(3, 0)

    def _sign_file(self):
        if not self.private_key:
            messagebox.showwarning("Clé manquante", "Générez d'abord la paire RSA.")
            return
        path = filedialog.askopenfilename(title="Fichier à signer", filetypes=[("Tous", "*")])
        if not path:
            return
        try:
            t0 = time.perf_counter()
            sig_b64 = self.sig_engine.sign_file(path, self.private_key)
            elapsed = self._perf(t0)
            tb_set(self.signature_box, sig_b64)
            self.current_signature = sig_b64
            self.perf_sign_lbl.configure(text=elapsed, text_color=C_MUTED)
            self._update_step(3, 2)
            name = path.split("/")[-1].split("\\")[-1]
            self._log(f"Fichier signé : {name}.{elapsed}")
            self._status(f"Fichier '{name}' signé", C_SUCCESS)
            save = filedialog.asksaveasfilename(title="Sauvegarder la signature",
                                                defaultextension=".sig", initialfile=name + ".sig",
                                                filetypes=[("Signature", "*.sig"), ("Tous", "*")])
            if save:
                with open(save, "w") as f:
                    f.write(sig_b64)
                self._log(f"Signature sauvegardée → {save}")
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def _verify_signature(self):
        if not self.public_key or not self.current_signature:
            messagebox.showwarning("Données manquantes", "Générez les clés et signez d'abord.")
            return
        try:
            self._update_step(4, 1)
            msg = self._msg()
            t0  = time.perf_counter()
            sig_valid    = self.sig_engine.verify(msg, self.current_signature, self.public_key)
            current_hash = self.hasher.hash_text(msg, "sha256")
            elapsed      = self._perf(t0)
            hash_match   = (current_hash == self.original_hash)
            self.perf_verify_lbl.configure(text=elapsed, text_color=C_MUTED)
            if sig_valid and hash_match:
                self.verify_result.configure(text="  ✔  Signature VALIDE — message authentique et intact", text_color=C_SUCCESS)
                self.verify_detail.configure(
                    text=f"Hash original : {self.original_hash[:56]}…\nHash actuel   : {current_hash[:56]}…  ← identiques",
                    text_color=C_SUCCESS)
                self._update_step(4, 2)
                self._log(f"Vérification réussie.{elapsed}")
                self._status("Vérification OK", C_SUCCESS)
            elif not sig_valid and hash_match:
                self.verify_result.configure(text="  ✘  Signature INVALIDE — clé privée non reconnue", text_color=C_DANGER)
                self.verify_detail.configure(text="La signature ne correspond pas à la clé publique légitime.\nCause probable : un attaquant a utilisé une autre clé privée.", text_color=C_WARN)
                self._update_step(4, 0)
                self._log("ALERTE — signature invalide, clé pirate probable.")
                self._status("Clé pirate détectée", C_DANGER)
            elif sig_valid and not hash_match:
                self.verify_result.configure(text="  ✘  INTÉGRITÉ COMPROMISE — message modifié après signature", text_color=C_DANGER)
                self.verify_detail.configure(
                    text=f"Hash original : {self.original_hash[:56]}…\nHash actuel   : {current_hash[:56]}…  ← DIFFÉRENTS",
                    text_color=C_DANGER)
                self._update_step(4, 0)
                self._log("ALERTE — message falsifié détecté.")
                self._status("Message falsifié", C_DANGER)
            else:
                self.verify_result.configure(text="  ✘  DOUBLE ÉCHEC — signature invalide ET message modifié", text_color=C_DANGER)
                self.verify_detail.configure(text="La signature ne correspond pas ET le message a été altéré.", text_color=C_DANGER)
                self._update_step(4, 0)
                self._log("ALERTE — double échec : signature invalide + message altéré.")
                self._status("Attaque détectée", C_DANGER)
        except Exception as e:
            messagebox.showerror("Erreur vérification", str(e))

    def _tamper_message(self):
        msg = self._msg()
        modified = msg + "  [FALSIFIÉ PAR ATTAQUANT]"
        self.message_entry.delete("1.0", "end")
        self.message_entry.insert("1.0", modified)
        self.verify_result.configure(text="  ⚠  Message modifié — relancez 'Vérifier' pour détecter la falsification", text_color=C_WARN)
        self.verify_detail.configure(text="")
        self._log("Message falsifié manuellement (simulation attaque).")
        self._status("Message modifié", C_WARN)

    def _generate_attacker_key(self):
        try:
            self.attacker_asym = AsymmetricCipher()
            t0 = time.perf_counter()
            self.attacker_priv, self.attacker_pub = self.attacker_asym.generate_keypair()
            elapsed = self._perf(t0)
            pub_pem  = self.attacker_asym.export_public_key()
            priv_pem = self.attacker_asym.export_private_key()
            tb_set(self.attacker_pub_box, pub_pem)
            tb_set(self.attacker_priv_box, priv_pem)
            tb_set(self.compare_pirate_box, pub_pem)
            self.attacker_status.configure(text=f"  ✔  Paire RSA pirate générée.{elapsed}", text_color="#c47fa0")
            self._log(f"Clé pirate RSA-2048 générée.{elapsed}")
            self._refresh_compare()
            self._status("Clé pirate prête", C_WARN)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def _attacker_sign(self):
        if not self.attacker_priv:
            messagebox.showwarning("Clé pirate manquante", "Générez d'abord la clé pirate (étape A).")
            return
        msg = self._msg()
        if not msg:
            messagebox.showwarning("Vide", "Saisissez un message.")
            return
        try:
            t0 = time.perf_counter()
            self.attack_signature = self.sig_engine.sign(msg, self.attacker_priv)
            elapsed = self._perf(t0)
            tb_set(self.attack_sig_box, self.attack_signature)
            self.attack_sign_status.configure(text=f"  ✔  Fausse signature produite.{elapsed}  → étape C", text_color="#d4935a")
            self._log(f"Pirate : message signé avec la clé pirate.{elapsed}")
            self._status("Fausse signature prête", C_WARN)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def _verify_attack(self):
        if not self.public_key:
            messagebox.showwarning("Clé légitime manquante", "Générez d'abord votre paire RSA légitime.")
            return
        if not self.attack_signature:
            messagebox.showwarning("Signature pirate manquante", "Exécutez l'étape B d'abord.")
            return
        try:
            msg = self._msg()
            t0  = time.perf_counter()
            sig_valid = self.sig_engine.verify(msg, self.attack_signature, self.public_key)
            elapsed = self._perf(t0)
            if not sig_valid:
                self.attack_result.configure(text="  ✘  ATTAQUE DÉTECTÉE — signature rejetée", text_color=C_DANGER)
                self.attack_detail.configure(
                    text="La fausse signature du pirate ne peut PAS être vérifiée\navec votre clé publique légitime.\n→ Preuve irréfutable que le pirate a utilisé SA propre clé privée.",
                    text_color=C_DANGER)
                self._update_step(5, 2)
                self._log(f"ATTAQUE DÉJOUÉE — fausse signature détectée.{elapsed}")
                self._status("Attaque déjouée !", C_DANGER)
            else:
                self.attack_result.configure(text="  (!) Résultat inattendu — vérifiez que les clés sont bien distinctes.", text_color=C_WARN)
                self.attack_detail.configure(text="")
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def _refresh_compare(self):
        legit  = self.pub_key_box.get("1.0", "end").strip()
        pirate = self.attacker_pub_box.get("1.0", "end").strip()
        if legit:
            tb_set(self.compare_legit_box, legit)
        if pirate:
            tb_set(self.compare_pirate_box, pirate)
        if legit and pirate:
            if legit == pirate:
                self.compare_verdict.configure(text="⚠  Les deux clés sont identiques — anomalie !", text_color=C_WARN)
            else:
                self.compare_verdict.configure(text="✔  Les deux clés publiques sont différentes — la fraude sera détectée", text_color=C_SUCCESS)

    def _run_demo(self):
        steps = [
            (self._generate_keys,         "Génération des clés RSA…"),
            (self._compute_hash,          "Calcul du hash SHA-256…"),
            (self._sign_message,          "Signature du message…"),
            (self._verify_signature,      "Vérification de la signature…"),
            (self._generate_attacker_key, "Génération de la clé pirate…"),
            (self._attacker_sign,         "Le pirate signe le message…"),
            (self._verify_attack,         "Détection de l'attaque…"),
        ]
        self._log("=== Démonstration automatique démarrée ===")

        def run_step(index):
            if index >= len(steps):
                self._status("Démonstration terminée ✔", C_SUCCESS)
                self._log("=== Démonstration automatique terminée ===")
                return
            func, msg = steps[index]
            self._status(msg, C_ACCENT)
            self._log(f"[DÉMO AUTO]  {msg}")
            func()
            self.after(2000, lambda i=index + 1: run_step(i))

        run_step(0)

    def _clear_all(self):
        self.message_entry.delete("1.0", "end")
        self.message_entry.insert("1.0", "Votre message confidentiel ici…")
        self.file_label.configure(text="Aucun fichier sélectionné", text_color=C_MUTED)
        for tb in (self.pub_key_box, self.priv_key_box, self.hash_box, self.signature_box,
                   self.attacker_pub_box, self.attacker_priv_box, self.attack_sig_box,
                   self.compare_legit_box, self.compare_pirate_box):
            tb_set(tb, "")
        self.verify_result.configure(text="  En attente de vérification…", text_color=C_MUTED)
        self.verify_detail.configure(text="")
        self.attack_result.configure(text="  En attente…", text_color=C_MUTED)
        self.attack_detail.configure(text="")
        self.attack_sign_status.configure(text="")
        self.attacker_status.configure(text="  Aucune clé pirate générée", text_color=C_MUTED)
        self.key_status.configure(text="  Aucune clé générée", text_color=C_MUTED)
        self.perf_sign_lbl.configure(text="")
        self.perf_verify_lbl.configure(text="")
        self.compare_verdict.configure(text="")
        self._status("")
        self._clear_log()
        for i in range(len(self.STEPS)):
            self._update_step(i, 0)
        self.private_key = None
        self.public_key = None
        self.attacker_asym = None
        self.attacker_priv = None
        self.attacker_pub = None
        self.current_signature = None
        self.attack_signature = None
        self.original_hash = None
        self._log("Page réinitialisée.")