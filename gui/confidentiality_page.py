"""
Module de Confidentialité - Interface graphique (adaptée en CTkFrame)
"""
import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import json
import os
import threading
import time
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from core.symmetric import generate_aes_key, encrypt_aes, decrypt_aes
from core.asymmetric import (
    generate_rsa_keys, encrypt_rsa, decrypt_rsa,
    generate_hybrid_keys, encrypt_hybrid, decrypt_hybrid,
    benchmark_encryption
)


class ConfidentialityPage(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)

        self.bg = "#161c34"
        self.header_bg = "#1a213d"
        self.panel_bg = "#202745"
        self.panel_bg_2 = "#242c4a"
        self.input_bg = "#31395f"
        self.border = "#6f8fc5"
        self.step_blue = "#56679e"
        self.step_green = "#57c48d"
        self.text_main = "#dbe6ff"
        self.text_muted = "#9cb0da"
        self.title_blue = "#7ea5e5"
        self.orange = "#e8a65b"
        self.red = "#f67676"
        self.green = "#57c48d"
        self.demo_btn = "#6f89b7"
        self.demo_btn_hover = "#7d97c6"
        self.action_btn = "#5f7db0"
        self.action_btn_hover = "#6f8dc0"
        self.result_bg = "#2d355a"

        self.configure(fg_color=self.bg)

        self.current_keys = {}
        self.selected_algorithm = ctk.StringVar(value="AES")
        self.current_ciphertext = ""
        self.last_ciphertext = ""
        self.demo_history = []
        self.demo_last_algo = "AES"
        self.demo_last_key_size = "256"
        self.demo_last_message = ""

        self.step_flags = [False, False, False, False, False]

        self.build_ui()

    def build_ui(self):
        self.fixed_top = ctk.CTkFrame(self, fg_color=self.bg)
        self.fixed_top.pack(fill="x", padx=16, pady=(12, 8))
        self.build_header(self.fixed_top)

        self.body = ctk.CTkScrollableFrame(self, fg_color=self.bg)
        self.body.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        self.build_step1(self.body)
        self.build_step2(self.body)
        self.build_step3(self.body)
        self.build_step4(self.body)
        self.build_step5(self.body)
        self.build_bottom_clear(self.body)

        self.update_steps_display()

    def build_header(self, parent):
        top_row = ctk.CTkFrame(parent, fg_color="transparent")
        top_row.pack(fill="x", pady=(0, 6))

        ctk.CTkLabel(top_row, text="🔐  Confidentialité — Chiffrement AES / RSA / Hybride",
                     font=ctk.CTkFont(size=24, weight="bold"),
                     text_color=self.title_blue).pack(side="left", padx=(8, 0))

        self.demo_button = ctk.CTkButton(
            top_row, text="▶️  Démonstration auto", command=self._demo_auto,
            width=190, height=38, corner_radius=10,
            fg_color=self.demo_btn, hover_color=self.demo_btn_hover,
            text_color="white", font=ctk.CTkFont(size=13, weight="bold"), border_width=0)
        self.demo_button.pack(side="right", padx=(0, 6))

        info_box = ctk.CTkFrame(parent, fg_color=self.panel_bg, corner_radius=14,
                                 border_width=1, border_color=self.border)
        info_box.pack(fill="x", pady=(0, 8))

        info_text = (
            "Objectif : chiffrer et déchiffrer des messages en utilisant les algorithmes AES, RSA et Hybride.\n"
            "Principe : générer la clé → saisir le message → chiffrer le message → déchiffrer le message → comparer les méthodes.\n"
            "Sécurité : AES pour la rapidité sur de grandes données, RSA pour l'échange sécurisé de clés, Hybride pour combiner les deux.\n"
            "Limite : ce module assure la confidentialité uniquement ; il ne prouve pas l'identité de l'expéditeur."
        )
        ctk.CTkLabel(info_box, text=info_text, justify="left", anchor="w",
                     text_color=self.text_main, font=ctk.CTkFont(size=13),
                     wraplength=1040).pack(fill="x", padx=18, pady=14)

        self.steps_wrap = ctk.CTkFrame(parent, fg_color=self.panel_bg, corner_radius=14,
                                        border_width=1, border_color="#48598f")
        self.steps_wrap.pack(fill="x")

        self.steps_row = ctk.CTkFrame(self.steps_wrap, fg_color="transparent")
        self.steps_row.pack(pady=(14, 14))

        labels = ["Clé", "Chiffrer", "Déchiffrer", "Comparaison", "Enregistrer"]
        self.step_items = []
        self.step_lines = []

        for i, label in enumerate(labels):
            item = ctk.CTkFrame(self.steps_row, fg_color="transparent")
            item.pack(side="left")
            circle = ctk.CTkLabel(item, text=str(i + 1), width=40, height=40,
                                   corner_radius=20, fg_color=self.step_blue,
                                   text_color="white", font=ctk.CTkFont(size=16, weight="bold"))
            circle.pack()
            txt = ctk.CTkLabel(item, text=label, text_color=self.text_muted, font=ctk.CTkFont(size=12))
            txt.pack(pady=(8, 0))
            self.step_items.append((circle, txt))
            if i < len(labels) - 1:
                line_holder = ctk.CTkFrame(self.steps_row, fg_color="transparent")
                line_holder.pack(side="left", padx=8)
                line = ctk.CTkFrame(line_holder, width=38, height=2, fg_color=self.step_blue)
                line.pack(pady=(18, 0))
                self.step_lines.append(line)

    def section_title(self, parent, text, color, icon):
        bar = ctk.CTkFrame(parent, fg_color=color, corner_radius=0)
        bar.pack(fill="x", pady=(12, 0))
        ctk.CTkLabel(bar, text=f"{icon}  {text}", text_color="white",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=16, pady=10)

    def section_card(self, parent):
        card = ctk.CTkFrame(parent, fg_color=self.panel_bg_2, corner_radius=0,
                             border_width=1, border_color="#394774")
        card.pack(fill="x", pady=(0, 8))
        return card

    def build_textbox(self, parent, height):
        return ctk.CTkTextbox(parent, height=height, fg_color=self.input_bg,
                              border_width=1, border_color="#4d5d94", text_color="white",
                              corner_radius=10, font=ctk.CTkFont(size=13))

    def make_btn(self, parent, text, command, fg=None, hover=None, width=215, height=40):
        return ctk.CTkButton(parent, text=text, command=command, width=width, height=height,
                             corner_radius=10, fg_color=fg if fg else self.action_btn,
                             hover_color=hover if hover else self.action_btn_hover,
                             text_color="white", font=ctk.CTkFont(size=13, weight="bold"))

    def make_status(self, parent):
        return ctk.CTkLabel(parent, text="", text_color=self.text_muted, font=ctk.CTkFont(size=12))

    # ========================= SECTIONS =========================

    def build_step1(self, parent):
        self.section_title(parent, "Étape 1 — Générer la clé de chiffrement", "#7698ca", "🔑")
        card = self.section_card(parent)
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=16, pady=14)

        sel_row = ctk.CTkFrame(inner, fg_color="transparent")
        sel_row.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(sel_row, text="Algorithme :", text_color=self.text_muted,
                     font=ctk.CTkFont(size=13, weight="bold")).pack(side="left", padx=(0, 12))
        for algo in ["AES", "RSA", "Hybride"]:
            ctk.CTkRadioButton(sel_row, text=algo, variable=self.selected_algorithm, value=algo,
                               font=ctk.CTkFont(size=13), text_color=self.text_main,
                               fg_color=self.action_btn, hover_color=self.action_btn_hover,
                               border_color=self.text_muted).pack(side="left", padx=10)

        sz_row = ctk.CTkFrame(inner, fg_color="transparent")
        sz_row.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(sz_row, text="Taille :", text_color=self.text_muted,
                     font=ctk.CTkFont(size=13)).pack(side="left")
        self.key_size_var = ctk.StringVar(value="256")
        ctk.CTkOptionMenu(sz_row, variable=self.key_size_var, values=["128", "192", "256"],
                          fg_color=self.input_bg, button_color=self.action_btn, width=100, height=30
                          ).pack(side="left", padx=8)
        ctk.CTkLabel(sz_row, text="bits (AES) / 2048 bits (RSA)",
                     text_color=self.text_muted, font=ctk.CTkFont(size=11)).pack(side="left")

        ctk.CTkLabel(inner, text="Clé générée :", text_color=self.text_muted,
                     font=ctk.CTkFont(size=13)).pack(anchor="w", pady=(0, 8))
        self.key_display = ctk.CTkTextbox(inner, height=78, fg_color=self.input_bg, text_color="white",
                                           font=ctk.CTkFont(family="Consolas", size=12),
                                           border_width=1, border_color="#4d5d94", corner_radius=10)
        self.key_display.pack(fill="x", pady=(0, 12))
        self.key_display.insert("1.0", "La clé générée s'affichera ici...")
        self.key_display.configure(state="disabled")

        row = ctk.CTkFrame(inner, fg_color="transparent")
        row.pack(fill="x")
        self.make_btn(row, "🔑 Générer la clé", self._on_generate_key,
                      fg=self.green, hover="#6ad49a", width=200).pack(side="left", padx=(0, 12))
        self.make_btn(row, "📋 Copier la clé",
                      lambda: self._copy(self.key_display.get("1.0", "end-1c")), width=170).pack(side="left")
        self.key_status = self.make_status(inner)
        self.key_status.pack(anchor="w", pady=(12, 0))

    def build_step2(self, parent):
        self.section_title(parent, "Étape 2 — Chiffrer le message", "#7698ca", "🔒")
        card = self.section_card(parent)
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=16, pady=14)

        top = ctk.CTkFrame(inner, fg_color="transparent")
        top.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(top, text="Message original :", text_color=self.text_muted,
                     font=ctk.CTkFont(size=13)).pack(side="left")
        self.make_btn(top, "📂 Importer fichier", self._import_to_encrypt, width=190).pack(side="right")

        self.encrypt_input = self.build_textbox(inner, 120)
        self.encrypt_input.pack(fill="x", pady=(0, 12))

        row = ctk.CTkFrame(inner, fg_color="transparent")
        row.pack(fill="x")
        self.make_btn(row, "🔒 Chiffrer", self._on_encrypt,
                      fg=self.action_btn, hover=self.action_btn_hover, width=190).pack(side="left", padx=(0, 12))
        self.make_btn(row, "📋 Copier résultat",
                      lambda: self._copy(self.encrypt_output.get("1.0", "end-1c")), width=190).pack(side="left")

        ctk.CTkLabel(inner, text="Message chiffré :", text_color=self.text_muted,
                     font=ctk.CTkFont(size=13)).pack(anchor="w", pady=(12, 8))
        self.encrypt_output = self.build_textbox(inner, 78)
        self.encrypt_output.pack(fill="x", pady=(0, 12))
        self.encrypt_status = self.make_status(inner)
        self.encrypt_status.pack(anchor="w")

    def build_step3(self, parent):
        self.section_title(parent, "Étape 3 — Déchiffrer le message", "#7698ca", "🔓")
        card = self.section_card(parent)
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=16, pady=14)

        top = ctk.CTkFrame(inner, fg_color="transparent")
        top.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(top, text="Cliquez sur Déchiffrer pour déchiffrer le dernier message chiffré automatiquement.",
                     text_color=self.text_muted, font=ctk.CTkFont(size=12), wraplength=700).pack(side="left")
        self.make_btn(top, "📂 Importer chiffré", self._import_to_decrypt, width=200).pack(side="right")

        row = ctk.CTkFrame(inner, fg_color="transparent")
        row.pack(fill="x", pady=(0, 12))
        self.make_btn(row, "🔓 Déchiffrer", self._on_decrypt,
                      fg=self.action_btn, hover=self.action_btn_hover, width=190).pack(side="left", padx=(0, 12))
        self.make_btn(row, "📋 Copier",
                      lambda: self._copy(self.decrypt_output.get("1.0", "end-1c")), width=150).pack(side="left")

        ctk.CTkLabel(inner, text="Message déchiffré :", text_color=self.text_muted,
                     font=ctk.CTkFont(size=13)).pack(anchor="w", pady=(0, 8))
        self.decrypt_output = self.build_textbox(inner, 78)
        self.decrypt_output.pack(fill="x", pady=(0, 12))

    def build_step4(self, parent):
        self.section_title(parent, "Étape 4 — Comparaison des méthodes", "#7698ca", "📊")
        card = self.section_card(parent)
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=16, pady=14)
        self.make_btn(inner, "📊 Lancer la comparaison", self._on_comparison,
                      fg=self.green, hover="#6ad49a", width=240).pack(anchor="w")
        self.comparison_status = self.make_status(inner)
        self.comparison_status.pack(anchor="w", pady=(12, 0))

    def build_step5(self, parent):
        self.section_title(parent, "Étape 5 — Enregistrer le message chiffré", "#59b985", "💾")
        card = self.section_card(parent)
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=16, pady=14)
        row = ctk.CTkFrame(inner, fg_color="transparent")
        row.pack(fill="x")
        ctk.CTkLabel(row, text="💾  Sauvegarder le message chiffré pour utilisation ultérieure",
                     text_color=self.text_muted, font=ctk.CTkFont(size=13)).pack(side="left")
        self.make_btn(row, "💾 Enregistrer", self._on_save,
                      fg=self.green, hover="#6ad49a", width=180).pack(side="right")
        self.save_status = self.make_status(inner)
        self.save_status.pack(anchor="w", pady=(12, 0))

    def build_bottom_clear(self, parent):
        holder = ctk.CTkFrame(parent, fg_color="transparent")
        holder.pack(fill="x", pady=(8, 18))
        self.make_btn(holder, "🗑️ Vider tous les champs", self._on_clear,
                      fg=self.red, hover="#ff8d8d", width=220).pack(anchor="w")

    # ========================= HELPERS =========================

    def set_status(self, label, text, color):
        label.configure(text=text, text_color=color)

    def get_text(self, textbox):
        return textbox.get("1.0", "end").strip()

    def set_box_content(self, box, content):
        box.configure(state="normal")
        box.delete("1.0", "end")
        box.insert("1.0", content)
        box.configure(state="disabled")

    def _copy(self, text):
        if text.strip():
            self.clipboard_clear()
            self.clipboard_append(text)

    # ========================= STEPS =========================

    def update_steps_display(self):
        for i, (circle, label) in enumerate(self.step_items):
            if self.step_flags[i]:
                circle.configure(fg_color=self.step_green)
                label.configure(text_color=self.step_green)
            else:
                circle.configure(fg_color=self.step_blue)
                label.configure(text_color=self.text_muted)
        for i, line in enumerate(self.step_lines):
            if self.step_flags[i] and self.step_flags[i + 1]:
                line.configure(fg_color=self.step_green)
            else:
                line.configure(fg_color=self.step_blue)

    def activate_step(self, index):
        if 0 <= index < len(self.step_flags):
            self.step_flags[index] = True
            self.update_steps_display()

    def reset_steps(self):
        self.step_flags = [False, False, False, False, False]
        self.update_steps_display()

    # ========================= HANDLERS =========================

    def _on_generate_key(self):
        self.activate_step(0)
        algo = self.selected_algorithm.get()
        self.demo_last_algo = algo
        self.demo_last_key_size = self.key_size_var.get()
        if "generate" not in [h[0] for h in self.demo_history]:
            self.demo_history.append(("generate", None))
        try:
            if algo == "AES":
                self.current_keys = generate_aes_key(int(self.key_size_var.get()))
                display = f"Clé AES ({self.current_keys['key_size']} bits) :\n{self.current_keys['key']}"
            elif algo == "RSA":
                self.current_keys = generate_rsa_keys(2048)
                display = (f"═══ Clé Publique RSA-2048 ═══\n{self.current_keys['public_key']}\n\n"
                           f"═══ Clé Privée RSA-2048 ═══\n{self.current_keys['private_key']}")
            else:
                self.current_keys = generate_hybrid_keys()
                display = (f"═══ Clé AES-{self.current_keys['aes_key_size']} (Hybride) ═══\n"
                           f"{self.current_keys['aes_key']}\n\n"
                           f"═══ Paire RSA-{self.current_keys['rsa_key_size']} (Hybride) ═══\n"
                           f"{self.current_keys['public_key']}\n\n{self.current_keys['private_key']}")
            self.key_display.configure(state="normal")
            self.key_display.delete("1.0", "end")
            self.key_display.insert("1.0", display)
            self.key_display.configure(state="disabled")
            self.set_status(self.key_status, f"✅ Clé {algo} générée avec succès.", self.green)
        except Exception as e:
            self.set_status(self.key_status, f"❌ Erreur : {e}", self.red)

    def _on_encrypt(self):
        if not self.current_keys:
            messagebox.showwarning("Attention", "Générez d'abord une clé !")
            return
        self.activate_step(1)
        msg = self.encrypt_input.get("1.0", "end-1c").strip()
        if not msg:
            messagebox.showwarning("Attention", "Entrez un message !")
            return
        self.demo_last_message = msg
        if "encrypt" not in [h[0] for h in self.demo_history]:
            self.demo_history.append(("encrypt", None))
        algo = self.current_keys.get("algorithm", "")
        try:
            if algo == "AES":
                result = encrypt_aes(msg, self.current_keys["key"])
            elif algo == "RSA":
                result = encrypt_rsa(msg, self.current_keys["public_key"])
            else:
                result = encrypt_hybrid(msg, self.current_keys["aes_key"], self.current_keys["public_key"])
            self.last_ciphertext = result
            self.encrypt_output.configure(state="normal")
            self.encrypt_output.delete("1.0", "end")
            self.encrypt_output.insert("1.0", result)
            self.set_status(self.encrypt_status, f"🔒 Chiffrement {algo} réussi • {len(result)} car.", self.green)
        except Exception as e:
            self.set_status(self.encrypt_status, f"❌ {e}", self.red)

    def _on_decrypt(self):
        if not self.current_keys:
            messagebox.showwarning("Attention", "Générez d'abord une clé !")
            return
        if not self.last_ciphertext:
            messagebox.showwarning("Attention", "Aucun message chiffré à déchiffrer !")
            return
        self.activate_step(2)
        if "decrypt" not in [h[0] for h in self.demo_history]:
            self.demo_history.append(("decrypt", None))
        algo = self.current_keys.get("algorithm", "")
        try:
            if algo == "AES":
                result = decrypt_aes(self.last_ciphertext, self.current_keys["key"])
            elif algo == "RSA":
                result = decrypt_rsa(self.last_ciphertext, self.current_keys["private_key"])
            else:
                result = decrypt_hybrid(self.last_ciphertext, self.current_keys["private_key"])
            self.decrypt_output.configure(state="normal")
            self.decrypt_output.delete("1.0", "end")
            self.decrypt_output.insert("1.0", result)
        except Exception as e:
            self.decrypt_output.configure(state="normal")
            self.decrypt_output.delete("1.0", "end")
            self.decrypt_output.insert("1.0", f"Erreur: {e}")

    def _import_to_encrypt(self):
        fp = filedialog.askopenfilename(filetypes=[("Texte", "*.txt"), ("Tous", "*.*")])
        if fp:
            with open(fp, 'r', encoding='utf-8') as f:
                self.encrypt_input.delete("1.0", "end")
                self.encrypt_input.insert("1.0", f.read())

    def _import_to_decrypt(self):
        fp = filedialog.askopenfilename(filetypes=[("JSON", "*.json"), ("Texte", "*.txt"), ("Tous", "*.*")])
        if fp:
            with open(fp, 'r', encoding='utf-8') as f:
                content = f.read()
            try:
                data = json.loads(content)
                self.last_ciphertext = data.get("ciphertext", content)
            except:
                self.last_ciphertext = content

    def _on_comparison(self):
        self.activate_step(3)
        win = ctk.CTkToplevel(self)
        win.title("📊 Comparaison")
        win.geometry("900x600")
        win.configure(fg_color=self.bg)
        win.grab_set()

        ctk.CTkLabel(win, text="📊  Comparaison AES vs RSA vs Hybride",
                     font=ctk.CTkFont(size=20, weight="bold"), text_color=self.title_blue).pack(pady=10)
        loading = ctk.CTkLabel(win, text="⏳ Benchmark en cours...",
                               font=ctk.CTkFont(size=13), text_color=self.orange)
        loading.pack(pady=15)

        def run():
            r = benchmark_encryption("Test message pour comparaison." * 2, 15)
            win.after(0, lambda: self._show_bench(win, loading, r))
        threading.Thread(target=run, daemon=True).start()

    def _show_bench(self, win, lbl, results):
        lbl.destroy()
        fig, axes = plt.subplots(1, 3, figsize=(11, 3.5))
        fig.patch.set_facecolor(self.bg)
        algos = list(results.keys())
        colors = [self.green, self.action_btn, self.step_blue]
        for ax, key, title in zip(axes,
            ["encrypt_time_ms", "decrypt_time_ms", "ciphertext_size"],
            ["Chiffrement (ms)", "Déchiffrement (ms)", "Taille chiffré"]):
            vals = [results[a][key] for a in algos]
            bars = ax.bar(algos, vals, color=colors, edgecolor=self.border)
            ax.set_title(title, color=self.text_main, fontsize=10)
            ax.set_facecolor(self.panel_bg_2)
            ax.tick_params(colors=self.text_muted)
            for s in ['top', 'right']:
                ax.spines[s].set_visible(False)
            for s in ['bottom', 'left']:
                ax.spines[s].set_color(self.border)
            for b, v in zip(bars, vals):
                ax.text(b.get_x() + b.get_width() / 2, b.get_height(), f'{v:.2f}',
                        ha='center', va='bottom', color=self.text_main, fontsize=8)
        fig.tight_layout()
        canvas = FigureCanvasTkAgg(fig, master=win)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=5)

    def _on_save(self):
        self.activate_step(4)
        if not self.last_ciphertext:
            messagebox.showwarning("Attention", "Aucun message chiffré !")
            return
        fp = filedialog.asksaveasfilename(defaultextension=".json",
                                          filetypes=[("JSON", "*.json"), ("Texte", "*.txt")])
        if fp:
            algo = self.current_keys.get("algorithm", "unknown")
            data = {"algorithm": algo, "ciphertext": self.last_ciphertext,
                    "metadata": {"description": "Module de Confidentialité"}}
            if algo in ["RSA", "Hybride"]:
                data["public_key"] = self.current_keys.get("public_key", "")
            with open(fp, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            messagebox.showinfo("Succès", f"Enregistré : {fp}")

    def _on_clear(self):
        self.reset_steps()
        self.current_keys = {}
        self.last_ciphertext = ""
        self.key_display.configure(state="normal")
        self.key_display.delete("1.0", "end")
        self.key_display.insert("1.0", "La clé générée s'affichera ici...")
        self.key_display.configure(state="disabled")
        self.key_status.configure(text="")
        self.encrypt_input.delete("1.0", "end")
        self.encrypt_output.configure(state="normal")
        self.encrypt_output.delete("1.0", "end")
        self.encrypt_status.configure(text="")
        self.decrypt_output.configure(state="normal")
        self.decrypt_output.delete("1.0", "end")
        self.selected_algorithm.set("AES")
        self.key_size_var.set("256")

    def _demo_auto(self):
        algo = self.demo_last_algo or "AES"
        key_size = self.demo_last_key_size or "256"
        message = self.demo_last_message or "Bonjour ! Ceci est une démonstration automatique."
        steps = self.demo_history if self.demo_history else [("generate", None), ("encrypt", None), ("decrypt", None)]

        self._on_clear()
        delay = 500

        for action, _ in steps:
            if action == "generate":
                self.after(delay, lambda a=algo, ks=key_size: self._demo_generate(a, ks))
                delay += 1500
            elif action == "encrypt":
                self.after(delay, lambda m=message: self._demo_encrypt(m))
                delay += 1500
            elif action == "decrypt":
                self.after(delay, self._on_decrypt)
                delay += 1500

    def _demo_generate(self, algo, key_size):
        self.selected_algorithm.set(algo)
        self.key_size_var.set(key_size)
        self._on_generate_key()

    def _demo_encrypt(self, message):
        self.encrypt_input.delete("1.0", "end")
        self.encrypt_input.insert("1.0", message)
        self._on_encrypt()