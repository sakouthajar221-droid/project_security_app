"""
Module Intégrité - Interface graphique (adaptée en CTkFrame pour intégration MainApp)
"""
import customtkinter as ctk
from tkinter import filedialog, messagebox

from core.hashing import HashManager


class IntegrityPage(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)

        # Palette
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

        self.original_hash_value = ""
        self.received_hash_value = ""

        self.saved_original_message = ""
        self.saved_original_hash = ""
        self.saved_received_message = ""
        self.saved_received_hash = ""
        self.saved_result_text = ""
        self.saved_result_color = self.border

        self.step_flags = [False, False, False, False, False]

        self.build_ui()

    # ========================= UI =========================

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

        ctk.CTkLabel(
            top_row,
            text="✍  Vérification d'intégrité SHA-256",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=self.title_blue
        ).pack(side="left", padx=(8, 0))

        self.demo_button = ctk.CTkButton(
            top_row,
            text="▶  Démonstration auto",
            command=self.auto_demo,
            width=190, height=38, corner_radius=10,
            fg_color=self.demo_btn, hover_color=self.demo_btn_hover,
            text_color="white", font=ctk.CTkFont(size=13, weight="bold"), border_width=0
        )
        self.demo_button.pack(side="right", padx=(0, 6))

        info_box = ctk.CTkFrame(parent, fg_color=self.panel_bg, corner_radius=14,
                                 border_width=1, border_color=self.border)
        info_box.pack(fill="x", pady=(0, 8))

        info_text = (
            "Objectif : vérifier si le message reçu a été modifié en comparant son hash avec celui du message original.\n"
            "Principe : saisir le message original → calculer le hash original → saisir le message reçu → calculer le hash reçu → comparer les deux empreintes.\n"
            "Attaque : un pirate peut modifier le message ; si les deux empreintes diffèrent, l'altération est détectée.\n"
            "Limite : le hash seul ne prouve pas l'identité de l'expéditeur."
        )
        ctk.CTkLabel(info_box, text=info_text, justify="left", anchor="w",
                     text_color=self.text_main, font=ctk.CTkFont(size=13),
                     wraplength=1040).pack(fill="x", padx=18, pady=14)

        self.steps_wrap = ctk.CTkFrame(parent, fg_color=self.panel_bg, corner_radius=14,
                                        border_width=1, border_color="#48598f")
        self.steps_wrap.pack(fill="x")

        self.steps_row = ctk.CTkFrame(self.steps_wrap, fg_color="transparent")
        self.steps_row.pack(pady=(14, 14))

        labels = ["Message", "Hash original", "Message reçu", "Hash reçu", "Vérification"]
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
        self.section_title(parent, "Étape 1 — Saisie du message original", "#7698ca", "📝")
        card = self.section_card(parent)
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=16, pady=14)
        ctk.CTkLabel(inner, text="Message original :", text_color=self.text_muted,
                     font=ctk.CTkFont(size=13)).pack(anchor="w", pady=(0, 8))
        self.original_text = self.build_textbox(inner, 120)
        self.original_text.pack(fill="x", pady=(0, 12))
        self.original_text.bind("<KeyRelease>", self.on_original_typing)
        row = ctk.CTkFrame(inner, fg_color="transparent")
        row.pack(fill="x")
        self.make_btn(row, "Enregistrer message", self.save_original_message, width=200).pack(side="left", padx=(0, 12))
        self.make_btn(row, "Importer message", self.import_original_message, width=190).pack(side="left", padx=(0, 12))
        self.make_btn(row, "Vider message", self.clear_original_message, width=170).pack(side="left")
        self.original_status = self.make_status(inner)
        self.original_status.pack(anchor="w", pady=(12, 0))

    def build_step2(self, parent):
        self.section_title(parent, "Étape 2 — Calcul du hash original", "#7698ca", "🧮")
        card = self.section_card(parent)
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=16, pady=14)
        self.make_btn(inner, "Calculer Hash", self.calculate_original_hash,
                      fg=self.green, hover="#6ad49a", width=190).pack(anchor="w", pady=(0, 14))
        ctk.CTkLabel(inner, text="Hash original :", text_color=self.text_muted,
                     font=ctk.CTkFont(size=13)).pack(anchor="w", pady=(0, 8))
        self.original_hash_box = self.build_textbox(inner, 78)
        self.original_hash_box.pack(fill="x", pady=(0, 12))
        self.original_hash_box.configure(state="disabled")
        self.make_btn(inner, "Vider Hash", self.clear_original_hash, width=150).pack(anchor="w")
        self.original_hash_status = self.make_status(inner)
        self.original_hash_status.pack(anchor="w", pady=(12, 0))

    def build_step3(self, parent):
        self.section_title(parent, "Étape 3 — Saisie du message reçu", "#7698ca", "📨")
        card = self.section_card(parent)
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=16, pady=14)
        ctk.CTkLabel(inner, text="Message reçu :", text_color=self.text_muted,
                     font=ctk.CTkFont(size=13)).pack(anchor="w", pady=(0, 8))
        self.received_text = self.build_textbox(inner, 120)
        self.received_text.pack(fill="x", pady=(0, 12))
        self.received_text.bind("<KeyRelease>", self.on_received_typing)
        row = ctk.CTkFrame(inner, fg_color="transparent")
        row.pack(fill="x")
        self.make_btn(row, "Enregistrer message reçu", self.save_received_message, width=225).pack(side="left", padx=(0, 12))
        self.make_btn(row, "Importer message reçu", self.import_received_message, width=210).pack(side="left", padx=(0, 12))
        self.make_btn(row, "Vider message reçu", self.clear_received_message, width=190).pack(side="left")
        self.received_status = self.make_status(inner)
        self.received_status.pack(anchor="w", pady=(12, 0))

    def build_step4(self, parent):
        self.section_title(parent, "Étape 4 — Calcul du hash reçu", "#7698ca", "🔍")
        card = self.section_card(parent)
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=16, pady=14)
        self.make_btn(inner, "Calculer Hash reçu", self.calculate_received_hash,
                      fg=self.green, hover="#6ad49a", width=220).pack(anchor="w", pady=(0, 14))
        ctk.CTkLabel(inner, text="Hash du message reçu :", text_color=self.text_muted,
                     font=ctk.CTkFont(size=13)).pack(anchor="w", pady=(0, 8))
        self.received_hash_box = self.build_textbox(inner, 78)
        self.received_hash_box.pack(fill="x", pady=(0, 12))
        self.received_hash_box.configure(state="disabled")
        self.make_btn(inner, "Vider Hash reçu", self.clear_received_hash, width=170).pack(anchor="w")
        self.received_hash_status = self.make_status(inner)
        self.received_hash_status.pack(anchor="w", pady=(12, 0))

    def build_step5(self, parent):
        self.section_title(parent, "Étape 5 — Vérifier l'intégrité", "#59b985", "✅")
        card = self.section_card(parent)
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=16, pady=14)
        self.make_btn(inner, "Vérifier l'intégrité", self.verify_integrity,
                      fg=self.green, hover="#6ad49a", width=210).pack(anchor="w", pady=(0, 16))
        ctk.CTkLabel(inner, text="Résultat", text_color=self.orange,
                     font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w", pady=(0, 8))
        self.result_box = ctk.CTkTextbox(inner, height=86, fg_color=self.result_bg,
                                          border_width=2, border_color="#506095",
                                          text_color=self.text_main, corner_radius=10,
                                          font=ctk.CTkFont(size=13))
        self.result_box.pack(fill="x", pady=(0, 12))
        self.result_box.insert("1.0", "Aucune vérification effectuée pour le moment.")
        self.result_box.configure(state="disabled")
        self.verify_status = self.make_status(inner)
        self.verify_status.pack(anchor="w")

    def build_bottom_clear(self, parent):
        holder = ctk.CTkFrame(parent, fg_color="transparent")
        holder.pack(fill="x", pady=(8, 18))
        self.make_btn(holder, "Vider tous les champs", self.clear_all_fields,
                      fg=self.red, hover="#ff8d8d", width=220).pack(anchor="w")

    # ========================= HELPERS =========================

    def set_status(self, label, text, color):
        label.configure(text=text, text_color=color)

    def clear_all_statuses(self):
        for lbl in [self.original_status, self.original_hash_status,
                    self.received_status, self.received_hash_status, self.verify_status]:
            lbl.configure(text="", text_color=self.text_muted)

    def get_text(self, textbox):
        return textbox.get("1.0", "end").strip()

    def set_box_content(self, box, content):
        box.configure(state="normal")
        box.delete("1.0", "end")
        box.insert("1.0", content)
        box.configure(state="disabled")

    def set_result(self, text, color):
        self.result_box.configure(state="normal", border_color=color)
        self.result_box.delete("1.0", "end")
        self.result_box.insert("1.0", text)
        self.result_box.configure(state="disabled")

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

    # ========================= EVENTS =========================

    def on_original_typing(self, event=None):
        if self.get_text(self.original_text):
            self.activate_step(0)

    def on_received_typing(self, event=None):
        if self.get_text(self.received_text):
            self.activate_step(2)

    def save_current_state(self):
        self.saved_original_message = self.get_text(self.original_text)
        self.saved_original_hash = self.original_hash_value
        self.saved_received_message = self.get_text(self.received_text)
        self.saved_received_hash = self.received_hash_value
        self.saved_result_text = self.result_box.get("1.0", "end").strip()
        self.saved_result_color = self.result_box.cget("border_color")

    # ========================= FILE ACTIONS =========================

    def import_original_message(self):
        path = filedialog.askopenfilename(title="Importer le message original",
                                          filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.original_text.delete("1.0", "end")
                self.original_text.insert("1.0", content)
                self.set_status(self.original_status, "Message original importé avec succès.", self.green)
                if content:
                    self.activate_step(0)
            except Exception as e:
                messagebox.showerror("Erreur", f"Impossible d'importer le fichier.\n{e}")

    def save_original_message(self):
        content = self.get_text(self.original_text)
        if not content:
            self.set_status(self.original_status, "Erreur : aucun message original à enregistrer.", self.red)
            return
        path = filedialog.asksaveasfilename(title="Enregistrer le message original",
                                             defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
                self.set_status(self.original_status, "Message original enregistré avec succès.", self.green)
                self.activate_step(0)
            except Exception as e:
                messagebox.showerror("Erreur", f"Impossible d'enregistrer le fichier.\n{e}")

    def import_received_message(self):
        path = filedialog.askopenfilename(title="Importer le message reçu",
                                          filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.received_text.delete("1.0", "end")
                self.received_text.insert("1.0", content)
                self.set_status(self.received_status, "Message reçu importé avec succès.", self.green)
                if content:
                    self.activate_step(2)
            except Exception as e:
                messagebox.showerror("Erreur", f"Impossible d'importer le fichier.\n{e}")

    def save_received_message(self):
        content = self.get_text(self.received_text)
        if not content:
            self.set_status(self.received_status, "Erreur : aucun message reçu à enregistrer.", self.red)
            return
        path = filedialog.asksaveasfilename(title="Enregistrer le message reçu",
                                             defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
                self.set_status(self.received_status, "Message reçu enregistré avec succès.", self.green)
                self.activate_step(2)
            except Exception as e:
                messagebox.showerror("Erreur", f"Impossible d'enregistrer le fichier.\n{e}")

    # ========================= ACTIONS =========================

    def calculate_original_hash(self):
        content = self.get_text(self.original_text)
        if not content:
            self.set_status(self.original_status, "Erreur : veuillez saisir ou importer le message original.", self.red)
            return
        self.activate_step(0)
        self.original_hash_value = HashManager.sha256_text(content)
        self.set_box_content(self.original_hash_box, self.original_hash_value)
        self.set_status(self.original_hash_status, "Hash original calculé avec succès.", self.green)
        self.activate_step(1)
        self.save_current_state()

    def calculate_received_hash(self):
        content = self.get_text(self.received_text)
        if not content:
            self.set_status(self.received_status, "Erreur : veuillez saisir ou importer le message reçu.", self.red)
            return
        self.activate_step(2)
        self.received_hash_value = HashManager.sha256_text(content)
        self.set_box_content(self.received_hash_box, self.received_hash_value)
        self.set_status(self.received_hash_status, "Hash du message reçu calculé avec succès.", self.green)
        self.activate_step(3)
        self.save_current_state()

    def verify_integrity(self):
        if not self.original_hash_value:
            self.set_status(self.original_hash_status, "Erreur : calculez d'abord le hash original.", self.red)
            return
        if not self.received_hash_value:
            self.set_status(self.received_hash_status, "Erreur : calculez d'abord le hash du message reçu.", self.red)
            return
        if HashManager.compare_hashes(self.original_hash_value, self.received_hash_value):
            self.set_result("✅ Intégrité vérifiée : le message reçu n'a pas été modifié.", self.green)
            self.set_status(self.verify_status, "Comparaison réussie.", self.green)
        else:
            self.set_result("❌ Intégrité échouée : le message reçu a été modifié.", self.red)
            self.set_status(self.verify_status, "Comparaison échouée : les empreintes sont différentes.", self.red)
        self.activate_step(4)
        self.save_current_state()

    def auto_demo(self):
        if not self.saved_original_message and not self.saved_received_message:
            self.set_status(self.verify_status,
                            "Aucune démonstration enregistrée. Faites d'abord un test manuel.", self.orange)
            return
        self.clear_all_fields()
        self.original_text.insert("1.0", self.saved_original_message)
        self.received_text.insert("1.0", self.saved_received_message)
        self.original_hash_value = self.saved_original_hash
        self.received_hash_value = self.saved_received_hash
        self.set_box_content(self.original_hash_box, self.saved_original_hash)
        self.set_box_content(self.received_hash_box, self.saved_received_hash)
        self.set_result(self.saved_result_text, self.saved_result_color)
        self.set_status(self.original_status, "Dernier message original restauré.", self.green)
        self.set_status(self.original_hash_status, "Dernier hash original restauré.", self.green)
        self.set_status(self.received_status, "Dernier message reçu restauré.", self.green)
        self.set_status(self.received_hash_status, "Dernier hash reçu restauré.", self.green)
        self.set_status(self.verify_status, "Dernière démonstration restaurée avec succès.", self.green)
        if self.saved_original_message: self.activate_step(0)
        if self.saved_original_hash: self.activate_step(1)
        if self.saved_received_message: self.activate_step(2)
        if self.saved_received_hash: self.activate_step(3)
        if self.saved_result_text and "Aucune vérification" not in self.saved_result_text:
            self.activate_step(4)

    # ========================= CLEAR =========================

    def clear_original_message(self):
        self.original_text.delete("1.0", "end")
        self.set_status(self.original_status, "Champ du message original vidé.", self.text_muted)

    def clear_received_message(self):
        self.received_text.delete("1.0", "end")
        self.set_status(self.received_status, "Champ du message reçu vidé.", self.text_muted)

    def clear_original_hash(self):
        self.original_hash_value = ""
        self.set_box_content(self.original_hash_box, "")
        self.set_status(self.original_hash_status, "Hash original vidé.", self.text_muted)

    def clear_received_hash(self):
        self.received_hash_value = ""
        self.set_box_content(self.received_hash_box, "")
        self.set_status(self.received_hash_status, "Hash reçu vidé.", self.text_muted)

    def clear_all_fields(self):
        self.original_text.delete("1.0", "end")
        self.received_text.delete("1.0", "end")
        self.original_hash_value = ""
        self.received_hash_value = ""
        self.set_box_content(self.original_hash_box, "")
        self.set_box_content(self.received_hash_box, "")
        self.set_result("Aucune vérification effectuée pour le moment.", "#506095")
        self.clear_all_statuses()
        self.set_status(self.verify_status, "Tous les champs ont été vidés.", self.text_muted)
        self.reset_steps()