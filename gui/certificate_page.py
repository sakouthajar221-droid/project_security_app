"""
certificate_page.py — Certificat Numérique X.509 (adaptée en CTkFrame)
"""

import customtkinter as ctk
from tkinter import filedialog, messagebox
import threading
import time
from core.certificate import CertificateManager


class CertificatePage(ctk.CTkFrame):
    STEPS = ["Informations", "Génération", "Détails", "Export PEM"]

    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)

        self.bg           = "#161c34"
        self.header_bg    = "#1a213d"
        self.panel_bg     = "#202745"
        self.panel_bg_2   = "#242c4a"
        self.input_bg     = "#31395f"
        self.border       = "#6f8fc5"
        self.step_blue    = "#56679e"
        self.step_green   = "#57c48d"
        self.text_main    = "#dbe6ff"
        self.text_muted   = "#9cb0da"
        self.title_blue   = "#7ea5e5"
        self.orange       = "#e8a65b"
        self.red          = "#f67676"
        self.green        = "#57c48d"
        self.green_hover  = "#6ad49a"
        self.demo_btn       = "#6f89b7"
        self.demo_btn_hover = "#7d97c6"
        self.action_btn      = "#5f7db0"
        self.action_btn_hover= "#6f8dc0"
        self.result_bg    = "#2d355a"

        self.configure(fg_color=self.bg)

        self.cert_manager    = CertificateManager()
        self._cert_generated = False
        self._current_step   = 0
        self._demo_running   = False

        self.step_flags = [False, False, False, False]

        self._build_ui()

    # ========================= UI =========================

    def _build_ui(self):
        self.fixed_top = ctk.CTkFrame(self, fg_color=self.bg)
        self.fixed_top.pack(fill="x", padx=16, pady=(12, 8))
        self._build_header(self.fixed_top)

        self.scroll = ctk.CTkScrollableFrame(self, fg_color=self.bg)
        self.scroll.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        self._build_step1_form(self.scroll)
        self._build_step2_generation(self.scroll)
        self._build_step3_details(self.scroll)
        self._build_step4_pem(self.scroll)
        self._build_bottom_clear(self.scroll)

        self._update_steps_display()

    def _build_header(self, parent):
        top_row = ctk.CTkFrame(parent, fg_color="transparent")
        top_row.pack(fill="x", pady=(0, 6))

        ctk.CTkLabel(top_row, text="🔏  Certificat Numérique X.509",
                     font=ctk.CTkFont(size=24, weight="bold"),
                     text_color=self.title_blue).pack(side="left", padx=(8, 0))

        self.btn_demo = ctk.CTkButton(
            top_row, text="▶  Démonstration auto", command=self._run_demo,
            width=190, height=38, corner_radius=10,
            fg_color=self.demo_btn, hover_color=self.demo_btn_hover,
            text_color="white", font=ctk.CTkFont(size=13, weight="bold"), border_width=0)
        self.btn_demo.pack(side="right", padx=(0, 6))

        info_box = ctk.CTkFrame(parent, fg_color=self.panel_bg, corner_radius=14,
                                 border_width=1, border_color=self.border)
        info_box.pack(fill="x", pady=(0, 8))
        info_text = (
            "Objectif : générer un certificat X.509 auto-signé liant une identité à une clé publique RSA.\n"
            "Principe : créer la paire RSA → remplir les champs X.509 → signer avec la clé privée → exporter en PEM.\n"
            "Attaque : un certificat auto-signé peut être falsifié ; en production une CA de confiance est requise.\n"
            "Limite : le certificat seul ne prouve pas l'identité sans une chaîne de confiance vérifiée."
        )
        ctk.CTkLabel(info_box, text=info_text, justify="left", anchor="w",
                     text_color=self.text_main, font=ctk.CTkFont(size=13),
                     wraplength=1040).pack(fill="x", padx=18, pady=14)

        self.steps_wrap = ctk.CTkFrame(parent, fg_color=self.panel_bg, corner_radius=14,
                                        border_width=1, border_color="#48598f")
        self.steps_wrap.pack(fill="x")

        self.steps_row = ctk.CTkFrame(self.steps_wrap, fg_color="transparent")
        self.steps_row.pack(pady=(14, 14))

        self._step_circles = []
        self._step_labels  = []
        self._step_lines   = []

        for i, label in enumerate(self.STEPS):
            item = ctk.CTkFrame(self.steps_row, fg_color="transparent")
            item.pack(side="left")
            circle = ctk.CTkLabel(item, text=str(i + 1), width=40, height=40,
                                   corner_radius=20, fg_color=self.step_blue,
                                   text_color="white", font=ctk.CTkFont(size=16, weight="bold"))
            circle.pack()
            txt = ctk.CTkLabel(item, text=label, text_color=self.text_muted, font=ctk.CTkFont(size=12))
            txt.pack(pady=(8, 0))
            self._step_circles.append(circle)
            self._step_labels.append(txt)
            if i < len(self.STEPS) - 1:
                line_holder = ctk.CTkFrame(self.steps_row, fg_color="transparent")
                line_holder.pack(side="left", padx=8)
                line = ctk.CTkFrame(line_holder, width=38, height=2, fg_color=self.step_blue)
                line.pack(pady=(18, 0))
                self._step_lines.append(line)

    def _section_title(self, parent, text, icon):
        bar = ctk.CTkFrame(parent, fg_color="#7698ca", corner_radius=0)
        bar.pack(fill="x", pady=(12, 0))
        ctk.CTkLabel(bar, text=f"{icon}  {text}", text_color="white",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=16, pady=10)

    def _section_card(self, parent):
        card = ctk.CTkFrame(parent, fg_color=self.panel_bg_2, corner_radius=0,
                             border_width=1, border_color="#394774")
        card.pack(fill="x", pady=(0, 8))
        return card

    def _make_btn(self, parent, text, command, fg=None, hover=None, width=215, height=40):
        return ctk.CTkButton(parent, text=text, command=command, width=width, height=height,
                             corner_radius=10, fg_color=fg if fg else self.action_btn,
                             hover_color=hover if hover else self.action_btn_hover,
                             text_color="white", font=ctk.CTkFont(size=13, weight="bold"))

    def _make_entry(self, parent, placeholder):
        return ctk.CTkEntry(parent, placeholder_text=placeholder, height=36,
                            fg_color=self.input_bg, border_color="#4d5d94",
                            text_color=self.text_main, placeholder_text_color=self.text_muted,
                            font=ctk.CTkFont(size=13))

    def _make_status(self, parent):
        return ctk.CTkLabel(parent, text="", text_color=self.text_muted, font=ctk.CTkFont(size=12))

    # ========================= SECTIONS =========================

    def _build_step1_form(self, parent):
        self._section_title(parent, "Étape 1 — Informations du certificat", "📝")
        card = self._section_card(parent)
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=16, pady=14)
        inner.columnconfigure((0, 1), weight=1)

        fields_config = [
            ("Common Name (CN) *",   "ex: MonServeur ou Alice", True,  0, 0),
            ("Organisation (O) *",   "ex: ENSA Fès",            True,  0, 1),
            ("Pays (C) *",           "ex: MA",                  True,  1, 0),
            ("État / Province (ST)", "ex: Fès-Meknès",          False, 1, 1),
            ("Ville / Localité (L)", "ex: Fès",                 False, 2, 0),
        ]

        self.form_vars = {}
        for label, placeholder, required, row, col in fields_config:
            c = ctk.CTkFrame(inner, fg_color="transparent")
            c.grid(row=row, column=col, padx=8, pady=6, sticky="ew")
            ctk.CTkLabel(c, text=label, font=ctk.CTkFont(size=13),
                         text_color=self.text_main if required else self.text_muted).pack(anchor="w")
            entry = self._make_entry(c, placeholder)
            entry.pack(fill="x", pady=(4, 0))
            self.form_vars[label] = entry

        adv = ctk.CTkFrame(card, fg_color="transparent")
        adv.pack(fill="x", padx=16, pady=(4, 14))
        adv.columnconfigure((0, 1), weight=1)

        left = ctk.CTkFrame(adv, fg_color="transparent")
        left.grid(row=0, column=0, padx=8, sticky="ew")
        self.validity_label = ctk.CTkLabel(left, text="Durée de validité : 365 jours",
                                            font=ctk.CTkFont(size=13), text_color=self.text_muted)
        self.validity_label.pack(anchor="w")
        self.validity_slider = ctk.CTkSlider(left, from_=30, to=3650, number_of_steps=30,
                                              button_color=self.action_btn, progress_color=self.action_btn,
                                              fg_color=self.input_bg, command=self._update_validity_label)
        self.validity_slider.set(365)
        self.validity_slider.pack(fill="x", pady=(6, 0))

        right = ctk.CTkFrame(adv, fg_color="transparent")
        right.grid(row=0, column=1, padx=8, sticky="ew")
        ctk.CTkLabel(right, text="Taille clé RSA", font=ctk.CTkFont(size=13),
                     text_color=self.text_muted).pack(anchor="w")
        self.key_size_var = ctk.StringVar(value="2048 bits")
        ctk.CTkOptionMenu(right, values=["1024 bits", "2048 bits", "4096 bits"],
                          variable=self.key_size_var, fg_color=self.input_bg,
                          button_color=self.action_btn, text_color=self.text_main,
                          font=ctk.CTkFont(size=13)).pack(anchor="w", pady=(6, 0))

    def _build_step2_generation(self, parent):
        self._section_title(parent, "Étape 2 — Génération du certificat", "⚙️")
        card = self._section_card(parent)
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=16, pady=14)

        btn_row = ctk.CTkFrame(inner, fg_color="transparent")
        btn_row.pack(fill="x", pady=(0, 12))

        self.btn_generate = self._make_btn(btn_row, "⚙️  Générer le certificat", self._on_generate,
                                           fg=self.green, hover=self.green_hover, width=220)
        self.btn_generate.pack(side="left", padx=(0, 12))
        self._make_btn(btn_row, "📂  Charger .pem / .crt", self._on_load, width=210).pack(side="left", padx=(0, 12))
        self._make_btn(btn_row, "🗑  Vider tout", self._on_clear_all, width=160).pack(side="left")

        self.progress_bar = ctk.CTkProgressBar(inner, mode="indeterminate",
                                                progress_color=self.green, fg_color=self.input_bg)

        self.success_banner = ctk.CTkFrame(inner, fg_color="#1a3a2a", corner_radius=10,
                                            border_width=1, border_color=self.step_green)
        self.success_label = ctk.CTkLabel(self.success_banner,
                                          text="✅  Le certificat a été généré avec succès !",
                                          font=ctk.CTkFont(size=14, weight="bold"), text_color=self.step_green)
        self.success_label.pack(padx=16, pady=12)

        self.status_label = self._make_status(inner)
        self.status_label.pack(anchor="w", pady=(4, 0))

    def _build_step3_details(self, parent):
        self._section_title(parent, "Étape 3 — Détails du certificat généré", "🔍")
        card = self._section_card(parent)
        self.info_placeholder = ctk.CTkLabel(card,
                                              text="Aucun certificat disponible. Générez-en un à l'étape 2.",
                                              font=ctk.CTkFont(size=13), text_color=self.text_muted)
        self.info_placeholder.pack(pady=16)
        self.info_grid = ctk.CTkFrame(card, fg_color="transparent")

    def _build_step4_pem(self, parent):
        self._section_title(parent, "Étape 4 — Export PEM", "📄")
        card = self._section_card(parent)
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=16, pady=14)

        ctrl_row = ctk.CTkFrame(inner, fg_color="transparent")
        ctrl_row.pack(fill="x", pady=(0, 10))
        self.pem_mode = ctk.StringVar(value="Certificat")
        ctk.CTkSegmentedButton(ctrl_row, values=["Certificat", "Clé privée"],
                               variable=self.pem_mode, command=self._update_pem_display,
                               selected_color=self.action_btn, unselected_color=self.input_bg,
                               text_color=self.text_main, font=ctk.CTkFont(size=13)).pack(side="left")
        self.btn_save = self._make_btn(ctrl_row, "💾  Sauvegarder (.crt + .key)", self._on_save,
                                       fg=self.green, hover=self.green_hover, width=260)
        self.btn_save.configure(state="disabled")
        self.btn_save.pack(side="right")

        self.pem_textbox = ctk.CTkTextbox(inner, height=180,
                                           font=ctk.CTkFont(family="Courier", size=11),
                                           fg_color=self.input_bg, border_color="#4d5d94",
                                           border_width=1, text_color="#7ecfff", corner_radius=10)
        self.pem_textbox.pack(fill="x", pady=(0, 4))
        self.pem_textbox.insert("1.0", "Le contenu PEM apparaîtra ici après la génération...")
        self.pem_textbox.configure(state="disabled")

    def _build_bottom_clear(self, parent):
        holder = ctk.CTkFrame(parent, fg_color="transparent")
        holder.pack(fill="x", pady=(8, 18))

    # ========================= STEPS =========================

    def _update_steps_display(self):
        for i, (circle, label) in enumerate(zip(self._step_circles, self._step_labels)):
            if self.step_flags[i]:
                circle.configure(fg_color=self.step_green, text="✓")
                label.configure(text_color=self.step_green)
            else:
                circle.configure(fg_color=self.step_blue, text=str(i + 1))
                label.configure(text_color=self.text_muted)
        for i, line in enumerate(self._step_lines):
            if self.step_flags[i] and self.step_flags[i + 1]:
                line.configure(fg_color=self.step_green)
            else:
                line.configure(fg_color=self.step_blue)

    def _activate_step(self, index):
        if 0 <= index < len(self.step_flags):
            self.step_flags[index] = True
            self._update_steps_display()

    def _reset_steps(self):
        self.step_flags = [False, False, False, False]
        self._update_steps_display()

    def _set_step(self, step):
        self._current_step = step
        for i in range(step):
            self.step_flags[i] = True
        self._update_steps_display()

    # ========================= CALLBACKS =========================

    def _update_validity_label(self, value):
        days = int(value)
        years = days // 365
        suffix = f" ({years} an{'s' if years > 1 else ''})" if years >= 1 else ""
        self.validity_label.configure(text=f"Durée de validité : {days} jours{suffix}")

    def _get_form_data(self):
        cn      = self.form_vars["Common Name (CN) *"].get().strip()
        org     = self.form_vars["Organisation (O) *"].get().strip()
        country = self.form_vars["Pays (C) *"].get().strip().upper()
        state   = self.form_vars["État / Province (ST)"].get().strip()
        loc     = self.form_vars["Ville / Localité (L)"].get().strip()
        if not cn:
            raise ValueError("Le champ 'Common Name (CN)' est obligatoire.")
        if not org:
            raise ValueError("Le champ 'Organisation (O)' est obligatoire.")
        if not country:
            raise ValueError("Le champ 'Pays (C)' est obligatoire.")
        if len(country) != 2:
            raise ValueError("Le pays doit être un code ISO à 2 lettres (ex: MA, FR, US).")
        return {
            "common_name": cn, "organization": org, "country": country,
            "state": state, "locality": loc,
            "validity_days": int(self.validity_slider.get()),
            "key_size": int(self.key_size_var.get().replace(" bits", ""))
        }

    def _on_generate(self):
        try:
            form_data = self._get_form_data()
        except ValueError as e:
            messagebox.showerror("Erreur de saisie", str(e))
            return
        self._activate_step(0)
        self.btn_generate.configure(state="disabled", text="⏳  Génération en cours...")
        self.progress_bar.pack(fill="x", pady=(0, 6))
        self.progress_bar.start()
        self.status_label.configure(text="Génération de la paire RSA et du certificat X.509...", text_color=self.text_muted)
        threading.Thread(target=self._generate_worker, args=(form_data,), daemon=True).start()

    def _generate_worker(self, form_data):
        try:
            self.cert_manager.generate_self_signed_cert(**form_data)
            self.after(0, self._on_generate_success)
        except Exception as e:
            self.after(0, lambda: self._on_generate_error(str(e)))

    def _on_generate_success(self):
        self.progress_bar.stop()
        self.progress_bar.pack_forget()
        self.btn_generate.configure(state="normal", text="⚙️  Générer le certificat")
        self.btn_save.configure(state="normal")
        self._cert_generated = True
        self.success_banner.pack(fill="x", pady=(0, 8))
        self.status_label.configure(text="", text_color=self.step_green)
        self._activate_step(1)
        self._display_certificate_info()
        self._update_pem_display()
        self._activate_step(2)
        self._activate_step(3)

    def _on_generate_error(self, error_msg):
        self.progress_bar.stop()
        self.progress_bar.pack_forget()
        self.btn_generate.configure(state="normal", text="⚙️  Générer le certificat")
        self.status_label.configure(text=f"❌  Erreur : {error_msg}", text_color=self.red)
        messagebox.showerror("Erreur de génération", error_msg)

    def _display_certificate_info(self):
        try:
            info = self.cert_manager.get_certificate_info()
        except ValueError as e:
            messagebox.showerror("Erreur", str(e))
            return
        self.info_placeholder.pack_forget()
        for w in self.info_grid.winfo_children():
            w.destroy()
        self.info_grid.pack(fill="x", padx=16, pady=(0, 14))
        self.info_grid.columnconfigure((0, 1), weight=1)

        fields = [
            ("🪪 Common Name", info["common_name"], 0, 0),
            ("🏢 Organisation", info["organization"], 0, 1),
            ("🌍 Pays", info["country"], 1, 0),
            ("📍 État / Ville", f"{info['state']} / {info['locality']}", 1, 1),
            ("✍️ Émetteur (Issuer)", info["issuer"], 2, 0),
            ("🔑 Taille clé publique", info["public_key_size"], 2, 1),
            ("📅 Valide du", info["valid_from"], 3, 0),
            ("📅 Valide jusqu'au", info["valid_to"], 3, 1),
            ("🔢 Numéro de série", info["serial_number"][:24] + "...", 4, 0),
            ("🔏 Algorithme signature", info["signature_algorithm"], 4, 1),
            ("✅ Auto-signé", info["is_self_signed"], 5, 0),
            ("📋 Version X.509", info["version"], 5, 1),
        ]

        for label, value, row, col in fields:
            card = ctk.CTkFrame(self.info_grid, fg_color=self.input_bg, corner_radius=10,
                                 border_width=1, border_color="#4d5d94")
            card.grid(row=row, column=col, padx=5, pady=4, sticky="ew")
            ctk.CTkLabel(card, text=label, font=ctk.CTkFont(size=11),
                         text_color=self.text_muted).pack(anchor="w", padx=10, pady=(8, 1))
            ctk.CTkLabel(card, text=value, font=ctk.CTkFont(size=12, weight="bold"),
                         text_color=self.text_main, wraplength=320).pack(anchor="w", padx=10, pady=(0, 8))

    def _update_pem_display(self, *args):
        if not self._cert_generated:
            return
        self.pem_textbox.configure(state="normal")
        self.pem_textbox.delete("1.0", "end")
        try:
            content = (self.cert_manager.export_certificate_pem()
                       if self.pem_mode.get() == "Certificat"
                       else self.cert_manager.export_private_key_pem())
            self.pem_textbox.insert("1.0", content)
        except ValueError as e:
            self.pem_textbox.insert("1.0", f"Erreur : {e}")
        self.pem_textbox.configure(state="disabled")

    def _on_save(self):
        if not self._cert_generated:
            messagebox.showwarning("Avertissement", "Aucun certificat à sauvegarder.")
            return
        folder = filedialog.askdirectory(title="Choisir le dossier de sauvegarde")
        if not folder:
            return
        cn = self.form_vars["Common Name (CN) *"].get().strip().replace(" ", "_")
        try:
            self.cert_manager.save_to_files(f"{folder}/{cn}_certificate.crt", f"{folder}/{cn}_private.key")
            messagebox.showinfo("Sauvegarde réussie ✅",
                                f"Certificat : {folder}/{cn}_certificate.crt\nClé privée : {folder}/{cn}_private.key")
        except Exception as e:
            messagebox.showerror("Erreur de sauvegarde", str(e))

    def _on_load(self):
        filepath = filedialog.askopenfilename(title="Charger un certificat",
                                              filetypes=[("Certificats PEM", "*.pem *.crt"), ("Tous les fichiers", "*.*")])
        if not filepath:
            return
        try:
            self.cert_manager.load_from_file(filepath)
            self._cert_generated = True
            self.btn_save.configure(state="normal")
            self._display_certificate_info()
            self._update_pem_display()
            self._set_step(3)
            self.success_banner.pack(fill="x", pady=(0, 8))
            self.success_label.configure(text="✅  Le certificat a été chargé avec succès !")
            self.status_label.configure(text="", text_color=self.step_green)
        except FileNotFoundError as e:
            messagebox.showerror("Fichier introuvable", str(e))
        except Exception as e:
            messagebox.showerror("Erreur de chargement", str(e))

    def _on_clear_all(self):
        for entry in self.form_vars.values():
            entry.delete(0, "end")
        self.validity_slider.set(365)
        self._update_validity_label(365)
        self.key_size_var.set("2048 bits")
        self.cert_manager    = CertificateManager()
        self._cert_generated = False
        self._current_step   = 0
        self._reset_steps()
        self.btn_generate.configure(state="normal", text="⚙️  Générer le certificat")
        self.btn_save.configure(state="disabled")
        self.success_banner.pack_forget()
        self.status_label.configure(text="", text_color=self.text_muted)
        for w in self.info_grid.winfo_children():
            w.destroy()
        self.info_grid.pack_forget()
        self.info_placeholder.pack(pady=16)
        self.pem_textbox.configure(state="normal")
        self.pem_textbox.delete("1.0", "end")
        self.pem_textbox.insert("1.0", "Le contenu PEM apparaîtra ici après la génération...")
        self.pem_textbox.configure(state="disabled")

    # ========================= DÉMONSTRATION =========================

    def _run_demo(self):
        if self._demo_running:
            return
        self._demo_running = True
        self.btn_demo.configure(state="disabled", text="⏳  Démonstration en cours...")
        threading.Thread(target=self._demo_worker, daemon=True).start()

    def _demo_worker(self):
        try:
            self.after(0, lambda: self.status_label.configure(
                text="🎬  Démo : remplissage du formulaire...", text_color=self.text_muted))
            demo_data = {
                "Common Name (CN) *"   : "Demo-ENSA-Fes",
                "Organisation (O) *"   : "ENSA Fès",
                "Pays (C) *"           : "MA",
                "État / Province (ST)" : "Fès-Meknès",
                "Ville / Localité (L)" : "Fès",
            }
            for field, value in demo_data.items():
                time.sleep(0.4)
                def fill(f=field, v=value):
                    self.form_vars[f].delete(0, "end")
                    self.form_vars[f].insert(0, v)
                self.after(0, fill)

            time.sleep(0.6)
            self.after(0, lambda: self._activate_step(0))
            self.after(0, lambda: self.status_label.configure(
                text="🎬  Démo : génération du certificat...", text_color=self.text_muted))
            self.after(0, lambda: self.progress_bar.pack(fill="x", pady=(0, 6)))
            self.after(0, self.progress_bar.start)

            self.cert_manager.generate_self_signed_cert(
                common_name="Demo-ENSA-Fes", organization="ENSA Fès",
                country="MA", state="Fès-Meknès", locality="Fès",
                validity_days=365, key_size=2048)
            time.sleep(0.5)

            self.after(0, self.progress_bar.stop)
            self.after(0, self.progress_bar.pack_forget)
            self._cert_generated = True
            self.after(0, lambda: self.btn_save.configure(state="normal"))
            self.after(0, lambda: self._activate_step(1))
            self.after(0, lambda: self.status_label.configure(
                text="🎬  Démo : affichage des détails...", text_color=self.text_muted))
            self.after(0, self._display_certificate_info)

            time.sleep(0.8)
            self.after(0, lambda: self._activate_step(2))
            self.after(0, lambda: self.status_label.configure(
                text="🎬  Démo : export PEM...", text_color=self.text_muted))
            self.after(0, self._update_pem_display)

            time.sleep(0.5)
            self.after(0, lambda: self._activate_step(3))
            self.after(0, lambda: self.status_label.configure(
                text="✅  Démonstration terminée avec succès !", text_color=self.step_green))
            self.after(0, lambda: self.success_banner.pack(fill="x", pady=(0, 8)))

        except Exception as e:
            self.after(0, lambda: self.status_label.configure(
                text=f"❌  Erreur démo : {e}", text_color=self.red))
        finally:
            self._demo_running = False
            self.after(0, lambda: self.btn_demo.configure(state="normal", text="▶  Démonstration auto"))