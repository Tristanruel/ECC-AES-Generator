from tkinterdnd2 import DND_FILES, TkinterDnD
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import glob
import shutil
import subprocess

try:
    from ctypes import windll
    windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    pass

class ToggleSwitch(tk.Frame):
    def __init__(self, master, on_toggle=None, width=60, height=30, is_on=False, bg=None):
        if bg is None:
            bg = master.cget("bg")
        super().__init__(master, width=width, height=height, bd=0, highlightthickness=0)
        self.on_toggle = on_toggle
        self.is_on = is_on
        self.width = width
        self.height = height
        self.config(bg=bg)
        self.canvas = tk.Canvas(self, width=width, height=height, bd=0, highlightthickness=0, bg=bg)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self.canvas.bind("<Button-1>", self._toggle)
        self.draw_switch()

    def draw_switch(self):
        self.canvas.delete("all")
        radius = self.height // 2
        x1, y1 = 0, 0
        x2, y2 = self.width, self.height
        if self.is_on:
            bg_color = "#4CD964"
            knob_x1 = self.width - self.height
            knob_x2 = self.width
        else:
            bg_color = "#CCCCCC"
            knob_x1 = 0
            knob_x2 = self.height
        self.canvas.create_arc(x1, y1, y1 + 2 * radius, y2, start=90, extent=180, fill=bg_color, outline=bg_color)
        self.canvas.create_arc(x2 - 2 * radius, y1, x2, y2, start=-90, extent=180, fill=bg_color, outline=bg_color)
        self.canvas.create_rectangle(radius, 0, self.width - radius, self.height, fill=bg_color, outline=bg_color)
        self.canvas.create_oval(knob_x1, 0, knob_x2, self.height, fill="#E0E0E0", outline="#E0E0E0")

    def _toggle(self, _event):
        self.is_on = not self.is_on
        self.draw_switch()
        if callable(self.on_toggle):
            self.on_toggle(self.is_on)

    def set_bg(self, bg):
        self.config(bg=bg)
        self.canvas.config(bg=bg)

class CryptoKeyGenUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptographic Key Generator")
        self.root.geometry("1200x800")
        self.theme_mode = "macOS"
        self.macOS_theme = {
            "bg_color": "#ECECEC",
            "sidebar_color": "#FFFFFF",
            "text_color": "#222222"
        }
        self.rustic_theme = {
            "bg_color": "#5C4033",
            "sidebar_color": "#7B6E5A",
            "text_color": "#FFFFFF"
        }
        self.style = ttk.Style()
        self.style.configure("Rounded.TButton", relief="flat", padding=10)
        self.default_font = ("SF Pro Display", 16)
        self.title_font = ("SF Pro Display", 22, "bold")
        self.subtitle_font = ("SF Pro Display", 18, "bold")
        self.root.option_add("*Font", self.default_font)
        self.container = tk.Frame(self.root)
        self.container.pack(fill=tk.BOTH, expand=True)
        self.dashboard_frame = tk.Frame(self.container, width=320)
        self.dashboard_frame.pack(side=tk.LEFT, fill=tk.Y)
        self.dashboard_frame.pack_propagate(False)
        self.menu_title = tk.Label(self.dashboard_frame, text="Menu", font=self.title_font)
        self.menu_title.pack(pady=10)
        self.content_frame = tk.Frame(self.container)
        self.content_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        self.menu_buttons = []
        buttons = [
            ("Home", "Home"),
            ("Generate Randomness", "VonNeumann"),
            ("File Operations", "AES"),
            ("Encrypt File", "ECC"),
            ("Decrypt File", "Preparation"),
            ("File Management", "FileManagement"),
            ("Settings", "Settings")
        ]
        for text, frame_name in buttons:
            btn = ttk.Button(self.dashboard_frame, text=text, style="Rounded.TButton", command=lambda fn=frame_name: self.show_frame(fn))
            btn.pack(pady=6, fill=tk.X, padx=20)
            self.menu_buttons.append(btn)
        self.frames = {}
        self.create_pages()
        self.nuclear_canvas = tk.Canvas(self.root, width=100, height=100, highlightthickness=0)
        self.set_theme("macOS")
        self.show_frame("Home")
        self.periodic_update()

    def create_pages(self):
        # Home Page
        home = tk.Frame(self.content_frame)
        self.frames["Home"] = home
        tk.Label(home, text="Welcome to the Cryptographic Suite", font=self.title_font).pack(pady=30)
        home_text = (
            "This tool provides a comprehensive set of cryptographic utilities including:\n"
            "• Secure file encryption and decryption\n"
            "• Generation of randomness using Von Neumann methods\n"
            "• AES and ECC key generation\n"
            "• File management and customisable settings\n\n"
            "Click 'Get Started' to proceed directly to file encryption."
        )
        tk.Label(home, text=home_text, wraplength=700, justify="left").pack(pady=10, padx=20, anchor="w")
        ttk.Button(home, text="Get Started", style="Rounded.TButton", command=lambda: self.show_frame("ECC")).pack(pady=30)
        
        # Generate Randomness Page
        gen_rand = tk.Frame(self.content_frame)
        self.frames["VonNeumann"] = gen_rand
        tk.Label(gen_rand, text="Generate Randomness", font=self.subtitle_font).pack(pady=10)
        self.radiation_upload = tk.Label(gen_rand, text="Upload .csv/.xlsx", width=15, height=5, relief="solid", bd=1)
        self.radiation_upload.config(font=("SF Pro Display", 10, "italic"))
        self.radiation_upload.pack(pady=10)
        self.radiation_upload.bind("<Button-1>", lambda e: self.upload_radiation_file())
        self.radiation_upload.drop_target_register(DND_FILES)
        self.radiation_upload.dnd_bind("<<Drop>>", self.drop_radiation_file)
        ttk.Button(gen_rand, text="Create Randomness", style="Rounded.TButton", command=self.create_randomness).pack(pady=10)
        
        # File Operations Page
        file_ops = tk.Frame(self.content_frame)
        self.frames["AES"] = file_ops
        tk.Label(file_ops, text="File Operations", font=self.subtitle_font).pack(pady=10)
        self.aes_status_labels = {}
        btn_specs = [
            ("Run Von Neumann Extractor", "von-neumann-extractor.exe", "von_neumann"),
            ("Run ECC Key Generator", "ECC-generator.exe", "ecc_private"),
            ("Run AES Key Generator", "AES-generator.exe", "aes_keys"),
            ("Run Public ECC Key Generator", "public.exe", "ecc_public"),
            ("Run File Encryption", "encryptor.exe", "imported"),
            ("Run File Decryption", "decryptor.exe", "exported")
        ]
        for btn_text, exe, status_key in btn_specs:
            row = tk.Frame(file_ops)
            row.pack(pady=6, fill="x", padx=10)
            btn = ttk.Button(row, text=btn_text, style="Rounded.TButton", command=lambda exe=exe: self.run_executable(exe))
            btn.pack(side=tk.LEFT)
            status_lbl = tk.Label(row, text="", font=self.default_font, anchor="e")
            status_lbl.pack(side=tk.RIGHT, fill="x", expand=True, padx=10)
            self.aes_status_labels[status_key] = status_lbl
        self.update_aes_status()
        
        # Encrypt File Page (ECC)
        encrypt_file = tk.Frame(self.content_frame)
        self.frames["ECC"] = encrypt_file
        tk.Label(encrypt_file, text="Encrypt File", font=self.subtitle_font).pack(pady=10)
        self.import_upload = tk.Label(encrypt_file, text="Upload File", width=15, height=5, relief="solid", bd=1)
        self.import_upload.config(font=("SF Pro Display", 10, "italic"))
        self.import_upload.pack(pady=10)
        self.import_upload.bind("<Button-1>", lambda e: self.upload_import_file())
        self.import_upload.drop_target_register(DND_FILES)
        self.import_upload.dnd_bind("<<Drop>>", self.drop_import_file)
        lb_frame = tk.Frame(encrypt_file)
        lb_frame.pack(pady=5, fill="both", expand=True)
        self.import_listbox = tk.Listbox(lb_frame)
        self.import_scroll = ttk.Scrollbar(lb_frame, orient="vertical", command=self.import_listbox.yview)
        self.import_listbox.config(yscrollcommand=self.import_scroll.set)
        self.import_listbox.pack(side="left", fill="both", expand=True)
        self.import_scroll.pack(side="right", fill="y")
        # The Encrypt button now uses the new function with checks
        ttk.Button(encrypt_file, text="Encrypt", style="Rounded.TButton", command=self.run_encryptor_with_checks).pack(pady=10)
        self.encrypt_status_text = tk.Text(encrypt_file, height=10, state="disabled")
        self.encrypt_status_text.pack(pady=10, fill="both", expand=True)
        self.update_import_status()
        
        # Decrypt File Page (Preparation)
        decrypt_file = tk.Frame(self.content_frame)
        self.frames["Preparation"] = decrypt_file
        tk.Label(decrypt_file, text="Decrypt File", font=self.subtitle_font).pack(pady=10)
        self.export_upload = tk.Label(decrypt_file, text="Upload File", width=15, height=5, relief="solid", bd=1)
        self.export_upload.config(font=("SF Pro Display", 10, "italic"))
        self.export_upload.pack(pady=10)
        self.export_upload.bind("<Button-1>", lambda e: self.upload_export_file())
        self.export_upload.drop_target_register(DND_FILES)
        self.export_upload.dnd_bind("<<Drop>>", self.drop_export_file)
        lb2_frame = tk.Frame(decrypt_file)
        lb2_frame.pack(pady=5, fill="both", expand=True)
        self.decrypted_listbox = tk.Listbox(lb2_frame)
        self.decrypted_scroll = ttk.Scrollbar(lb2_frame, orient="vertical", command=self.decrypted_listbox.yview)
        self.decrypted_listbox.config(yscrollcommand=self.decrypted_scroll.set)
        self.decrypted_listbox.pack(side="left", fill="both", expand=True)
        self.decrypted_scroll.pack(side="right", fill="y")
        ttk.Button(decrypt_file, text="Decrypt", style="Rounded.TButton", command=self.run_decryptor).pack(pady=10)
        self.decrypt_status_text = tk.Text(decrypt_file, height=10, state="disabled")
        self.decrypt_status_text.pack(pady=10, fill="both", expand=True)
        self.update_decrypted_status()
        
        # File Management Page
        filemgmt = tk.Frame(self.content_frame)
        self.frames["FileManagement"] = filemgmt
        tk.Label(filemgmt, text="File Management", font=self.subtitle_font).pack(pady=30)
        ttk.Button(filemgmt, text="View Import Files", style="Rounded.TButton", command=self.open_import_folder).pack(pady=10)
        ttk.Button(filemgmt, text="View Export Files", style="Rounded.TButton", command=self.open_export_folder).pack(pady=10)
        
        # Settings Page
        settings = tk.Frame(self.content_frame)
        self.frames["Settings"] = settings
        tk.Label(settings, text="Settings", font=self.subtitle_font).pack(pady=30)
        toggle_line = tk.Frame(settings)
        toggle_line.pack(pady=10)
        tk.Label(toggle_line, text="Toggle the 'rustic nuclear' mode:").pack(side=tk.LEFT, padx=5)
        self.toggle_switch = ToggleSwitch(toggle_line, on_toggle=self.on_theme_toggled, width=60, height=30, is_on=False)
        self.toggle_switch.pack(side=tk.LEFT, padx=5)
        file_size_frame = tk.Frame(settings)
        file_size_frame.pack(pady=10)
        tk.Label(file_size_frame, text="Max Encryption File Size:").pack(side=tk.LEFT, padx=5)
        self.max_file_size = tk.StringVar()
        self.max_file_size_combobox = ttk.Combobox(file_size_frame, textvariable=self.max_file_size,
                                                   values=["1GB", "2GB", "4GB", "8GB", "16GB", "32GB", "64GB", "Other"],
                                                   state="readonly")
        self.max_file_size_combobox.pack(side=tk.LEFT, padx=5)
        self.max_file_size_combobox.bind("<<ComboboxSelected>>", self.on_file_size_selected)
        self.other_file_size_entry = tk.Entry(file_size_frame)
        self.other_file_size_entry.pack(side=tk.LEFT, padx=5)
        self.other_file_size_entry.config(state="disabled")
        encrypt_frame = tk.Frame(settings)
        encrypt_frame.pack(pady=10)
        tk.Label(encrypt_frame, text="Encrypt File Name:").pack(side=tk.LEFT, padx=5)
        self.encrypt_toggle = ToggleSwitch(encrypt_frame, on_toggle=None, width=60, height=30, is_on=False)
        self.encrypt_toggle.pack(side=tk.LEFT, padx=5)
        delete_temp_frame = tk.Frame(settings)
        delete_temp_frame.pack(pady=10)
        tk.Label(delete_temp_frame, text="Delete Temp Files after use?").pack(side=tk.LEFT, padx=5)
        self.delete_temp_toggle = ToggleSwitch(delete_temp_frame, on_toggle=None, width=60, height=30, is_on=True)
        self.delete_temp_toggle.pack(side=tk.LEFT, padx=5)
        delete_rad_frame = tk.Frame(settings)
        delete_rad_frame.pack(pady=10)
        tk.Label(delete_rad_frame, text="Delete Radiation Files after use?").pack(side=tk.LEFT, padx=5)
        self.delete_radiation_toggle = ToggleSwitch(delete_rad_frame, on_toggle=None, width=60, height=30, is_on=False)
        self.delete_radiation_toggle.pack(side=tk.LEFT, padx=5)
        ttk.Button(settings, text="Save Settings", style="Rounded.TButton", command=self.save_settings).pack(pady=20)
        ttk.Button(settings, text="Reinstall Dependencies", style="Rounded.TButton", command=self.run_install_bat).pack(pady=10)
        self.status_label = tk.Label(settings, text="", font=self.default_font)
        self.status_label.pack(pady=5)

    def show_frame(self, name):
        for frame in self.frames.values():
            frame.pack_forget()
        self.frames[name].pack(fill=tk.BOTH, expand=True)
        if name == "AES":
            self.update_aes_status()
        elif name == "ECC":
            self.update_import_status()
        elif name == "Preparation":
            self.update_decrypted_status()

    def open_import_folder(self):
        import_folder = os.path.join(os.getcwd(), "Import")
        if not os.path.exists(import_folder):
            os.makedirs(import_folder)
        try:
            os.startfile(import_folder)
        except Exception as e:
            messagebox.showerror("Error", f"Error opening Import folder: {e}")

    def open_export_folder(self):
        export_folder = os.path.join(os.getcwd(), "Export")
        if not os.path.exists(export_folder):
            os.makedirs(export_folder)
        try:
            os.startfile(export_folder)
        except Exception as e:
            messagebox.showerror("Error", f"Error opening Export folder: {e}")

    def view_files(self):
        self.status_label.config(text="(File list would be displayed here.)", fg="black")

    def on_theme_toggled(self, is_on):
        if is_on:
            self.set_theme("rustic_nuclear")
        else:
            self.set_theme("macOS")

    def set_theme(self, theme):
        self.theme_mode = theme
        if theme == "macOS":
            colors = self.macOS_theme
            self.nuclear_canvas.place_forget()
        else:
            colors = self.rustic_theme
            self.nuclear_canvas.config(bg=colors["bg_color"])
            self.draw_nuclear_symbol()
            self.nuclear_canvas.place(relx=1.0, rely=1.0, anchor="se", x=-15, y=-15)
        self.root.config(bg=colors["bg_color"])
        self.container.config(bg=colors["bg_color"])
        self.dashboard_frame.config(bg=colors["sidebar_color"])
        self.content_frame.config(bg=colors["bg_color"])
        self.menu_title.config(bg=colors["sidebar_color"], fg=colors["text_color"])
        self.apply_theme_to_children(self.dashboard_frame, colors["sidebar_color"], colors["text_color"])
        self.apply_theme_to_children(self.content_frame, colors["bg_color"], colors["text_color"])
        self.toggle_switch.set_bg(colors["bg_color"])
        self.root.update_idletasks()

    def apply_theme_to_children(self, parent, bg_color, fg_color):
        for child in parent.winfo_children():
            if isinstance(child, tk.Frame):
                child.config(bg=bg_color)
                self.apply_theme_to_children(child, bg_color, fg_color)
            elif isinstance(child, tk.Label):
                child.config(bg=bg_color, fg=fg_color)
            elif isinstance(child, tk.Checkbutton):
                child.config(bg=bg_color, fg=fg_color, selectcolor=bg_color)
            elif isinstance(child, ttk.Button):
                child.configure(style="Rounded.TButton")
            elif isinstance(child, ToggleSwitch):
                child.set_bg(bg_color)
            else:
                try:
                    child.config(bg=bg_color)
                except Exception:
                    pass
                self.apply_theme_to_children(child, bg_color, fg_color)

    def draw_nuclear_symbol(self):
        self.nuclear_canvas.delete("all")
        self.nuclear_canvas.create_oval(0, 0, 100, 100, fill="#FFD700", outline="#000000", width=2)
        for i in range(3):
            start_angle = 30 + i * 120
            self.nuclear_canvas.create_arc(0, 0, 100, 100, start=start_angle, extent=60, fill="black", outline="")
        self.nuclear_canvas.create_oval(40, 40, 60, 60, fill="black", outline="")

    def periodic_update(self):
        if self.frames["AES"].winfo_ismapped():
            self.update_aes_status()
        if self.frames["ECC"].winfo_ismapped():
            self.update_import_status()
        if self.frames["Preparation"].winfo_ismapped():
            self.update_decrypted_status()
        self.root.after(2000, self.periodic_update)

    def upload_radiation_file(self):
        file_path = filedialog.askopenfilename(title="Select Radiation Data File", filetypes=[("CSV Files", "*.csv"), ("Excel Files", "*.xlsx")])
        if file_path:
            dest_folder = os.path.join(os.getcwd(), "Radiation Data")
            os.makedirs(dest_folder, exist_ok=True)
            try:
                shutil.copy(file_path, dest_folder)
                messagebox.showinfo("Upload", "File uploaded to Radiation Data folder.")
                if messagebox.askyesno("Run prepkey.py", "Do you want to run prepkey.py now?"):
                    subprocess.Popen(["prepkey.py"], creationflags=subprocess.CREATE_NO_WINDOW)
            except Exception as e:
                messagebox.showerror("Error", f"Error uploading file: {e}")

    def drop_radiation_file(self, event):
        files = self.root.tk.splitlist(event.data)
        if files:
            file_path = files[0]
            dest_folder = os.path.join(os.getcwd(), "Radiation Data")
            os.makedirs(dest_folder, exist_ok=True)
            try:
                shutil.copy(file_path, dest_folder)
                messagebox.showinfo("Upload", "File uploaded to Radiation Data folder.")
                if messagebox.askyesno("Run prepkey.py", "Do you want to run prepkey.py now?"):
                    subprocess.Popen(["prepkey.py"], creationflags=subprocess.CREATE_NO_WINDOW)
            except Exception as e:
                messagebox.showerror("Error", f"Error uploading file: {e}")

    def create_randomness(self):
        if not messagebox.askyesno("Confirm", "This will delete all files in the Randomness folder (and if enabled, in Radiation Data). Continue?"):
            return
        randomness_folder = os.path.join(os.getcwd(), "Randomness")
        for f in glob.glob(os.path.join(randomness_folder, "*")):
            try:
                os.remove(f)
            except Exception as e:
                print(f"Error deleting {f}: {e}")
        settings_path = os.path.join("Settings", "settings.txt")
        delete_rad = False
        if os.path.exists(settings_path):
            with open(settings_path, "r") as f:
                for line in f:
                    if "Delete_Radiation_Files" in line and "1" in line:
                        delete_rad = True
        if delete_rad:
            rad_folder = os.path.join(os.getcwd(), "Radiation Data")
            for f in glob.glob(os.path.join(rad_folder, "*")):
                try:
                    os.remove(f)
                except Exception as e:
                    print(f"Error deleting radiation file {f}: {e}")
        subprocess.Popen(["von-neumann-extractor.exe"], creationflags=subprocess.CREATE_NO_WINDOW)
        messagebox.showinfo("Done", "Randomness generated successfully.")

    def update_aes_status(self):
        vn_files = len(glob.glob(os.path.join("Randomness", "Von_Neumann_randomness_*.txt")))
        ecc_private = len(glob.glob(os.path.join("ECC Keys", "ECC_key_pair_*.txt")))
        ecc_public = len(glob.glob(os.path.join("ECC Keys", "ECC_public_key_*.txt")))
        aes_keys = len(glob.glob(os.path.join("AES Keys", "AES_key_*.txt")))
        imported = len(glob.glob(os.path.join("Import", "*")))
        exported = len(glob.glob(os.path.join("Decrypted", "*")))
        if "von_neumann" in self.aes_status_labels:
            self.aes_status_labels["von_neumann"].config(text=f"{vn_files} files")
        if "ecc_private" in self.aes_status_labels:
            self.aes_status_labels["ecc_private"].config(text=f"{ecc_private} keys")
        if "aes_keys" in self.aes_status_labels:
            self.aes_status_labels["aes_keys"].config(text=f"{aes_keys} keys")
        if "ecc_public" in self.aes_status_labels:
            self.aes_status_labels["ecc_public"].config(text=f"{ecc_public} keys")
        if "imported" in self.aes_status_labels:
            self.aes_status_labels["imported"].config(text=f"{imported} files")
        if "exported" in self.aes_status_labels:
            self.aes_status_labels["exported"].config(text=f"{exported} files")

    def update_import_status(self):
        import_folder = os.path.join(os.getcwd(), "Import")
        os.makedirs(import_folder, exist_ok=True)
        files = os.listdir(import_folder)
        self.import_listbox.delete(0, tk.END)
        for f in files:
            self.import_listbox.insert(tk.END, f)
        self.import_listbox.insert(tk.END, f"Total: {len(files)} files")

    def update_decrypted_status(self):
        decrypted_folder = os.path.join(os.getcwd(), "Decrypted")
        os.makedirs(decrypted_folder, exist_ok=True)
        files = os.listdir(decrypted_folder)
        self.decrypted_listbox.delete(0, tk.END)
        for f in files:
            self.decrypted_listbox.insert(tk.END, f)
        self.decrypted_listbox.insert(tk.END, f"Total: {len(files)} files")

    def upload_import_file(self):
        file_path = filedialog.askopenfilename(title="Select file to import")
        if file_path:
            dest_folder = os.path.join(os.getcwd(), "Import")
            os.makedirs(dest_folder, exist_ok=True)
            try:
                shutil.copy(file_path, dest_folder)
                messagebox.showinfo("Upload", "File uploaded to Import folder.")
                self.update_import_status()
            except Exception as e:
                messagebox.showerror("Error", f"Error uploading file: {e}")

    def drop_import_file(self, event):
        files = self.root.tk.splitlist(event.data)
        if files:
            file_path = files[0]
            dest_folder = os.path.join(os.getcwd(), "Import")
            os.makedirs(dest_folder, exist_ok=True)
            try:
                shutil.copy(file_path, dest_folder)
                messagebox.showinfo("Upload", "File uploaded to Import folder.")
                self.update_import_status()
            except Exception as e:
                messagebox.showerror("Error", f"Error uploading file: {e}")

    def upload_export_file(self):
        file_path = filedialog.askopenfilename(title="Select file to export")
        if file_path:
            dest_folder = os.path.join(os.getcwd(), "Export")
            os.makedirs(dest_folder, exist_ok=True)
            try:
                shutil.copy(file_path, dest_folder)
                messagebox.showinfo("Upload", "File uploaded to Export folder.")
            except Exception as e:
                messagebox.showerror("Error", f"Error uploading file: {e}")

    def drop_export_file(self, event):
        files = self.root.tk.splitlist(event.data)
        if files:
            file_path = files[0]
            dest_folder = os.path.join(os.getcwd(), "Export")
            os.makedirs(dest_folder, exist_ok=True)
            try:
                shutil.copy(file_path, dest_folder)
                messagebox.showinfo("Upload", "File uploaded to Export folder.")
            except Exception as e:
                messagebox.showerror("Error", f"Error uploading file: {e}")

    def run_executable(self, exe_name):
        try:
            subprocess.Popen([exe_name], creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception as e:
            messagebox.showerror("Error", f"Error running {exe_name}: {e}")

    def run_encryptor_with_checks(self):
        vn_files = len(glob.glob(os.path.join("Randomness", "Von_Neumann_randomness_*.txt")))
        if vn_files <= 4:
            try:
                subprocess.Popen(["von-neumann-extractor.exe"], creationflags=subprocess.CREATE_NO_WINDOW)
            except Exception as e:
                messagebox.showerror("Error", f"Error running von-neumann-extractor.exe: {e}")
        aes_keys = len(glob.glob(os.path.join("AES Keys", "AES_key_*.txt")))
        if aes_keys == 0:
            try:
                subprocess.Popen(["AES-generator.exe"], creationflags=subprocess.CREATE_NO_WINDOW)
            except Exception as e:
                messagebox.showerror("Error", f"Error running AES-generator.exe: {e}")
        ecc_private = len(glob.glob(os.path.join("ECC Keys", "ECC_key_pair_*.txt")))
        if ecc_private == 0:
            try:
                subprocess.Popen(["ECC-generator.exe"], creationflags=subprocess.CREATE_NO_WINDOW)
            except Exception as e:
                messagebox.showerror("Error", f"Error running ECC-generator.exe: {e}")
        ecc_public = len(glob.glob(os.path.join("ECC Keys", "ECC_public_key_*.txt")))
        if ecc_public == 0:
            try:
                subprocess.Popen(["public.exe"], creationflags=subprocess.CREATE_NO_WINDOW)
            except Exception as e:
                messagebox.showerror("Error", f"Error running public.exe: {e}")
        self.run_encryptor()

    def run_encryptor(self):
        self.encrypt_status_text.config(state="normal")
        self.encrypt_status_text.delete("1.0", tk.END)
        self.encrypt_status_text.config(state="disabled")
        try:
            self.encrypt_process = subprocess.Popen(
                ["encryptor.exe"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            self.check_encrypt_output()
        except Exception as e:
            messagebox.showerror("Error", f"Error running encryptor.exe: {e}")

    def check_encrypt_output(self):
        if self.encrypt_process:
            line = self.encrypt_process.stdout.readline()
            if line:
                self.encrypt_status_text.config(state="normal")
                self.encrypt_status_text.insert(tk.END, line)
                self.encrypt_status_text.see(tk.END)
                self.encrypt_status_text.config(state="disabled")
            if self.encrypt_process.poll() is None:
                self.root.after(100, self.check_encrypt_output)
            else:
                remaining = self.encrypt_process.stdout.read()
                if remaining:
                    self.encrypt_status_text.config(state="normal")
                    self.encrypt_status_text.insert(tk.END, remaining)
                    self.encrypt_status_text.see(tk.END)
                    self.encrypt_status_text.config(state="disabled")

    # New methods to run decryptor.exe and capture its output
    def run_decryptor(self):
        self.decrypt_status_text.config(state="normal")
        self.decrypt_status_text.delete("1.0", tk.END)
        self.decrypt_status_text.config(state="disabled")
        try:
            self.decrypt_process = subprocess.Popen(
                ["decryptor.exe"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            self.check_decrypt_output()
        except Exception as e:
            messagebox.showerror("Error", f"Error running decryptor.exe: {e}")

    def check_decrypt_output(self):
        if self.decrypt_process:
            line = self.decrypt_process.stdout.readline()
            if line:
                self.decrypt_status_text.config(state="normal")
                self.decrypt_status_text.insert(tk.END, line)
                self.decrypt_status_text.see(tk.END)
                self.decrypt_status_text.config(state="disabled")
            if self.decrypt_process.poll() is None:
                self.root.after(100, self.check_decrypt_output)
            else:
                remaining = self.decrypt_process.stdout.read()
                if remaining:
                    self.decrypt_status_text.config(state="normal")
                    self.decrypt_status_text.insert(tk.END, remaining)
                    self.decrypt_status_text.see(tk.END)
                    self.decrypt_status_text.config(state="disabled")

    def on_file_size_selected(self, event):
        if self.max_file_size.get() == "Other":
            self.other_file_size_entry.config(state="normal")
        else:
            self.other_file_size_entry.delete(0, tk.END)
            self.other_file_size_entry.config(state="disabled")

    def save_settings(self):
        selected = self.max_file_size.get()
        if not selected:
            self.status_label.config(text="Error: Please select a max file size.", fg="red")
            return
        if selected == "Other":
            value = self.other_file_size_entry.get().strip()
            if not value:
                self.status_label.config(text="Error: Please enter a value for 'Other'.", fg="red")
                return
            if not value.isdigit():
                self.status_label.config(text="Error: Please enter a numeric value for 'Other'.", fg="red")
                return
            final_value = value + "GB"
        else:
            final_value = selected
        name_encrypt = "1" if self.encrypt_toggle.is_on else "0"
        deletion_temp = "1" if self.delete_temp_toggle.is_on else "0"
        deletion_rad = "1" if self.delete_radiation_toggle.is_on else "0"
        rustic_mode = "1" if self.toggle_switch.is_on else "0"
        if not os.path.exists("Settings"):
            os.makedirs("Settings")
        try:
            with open(os.path.join("Settings", "settings.txt"), "w") as f:
                f.write(f"Max_File_Size = {final_value}\n")
                f.write(f"Name_encryption = {name_encrypt}\n")
                f.write(f"Deletion_Setting = {deletion_temp}\n")
                f.write(f"Delete_Radiation_Files = {deletion_rad}\n")
                f.write(f"Rustic_Nuclear_Mode = {rustic_mode}")
            self.status_label.config(text=f"Settings saved:\nMax_File_Size = {final_value}\nName_encryption = {name_encrypt}\nDeletion_Setting = {deletion_temp}\nDelete_Radiation_Files = {deletion_rad}\nRustic_Nuclear_Mode = {rustic_mode}", fg="green")
        except Exception as e:
            self.status_label.config(text=f"Error: Failed to save settings: {e}", fg="red")

    def run_install_bat(self):
        try:
            subprocess.Popen("start cmd /k install.bat", shell=True)
            self.root.after(1000, lambda: self.status_label.config(text="Dependencies reinstalled successfully.", fg="green"))
        except Exception as e:
            messagebox.showerror("Error", f"Error running install.bat: {e}")

if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app = CryptoKeyGenUI(root)
    root.mainloop()
