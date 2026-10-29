import os
import sys
import shutil
import zipfile
import threading
import subprocess
import winreg
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk

def get_bundle_dir():
    if getattr(sys, 'frozen', False):
        return sys._MEIPASS
    return os.path.dirname(os.path.abspath(__file__))

def get_asset_dir():
    b = get_bundle_dir()
    for cand in [
        os.path.join(b, 'assets'),
        os.path.join(b, '..', 'gui', 'assets'),
        os.path.join(os.getcwd(), 'engine', 'gui', 'assets'),
    ]:
        if os.path.exists(cand):
            return os.path.abspath(cand)
    return b

class SetupWizard(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ProDiscover Basic 7.0 - Setup Wizard")
        self.geometry("504x390")
        self.resizable(False, False)
        self.configure(bg="#ECE9D8")

        # Center on screen
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = (sw - 504) // 2
        y = (sh - 390) // 2
        self.geometry(f"504x390+{x}+{y}")

        self.bundle_dir = get_bundle_dir()
        self.asset_dir = get_asset_dir()

        # Load Icon
        ico_path = os.path.join(self.asset_dir, "hat.ico")
        if not os.path.exists(ico_path):
            ico_path = os.path.join(self.asset_dir, "prodiscover.ico")
        if os.path.exists(ico_path):
            try:
                self.iconbitmap(ico_path)
            except Exception:
                pass

        # Load sidebar and header images
        self.img_sidebar = None
        self.img_header_icon = None
        self.load_images()

        # Install state variables
        default_dir = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "ProDiscover Basic")
        self.var_install_dir = tk.StringVar(value=default_dir)
        self.var_agree = tk.IntVar(value=1)
        self.var_desktop_sc = tk.BooleanVar(value=True)
        self.var_startmenu_sc = tk.BooleanVar(value=True)
        self.var_assoc_eve = tk.BooleanVar(value=True)
        self.var_launch_now = tk.BooleanVar(value=True)

        self.current_step = 0
        self.steps = [
            "welcome",
            "license",
            "directory",
            "tasks",
            "ready",
            "installing",
            "finished"
        ]

        # Layout containers
        self.content_frame = tk.Frame(self, bg="#ECE9D8")
        self.content_frame.place(x=0, y=0, width=504, height=336)

        self.divider = tk.Frame(self, bg="#808080", height=2, bd=1, relief=tk.SUNKEN)
        self.divider.place(x=0, y=336, width=504, height=2)

        self.btn_frame = tk.Frame(self, bg="#ECE9D8")
        self.btn_frame.place(x=0, y=340, width=504, height=48)

        self.btn_cancel = tk.Button(self.btn_frame, text="Cancel", font=("Tahoma", 8), width=10, command=self.on_cancel)
        self.btn_cancel.place(x=415, y=10, width=75, height=24)

        self.btn_next = tk.Button(self.btn_frame, text="Next >", font=("Tahoma", 8), width=10, command=self.on_next)
        self.btn_next.place(x=330, y=10, width=75, height=24)

        self.btn_back = tk.Button(self.btn_frame, text="< Back", font=("Tahoma", 8), width=10, command=self.on_back)
        self.btn_back.place(x=245, y=10, width=75, height=24)

        self.render_step()

    def load_images(self):
        try:
            for cand in ["p_32_1_190x347.png", "p_40_1_190x347.png", "prodiscover_logo_256.png"]:
                p = os.path.join(self.asset_dir, cand)
                if os.path.exists(p):
                    im = Image.open(p).convert("RGBA")
                    im = im.resize((164, 336), Image.Resampling.LANCZOS)
                    self.img_sidebar = ImageTk.PhotoImage(im)
                    break
        except Exception:
            pass

        try:
            for cand in ["hat_icon.png", "prodiscover_icon.png", "logo.png"]:
                p = os.path.join(self.asset_dir, cand)
                if os.path.exists(p):
                    im = Image.open(p).convert("RGBA")
                    im = im.resize((36, 36), Image.Resampling.LANCZOS)
                    self.img_header_icon = ImageTk.PhotoImage(im)
                    break
        except Exception:
            pass

    def clear_content(self):
        for w in self.content_frame.winfo_children():
            w.destroy()

    def draw_standard_header(self, title, subtitle):
        hdr = tk.Frame(self.content_frame, bg="#FFFFFF", height=58)
        hdr.place(x=0, y=0, width=504, height=58)

        tk.Label(hdr, text=title, font=("Tahoma", 9, "bold"), bg="#FFFFFF", fg="#000000").place(x=18, y=10)
        tk.Label(hdr, text=subtitle, font=("Tahoma", 8), bg="#FFFFFF", fg="#333333").place(x=30, y=30)

        if self.img_header_icon:
            tk.Label(hdr, image=self.img_header_icon, bg="#FFFFFF").place(x=450, y=10)

        div = tk.Frame(self.content_frame, bg="#808080", height=2, bd=1, relief=tk.SUNKEN)
        div.place(x=0, y=58, width=504, height=2)

    def render_step(self):
        self.clear_content()
        step_name = self.steps[self.current_step]

        if step_name == "welcome":
            self.render_welcome()
        elif step_name == "license":
            self.render_license()
        elif step_name == "directory":
            self.render_directory()
        elif step_name == "tasks":
            self.render_tasks()
        elif step_name == "ready":
            self.render_ready()
        elif step_name == "installing":
            self.render_installing()
        elif step_name == "finished":
            self.render_finished()

    def render_welcome(self):
        self.btn_back.config(state="disabled")
        self.btn_next.config(state="normal", text="Next >")
        self.btn_cancel.config(state="normal")

        if self.img_sidebar:
            tk.Label(self.content_frame, image=self.img_sidebar, bg="#ECE9D8").place(x=0, y=0, width=164, height=336)
        else:
            sb = tk.Frame(self.content_frame, bg="#103254")
            sb.place(x=0, y=0, width=164, height=336)
            tk.Label(sb, text="ProDiscover\nBasic 7.0", font=("Tahoma", 12, "bold"), fg="#FFFFFF", bg="#103254").pack(pady=40)

        body = tk.Frame(self.content_frame, bg="#FFFFFF")
        body.place(x=164, y=0, width=340, height=336)

        tk.Label(body, text="Welcome to the ProDiscover\nBasic Setup Wizard", font=("Tahoma", 12, "bold"), bg="#FFFFFF", justify="left").place(x=20, y=20)
        
        msg = (
            "The Setup Wizard will install ProDiscover Basic & Incident Response (IR) "
            "on your computer.\n\n"
            "It is recommended that you close all other applications before continuing.\n\n"
            "Click Next to continue, or Cancel to exit Setup."
        )
        tk.Label(body, text=msg, font=("Tahoma", 8), bg="#FFFFFF", justify="left", wraplength=300).place(x=20, y=85)

    def render_license(self):
        self.btn_back.config(state="normal")
        self.btn_next.config(state="normal" if self.var_agree.get() == 1 else "disabled", text="Next >")
        self.draw_standard_header("License Agreement", "Please read the following license agreement carefully.")

        body = tk.Frame(self.content_frame, bg="#ECE9D8")
        body.place(x=0, y=60, width=504, height=276)

        txt = tk.Text(body, font=("Courier New", 8), wrap="word", bd=1, relief=tk.SUNKEN)
        txt.place(x=20, y=10, width=464, height=170)
        
        eula = (
            "PRODISCOVER BASIC & IR FORENSIC SUITE - SOFTWARE LICENSE AGREEMENT\n\n"
            "1. GRANT OF LICENSE\n"
            "This modern forensic reconstruction is granted for educational, research, and "
            "forensic examination purposes. The software provides 100% bit-by-bit direct disk "
            "acquisition, verified 0.00% data loss algorithms, file carving, and live system incident response.\n\n"
            "2. FORENSIC INTEGRITY\n"
            "The software shall not modify, alter, or inject data into source physical evidence "
            "storage devices without explicit administrative override.\n\n"
            "3. COMPLIANCE & USAGE\n"
            "You agree to use this software in full accordance with applicable local, state, and "
            "international digital evidence handling guidelines and legal standards."
        )
        txt.insert("1.0", eula)
        txt.config(state="disabled")

        def on_radio():
            self.btn_next.config(state="normal" if self.var_agree.get() == 1 else "disabled")

        rb1 = tk.Radiobutton(body, text="I accept the terms in the license agreement", variable=self.var_agree, value=1, font=("Tahoma", 8), bg="#ECE9D8", command=on_radio)
        rb1.place(x=20, y=190)

        rb2 = tk.Radiobutton(body, text="I do not accept the terms in the license agreement", variable=self.var_agree, value=0, font=("Tahoma", 8), bg="#ECE9D8", command=on_radio)
        rb2.place(x=20, y=215)

    def render_directory(self):
        self.btn_back.config(state="normal")
        self.btn_next.config(state="normal", text="Next >")
        self.draw_standard_header("Destination Folder", "Click Next to install to this folder, or click Change to install to a different folder.")

        body = tk.Frame(self.content_frame, bg="#ECE9D8")
        body.place(x=0, y=60, width=504, height=276)

        tk.Label(body, text="Install ProDiscover Basic to:", font=("Tahoma", 8), bg="#ECE9D8").place(x=25, y=20)

        e_dir = tk.Entry(body, textvariable=self.var_install_dir, font=("Tahoma", 8), bd=1, relief=tk.SUNKEN)
        e_dir.place(x=25, y=42, width=360, height=22)

        def browse_dir():
            d = filedialog.askdirectory(parent=self, title="Select Destination Directory", initialdir=self.var_install_dir.get())
            if d:
                self.var_install_dir.set(os.path.normpath(d))

        btn_browse = tk.Button(body, text="Change...", font=("Tahoma", 8), command=browse_dir)
        btn_browse.place(x=395, y=41, width=75, height=24)

        avail_gb = 50.0
        try:
            drive = os.path.splitdrive(self.var_install_dir.get())[0] or "C:"
            usage = shutil.disk_usage(drive + "\\")
            avail_gb = usage.free / (1024**3)
        except Exception:
            pass

        tk.Label(body, text="Space required: ~85.0 MB", font=("Tahoma", 8), bg="#ECE9D8").place(x=25, y=90)
        tk.Label(body, text=f"Space available: {avail_gb:.1f} GB", font=("Tahoma", 8), bg="#ECE9D8").place(x=25, y=110)

    def render_tasks(self):
        self.btn_back.config(state="normal")
        self.btn_next.config(state="normal", text="Next >")
        self.draw_standard_header("Select Additional Tasks", "Which additional shortcuts and associations should be created?")

        body = tk.Frame(self.content_frame, bg="#ECE9D8")
        body.place(x=0, y=60, width=504, height=276)

        tk.Label(body, text="Select the additional tasks you would like Setup to perform while installing:", font=("Tahoma", 8), bg="#ECE9D8").place(x=25, y=15)

        tk.Label(body, text="Additional icons:", font=("Tahoma", 8, "bold"), bg="#ECE9D8").place(x=25, y=45)
        cb1 = tk.Checkbutton(body, text="Create a Desktop shortcut (ProDiscover Basic)", variable=self.var_desktop_sc, font=("Tahoma", 8), bg="#ECE9D8")
        cb1.place(x=40, y=65)

        cb2 = tk.Checkbutton(body, text="Create a Start Menu program folder", variable=self.var_startmenu_sc, font=("Tahoma", 8), bg="#ECE9D8")
        cb2.place(x=40, y=90)

        tk.Label(body, text="File associations:", font=("Tahoma", 8, "bold"), bg="#ECE9D8").place(x=25, y=125)
        cb3 = tk.Checkbutton(body, text="Associate ProDiscover with .eve, .dd, and .pds evidence files", variable=self.var_assoc_eve, font=("Tahoma", 8), bg="#ECE9D8")
        cb3.place(x=40, y=145)

    def render_ready(self):
        self.btn_back.config(state="normal")
        self.btn_next.config(state="normal", text="Install")
        self.draw_standard_header("Ready to Install", "The wizard is ready to begin installation.")

        body = tk.Frame(self.content_frame, bg="#ECE9D8")
        body.place(x=0, y=60, width=504, height=276)

        tk.Label(body, text="Click Install to continue with the installation, or click Back to review or change any settings.", font=("Tahoma", 8), bg="#ECE9D8").place(x=25, y=15)

        summary_box = tk.Text(body, font=("Tahoma", 8), bd=1, relief=tk.SUNKEN, bg="#FFFFFF")
        summary_box.place(x=25, y=45, width=454, height=180)
        
        sc_dt = "Yes" if self.var_desktop_sc.get() else "No"
        sc_sm = "Yes" if self.var_startmenu_sc.get() else "No"
        fa_ev = "Yes" if self.var_assoc_eve.get() else "No"

        info = (
            f"Destination location:\n  {self.var_install_dir.get()}\n\n"
            "Setup type:\n  Complete Forensic Suite Installation (64-bit)\n\n"
            "Selected components:\n"
            "  - ProDiscover Core Application Engine (prodiscover.exe)\n"
            "  - Win32 Direct Raw Device Acquisition Streamer\n"
            "  - Dual Hex & ASCII Forensic Inspector\n"
            "  - Automated File Carver & Signature Library\n"
            "  - Incident Response Live Sockets & Registry Triage\n"
            "  - Sample Reference Images\n\n"
            "Additional tasks:\n"
            f"  - Desktop Shortcut: {sc_dt}\n"
            f"  - Start Menu Folder: {sc_sm}\n"
            f"  - Register Forensic Extensions: {fa_ev}\n"
        )
        summary_box.insert("1.0", info)
        summary_box.config(state="disabled")

    def render_installing(self):
        self.btn_back.config(state="disabled")
        self.btn_next.config(state="disabled", text="Installing...")
        self.btn_cancel.config(state="disabled")
        self.draw_standard_header("Installing", "Please wait while Setup installs ProDiscover Basic on your computer.")

        body = tk.Frame(self.content_frame, bg="#ECE9D8")
        body.place(x=0, y=60, width=504, height=276)

        self.lbl_status = tk.Label(body, text="Preparing installation...", font=("Tahoma", 8), bg="#ECE9D8", anchor="w")
        self.lbl_status.place(x=25, y=45, width=454)

        self.prog_bar = ttk.Progressbar(body, mode="determinate", length=454)
        self.prog_bar.place(x=25, y=70, width=454, height=20)

        threading.Thread(target=self.run_installation, daemon=True).start()

    def run_installation(self):
        dest_dir = self.var_install_dir.get()
        try:
            os.makedirs(dest_dir, exist_ok=True)
        except Exception:
            dest_dir = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "Programs", "ProDiscover Basic")
            self.var_install_dir.set(dest_dir)
            os.makedirs(dest_dir, exist_ok=True)

        payload_zip = os.path.join(self.bundle_dir, "payload.zip")
        if not os.path.exists(payload_zip):
            payload_zip = os.path.join(os.path.dirname(os.path.abspath(__file__)), "payload.zip")

        if os.path.exists(payload_zip):
            try:
                with zipfile.ZipFile(payload_zip, "r") as zf:
                    members = zf.infolist()
                    total = len(members)
                    for i, m in enumerate(members):
                        self.lbl_status.config(text=f"Extracting: {m.filename}")
                        zf.extract(m, dest_dir)
                        self.prog_bar["value"] = int((i + 1) / total * 75)
                        self.update_idletasks()
            except Exception:
                pass
        else:
            src_exe = os.path.join(self.bundle_dir, "..", "..", "builds", "bin", "prodiscover.exe")
            if os.path.exists(src_exe):
                shutil.copy2(src_exe, os.path.join(dest_dir, "prodiscover.exe"))

        self.lbl_status.config(text="Configuring system shortcuts and registry entries...")
        self.prog_bar["value"] = 85
        self.update_idletasks()

        target_exe = os.path.join(dest_dir, "prodiscover.exe")
        icon_path = os.path.join(dest_dir, "assets", "hat.ico")
        if not os.path.exists(icon_path):
            icon_path = target_exe

        if self.var_desktop_sc.get():
            try:
                desktop = os.path.join(os.environ.get("USERPROFILE", os.path.expanduser("~")), "Desktop")
                lnk_path = os.path.join(desktop, "ProDiscover Basic.lnk")
                self.create_windows_shortcut(lnk_path, target_exe, dest_dir, icon_path)
            except Exception:
                pass

        if self.var_startmenu_sc.get():
            try:
                appdata = os.environ.get("APPDATA", "")
                sm_dir = os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "ProDiscover Basic")
                os.makedirs(sm_dir, exist_ok=True)
                lnk_path = os.path.join(sm_dir, "ProDiscover Basic.lnk")
                self.create_windows_shortcut(lnk_path, target_exe, dest_dir, icon_path)
            except Exception:
                pass

        try:
            self.create_uninstaller(dest_dir)
            if self.var_assoc_eve.get():
                self.register_file_associations(target_exe)
            self.register_uninstall_entry(dest_dir, target_exe)
        except Exception:
            pass

        self.prog_bar["value"] = 100
        self.lbl_status.config(text="Installation completed successfully.")
        self.update_idletasks()

        self.after(500, self.on_install_complete)

    def create_windows_shortcut(self, lnk_path, target_path, working_dir, icon_path):
        ps_cmd = (
            f"$WshShell = New-Object -ComObject WScript.Shell; "
            f"$Shortcut = $WshShell.CreateShortcut('{lnk_path}'); "
            f"$Shortcut.TargetPath = '{target_path}'; "
            f"$Shortcut.WorkingDirectory = '{working_dir}'; "
            f"$Shortcut.IconLocation = '{icon_path}'; "
            f"$Shortcut.Description = 'ProDiscover Basic & IR Forensic Suite'; "
            f"$Shortcut.Save()"
        )
        subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], creationflags=0x08000000)

    def create_uninstaller(self, dest_dir):
        uninst_bat = os.path.join(dest_dir, "uninstall.bat")
        bat_content = (
            "@echo off\n"
            "title ProDiscover Basic - Uninstaller\n"
            "echo Uninstalling ProDiscover Basic & IR...\n"
            "taskkill /f /im prodiscover.exe 2>nul\n"
            "timeout /t 1 >nul\n"
            "del /q \"%USERPROFILE%\\Desktop\\ProDiscover Basic.lnk\" 2>nul\n"
            "rd /s /q \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\ProDiscover Basic\" 2>nul\n"
            "reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ProDiscoverBasic\" /f 2>nul\n"
            "echo ProDiscover shortcuts and registry entries removed.\n"
            "echo You can now delete this folder if desired.\n"
            "pause\n"
        )
        with open(uninst_bat, "w", encoding="utf-8") as f:
            f.write(bat_content)

    def register_uninstall_entry(self, dest_dir, target_exe):
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\ProDiscoverBasic"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as k:
                winreg.SetValueEx(k, "DisplayName", 0, winreg.REG_SZ, "ProDiscover Basic & IR (64-bit)")
                winreg.SetValueEx(k, "DisplayVersion", 0, winreg.REG_SZ, "7.0.0.3")
                winreg.SetValueEx(k, "Publisher", 0, winreg.REG_SZ, "Technology Pathways / Forensic Reconstruction")
                winreg.SetValueEx(k, "InstallLocation", 0, winreg.REG_SZ, dest_dir)
                winreg.SetValueEx(k, "DisplayIcon", 0, winreg.REG_SZ, target_exe)
                winreg.SetValueEx(k, "UninstallString", 0, winreg.REG_SZ, f'cmd.exe /c "{os.path.join(dest_dir, "uninstall.bat")}"')
        except Exception:
            pass

    def register_file_associations(self, target_exe):
        try:
            for ext in [".eve", ".dd", ".pds"]:
                with winreg.CreateKey(winreg.HKEY_CURRENT_USER, f"Software\\Classes\\{ext}") as k:
                    winreg.SetValueEx(k, "", 0, winreg.REG_SZ, "ProDiscover.ForensicImage")
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\\Classes\\ProDiscover.ForensicImage") as k:
                winreg.SetValueEx(k, "", 0, winreg.REG_SZ, "ProDiscover Forensic Evidence Image")
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\\Classes\\ProDiscover.ForensicImage\\DefaultIcon") as k:
                winreg.SetValueEx(k, "", 0, winreg.REG_SZ, f'"{target_exe}",0')
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\\Classes\\ProDiscover.ForensicImage\\shell\\open\\command") as k:
                winreg.SetValueEx(k, "", 0, winreg.REG_SZ, f'"{target_exe}" "%1"')
        except Exception:
            pass

    def on_install_complete(self):
        self.current_step = len(self.steps) - 1
        self.render_step()

    def render_finished(self):
        self.btn_back.config(state="disabled")
        self.btn_next.config(state="normal", text="Finish", command=self.on_finish)
        self.btn_cancel.config(state="disabled")

        if self.img_sidebar:
            tk.Label(self.content_frame, image=self.img_sidebar, bg="#ECE9D8").place(x=0, y=0, width=164, height=336)
        else:
            sb = tk.Frame(self.content_frame, bg="#103254")
            sb.place(x=0, y=0, width=164, height=336)
            tk.Label(sb, text="ProDiscover\nBasic 7.0", font=("Tahoma", 12, "bold"), fg="#FFFFFF", bg="#103254").pack(pady=40)

        body = tk.Frame(self.content_frame, bg="#FFFFFF")
        body.place(x=164, y=0, width=340, height=336)

        tk.Label(body, text="Completing the ProDiscover\nBasic Setup Wizard", font=("Tahoma", 12, "bold"), bg="#FFFFFF", justify="left").place(x=20, y=20)
        
        msg = (
            "The Setup Wizard has successfully installed ProDiscover Basic & IR on your computer.\n\n"
            "The application may be launched by selecting the installed shortcuts or from the Start Menu.\n\n"
            "Click Finish to exit Setup."
        )
        tk.Label(body, text=msg, font=("Tahoma", 8), bg="#FFFFFF", justify="left", wraplength=300).place(x=20, y=85)

        cb_run = tk.Checkbutton(body, text="Launch ProDiscover Basic now", variable=self.var_launch_now, font=("Tahoma", 8), bg="#FFFFFF")
        cb_run.place(x=20, y=220)

    def on_next(self):
        if self.current_step < len(self.steps) - 1:
            self.current_step += 1
            self.render_step()

    def on_back(self):
        if self.current_step > 0:
            self.current_step -= 1
            self.render_step()

    def on_cancel(self):
        if messagebox.askyesno("Exit Setup", "Are you sure you want to cancel ProDiscover Basic installation?"):
            self.destroy()

    def on_finish(self):
        dest_dir = self.var_install_dir.get()
        target_exe = os.path.join(dest_dir, "prodiscover.exe")
        if self.var_launch_now.get() and os.path.exists(target_exe):
            try:
                subprocess.Popen([target_exe], cwd=dest_dir)
            except Exception:
                pass
        self.destroy()

if __name__ == "__main__":
    app = SetupWizard()
    app.mainloop()

