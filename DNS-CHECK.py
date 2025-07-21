import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import platform
import re
import threading
import queue
import csv
import concurrent.futures
import sys
import os

try:
    import geoip2.database
    GEOIP_ENABLED = True
except ImportError:
    GEOIP_ENABLED = False

# ==============================================================================
#  Translation Dictionary
# ==============================================================================
I18N = {
    'fa': {
        "window_title": "IRNET DNS CHECKER PRO",
        "input_frame": "دی ان اس ورودی",
        "single_dns_label": "چک کردن تکی DNS:",
        "single_test_button": "تست تکی",
        "import_button": "وارد کردن لیست",
        "start_button": "شروع تست",
        "pause_button": "توقف",
        "resume_button": "ادامه",
        "export_csv_button": "خروجی (CSV)",
        "export_txt_button": "خروجی (TXT)",
        "results_frame": "نتایج",
        "status_ready": "آماده",
        "status_loaded": "{count} آدرس DNS بارگذاری شد. برای شروع کلیک کنید.",
        "status_testing": "تست {current} از {total} انجام شد...",
        "status_paused": "متوقف شد.",
        "status_done": "تمام عملیات با موفقیت کامل شد!",
        "status_copied": '"{text}" در کلیپ‌بورد کپی شد.',
        "col_dns": "آدرس DNS", "col_ping": "پینگ (ms)", "col_loss": "پکت لاست (%)", "col_loc": "موقعیت", "col_isp": "سرویس‌دهنده",
        "ping_fail": "ناموفق",
        "ctx_copy_dns": "کپی آدرس DNS", "ctx_copy_ping": "کپی پینگ", "ctx_copy_row": "کپی کل ردیف",
        "err_title": "خطا", "info_title": "موفق", "warn_title": "خالی",
        "err_read_file": "مشکلی در خواندن فایل پیش آمد: {e}",
        "warn_no_results": "هیچ نتیجه‌ای برای خروجی گرفتن وجود ندارد.",
        "info_export_success": "نتایج با موفقیت ذخیره شد.",
        "err_export_fail": "مشکلی در ذخیره فایل پیش آمد: {e}",
        "select_lang_title": "انتخاب زبان / SELECT LANGUAGE",
        "lang_button_fa": "فارسی", "lang_button_en": "ENGLISH",
        "file_dialog_txt": "فایل متنی", "file_dialog_csv": "فایل CSV",
        "save_csv_title": "ذخیره نتایج به عنوان CSV", "save_txt_title": "ذخیره نتایج به عنوان TXT",
        "geoip_lib_error": "کتابخانه 'geoip2' نصب نیست. لطفاً با دستور 'pip install geoip2' آن را نصب کنید.",
        "geoip_db_error": "فایل دیتابیس '{db_name}' در کنار برنامه یافت نشد. لطفاً آن را دانلود و در پوشه برنامه قرار دهید.",
    },
    'en': {
        "window_title": "IRNET DNS CHECKER PRO",
        "input_frame": "DNS INPUT",
        "single_dns_label": "SINGLE DNS CHECK:",
        "single_test_button": "TEST SINGLE",
        "import_button": "IMPORT LIST",
        "start_button": "START TEST",
        "pause_button": "PAUSE",
        "resume_button": "RESUME",
        "export_csv_button": "EXPORT (CSV)",
        "export_txt_button": "EXPORT (TXT)",
        "results_frame": "RESULTS",
        "status_ready": "READY",
        "status_loaded": "{count} DNS ADDRESSES LOADED. CLICK START TO TEST.",
        "status_testing": "TESTING {current} OF {total}...",
        "status_paused": "PAUSED.",
        "status_done": "ALL OPERATIONS COMPLETED SUCCESSFULLY!",
        "status_copied": 'COPIED "{text}" TO CLIPBOARD.',
        "col_dns": "DNS ADDRESS", "col_ping": "PING (MS)", "col_loss": "PACKET LOSS (%)", "col_loc": "LOCATION", "col_isp": "SERVICE PROVIDER",
        "ping_fail": "FAILED",
        "ctx_copy_dns": "COPY DNS ADDRESS", "ctx_copy_ping": "COPY PING", "ctx_copy_row": "COPY ENTIRE ROW",
        "err_title": "ERROR", "info_title": "SUCCESS", "warn_title": "EMPTY",
        "err_read_file": "ERROR READING FILE: {e}",
        "warn_no_results": "THERE ARE NO RESULTS TO EXPORT.",
        "info_export_success": "RESULTS EXPORTED SUCCESSFULLY.",
        "err_export_fail": "AN ERROR OCCURRED WHILE SAVING THE FILE: {e}",
        "select_lang_title": "SELECT LANGUAGE / انتخاب زبان",
        "lang_button_fa": "فارسی", "lang_button_en": "ENGLISH",
        "file_dialog_txt": "TEXT FILE", "file_dialog_csv": "CSV FILE",
        "save_csv_title": "SAVE RESULTS AS CSV", "save_txt_title": "SAVE RESULTS AS TXT",
        "geoip_lib_error": "The 'geoip2' library is not installed. Please install it using 'pip install geoip2'.",
        "geoip_db_error": "The database file '{db_name}' was not found. Please download it and place it in the application's folder.",
    }
}

class DNSCheckerApp:
    def __init__(self, root, lang_code):
        self.root = root
        self.lang = I18N[lang_code]
        self.root.title(self.lang["window_title"])
        self.root.geometry("900x650")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.city_reader = None
        self.asn_reader = None
        self.setup_geoip()

        self.pause_event = threading.Event(); self.pause_event.set()
        self.dns_to_test = []; self.test_running = False
        self.os_type = platform.system().lower()
        self.gui_queue = queue.Queue()
        self.sort_column = None; self.sort_reverse = False
        self.setup_widgets()
    
    def setup_geoip(self):
        if not GEOIP_ENABLED:
            messagebox.showerror(self.lang["err_title"], self.lang["geoip_lib_error"])
            return
        db_path = os.path.dirname(os.path.abspath(__file__))
        city_db_file = os.path.join(db_path, 'GeoLite2-City.mmdb')
        asn_db_file = os.path.join(db_path, 'GeoLite2-ASN.mmdb')
        try:
            self.city_reader = geoip2.database.Reader(city_db_file)
        except FileNotFoundError: messagebox.showerror(self.lang["err_title"], self.lang["geoip_db_error"].format(db_name='GeoLite2-City.mmdb'))
        try:
            self.asn_reader = geoip2.database.Reader(asn_db_file)
        except FileNotFoundError: messagebox.showerror(self.lang["err_title"], self.lang["geoip_db_error"].format(db_name='GeoLite2-ASN.mmdb'))

    def on_closing(self):
        self.test_running = False
        if self.city_reader: self.city_reader.close()
        if self.asn_reader: self.asn_reader.close()
        self.root.destroy()

    def setup_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10"); main_frame.pack(fill=tk.BOTH, expand=True)
        input_frame = ttk.LabelFrame(main_frame, text=self.lang["input_frame"], padding="10"); input_frame.pack(fill=tk.X)
        ttk.Label(input_frame, text=self.lang["single_dns_label"]).pack(side=tk.RIGHT, padx=(0, 5))
        self.single_dns_entry = ttk.Entry(input_frame); self.single_dns_entry.pack(side=tk.RIGHT, fill=tk.X, expand=True)
        button_frame = ttk.Frame(main_frame, padding=(0, 10)); button_frame.pack(fill=tk.X)
        self.single_test_button = ttk.Button(button_frame, text=self.lang["single_test_button"], command=self.start_single_test); self.single_test_button.pack(side=tk.RIGHT, padx=(0, 5))
        self.file_test_button = ttk.Button(button_frame, text=self.lang["import_button"], command=self.load_file); self.file_test_button.pack(side=tk.RIGHT, padx=(0, 5))
        self.start_button = ttk.Button(button_frame, text=self.lang["start_button"], command=self.start_scan, state=tk.DISABLED); self.start_button.pack(side=tk.RIGHT, padx=(0, 5))
        self.pause_resume_button = ttk.Button(button_frame, text=self.lang["pause_button"], command=self.toggle_pause, state=tk.DISABLED); self.pause_resume_button.pack(side=tk.LEFT, padx=5)
        self.export_csv_button = ttk.Button(button_frame, text=self.lang["export_csv_button"], command=lambda: self.export_results('csv'), state=tk.DISABLED); self.export_csv_button.pack(side=tk.LEFT, padx=5)
        self.export_txt_button = ttk.Button(button_frame, text=self.lang["export_txt_button"], command=lambda: self.export_results('txt'), state=tk.DISABLED); self.export_txt_button.pack(side=tk.LEFT, padx=5)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100); self.progress_bar.pack(fill=tk.X, pady=5)
        result_frame = ttk.LabelFrame(main_frame, text=self.lang["results_frame"], padding="10"); result_frame.pack(fill=tk.BOTH, expand=True, pady=(5,0))
        columns = ('dns_server', 'avg_ping', 'packet_loss', 'location', 'isp')
        self.tree = ttk.Treeview(result_frame, columns=columns, show='headings')
        column_to_lang_key = { 'dns_server': 'col_dns', 'avg_ping': 'col_ping', 'packet_loss': 'col_loss', 'location': 'col_loc', 'isp': 'col_isp' }
        for col in columns: self.tree.heading(col, text=self.lang[column_to_lang_key[col]], command=lambda c=col: self.sort_by_column(c))
        self.tree.column('dns_server', width=150, anchor=tk.W); self.tree.column('avg_ping', width=100, anchor=tk.CENTER)
        self.tree.column('packet_loss', width=120, anchor=tk.CENTER); self.tree.column('location', width=120, anchor=tk.CENTER)
        self.tree.column('isp', width=250, anchor=tk.W)
        scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set); scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label=self.lang["ctx_copy_dns"], command=self.copy_dns)
        self.context_menu.add_command(label=self.lang["ctx_copy_ping"], command=self.copy_ping)
        self.context_menu.add_separator(); self.context_menu.add_command(label=self.lang["ctx_copy_row"], command=self.copy_row)
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.status_var = tk.StringVar(); self.status_var.set(self.lang["status_ready"])
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=5)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def load_file(self):
        if self.test_running: return
        filepath = filedialog.askopenfilename(title=self.lang["import_button"], filetypes=[(self.lang["file_dialog_txt"], "*.txt")])
        if not filepath: return
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                self.dns_to_test = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            if self.dns_to_test:
                self.status_var.set(self.lang["status_loaded"].format(count=len(self.dns_to_test)))
                self.start_button.config(state=tk.NORMAL)
                for i in self.tree.get_children(): self.tree.delete(i)
                self.toggle_ui_state(True) # Ensure buttons are in a clean state
        except Exception as e: messagebox.showerror(self.lang["err_title"], self.lang["err_read_file"].format(e=e))

    def start_scan(self):
        if self.dns_to_test: self.start_testing_thread(self.dns_to_test)

    def start_single_test(self):
        if self.test_running: return
        dns_ip = self.single_dns_entry.get().strip()
        if dns_ip: self.start_testing_thread([dns_ip])

    def start_testing_thread(self, dns_list):
        if self.test_running: return
        if GEOIP_ENABLED and not (self.city_reader and self.asn_reader):
            messagebox.showerror(self.lang["err_title"], self.lang["geoip_db_error"].format(db_name="City/ASN"))
            return
        self.test_running = True; self.dns_to_test = dns_list; self.progress_var.set(0)
        for i in self.tree.get_children(): self.tree.delete(i)
        self.toggle_ui_state(False); self.pause_event.set()
        threading.Thread(target=self.worker_function, daemon=True).start()
        self.process_gui_queue()

    def worker_function(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(self.check_single_dns, dns) for dns in self.dns_to_test]
            for future in concurrent.futures.as_completed(futures):
                if not self.test_running: break
                self.gui_queue.put(future.result())
        self.gui_queue.put("DONE")

    def check_single_dns(self, dns_ip):
        self.pause_event.wait()
        if not self.test_running: return None
        ping, loss = self._check_dns_quality(dns_ip)
        country, isp = self._get_ip_info_local(dns_ip)
        return dns_ip, ping, loss, country, isp

    def process_gui_queue(self):
        try:
            while not self.gui_queue.empty():
                result = self.gui_queue.get_nowait()
                if result is None: continue
                if result == "DONE":
                    self.test_running = False; self.toggle_ui_state(True)
                    self.status_var.set(self.lang["status_done"]); self.progress_var.set(100)
                    messagebox.showinfo(self.lang["info_title"], self.lang["status_done"])
                    return
                dns_ip, avg_ping, packet_loss, country, isp = result
                ping_val = f"{avg_ping:.2f}" if avg_ping is not None else self.lang["ping_fail"]
                self.tree.insert('', tk.END, values=(dns_ip, ping_val, f"{packet_loss}%", country, isp))
                current_count = len(self.tree.get_children())
                self.progress_var.set((current_count / len(self.dns_to_test)) * 100)
                self.status_var.set(self.lang["status_testing"].format(current=current_count, total=len(self.dns_to_test)))
        except queue.Empty: pass
        if self.test_running: self.root.after(200, self.process_gui_queue)

    def _get_ip_info_local(self, ip):
        country, isp = "N/A", "N/A"
        try:
            if self.city_reader:
                try: country = self.city_reader.city(ip).country.name or "N/A"
                except geoip2.errors.AddressNotFoundError: pass
            if self.asn_reader:
                try: isp = self.asn_reader.asn(ip).autonomous_system_organization or "N/A"
                except geoip2.errors.AddressNotFoundError: pass
            return country, isp
        except Exception as e:
            print(f"GeoIP Error for {ip}: {e}", file=sys.stderr)
            return "Error", "Error"

    def _check_dns_quality(self, dns_ip):
        cmd = ["ping", "-n", "4", "-w", "2000", dns_ip] if self.os_type == "windows" else ["ping", "-c", "4", "-W", "2", dns_ip]
        try:
            output = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore').stdout
            loss_match = re.search(r"\((\d+)% loss\)", output) or re.search(r"(\d+)%\s+packet loss", output)
            ping_match = re.search(r"Average = (\d+)ms", output) or re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", output)
            loss = int(loss_match.group(1)) if loss_match else 100
            ping = float(ping_match.group(1)) if ping_match else None
            return ping, loss
        except Exception: return None, 100

    def toggle_pause(self):
        if self.pause_event.is_set():
            self.pause_event.clear(); self.pause_resume_button.config(text=self.lang["resume_button"]); self.status_var.set(self.lang["status_paused"])
        else:
            self.pause_event.set(); self.pause_resume_button.config(text=self.lang["pause_button"]); self.status_var.set(self.lang["status_testing"].format(current=len(self.tree.get_children()), total=len(self.dns_to_test)))

    # --- FIX ---
    # Corrected logic for enabling/disabling UI elements
    def toggle_ui_state(self, is_enabled):
        state = tk.NORMAL if is_enabled else tk.DISABLED
        
        # These buttons are always enabled when not testing
        self.single_test_button.config(state=state)
        self.file_test_button.config(state=state)

        # The Start button is managed by load_file and should be disabled after a test starts
        if not is_enabled:
            self.start_button.config(state=tk.DISABLED)

        # Pause button is only active during a test
        self.pause_resume_button.config(state=tk.DISABLED if is_enabled else tk.NORMAL)
        
        # Export buttons are only active when a test is NOT running AND there are results
        if self.tree.get_children() and is_enabled:
            self.export_csv_button.config(state=tk.NORMAL)
            self.export_txt_button.config(state=tk.NORMAL)
        else:
            self.export_csv_button.config(state=tk.DISABLED)
            self.export_txt_button.config(state=tk.DISABLED)
    # --- END FIX ---

    def export_results(self, file_format):
        if not self.tree.get_children():
            messagebox.showwarning(self.lang["warn_title"], self.lang["warn_no_results"]); return
        filetypes_map = {'csv': [(self.lang["file_dialog_csv"], "*.csv")], 'txt': [(self.lang["file_dialog_txt"], "*.txt")]}
        titles_map = {'csv': self.lang["save_csv_title"], 'txt': self.lang["save_txt_title"]}
        filepath = filedialog.asksaveasfilename(defaultextension=f".{file_format}", filetypes=filetypes_map[file_format], title=titles_map[file_format])
        if not filepath: return
        try:
            column_to_lang_key = {'dns_server': 'col_dns', 'avg_ping': 'col_ping', 'packet_loss': 'col_loss', 'location': 'col_loc', 'isp': 'col_isp'}
            headers = [self.lang[column_to_lang_key[c]].replace(' ▼', '').replace(' ▲', '') for c in self.tree['columns']]
            data = [self.tree.item(item_id)['values'] for item_id in self.tree.get_children()]
            if file_format == 'csv':
                with open(filepath, 'w', newline='', encoding='utf-8-sig') as f:
                    writer = csv.writer(f); writer.writerow(headers); writer.writerows(data)
            elif file_format == 'txt':
                col_widths = [max(len(str(h)), *[len(str(row[i])) for row in data]) for i, h in enumerate(headers)]
                with open(filepath, 'w', encoding='utf-8') as f:
                    header_line = " | ".join([h.ljust(w) for h, w in zip(headers, col_widths)])
                    f.write(header_line + "\n" + "-" * len(header_line) + "\n")
                    for row in data: f.write(" | ".join([str(cell).ljust(w) for cell, w in zip(row, col_widths)]) + "\n")
            messagebox.showinfo(self.lang["info_title"], self.lang["info_export_success"])
        except Exception as e:
            print(f"Export Error: {e}", file=sys.stderr)
            messagebox.showerror(self.lang["err_title"], self.lang["err_export_fail"].format(e=e))

    def sort_by_column(self, col):
        items = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        def sort_key(item):
            value = item[0]
            if value == self.lang["ping_fail"]: return float('inf')
            try: return float(re.sub(r'[^\d.]', '', value))
            except (ValueError, TypeError): return value
        items.sort(key=sort_key, reverse=self.sort_reverse)
        for index, (val, k) in enumerate(items): self.tree.move(k, '', index)
        self.sort_reverse = not self.sort_reverse
        column_to_lang_key = {'dns_server': 'col_dns', 'avg_ping': 'col_ping', 'packet_loss': 'col_loss', 'location': 'col_loc', 'isp': 'col_isp'}
        for c in self.tree['columns']: self.tree.heading(c, text=self.lang[column_to_lang_key[c]])
        arrow = ' ▼' if self.sort_reverse else ' ▲'
        self.tree.heading(col, text=self.lang[column_to_lang_key[c]] + arrow)

    def show_context_menu(self, event):
        if self.tree.identify_row(event.y):
            self.tree.selection_set(self.tree.identify_row(event.y)); self.context_menu.post(event.x_root, event.y_root)

    def copy_to_clipboard(self, text):
        self.root.clipboard_clear(); self.root.clipboard_append(text); self.status_var.set(self.lang["status_copied"].format(text=text))

    def copy_dns(self): self.copy_to_clipboard(self.tree.item(self.tree.selection()[0])['values'][0])
    def copy_ping(self): self.copy_to_clipboard(str(self.tree.item(self.tree.selection()[0])['values'][1]))
    def copy_row(self): self.copy_to_clipboard(", ".join(map(str, self.tree.item(self.tree.selection()[0])['values'])))


def main():
    root = tk.Tk()
    root.withdraw()
    lang_selector = tk.Toplevel(root)
    lang_selector.title(I18N['en']["select_lang_title"])
    lang_selector.geometry("300x120")
    lang_selector.resizable(False, False)
    lang_selector.update_idletasks()
    width = lang_selector.winfo_width(); height = lang_selector.winfo_height()
    x = (lang_selector.winfo_screenwidth() // 2) - (width // 2); y = (lang_selector.winfo_screenheight() // 2) - (height // 2)
    lang_selector.geometry(f'{width}x{height}+{x}+{y}')
    def start_main_app(lang_code):
        lang_selector.destroy(); root.deiconify(); DNSCheckerApp(root, lang_code)
    ttk.Label(lang_selector, text=I18N['en']["select_lang_title"], font=('Arial', 12)).pack(pady=10)
    ttk.Button(lang_selector, text=I18N['en']["lang_button_en"], command=lambda: start_main_app('en')).pack(pady=5, padx=20, fill='x')
    ttk.Button(lang_selector, text=I18N['fa']["lang_button_fa"], command=lambda: start_main_app('fa')).pack(pady=5, padx=20, fill='x')
    def on_lang_selector_close(): root.destroy()
    lang_selector.protocol("WM_DELETE_WINDOW", on_lang_selector_close)
    root.mainloop()

if __name__ == "__main__":
    main()