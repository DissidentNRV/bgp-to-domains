# asn_scanner_ctk.py
# Responsive CustomTkinter UI (EN) + cooperative threading over a shared task queue.
# Adds global prefix counter (processed / total) in the summary.

import requests
from bs4 import BeautifulSoup
import re
import threading
import random
import time
import queue
import os
from datetime import datetime

import customtkinter as ctk
from tkinter import filedialog, messagebox

BREAKPOINT_WIDTH = 1200   # 2 columns >= this width; stacked below otherwise
MAX_THREADS = 2048        # slider upper bound

class ASNScannerApp:
    def __init__(self, root: ctk.CTk):
        self.root = root
        self.root.title("ASN/IP → Domain Scanner")
        self.root.geometry("1120x760")
        self.root.minsize(860, 640)

        # Theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # State
        self.proxy_list = []
        self.stop_flag = threading.Event()
        self.pause_flag = threading.Event()
        self.q = queue.Queue()           # GUI message queue (logs/progress)
        self.task_q = queue.Queue()      # Work queue (ASN_INIT / PREFIX_SCAN)
        self.lock = threading.Lock()     # Protect shared counters

        self.completed_asns = 0          # how many targets (ASN/IP) fully done
        self.total_asns = 0
        self.filename_domains = ""
        self.filename_ips = ""
        self.start_time = time.time()

        # Global prefix counters
        self.total_prefixes = 0
        self.processed_prefixes = 0

        # Per-target pending prefix counter {target_key -> remaining_prefixes}
        self.asn_pending = {}

        # UI vars
        self.save_single_file_var = ctk.BooleanVar(value=True)
        self.thread_var = ctk.IntVar(value=50)
        self.autoscroll_var = ctk.BooleanVar(value=True)
        self.wrap_var = ctk.BooleanVar(value=False)

        # Build UI
        self._build_ui()

        # Shortcuts
        self.root.bind("<F5>",     lambda e: self.start_scanning())
        self.root.bind("<space>",  lambda e: self.toggle_pause())
        self.root.bind("<Escape>", lambda e: self.stop_scanning())
        self.root.bind("<Configure>", self._on_resize)

        # Loops
        self.root.after(200, self.update_gui_loop)
        self.root.after(600, self._update_target_count_periodic)

    # ============================= UI =================================
    def _build_ui(self):
        self.root.grid_rowconfigure(0, weight=0)  # header
        self.root.grid_rowconfigure(1, weight=1)  # scrollable content
        self.root.grid_rowconfigure(2, weight=0)  # logs toolbar
        self.root.grid_rowconfigure(3, weight=1)  # logs
        self.root.grid_columnconfigure(0, weight=1)

        # Header
        header = ctk.CTkFrame(self.root, corner_radius=0)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(0, weight=1)

        title_box = ctk.CTkFrame(header, fg_color="transparent")
        title_box.grid(row=0, column=0, sticky="w", padx=14, pady=10)
        ctk.CTkLabel(title_box, text="ASN/IP → Domain Scanner",
                     font=ctk.CTkFont(size=18, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(title_box, text="Steps on the left • Summary on the right • Logs at the bottom",
                     font=ctk.CTkFont(size=12)).pack(anchor="w")

        theme_box = ctk.CTkFrame(header, fg_color="transparent")
        theme_box.grid(row=0, column=1, sticky="e", padx=14, pady=10)
        self.theme_seg = ctk.CTkSegmentedButton(theme_box, values=["Dark", "Light", "System"], command=self._toggle_theme)
        self.theme_seg.set("Dark")
        self.theme_seg.pack()

        # Scrollable content for small screens
        self.content = ctk.CTkScrollableFrame(self.root, label_text="")
        self.content.grid(row=1, column=0, sticky="nsew", padx=10, pady=(4, 6))
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_columnconfigure(1, weight=1)

        # Columns
        self.left_col  = ctk.CTkFrame(self.content)
        self.right_col = ctk.CTkFrame(self.content)
        self.left_col.grid_rowconfigure(2, weight=1)

        # ---- Left: Steps
        self.step1 = self._make_step(self.left_col, "Step 1 — Targets (ASNs / IPv4, one per line)")
        self.step1.grid(row=0, column=0, sticky="nsew", padx=8, pady=(8, 6))

        actions_row = ctk.CTkFrame(self.step1, fg_color="transparent")
        actions_row.pack(fill="x", padx=8, pady=(8, 4))
        ctk.CTkButton(actions_row, text="Import targets (.txt)", command=self.load_targets).pack(side="left")
        ctk.CTkButton(actions_row, text="Load proxies", command=self.load_proxies).pack(side="left", padx=(8, 0))
        self.targets_count_lbl = ctk.CTkLabel(actions_row, text="0 entries")
        self.targets_count_lbl.pack(side="right")

        self.asn_text = ctk.CTkTextbox(self.step1, height=220, wrap="none")
        self.asn_text.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self.step2 = self._make_step(self.left_col, "Step 2 — Options")
        self.step2.grid(row=1, column=0, sticky="nsew", padx=8, pady=6)

        opts_row1 = ctk.CTkFrame(self.step2, fg_color="transparent")
        opts_row1.pack(fill="x", padx=8, pady=8)
        self.single_file_cb = ctk.CTkCheckBox(opts_row1, text="Save everything into a single file",
                                              variable=self.save_single_file_var)
        self.single_file_cb.pack(side="left")

        threads_box = ctk.CTkFrame(self.step2, fg_color="transparent")
        threads_box.pack(fill="x", padx=8, pady=(0, 10))
        ctk.CTkLabel(threads_box, text="Threads:").pack(side="left")
        self.thread_slider = ctk.CTkSlider(threads_box, from_=1, to=MAX_THREADS, number_of_steps=MAX_THREADS-1,
                                           command=self._on_threads_changed)
        self.thread_slider.set(self.thread_var.get())
        self.thread_slider.pack(side="left", fill="x", expand=True, padx=8)
        self.thread_value_lbl = ctk.CTkLabel(threads_box, text=str(self.thread_var.get()))
        self.thread_value_lbl.pack(side="left")

        self.step3 = self._make_step(self.left_col, "Step 3 — Controls")
        self.step3.grid(row=2, column=0, sticky="nsew", padx=8, pady=(6, 8))
        controls = ctk.CTkFrame(self.step3, fg_color="transparent")
        controls.pack(fill="x", padx=8, pady=8)
        for i in (0, 1, 2):
            controls.grid_columnconfigure(i, weight=1)

        self.start_btn = ctk.CTkButton(controls, text="Start  (F5)", command=self.start_scanning)
        self.pause_btn = ctk.CTkButton(controls, text="Pause  (Space)", command=self.toggle_pause)
        self.stop_btn  = ctk.CTkButton(controls, text="Stop  (Esc)", fg_color="#8d1010", hover_color="#700d0d",
                                       command=self.stop_scanning)
        self.start_btn.grid(row=0, column=0, padx=6, pady=6, sticky="ew")
        self.pause_btn.grid(row=0, column=1, padx=6, pady=6, sticky="ew")
        self.stop_btn.grid (row=0, column=2, padx=6, pady=6, sticky="ew")

        # ---- Right: Summary & Progress
        for i in range(6):
            self.right_col.grid_rowconfigure(i, weight=0)
        self.right_col.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self.right_col, text="Session summary",
                     font=ctk.CTkFont(size=14, weight="bold")).grid(row=0, column=0, sticky="w", padx=12, pady=(12, 4))

        summary = ctk.CTkFrame(self.right_col)
        summary.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 10))
        for i in range(2):
            summary.grid_columnconfigure(i, weight=1)

        self.lbl_total   = self._kv(summary, "Total targets", "0", 0, 0)
        self.lbl_done    = self._kv(summary, "Completed",     "0", 0, 1)
        self.lbl_remain  = self._kv(summary, "Remaining",     "0", 1, 0)
        self.lbl_threads = self._kv(summary, "Threads",       str(self.thread_var.get()), 1, 1)
        # New global prefix counter
        self.lbl_prefixes = self._kv(summary, "Prefixes (processed / total)", "0 / 0", 2, 0, col_span=2)

        ctk.CTkLabel(self.right_col, text="Progress",
                     font=ctk.CTkFont(size=14, weight="bold")).grid(row=2, column=0, sticky="w", padx=12, pady=(6, 2))

        prog_frame = ctk.CTkFrame(self.right_col)
        prog_frame.grid(row=3, column=0, sticky="ew", padx=12, pady=(0, 12))
        prog_frame.grid_columnconfigure(0, weight=1)

        self.progress = ctk.CTkProgressBar(prog_frame)
        self.progress.set(0.0)
        self.progress.grid(row=0, column=0, sticky="ew", padx=8, pady=(10, 6))

        self.progress_lbl = ctk.CTkLabel(prog_frame, text="Progress: 0/0 (0%) • ETA: – • Elapsed: 0.0s")
        self.progress_lbl.grid(row=1, column=0, sticky="w", padx=8, pady=(0, 10))

        # Initial placement (may be re-applied on resize)
        self.left_col.grid(row=0, column=0, sticky="nsew", padx=(4, 6), pady=4)
        self.right_col.grid(row=0, column=1, sticky="nsew", padx=(6, 4), pady=4)

        # Logs toolbar
        logs_toolbar = ctk.CTkFrame(self.root, corner_radius=0)
        logs_toolbar.grid(row=2, column=0, sticky="ew")
        logs_toolbar.grid_columnconfigure(0, weight=1)

        left_tools = ctk.CTkFrame(logs_toolbar, fg_color="transparent")
        left_tools.grid(row=0, column=0, sticky="w", padx=12, pady=8)
        ctk.CTkLabel(left_tools, text="Logs", font=ctk.CTkFont(size=13, weight="bold")).pack(side="left", padx=(0, 10))
        ctk.CTkButton(left_tools, text="Clear", command=self._logs_clear, width=86).pack(side="left")
        ctk.CTkButton(left_tools, text="Copy",  command=self._logs_copy,  width=86).pack(side="left", padx=(8, 0))
        ctk.CTkButton(left_tools, text="Save…", command=self._logs_save,  width=86).pack(side="left", padx=(8, 0))

        right_tools = ctk.CTkFrame(logs_toolbar, fg_color="transparent")
        right_tools.grid(row=0, column=1, sticky="e", padx=12, pady=8)
        ctk.CTkCheckBox(right_tools, text="Autoscroll", variable=self.autoscroll_var).pack(side="left")
        ctk.CTkCheckBox(right_tools, text="Word wrap", variable=self.wrap_var, command=self._toggle_wrap).pack(side="left", padx=(10, 0))

        # Logs area
        logs_frame = ctk.CTkFrame(self.root)
        logs_frame.grid(row=3, column=0, sticky="nsew", padx=10, pady=(0, 10))
        logs_frame.grid_rowconfigure(0, weight=1)
        logs_frame.grid_columnconfigure(0, weight=1)

        self.log_output = ctk.CTkTextbox(logs_frame, wrap="none", font=ctk.CTkFont(size=12, family="Consolas"))
        self.log_output.grid(row=0, column=0, sticky="nsew", padx=(8, 0), pady=8)
        log_scroll = ctk.CTkScrollbar(logs_frame, command=self.log_output.yview)
        log_scroll.grid(row=0, column=1, sticky="ns", padx=(0, 8), pady=8)
        self.log_output.configure(yscrollcommand=log_scroll.set)
        self.log_output.configure(state="disabled")

        # Apply initial layout
        self._apply_layout_mode(self.root.winfo_width())

    def _make_step(self, parent, title: str) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent)
        ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", padx=8, pady=(8, 6))
        return frame

    def _kv(self, parent, key, value, r, c, col_span=1):
        cell = ctk.CTkFrame(parent)
        cell.grid(row=r, column=c, columnspan=col_span, sticky="ew", padx=6, pady=6)
        ctk.CTkLabel(cell, text=key, text_color=("#AAAAAA"), font=ctk.CTkFont(size=12)).pack(anchor="w", padx=8, pady=(8, 0))
        val = ctk.CTkLabel(cell, text=value, font=ctk.CTkFont(size=16, weight="bold"))
        val.pack(anchor="w", padx=8, pady=(0, 8))
        return val

    # ========================= Responsive ==============================
    def _on_resize(self, _event=None):
        self._apply_layout_mode(self.root.winfo_width())

    def _apply_layout_mode(self, width: int):
        try:
            self.left_col.grid_forget()
            self.right_col.grid_forget()
        except Exception:
            pass

        if width < BREAKPOINT_WIDTH:
            self.content.grid_columnconfigure(0, weight=1)
            self.content.grid_columnconfigure(1, weight=0)
            self.left_col.grid (row=0, column=0, sticky="nsew", padx=4, pady=(4, 2))
            self.right_col.grid(row=1, column=0, sticky="nsew", padx=4, pady=(2, 4))
            self.asn_text.configure(height=180)
            self.progress_lbl.configure(font=ctk.CTkFont(size=12))
        else:
            self.content.grid_columnconfigure(0, weight=1)
            self.content.grid_columnconfigure(1, weight=1)
            self.left_col.grid (row=0, column=0, sticky="nsew", padx=(4, 6), pady=4)
            self.right_col.grid(row=0, column=1, sticky="nsew", padx=(6, 4), pady=4)
            self.asn_text.configure(height=220)
            self.progress_lbl.configure(font=ctk.CTkFont(size=13))

    # =========================== Callbacks =============================
    def _toggle_theme(self, value: str):
        v = value.lower()
        if v == "dark":
            ctk.set_appearance_mode("dark")
        elif v == "light":
            ctk.set_appearance_mode("light")
        else:
            ctk.set_appearance_mode("system")

    def _on_threads_changed(self, _value):
        val = int(round(self.thread_slider.get()))
        self.thread_var.set(val)
        self.thread_value_lbl.configure(text=str(val))
        self.lbl_threads.configure(text=str(val))

    def _toggle_wrap(self):
        self.log_output.configure(wrap="word" if self.wrap_var.get() else "none")

    def _logs_clear(self):
        self.log_output.configure(state="normal")
        self.log_output.delete("1.0", "end")
        self.log_output.configure(state="disabled")

    def _logs_copy(self):
        try:
            content = self.log_output.get("1.0", "end").rstrip()
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            self.root.update()
        except Exception:
            pass

    def _logs_save(self):
        path = filedialog.asksaveasfilename(defaultextension=".log",
                                            filetypes=[("Log file", "*.log"), ("Text file", "*.txt"), ("All files", "*.*")],
                                            title="Save logs as…")
        if not path:
            return
        try:
            content = self.log_output.get("1.0", "end").rstrip()
            with open(path, "w", encoding="utf-8") as f:
                f.write(content + "\n")
            messagebox.showinfo("Logs", f"Logs saved:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save logs: {e}")

    def load_targets(self):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")], title="Import targets (.txt)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = [ln.strip() for ln in f if ln.strip()]
            if not lines:
                self._info("Import targets", "The file has no entries.")
                return
            prefix = "" if not self.asn_text.get("1.0", "end").strip() else "\n"
            self.asn_text.insert("end", prefix + "\n".join(lines) + "\n")
            self._update_target_count()
        except Exception as e:
            self._error("Import targets", f"Read error: {e}")

    # ===================== Scanning logic (cooperative) =================
    def load_proxies(self):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")], title="Load proxies (.txt)")
        if path:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                self.proxy_list = [line.strip() for line in f if line.strip()]
            self.log(f"{len(self.proxy_list)} proxies loaded.")

    def get_proxy(self):
        if self.proxy_list:
            proxy = random.choice(self.proxy_list)
            return {"http": proxy, "https": proxy}
        return None

    def extract_prefixes_from_asn(self, asn):
        url = f"https://bgp.he.net/{asn}#_prefixes"
        attempts = 3
        for attempt in range(attempts):
            try:
                response = requests.get(url, headers=self.user_agent(), proxies=self.get_proxy(), timeout=15)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, 'html.parser')
                prefixes = set()
                for a in soup.select("table tr td a[href^='/net/']"):
                    match = re.search(r'/net/([\d\.]+/\d+)', a.get('href', ''))
                    if match:
                        prefixes.add(match.group(1))
                return list(prefixes)
            except Exception as e:
                if attempt < attempts - 1:
                    self.log(f"[!] Attempt {attempt+1} failed for ASN {asn}, retrying…")
                    time.sleep(2)
                else:
                    self.log(f"[!] ASN {asn} error after {attempts} tries: {e}")
                    return []

    def extract_dns_records_from_prefix(self, prefix):
        url = f"https://bgp.he.net/net/{prefix}#_dnsrecords"
        attempts = 3
        for attempt in range(attempts):
            try:
                response = requests.get(url, headers=self.user_agent(), proxies=self.get_proxy(), timeout=15)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, 'html.parser')
                ip_addresses = []
                domain_names = []
                for row in soup.select("table tr"):
                    cols = row.find_all("td")
                    if len(cols) < 3:
                        continue
                    ip_tag = cols[0].find("a")
                    if ip_tag:
                        ip = ip_tag.text.strip()
                        if re.match(r"\d+\.\d+\.\d+\.\d+", ip):
                            ip_addresses.append(ip)
                    for a in cols[2].find_all("a"):
                        domain = a.text.strip()
                        if domain and not re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
                            domain_names.append(domain)
                            self.q.put(("log", f"[+] Found domain on {prefix}: {domain}"))
                return ip_addresses, domain_names
            except Exception as e:
                if attempt < attempts - 1:
                    self.log(f"[!] Attempt {attempt+1} failed for DNS {prefix}, retrying…")
                    time.sleep(2)
                else:
                    self.log(f"[!] DNS error for {prefix} after {attempts} tries: {e}")
                    return [], []

    def user_agent(self):
        return {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"}

    def save_to_file(self, data, filename):
        try:
            with open(filename, "a", encoding="utf-8") as f:
                for line in data:
                    f.write(line + "\n")
        except Exception as e:
            self.log(f"[!] Write error {filename}: {e}")

    def log(self, text):
        timestamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{timestamp}] {text}"
        self.log_output.configure(state="normal")
        self.log_output.insert("end", line + "\n")
        if self.autoscroll_var.get():
            self.log_output.see("end")
        self.log_output.configure(state="disabled")

    # ---------------- cooperative workers over task_q ------------------
    def worker(self):
        while not self.stop_flag.is_set():
            try:
                task = self.task_q.get(timeout=0.3)
            except queue.Empty:
                continue

            ttype = task[0]

            if ttype == "ASN_INIT":
                asn = task[1]
                self.q.put(("log", f"[>] Fetching prefixes for {asn}"))
                prefixes = self.extract_prefixes_from_asn(asn)
                if not prefixes:
                    with self.lock:
                        self.completed_asns += 1
                    self.q.put(("log", f"[!] No prefixes for {asn} (or fetch failed). Marked complete."))
                    self.q.put(("progress", self.completed_asns, self.total_asns))
                else:
                    # Register pending count and enqueue prefix scans
                    with self.lock:
                        self.asn_pending[asn] = len(prefixes)
                        self.total_prefixes += len(prefixes)
                        processed, total = self.processed_prefixes, self.total_prefixes
                    self.q.put(("prefix", processed, total))
                    for prefix in prefixes:
                        if self.stop_flag.is_set():
                            break
                        self.task_q.put(("PREFIX_SCAN", asn, prefix))

            elif ttype == "PREFIX_SCAN":
                asn_key, prefix = task[1], task[2]
                # Respect pause
                while self.pause_flag.is_set() and not self.stop_flag.is_set():
                    time.sleep(0.2)
                if self.stop_flag.is_set():
                    self.task_q.task_done()
                    continue

                ips, domains = self.extract_dns_records_from_prefix(prefix)
                if self.save_single_file_var.get():
                    self.save_to_file(ips, self.filename_ips)
                    self.save_to_file(domains, self.filename_domains)
                else:
                    prefix_clean = prefix.replace("/", "_")
                    self.save_to_file(ips, f"ips_{prefix_clean}.txt")
                    self.save_to_file(domains, f"domains_{prefix_clean}.txt")

                # Update counters
                with self.lock:
                    self.processed_prefixes += 1
                    p_processed, p_total = self.processed_prefixes, self.total_prefixes
                self.q.put(("prefix", p_processed, p_total))

                # Decrement pending; if reaches 0, mark ASN complete
                with self.lock:
                    if asn_key in self.asn_pending:
                        self.asn_pending[asn_key] -= 1
                        if self.asn_pending[asn_key] <= 0:
                            del self.asn_pending[asn_key]
                            self.completed_asns += 1
                            self.q.put(("log", f"[✓] {asn_key} finished."))
                            self.q.put(("progress", self.completed_asns, self.total_asns))

            self.task_q.task_done()

    # ====================== GUI update / progress ======================
    def update_gui_loop(self):
        try:
            while not self.q.empty():
                msg = self.q.get_nowait()
                if msg[0] == "progress":
                    current, total = msg[1], msg[2]
                    frac = (current / total) if total else 0.0
                    self.progress.set(frac)
                    eta = self.estimate_eta(current, total)
                    dur = time.time() - self.start_time
                    pct = int(frac * 100) if total else 0
                    self.progress_lbl.configure(
                        text=f"Progress: {current}/{total} ({pct}%) • ETA: {eta:.1f}s • Elapsed: {dur:.1f}s" if total else
                             "Progress: 0/0 (0%) • ETA: – • Elapsed: 0.0s"
                    )
                    self.lbl_total.configure(text=str(total))
                    self.lbl_done.configure(text=str(current))
                    self.lbl_remain.configure(text=str(max(0, total - current)))
                elif msg[0] == "prefix":
                    processed, total = msg[1], msg[2]
                    self.lbl_prefixes.configure(text=f"{processed} / {total}")
                elif msg[0] == "log":
                    self.log(msg[1])
        except queue.Empty:
            pass
        self.root.after(200, self.update_gui_loop)

    def estimate_eta(self, current, total):
        elapsed = time.time() - self.start_time
        if current == 0:
            return 0.0
        remaining = total - current
        avg = elapsed / current
        return max(0.0, avg * remaining)

    def _ask_output_filenames(self):
        dlg = OutputFilesDialog(self.root)
        self.root.wait_window(dlg.top)
        domains_name = dlg.domains_name or "domains_all.txt"
        ips_name = dlg.ips_name or "ips_all.txt"
        return domains_name, ips_name

    # ============================ Control ==============================
    def start_scanning(self):
        self.stop_flag.clear()
        self.pause_flag.clear()

        # Reset queues/counters
        with self.lock:
            self.asn_pending.clear()
            self.completed_asns = 0
            self.total_prefixes = 0
            self.processed_prefixes = 0
        while not self.task_q.empty():
            try:
                self.task_q.get_nowait()
                self.task_q.task_done()
            except queue.Empty:
                break
        self.q.put(("prefix", 0, 0))

        raw = self.asn_text.get("1.0", "end").strip()
        targets = [a.strip() for a in raw.splitlines() if a.strip()]
        self.total_asns = len(targets)
        self.progress.set(0)
        self.progress_lbl.configure(text="Progress: 0/0 (0%) • ETA: – • Elapsed: 0.0s")
        self._logs_clear()

        if self.total_asns == 0:
            self.log("[!] No input detected. Add ASNs/IPs (one per line).")
            return

        self.filename_domains, self.filename_ips = self._ask_output_filenames()
        for path in (self.filename_domains, self.filename_ips):
            try:
                if os.path.exists(path):
                    os.remove(path)
            except Exception as e:
                self.log(f"[!] Could not reset {path}: {e}")

        self.start_time = time.time()

        # Enqueue tasks:
        ipv4_re = re.compile(r"^\d+\.\d+\.\d+\.\d+$")
        for tgt in targets:
            if ipv4_re.match(tgt):
                key = tgt
                with self.lock:
                    self.asn_pending[key] = 1
                    self.total_prefixes += 1
                    processed, total = self.processed_prefixes, self.total_prefixes
                self.q.put(("prefix", processed, total))
                self.task_q.put(("PREFIX_SCAN", key, f"{tgt}/32"))
                self.q.put(("log", f"[>] Queued /32 scan for {tgt}"))
            else:
                self.task_q.put(("ASN_INIT", tgt))

        # Spawn workers
        n_threads = max(1, int(self.thread_var.get()))
        self._workers = []
        for _ in range(n_threads):
            t = threading.Thread(target=self.worker, daemon=True)
            t.start()
            self._workers.append(t)

        # UI labels
        self.lbl_total.configure(text=str(self.total_asns))
        self.lbl_done.configure(text="0")
        self.lbl_remain.configure(text=str(self.total_asns))
        self.lbl_threads.configure(text=str(n_threads))
        self.start_btn.configure(state="disabled")
        self.log(f"[▶] Scan started with {n_threads} thread(s) | {self.total_asns} target(s)")

        # Poll end
        self.root.after(500, self._check_finished)

    def _check_finished(self):
        if self.stop_flag.is_set():
            self.start_btn.configure(state="normal")
            return
        if self.completed_asns >= self.total_asns and self.total_asns > 0:
            self.log("[✓] Scan finished.")
            self.start_btn.configure(state="normal")
            return
        self.root.after(500, self._check_finished)

    def stop_scanning(self):
        self.stop_flag.set()
        self.start_btn.configure(state="normal")
        self.log("[!] Stop requested.")

    def toggle_pause(self):
        if self.pause_flag.is_set():
            self.pause_flag.clear()
            self.pause_btn.configure(text="Pause  (Space)")
            self.log("[▶] Resumed.")
        else:
            self.pause_flag.set()
            self.pause_btn.configure(text="Resume  (Space)")
            self.log("[⏸] Paused.")

    # ============================== Utils ==============================
    def _update_target_count(self):
        text = self.asn_text.get("1.0", "end").strip()
        count = len([ln for ln in text.splitlines() if ln.strip()])
        self.targets_count_lbl.configure(text=f"{count} entries")

    def _update_target_count_periodic(self):
        self._update_target_count()
        self.root.after(600, self._update_target_count_periodic)

    def _info(self, title, msg):
        try: messagebox.showinfo(title, msg)
        except Exception: pass

    def _error(self, title, msg):
        try: messagebox.showerror(title, msg)
        except Exception: pass


class OutputFilesDialog:
    def __init__(self, parent):
        self.top = ctk.CTkToplevel(parent)
        self.top.title("Output files")
        self.top.transient(parent)
        self.top.grab_set()
        self.top.geometry("420x200")
        self.top.resizable(False, False)

        title = ctk.CTkLabel(self.top, text="Names of output files", font=ctk.CTkFont(size=16, weight="bold"))
        title.pack(padx=16, pady=(16, 4))
        hint = ctk.CTkLabel(self.top, text="(leave empty to use defaults)")
        hint.pack(padx=16, pady=(0, 12))

        form = ctk.CTkFrame(self.top)
        form.pack(fill="x", padx=16, pady=8)

        dn_lbl = ctk.CTkLabel(form, text="Domains file (.txt):")
        dn_lbl.grid(row=0, column=0, sticky="w", padx=8, pady=8)
        self.domains_entry = ctk.CTkEntry(form, placeholder_text="domains_all.txt")
        self.domains_entry.grid(row=0, column=1, sticky="ew", padx=8, pady=8)

        ip_lbl = ctk.CTkLabel(form, text="IPs file (.txt):")
        ip_lbl.grid(row=1, column=0, sticky="w", padx=8, pady=8)
        self.ips_entry = ctk.CTkEntry(form, placeholder_text="ips_all.txt")
        self.ips_entry.grid(row=1, column=1, sticky="ew", padx=8, pady=8)

        form.grid_columnconfigure(1, weight=1)

        btns = ctk.CTkFrame(self.top)
        btns.pack(fill="x", padx=16, pady=12)
        ok = ctk.CTkButton(btns, text="OK", command=self._ok)
        cancel = ctk.CTkButton(btns, text="Cancel", command=self._cancel, fg_color="#5a5a5a", hover_color="#4a4a4a")
        ok.pack(side="right", padx=(8, 0))
        cancel.pack(side="right")

        self.domains_name = None
        self.ips_name = None

    def _ok(self):
        self.domains_name = (self.domains_entry.get() or "").strip()
        self.ips_name = (self.ips_entry.get() or "").strip()
        self.top.destroy()

    def _cancel(self):
        self.top.destroy()


if __name__ == "__main__":
    app = ctk.CTk()
    gui = ASNScannerApp(app)
    app.mainloop()
