"""
app.py — Interface gráfica do App Vault Protection.

Guarda credenciais de plataformas de dados (FTP/SFTP, APIs, painéis, bancos de dados,
SSH, nuvem...) separadas por ambiente, num arquivo local criptografado (ver vault.py).

Execute:  python app.py [caminho/do/cofre.db]
"""
from __future__ import annotations

import json
import math
import os
import sys
import time
import tkinter as tk
from collections import Counter
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

import secure_clipboard
from vault import (KINDS, MIN_MASTER_PASSWORD_LEN, Entry, Vault, VaultError,
                   WrongPasswordError, generate_password)
from version import APP_NAME, __version__

AUTO_LOCK_SECONDS = 5 * 60       # bloqueia após 5 min sem uso
CLIPBOARD_CLEAR_SECONDS = 30     # limpa a área de transferência após 30 s
REVEAL_SECONDS = 20              # segredo revelado volta a ser mascarado após 20 s
# No executável (PyInstaller) os arquivos de apoio ficam em sys._MEIPASS.
ASSETS_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)) / "assets"
DATA_DIR = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "AppVaultProtection"
CONFIG_PATH = DATA_DIR / "config.json"   # só guarda o caminho do último cofre aberto
DEFAULT_VAULT = DATA_DIR / "cofre.db"
FONT = "Segoe UI" if sys.platform == "win32" else "Helvetica"
MONO = "Consolas" if sys.platform == "win32" else "Courier"

KIND_LABELS = {
    "ftp": "FTP / SFTP",
    "api": "API",
    "panel": "Painel / Web",
    "database": "Banco de dados",
    "ssh": "SSH / Servidor",
    "cloud": "Nuvem",
    "other": "Outro",
}
# campo -> (rótulo padrão, é secreto?)
FIELDS = {
    "host": ("Host", False),
    "port": ("Porta", False),
    "url": ("URL", False),
    "database": ("Banco / schema", False),
    "username": ("Usuário", False),
    "password": ("Senha", True),
    "token": ("Token / API key", True),
}
KIND_FIELDS = {
    "ftp": ["host", "port", "username", "password"],
    "api": ["url", "username", "password", "token"],
    "panel": ["url", "username", "password"],
    "database": ["host", "port", "database", "username", "password"],
    "ssh": ["host", "port", "username", "password", "token"],
    "cloud": ["url", "username", "password", "token"],
    "other": list(FIELDS),
}
KIND_LABEL_OVERRIDES = {
    "api": {"url": "URL base / endpoint", "username": "Client ID / usuário",
            "password": "Client secret / senha", "token": "API key / token"},
    "panel": {"url": "URL do painel"},
    "ssh": {"token": "Chave privada / passphrase"},
    "cloud": {"url": "Console / região", "username": "Access key ID",
              "password": "Senha do console", "token": "Secret access key"},
}
DEFAULT_PORTS = {"ftp": "21", "ssh": "22"}


def field_label(kind: str, name: str) -> str:
    return KIND_LABEL_OVERRIDES.get(kind, {}).get(name, FIELDS[name][0])


def fmt_time(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).astimezone().strftime("%d/%m/%Y %H:%M")
    except (TypeError, ValueError):
        return ""


def target_of(e: Entry) -> str:
    if e.url:
        return e.url
    return f"{e.host}:{e.port}" if e.host and e.port else e.host


def env_color(env: str) -> str:
    k = env.casefold()
    if "prod" in k:
        return "#c0392b"
    if any(s in k for s in ("homol", "hml", "stag", "qa", "test")):
        return "#ca6f1e"
    if any(s in k for s in ("dev", "local", "sandbox")):
        return "#1e8449"
    return "#2e6da4"


def is_production(env: str) -> bool:
    return "prod" in env.casefold()


def password_strength(pw: str) -> tuple[str, str]:
    """Estimativa simples (tamanho x variedade de caracteres)."""
    if not pw:
        return "", "#666"
    pool = sum(size for test, size in (
        (str.islower, 26), (str.isupper, 26), (str.isdigit, 10)) if any(test(c) for c in pw))
    pool += 33 if any(not c.isalnum() for c in pw) else 0
    bits = len(pw) * math.log2(max(pool, 2))
    if len(set(pw)) < len(pw) / 3:
        bits /= 2
    if bits < 50:
        return "Força: fraca", "#b03a2e"
    if bits < 80:
        return "Força: razoável", "#ca6f1e"
    return "Força: forte", "#1e8449"


def load_config() -> dict:
    try:
        data = json.loads(CONFIG_PATH.read_text("utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_config(cfg: dict) -> None:
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), "utf-8")
    except OSError:
        pass


def center_on(win: tk.Toplevel, parent: tk.Misc) -> None:
    win.update_idletasks()
    top = parent.winfo_toplevel()
    x = top.winfo_rootx() + (top.winfo_width() - win.winfo_reqwidth()) // 2
    y = top.winfo_rooty() + (top.winfo_height() - win.winfo_reqheight()) // 3
    win.geometry(f"+{max(x, 0)}+{max(y, 0)}")


# ================================================================ aplicação

class App(tk.Tk):
    def __init__(self, path: str | None = None):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1440x760")
        self.minsize(1100, 600)
        self._setup_style()
        self.logo: tk.PhotoImage | None = None
        try:
            if sys.platform == "win32":
                self.iconbitmap(default=str(ASSETS_DIR / "app.ico"))
            self.logo = tk.PhotoImage(file=str(ASSETS_DIR / "app.png")).subsample(4)
            self.iconphoto(True, self.logo)
        except tk.TclError:
            pass  # sem ícone, o app funciona igual
        self.config_data = load_config()
        last = self.config_data.get("last_vault")
        if not (isinstance(last, str) and os.path.isfile(last)):
            last = None
        self.vault_path = path or last or str(DEFAULT_VAULT)
        self.vault: Vault | None = None
        self.failed_attempts = 0
        self._last_activity = time.monotonic()
        self._clip_digest: bytes | None = None
        self._clip_job: str | None = None
        self._view: ttk.Frame | None = None
        for seq in ("<KeyPress>", "<ButtonPress>", "<Motion>", "<MouseWheel>"):
            self.bind_all(seq, self._touch, add="+")
        self.protocol("WM_DELETE_WINDOW", self.quit_app)
        self.show_unlock()
        self.after(1000, self._idle_tick)

    def _setup_style(self) -> None:
        style = ttk.Style(self)
        if sys.platform == "win32" and "vista" in style.theme_names():
            style.theme_use("vista")
        else:
            style.theme_use("clam")
        style.configure(".", font=(FONT, 10))
        style.configure("Treeview", rowheight=28)
        style.configure("Treeview.Heading", font=(FONT, 10, "bold"))
        style.configure("Title.TLabel", font=(FONT, 20, "bold"))
        style.configure("H2.TLabel", font=(FONT, 14, "bold"))
        style.configure("Muted.TLabel", foreground="#666")
        style.configure("Error.TLabel", foreground="#b03a2e")
        style.configure("Field.TLabel", foreground="#555", font=(FONT, 9))
        style.configure("Side.TLabel", foreground="#666", font=(FONT, 9, "bold"))

    # ---- telas

    def _show(self, view: ttk.Frame) -> None:
        if self._view is not None:
            self._view.destroy()
        self._view = view
        view.pack(fill="both", expand=True)

    def show_unlock(self, message: str = "") -> None:
        self.config(menu="")
        self.title(APP_NAME)
        self._show(UnlockView(self, message))

    def unlocked(self, vault: Vault) -> None:
        self.vault = vault
        self.failed_attempts = 0
        self.vault_path = vault.path
        self.config_data["last_vault"] = vault.path
        save_config(self.config_data)
        self._touch()
        self.title(f"{APP_NAME} — {os.path.basename(vault.path)}")
        self._show(MainView(self))

    def lock(self, message: str = "Cofre bloqueado.") -> None:
        if self.vault is None:
            return
        for w in list(self.winfo_children()):
            if isinstance(w, tk.Toplevel):
                w.destroy()
        self.clear_clipboard_if_ours()
        try:
            self.vault.close()
        except Exception:
            pass
        self.vault = None
        self.show_unlock(message)

    def quit_app(self) -> None:
        self.clear_clipboard_if_ours()
        if self.vault is not None:
            try:
                self.vault.close()
            except Exception:
                pass
            self.vault = None
        self.destroy()

    # ---- inatividade

    def _touch(self, _event=None) -> None:
        self._last_activity = time.monotonic()

    def _idle_tick(self) -> None:
        if self.vault is not None:
            remaining = AUTO_LOCK_SECONDS - (time.monotonic() - self._last_activity)
            if remaining <= 0:
                self.lock("Cofre bloqueado por inatividade.")
            elif isinstance(self._view, MainView):
                self._view.show_lock_countdown(int(remaining))
        self.after(1000, self._idle_tick)

    # ---- área de transferência

    def copy_to_clipboard(self, text: str, label: str) -> None:
        try:
            secure_clipboard.copy(self, text)
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Não foi possível copiar: {exc}", parent=self)
            return
        self._clip_digest = secure_clipboard.digest(text)
        if self._clip_job:
            self.after_cancel(self._clip_job)
        self._clip_job = self.after(CLIPBOARD_CLEAR_SECONDS * 1000, self.clear_clipboard_if_ours)
        self.status(f"“{label}” copiado. A área de transferência será limpa em "
                    f"{CLIPBOARD_CLEAR_SECONDS} s.")

    def clear_clipboard_if_ours(self) -> None:
        """Só limpa se o conteúdo ainda for o que copiamos (não apaga o que o usuário copiou depois)."""
        if self._clip_job:
            self.after_cancel(self._clip_job)
            self._clip_job = None
        if self._clip_digest is None:
            return
        try:
            current = secure_clipboard.paste(self)
            if current is not None and secure_clipboard.digest(current) == self._clip_digest:
                secure_clipboard.clear(self)
                self.status("Área de transferência limpa.")
        except Exception:
            pass
        self._clip_digest = None

    def status(self, message: str) -> None:
        if isinstance(self._view, MainView):
            self._view.set_status(message)


# ================================================================ desbloqueio

class UnlockView(ttk.Frame):
    def __init__(self, app: App, message: str = ""):
        super().__init__(app)
        self.app = app
        self._wait_until = 0.0
        card = ttk.Frame(self, padding=32)
        card.place(relx=0.5, rely=0.45, anchor="center")
        card.columnconfigure(0, weight=1)

        if app.logo is not None:
            ttk.Label(card, image=app.logo).grid(row=0, column=0, pady=(0, 6))
        else:
            ttk.Label(card, text="🔐", font=(FONT, 34)).grid(row=0, column=0)
        ttk.Label(card, text=APP_NAME, style="Title.TLabel").grid(row=1, column=0)
        ttk.Label(card, text="Credenciais de FTP, APIs, painéis e bancos de dados, por ambiente.",
                  style="Muted.TLabel").grid(row=2, column=0, pady=(2, 20))

        ttk.Label(card, text="Arquivo do cofre", style="Field.TLabel").grid(row=3, column=0, sticky="w")
        file_row = ttk.Frame(card)
        file_row.grid(row=4, column=0, sticky="ew")
        file_row.columnconfigure(0, weight=1)
        self.path_label = ttk.Label(file_row, wraplength=330)
        self.path_label.grid(row=0, column=0, sticky="w")
        ttk.Button(file_row, text="Abrir…", command=self.choose_existing).grid(row=0, column=1, padx=(8, 0))
        ttk.Button(file_row, text="Novo…", command=self.choose_new).grid(row=0, column=2, padx=(4, 0))

        self.mode_label = ttk.Label(card, style="Muted.TLabel")
        self.mode_label.grid(row=5, column=0, sticky="w", pady=(14, 2))
        ttk.Label(card, text="Senha mestra", style="Field.TLabel").grid(row=6, column=0, sticky="w")
        self.pw = ttk.Entry(card, show="•", width=46)
        self.pw.grid(row=7, column=0, sticky="ew", ipady=3)
        self.confirm_label = ttk.Label(card, text="Confirme a senha mestra", style="Field.TLabel")
        self.confirm = ttk.Entry(card, show="•", width=46)
        self.strength = ttk.Label(card, font=(FONT, 9))
        self.msg = ttk.Label(card, text=message, style="Error.TLabel", wraplength=420)
        self.msg.grid(row=11, column=0, sticky="w", pady=(10, 0))
        self.button = ttk.Button(card, command=self.submit)
        self.button.grid(row=12, column=0, sticky="ew", pady=(12, 0), ipady=4)

        self.pw.bind("<Return>", lambda e: self.submit())
        self.confirm.bind("<Return>", lambda e: self.submit())
        self.pw.bind("<KeyRelease>", self._update_strength)
        self._apply_mode()
        self.after(80, self.pw.focus_set)

    @property
    def creating(self) -> bool:
        return not os.path.exists(self.app.vault_path)

    def _apply_mode(self) -> None:
        self.path_label.config(text=self.app.vault_path)
        if self.creating:
            self.mode_label.config(text="Novo cofre — defina uma senha mestra forte. "
                                        "Sem ela, os dados são irrecuperáveis.")
            self.confirm_label.grid(row=8, column=0, sticky="w", pady=(8, 0))
            self.confirm.grid(row=9, column=0, sticky="ew", ipady=3)
            self.strength.grid(row=10, column=0, sticky="w", pady=(4, 0))
            self.button.config(text="Criar cofre")
        else:
            self.mode_label.config(text="Digite a senha mestra para desbloquear.")
            for w in (self.confirm_label, self.confirm, self.strength):
                w.grid_remove()
            self.button.config(text="Desbloquear")

    def _update_strength(self, _event=None) -> None:
        if self.creating:
            text, color = password_strength(self.pw.get())
            self.strength.config(text=text, foreground=color)

    def choose_existing(self) -> None:
        path = filedialog.askopenfilename(
            parent=self, title="Abrir cofre",
            initialdir=os.path.dirname(self.app.vault_path) or None,
            filetypes=[("Cofre", "*.db *.vault"), ("Todos os arquivos", "*.*")])
        if path:
            self.app.vault_path = os.path.abspath(path)
            self.msg.config(text="")
            self._apply_mode()

    def choose_new(self) -> None:
        path = filedialog.asksaveasfilename(
            parent=self, title="Criar novo cofre", defaultextension=".db",
            initialdir=os.path.dirname(self.app.vault_path) or None, initialfile="cofre.db",
            filetypes=[("Cofre", "*.db"), ("Todos os arquivos", "*.*")])
        if not path:
            return
        if os.path.exists(path):
            self.msg.config(text="Esse arquivo já existe. Escolha outro nome ou use “Abrir…”.")
            return
        self.app.vault_path = os.path.abspath(path)
        self.msg.config(text="")
        self._apply_mode()

    def submit(self) -> None:
        if time.monotonic() < self._wait_until:
            return
        pw = self.pw.get()
        if not pw:
            self.msg.config(text="Digite a senha mestra.")
            return
        if self.creating:
            if len(pw) < MIN_MASTER_PASSWORD_LEN:
                self.msg.config(text=f"A senha mestra precisa ter pelo menos "
                                     f"{MIN_MASTER_PASSWORD_LEN} caracteres.")
                return
            if pw != self.confirm.get():
                self.msg.config(text="As senhas não conferem.")
                return
        self.msg.config(text="Derivando chave…", style="Muted.TLabel")
        self.button.state(["disabled"])
        self.app.config(cursor="watch")
        self.update_idletasks()
        try:
            if self.creating:
                os.makedirs(os.path.dirname(self.app.vault_path) or ".", exist_ok=True)
                vault = Vault.create(self.app.vault_path, pw)
            else:
                vault = Vault.open(self.app.vault_path, pw)
        except WrongPasswordError:
            self.app.failed_attempts += 1
            self.pw.delete(0, "end")
            # Atraso crescente na interface (1, 2, 4... até 30 s). A proteção real
            # contra força bruta offline é o custo do scrypt.
            self._throttle(min(2 ** (self.app.failed_attempts - 1), 30))
            return
        except (VaultError, OSError) as exc:
            self.msg.config(text=str(exc), style="Error.TLabel")
            self.button.state(["!disabled"])
            return
        finally:
            self.app.config(cursor="")
        self.app.unlocked(vault)

    def _throttle(self, seconds: int) -> None:
        self._wait_until = time.monotonic() + seconds
        self._countdown()

    def _countdown(self) -> None:
        if not self.winfo_exists():
            return
        remaining = math.ceil(self._wait_until - time.monotonic())
        if remaining > 0:
            self.button.state(["disabled"])
            self.msg.config(text=f"Senha mestra incorreta. Tente de novo em {remaining} s.",
                            style="Error.TLabel")
            self.after(250, self._countdown)
        else:
            self.button.state(["!disabled"])
            self.msg.config(text="Senha mestra incorreta.", style="Error.TLabel")
            self.pw.focus_set()


# ================================================================ tela principal

class MainView(ttk.Frame):
    COLUMNS = (("name", "Nome", 170), ("env", "Ambiente", 110), ("kind", "Tipo", 110),
               ("target", "Host / URL", 180), ("user", "Usuário", 115),
               ("updated", "Atualizado", 110))

    def __init__(self, app: App):
        super().__init__(app)
        self.app = app
        self.selected_env: str | None = None
        self._rows: list[dict] = []
        self._iid_map: dict[str, tuple[str, str]] = {}
        self._env_keys: list[str | None] = []
        self._sort = ("name", False)
        self._status_job: str | None = None
        self._build_menu()
        self._build_toolbar()
        self._build_body()
        self._build_statusbar()
        self._shortcuts = {"<Control-n>": lambda e: self.new_entry(),
                           "<Control-f>": lambda e: self.search_entry.focus_set(),
                           "<Control-l>": lambda e: self.app.lock()}
        for seq, fn in self._shortcuts.items():
            self.app.bind(seq, fn)
        self.refresh()

    def destroy(self) -> None:
        for seq in self._shortcuts:
            self.app.unbind(seq)
        super().destroy()

    @property
    def vault(self) -> Vault:
        return self.app.vault

    # ---- construção

    def _build_menu(self) -> None:
        bar = tk.Menu(self.app)
        m = tk.Menu(bar, tearoff=False)
        m.add_command(label="Novo segredo", accelerator="Ctrl+N", command=self.new_entry)
        m.add_separator()
        m.add_command(label="Trocar senha mestra…", command=self.change_master)
        m.add_command(label="Fazer backup…", command=self.backup)
        m.add_separator()
        m.add_command(label="Bloquear", accelerator="Ctrl+L", command=self.app.lock)
        m.add_command(label="Sair", command=self.app.quit_app)
        bar.add_cascade(label="Cofre", menu=m)
        m = tk.Menu(bar, tearoff=False)
        m.add_command(label="Novo ambiente…", command=self.add_env)
        m.add_command(label="Renomear ambiente…", command=self.rename_env)
        m.add_command(label="Excluir ambiente", command=self.delete_env)
        bar.add_cascade(label="Ambientes", menu=m)
        m = tk.Menu(bar, tearoff=False)
        m.add_command(label="Gerador de senhas…", command=lambda: GeneratorDialog(self.app))
        bar.add_cascade(label="Ferramentas", menu=m)
        m = tk.Menu(bar, tearoff=False)
        m.add_command(label=f"Sobre o {APP_NAME}", command=self.about)
        bar.add_cascade(label="Ajuda", menu=m)
        self.app.config(menu=bar)

    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self, padding=(10, 10, 10, 6))
        bar.pack(fill="x")
        ttk.Button(bar, text="＋  Novo segredo", command=self.new_entry).pack(side="left")
        self.btn_edit = ttk.Button(bar, text="Editar", command=self.edit_entry)
        self.btn_edit.pack(side="left", padx=(6, 0))
        self.btn_dup = ttk.Button(bar, text="Duplicar", command=self.duplicate_entry)
        self.btn_dup.pack(side="left", padx=(6, 0))
        self.btn_del = ttk.Button(bar, text="Excluir", command=self.delete_entry)
        self.btn_del.pack(side="left", padx=(6, 0))

        ttk.Button(bar, text="🔒  Bloquear", command=self.app.lock).pack(side="right")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.apply_filter())
        self.search_entry = ttk.Entry(bar, textvariable=self.search_var, width=28)
        self.search_entry.pack(side="right", padx=(4, 16))
        ttk.Label(bar, text="Buscar").pack(side="right")
        self.kind_filter = ttk.Combobox(bar, state="readonly", width=16,
                                        values=["Todos os tipos"] + [KIND_LABELS[k] for k in KINDS])
        self.kind_filter.current(0)
        self.kind_filter.bind("<<ComboboxSelected>>", lambda e: self.apply_filter())
        self.kind_filter.pack(side="right", padx=(4, 16))
        ttk.Label(bar, text="Tipo").pack(side="right")

    def _build_body(self) -> None:
        body = ttk.Frame(self, padding=(10, 0))
        body.pack(fill="both", expand=True)

        side = ttk.Frame(body, padding=(0, 0, 10, 0))
        side.pack(side="left", fill="y")
        ttk.Label(side, text="AMBIENTES", style="Side.TLabel").pack(anchor="w", pady=(0, 4))
        self.env_list = tk.Listbox(side, activestyle="none", exportselection=False, width=24,
                                   borderwidth=1, relief="solid", highlightthickness=0,
                                   font=(FONT, 10), selectbackground="#dbe9f6",
                                   selectforeground="#000")
        self.env_list.pack(fill="both", expand=True)
        self.env_list.bind("<<ListboxSelect>>", self._on_env_select)
        self.env_list.bind("<Double-1>", lambda e: self.rename_env())
        btns = ttk.Frame(side)
        btns.pack(fill="x", pady=(6, 0))
        ttk.Button(btns, text="Novo", width=7, command=self.add_env).pack(side="left")
        ttk.Button(btns, text="Renomear", width=9, command=self.rename_env).pack(side="left", padx=4)
        ttk.Button(btns, text="Excluir", width=7, command=self.delete_env).pack(side="left")

        # Painel de detalhes com largura fixa à direita; a tabela ocupa o resto.
        self.detail = ttk.Frame(body, padding=(16, 0, 0, 0), width=400)
        self.detail.pack(side="right", fill="y")
        self.detail.pack_propagate(False)

        center = ttk.Frame(body)
        center.pack(side="left", fill="both", expand=True)
        cols = [c[0] for c in self.COLUMNS]
        self.tree = ttk.Treeview(center, columns=cols, show="headings", selectmode="browse")
        for col, title, width in self.COLUMNS:
            self.tree.heading(col, text=title, command=lambda c=col: self._sort_by(c))
            self.tree.column(col, width=width, minwidth=60, stretch=col in ("name", "target"))
        scroll = ttk.Scrollbar(center, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="left", fill="y")
        self.empty_label = ttk.Label(center, style="Muted.TLabel", justify="center")
        self.tree.bind("<<TreeviewSelect>>", lambda e: self.show_detail(self._selected_key()))
        self.tree.bind("<Double-1>", lambda e: self.edit_entry() if self.tree.identify_row(e.y) else None)
        self.tree.bind("<Return>", lambda e: self.edit_entry())
        self.tree.bind("<Delete>", lambda e: self.delete_entry())

    def _build_statusbar(self) -> None:
        bar = ttk.Frame(self, padding=(10, 4))
        bar.pack(fill="x", side="bottom")
        self.status_var = tk.StringVar()
        self.lock_var = tk.StringVar()
        ttk.Label(bar, textvariable=self.status_var, style="Muted.TLabel").pack(side="left")
        ttk.Label(bar, textvariable=self.lock_var, style="Muted.TLabel").pack(side="right")

    # ---- status

    def set_status(self, message: str) -> None:
        self.status_var.set(message)
        if self._status_job:
            self.after_cancel(self._status_job)
        self._status_job = self.after(10_000, lambda: self.status_var.set(""))

    def show_lock_countdown(self, seconds: int) -> None:
        self.lock_var.set(f"Bloqueio automático em {seconds // 60}:{seconds % 60:02d}")

    # ---- dados

    def refresh(self, select: tuple[str, str] | None = None) -> None:
        if self.vault is None:
            return
        try:
            envs = self.vault.environments()
            entries = self.vault.list_entries()
        except VaultError as exc:
            messagebox.showerror(APP_NAME, str(exc), parent=self.app)
            return
        # Na lista só ficam campos não secretos; o segredo é lido de novo ao selecionar.
        self._rows = [{
            "env": e.environment, "name": e.name, "kind": e.kind, "target": target_of(e),
            "user": e.username, "updated": e.updated_at,
            "search": " ".join((e.name, e.environment, KIND_LABELS.get(e.kind, ""), e.host,
                                e.url, e.username, e.database)).casefold(),
        } for e in entries]
        del entries
        counts = Counter(r["env"] for r in self._rows)
        if self.selected_env not in envs:
            self.selected_env = None
        self._env_keys = [None] + envs
        self.env_list.delete(0, "end")
        self.env_list.insert("end", f"  Todos  ({len(self._rows)})")
        for env in envs:
            self.env_list.insert("end", f"  ●  {env}  ({counts.get(env, 0)})")
            self.env_list.itemconfig("end", foreground=env_color(env))
        self.env_list.selection_set(self._env_keys.index(self.selected_env))
        self.apply_filter(select)

    def apply_filter(self, select: tuple[str, str] | None = None) -> None:
        select = select or self._selected_key()
        query = self.search_var.get().strip().casefold()
        kind_idx = self.kind_filter.current()
        kind = KINDS[kind_idx - 1] if kind_idx > 0 else None
        rows = [r for r in self._rows
                if (self.selected_env is None or r["env"] == self.selected_env)
                and (kind is None or r["kind"] == kind)
                and (not query or query in r["search"])]
        col, reverse = self._sort
        rows.sort(key=lambda r: (r[col] or "").casefold() if col != "updated" else r[col],
                  reverse=reverse)

        self.tree.delete(*self.tree.get_children())
        self._iid_map.clear()
        target_iid = None
        for i, r in enumerate(rows):
            iid = f"r{i}"
            self._iid_map[iid] = (r["env"], r["name"])
            self.tree.insert("", "end", iid=iid, values=(
                r["name"], r["env"], KIND_LABELS.get(r["kind"], r["kind"]), r["target"],
                r["user"], fmt_time(r["updated"])))
            if select and (r["env"], r["name"]) == select:
                target_iid = iid
        for c, title, _ in self.COLUMNS:
            arrow = (" ▼" if reverse else " ▲") if c == col else ""
            self.tree.heading(c, text=title + arrow)

        if rows:
            self.empty_label.place_forget()
        else:
            text = ("Nenhum segredo encontrado para esse filtro." if (query or kind)
                    else "Nenhum segredo aqui ainda.\nClique em “＋ Novo segredo” para cadastrar.")
            self.empty_label.config(text=text)
            self.empty_label.place(relx=0.5, rely=0.3, anchor="center")
        if target_iid:
            self.tree.selection_set(target_iid)
            self.tree.see(target_iid)
        else:
            self.show_detail(None)

    def _sort_by(self, col: str) -> None:
        current, reverse = self._sort
        self._sort = (col, not reverse if col == current else col == "updated")
        self.apply_filter()

    def _selected_key(self) -> tuple[str, str] | None:
        sel = self.tree.selection()
        return self._iid_map.get(sel[0]) if sel else None

    def _on_env_select(self, _event=None) -> None:
        sel = self.env_list.curselection()
        if sel:
            self.selected_env = self._env_keys[sel[0]]
            self.apply_filter()

    # ---- painel de detalhes

    def show_detail(self, key: tuple[str, str] | None) -> None:
        for w in self.detail.winfo_children():
            w.destroy()
        for b in (self.btn_edit, self.btn_dup, self.btn_del):
            b.state(["!disabled"] if key else ["disabled"])
        if key is None or self.vault is None:
            ttk.Label(self.detail, text="Selecione um segredo para ver os detalhes.",
                      style="Muted.TLabel", wraplength=320).pack(anchor="nw", pady=24)
            return
        try:
            e = self.vault.get(*key)
        except VaultError as exc:
            messagebox.showerror(APP_NAME, str(exc), parent=self.app)
            return

        ttk.Label(self.detail, text=e.name, style="H2.TLabel", wraplength=340).pack(anchor="w")
        badges = ttk.Frame(self.detail)
        badges.pack(anchor="w", pady=(4, 6))
        tk.Label(badges, text=f" {e.environment} ", bg=env_color(e.environment), fg="white",
                 font=(FONT, 9, "bold")).pack(side="left")
        ttk.Label(badges, text="  " + KIND_LABELS.get(e.kind, e.kind), style="Muted.TLabel").pack(side="left")

        grid = ttk.Frame(self.detail)
        grid.pack(fill="x")
        grid.columnconfigure(0, weight=1)
        shown = 0
        for f in KIND_FIELDS.get(e.kind, list(FIELDS)):
            value = getattr(e, f)
            if value:
                self._detail_row(grid, field_label(e.kind, f), value, FIELDS[f][1])
                shown += 1
        for x in e.extras:
            self._detail_row(grid, x["key"], x["value"], x.get("secret", False))
            shown += 1
        if not shown:
            ttk.Label(grid, text="Nenhum campo preenchido.", style="Muted.TLabel").grid(sticky="w", pady=8)

        if e.notes:
            ttk.Label(self.detail, text="Observações", style="Field.TLabel").pack(anchor="w", pady=(12, 0))
            notes = tk.Text(self.detail, height=min(8, e.notes.count("\n") + 2), wrap="word",
                            relief="solid", borderwidth=1, font=(FONT, 10), padx=6, pady=4)
            notes.insert("1.0", e.notes)
            notes.config(state="disabled")
            notes.pack(fill="x")

        ttk.Label(self.detail, style="Muted.TLabel", font=(FONT, 9),
                  text=f"Criado em {fmt_time(e.created_at)}\nAtualizado em {fmt_time(e.updated_at)}"
                  ).pack(anchor="w", pady=(14, 0))

    def _detail_row(self, grid: ttk.Frame, label: str, value: str, secret: bool) -> None:
        row = grid.grid_size()[1]
        ttk.Label(grid, text=label, style="Field.TLabel").grid(row=row, column=0, columnspan=3,
                                                              sticky="w", pady=(8, 0))
        # Sem exportselection: o texto não vai para a seleção PRIMARY do sistema.
        ent = ttk.Entry(grid, exportselection=False, show="•" if secret else "",
                        font=(MONO, 10) if secret else (FONT, 10))
        ent.insert(0, value)
        ent.state(["readonly"])
        ent.grid(row=row + 1, column=0, sticky="ew", ipady=2)
        if secret:
            btn = ttk.Button(grid, text="Mostrar", width=8)
            btn.config(command=lambda: self._toggle_reveal(ent, btn))
            btn.grid(row=row + 1, column=1, padx=(4, 0))
        ttk.Button(grid, text="Copiar", width=7,
                   command=lambda: self.app.copy_to_clipboard(value, label)
                   ).grid(row=row + 1, column=2, padx=(4, 0))

    def _toggle_reveal(self, ent: ttk.Entry, btn: ttk.Button) -> None:
        def hide():
            try:
                ent.config(show="•")
                btn.config(text="Mostrar")
            except tk.TclError:
                pass  # o painel já foi redesenhado
        if ent.cget("show"):
            ent.config(show="")
            btn.config(text="Ocultar")
            self.after(REVEAL_SECONDS * 1000, hide)
        else:
            hide()

    # ---- ações sobre segredos

    def new_entry(self) -> None:
        envs = self.vault.environments()
        kind_idx = self.kind_filter.current()
        entry = Entry(name="", environment=self.selected_env or envs[0],
                      kind=KINDS[kind_idx - 1] if kind_idx > 0 else "ftp")
        EntryDialog(self.app, envs, entry, "Novo segredo", self._save_new)

    def _save_new(self, entry: Entry) -> None:
        saved = self.vault.add(entry)
        self.refresh(select=(saved.environment, saved.name))
        self.set_status(f"Segredo “{saved.name}” criado em {saved.environment}.")

    def edit_entry(self) -> None:
        key = self._selected_key()
        if not key:
            return
        entry = self.vault.get(*key)

        def save(new: Entry) -> None:
            saved = self.vault.update(key[0], key[1], new)
            self.refresh(select=(saved.environment, saved.name))
            self.set_status(f"Segredo “{saved.name}” atualizado.")

        EntryDialog(self.app, self.vault.environments(), entry, f"Editar — {entry.name}", save)

    def duplicate_entry(self) -> None:
        key = self._selected_key()
        if not key:
            return
        envs = self.vault.environments()
        entry = self.vault.get(*key)
        others = [e for e in envs if e != entry.environment]
        copy = replace(entry, environment=others[0] if others else entry.environment,
                       name=entry.name if others else f"{entry.name} (cópia)",
                       extras=[dict(x) for x in entry.extras], created_at="", updated_at="")
        EntryDialog(self.app, envs, copy, "Duplicar segredo", self._save_new,
                    hint="Cópia de um segredo existente. Ajuste o ambiente e os valores "
                         "(ex.: credenciais de homologação → produção).")

    def delete_entry(self) -> None:
        key = self._selected_key()
        if not key:
            return
        env, name = key
        warning = "\n\n⚠ Este segredo é do ambiente de PRODUÇÃO." if is_production(env) else ""
        if not messagebox.askyesno("Excluir segredo",
                                   f"Excluir “{name}” do ambiente “{env}”?\n"
                                   f"Esta ação não pode ser desfeita.{warning}",
                                   icon="warning", default="no", parent=self.app):
            return
        if self.vault is None:
            return
        try:
            self.vault.delete(env, name)
        except VaultError as exc:
            messagebox.showerror(APP_NAME, str(exc), parent=self.app)
            return
        self.refresh()
        self.set_status(f"Segredo “{name}” excluído.")

    # ---- ambientes

    def add_env(self) -> None:
        name = simpledialog.askstring("Novo ambiente", "Nome do ambiente\n(ex.: Produção, "
                                      "Homologação, Cliente X):", parent=self.app)
        if not name or self.vault is None:
            return
        try:
            self.selected_env = self.vault.add_environment(name)
        except VaultError as exc:
            messagebox.showerror(APP_NAME, str(exc), parent=self.app)
            return
        self.refresh()

    def rename_env(self) -> None:
        if self.selected_env is None:
            messagebox.showinfo(APP_NAME, "Selecione um ambiente na lista à esquerda.", parent=self.app)
            return
        old = self.selected_env
        new = simpledialog.askstring("Renomear ambiente", f"Novo nome para “{old}”:",
                                     initialvalue=old, parent=self.app)
        if not new or self.vault is None:
            return
        try:
            self.selected_env = self.vault.rename_environment(old, new)
        except VaultError as exc:
            messagebox.showerror(APP_NAME, str(exc), parent=self.app)
            return
        self.refresh()

    def delete_env(self) -> None:
        env = self.selected_env
        if env is None:
            messagebox.showinfo(APP_NAME, "Selecione um ambiente na lista à esquerda.", parent=self.app)
            return
        if not messagebox.askyesno("Excluir ambiente", f"Excluir o ambiente “{env}”?",
                                   default="no", parent=self.app) or self.vault is None:
            return
        try:
            self.vault.delete_environment(env)
        except VaultError as exc:
            messagebox.showerror(APP_NAME, str(exc), parent=self.app)
            return
        self.selected_env = None
        self.refresh()

    # ---- cofre

    def change_master(self) -> None:
        ChangePasswordDialog(self.app)

    def about(self) -> None:
        messagebox.showinfo(f"Sobre o {APP_NAME}",
                            f"{APP_NAME}\nVersão {__version__}\n\n"
                            f"Cofre local e criptografado (AES-256-GCM + scrypt).\n"
                            f"Arquivo aberto:\n{self.vault.path if self.vault else '-'}",
                            parent=self.app)

    def backup(self) -> None:
        dest = filedialog.asksaveasfilename(
            parent=self.app, title="Salvar backup do cofre", defaultextension=".db",
            initialfile=f"cofre-backup-{datetime.now():%Y%m%d-%H%M}.db",
            filetypes=[("Cofre", "*.db"), ("Todos os arquivos", "*.*")])
        if not dest or self.vault is None:
            return
        try:
            self.vault.backup(dest, overwrite=True)  # o diálogo já confirmou a substituição
        except (VaultError, OSError) as exc:
            messagebox.showerror(APP_NAME, f"Falha no backup: {exc}", parent=self.app)
            return
        messagebox.showinfo(APP_NAME, f"Backup salvo em:\n{dest}\n\nEle continua criptografado "
                            "e abre com a senha mestra ATUAL.", parent=self.app)


# ================================================================ diálogos

class EntryDialog(tk.Toplevel):
    """Cadastro/edição de um segredo. on_save recebe o Entry; VaultError mantém o diálogo aberto."""

    def __init__(self, app: App, environments: list[str], entry: Entry, title: str,
                 on_save, hint: str = ""):
        super().__init__(app)
        self.app = app
        self.on_save = on_save
        self.original = entry
        self.extras = [dict(x) for x in entry.extras]
        self.title(title)
        self.transient(app)
        self.resizable(True, False)
        self.minsize(600, 0)

        body = ttk.Frame(self, padding=18)
        body.pack(fill="both", expand=True)
        body.columnconfigure(1, weight=1)
        r = 0
        if hint:
            ttk.Label(body, text=hint, style="Muted.TLabel", wraplength=540).grid(
                row=r, column=0, columnspan=3, sticky="w", pady=(0, 10))
            r += 1

        ttk.Label(body, text="Nome *").grid(row=r, column=0, sticky="w", pady=4)
        self.name = ttk.Entry(body)
        self.name.insert(0, entry.name)
        self.name.grid(row=r, column=1, columnspan=2, sticky="ew", pady=4)
        r += 1
        ttk.Label(body, text="Ambiente *").grid(row=r, column=0, sticky="w", pady=4)
        self.env = ttk.Combobox(body, state="readonly", values=environments)
        self.env.set(entry.environment if entry.environment in environments else environments[0])
        self.env.grid(row=r, column=1, columnspan=2, sticky="ew", pady=4)
        r += 1
        ttk.Label(body, text="Tipo *").grid(row=r, column=0, sticky="w", pady=4)
        self.kind = ttk.Combobox(body, state="readonly", values=[KIND_LABELS[k] for k in KINDS])
        self.kind.current(KINDS.index(entry.kind) if entry.kind in KINDS else len(KINDS) - 1)
        self.kind.bind("<<ComboboxSelected>>", lambda e: self._on_kind_change())
        self.kind.grid(row=r, column=1, columnspan=2, sticky="ew", pady=4)
        r += 1
        ttk.Separator(body).grid(row=r, column=0, columnspan=3, sticky="ew", pady=10)
        r += 1

        self.inputs: dict[str, ttk.Entry] = {}
        self.rows: dict[str, list[tk.Widget]] = {}
        for f, (label, secret) in FIELDS.items():
            lbl = ttk.Label(body, text=label)
            lbl.grid(row=r, column=0, sticky="w", pady=4, padx=(0, 12))
            ent = ttk.Entry(body, show="•" if secret else "", font=(MONO, 10) if secret else (FONT, 10))
            ent.insert(0, getattr(entry, f))
            ent.grid(row=r, column=1, sticky="ew", pady=4)
            widgets: list[tk.Widget] = [lbl, ent]
            if secret:
                tools = ttk.Frame(body)
                tools.grid(row=r, column=2, sticky="w", padx=(4, 0))
                show = ttk.Button(tools, text="👁", width=3)
                show.config(command=lambda e=ent: e.config(show="" if e.cget("show") else "•"))
                show.pack(side="left")
                if f == "password":
                    ttk.Button(tools, text="Gerar", width=6,
                               command=lambda e=ent: self._generate(e)).pack(side="left", padx=(2, 0))
                widgets.append(tools)
            self.inputs[f] = ent
            self.rows[f] = widgets
            r += 1

        ttk.Label(body, text="Campos extras").grid(row=r, column=0, sticky="nw", pady=(10, 4))
        extras = ttk.Frame(body)
        extras.grid(row=r, column=1, columnspan=2, sticky="ew", pady=(10, 4))
        extras.columnconfigure(0, weight=1)
        self.extras_tree = ttk.Treeview(extras, columns=("key", "value"), show="headings",
                                        height=3, selectmode="browse")
        self.extras_tree.heading("key", text="Campo")
        self.extras_tree.heading("value", text="Valor")
        self.extras_tree.column("key", width=150)
        self.extras_tree.column("value", width=280)
        self.extras_tree.grid(row=0, column=0, sticky="ew")
        self.extras_tree.bind("<Double-1>", lambda e: self._edit_extra())
        xb = ttk.Frame(extras)
        xb.grid(row=0, column=1, sticky="n", padx=(6, 0))
        ttk.Button(xb, text="Adicionar", command=self._add_extra).pack(fill="x")
        ttk.Button(xb, text="Editar", command=self._edit_extra).pack(fill="x", pady=2)
        ttk.Button(xb, text="Remover", command=self._remove_extra).pack(fill="x")
        r += 1

        ttk.Label(body, text="Observações").grid(row=r, column=0, sticky="nw", pady=(10, 4))
        self.notes = tk.Text(body, height=4, wrap="word", relief="solid", borderwidth=1,
                             font=(FONT, 10), padx=6, pady=4)
        self.notes.insert("1.0", entry.notes)
        self.notes.grid(row=r, column=1, columnspan=2, sticky="ew", pady=(10, 4))
        r += 1
        ttk.Label(body, text="Não coloque senhas nas observações: elas não são mascaradas na tela.",
                  style="Field.TLabel").grid(row=r, column=1, columnspan=2, sticky="w")
        r += 1

        buttons = ttk.Frame(body)
        buttons.grid(row=r, column=0, columnspan=3, sticky="e", pady=(16, 0))
        ttk.Button(buttons, text="Cancelar", command=self.destroy).pack(side="right")
        ttk.Button(buttons, text="Salvar", command=self.save).pack(side="right", padx=(0, 6))

        self._render_extras()
        self._on_kind_change(initial=True)
        self.bind("<Escape>", lambda e: self.destroy())
        self.bind("<Control-s>", lambda e: self.save())
        for ent in [self.name, *self.inputs.values()]:
            ent.bind("<Return>", lambda e: self.save())
        center_on(self, app)
        self.grab_set()
        self.name.focus_set()

    def _current_kind(self) -> str:
        return KINDS[self.kind.current()]

    def _on_kind_change(self, initial: bool = False) -> None:
        kind = self._current_kind()
        visible = KIND_FIELDS[kind]
        for f, widgets in self.rows.items():
            for w in widgets:
                w.grid() if f in visible else w.grid_remove()
            widgets[0].config(text=field_label(kind, f))
        port = self.inputs["port"]
        if not initial and not port.get() and kind in DEFAULT_PORTS:
            port.insert(0, DEFAULT_PORTS[kind])

    def _generate(self, ent: ttk.Entry) -> None:
        if ent.get() and not messagebox.askyesno("Gerar senha", "Substituir a senha atual?",
                                                 parent=self):
            return
        ent.delete(0, "end")
        ent.insert(0, generate_password(24))
        ent.config(show="")

    # ---- campos extras

    def _render_extras(self) -> None:
        self.extras_tree.delete(*self.extras_tree.get_children())
        for i, x in enumerate(self.extras):
            shown = "•" * 10 + "  (secreto)" if x.get("secret") else x.get("value", "")
            self.extras_tree.insert("", "end", iid=str(i), values=(x["key"], shown.replace("\n", " ")))

    def _add_extra(self) -> None:
        result = ExtraDialog(self).result
        if result and self.winfo_exists():
            self.extras.append(result)
            self._render_extras()

    def _edit_extra(self) -> None:
        sel = self.extras_tree.selection()
        if not sel:
            return
        i = int(sel[0])
        result = ExtraDialog(self, self.extras[i]).result
        if result and self.winfo_exists():
            self.extras[i] = result
            self._render_extras()

    def _remove_extra(self) -> None:
        sel = self.extras_tree.selection()
        if sel:
            del self.extras[int(sel[0])]
            self._render_extras()

    # ---- salvar

    def save(self) -> None:
        kind = self._current_kind()
        # Só os campos do tipo escolhido são gravados: nada de valores "escondidos".
        values = {f: (self.inputs[f].get() if f in KIND_FIELDS[kind] else "") for f in FIELDS}
        entry = Entry(name=self.name.get(), environment=self.env.get(), kind=kind,
                      notes=self.notes.get("1.0", "end-1c"), extras=[dict(x) for x in self.extras],
                      created_at=self.original.created_at, **values)
        if is_production(entry.environment) and self.original.environment != entry.environment \
                and self.original.updated_at:
            if not messagebox.askyesno("Mover para produção",
                                       f"Mover “{entry.name}” para o ambiente {entry.environment}?",
                                       parent=self):
                return
        try:
            self.on_save(entry)
        except VaultError as exc:
            messagebox.showerror("Não foi possível salvar", str(exc), parent=self)
            return
        self.destroy()


class ExtraDialog(tk.Toplevel):
    def __init__(self, parent: tk.Toplevel, extra: dict | None = None):
        super().__init__(parent)
        self.result: dict | None = None
        extra = extra or {"key": "", "value": "", "secret": True}
        self.title("Campo extra")
        self.transient(parent)
        self.resizable(False, False)
        body = ttk.Frame(self, padding=16)
        body.pack(fill="both", expand=True)
        body.columnconfigure(1, weight=1)
        ttk.Label(body, text="Nome do campo").grid(row=0, column=0, sticky="w", pady=4)
        self.key = ttk.Entry(body, width=40)
        self.key.insert(0, extra["key"])
        self.key.grid(row=0, column=1, sticky="ew", pady=4)
        ttk.Label(body, text="Valor").grid(row=1, column=0, sticky="w", pady=4, padx=(0, 10))
        self.value = ttk.Entry(body, width=40)
        self.value.insert(0, extra["value"])
        self.value.grid(row=1, column=1, sticky="ew", pady=4)
        self.secret = tk.BooleanVar(value=bool(extra.get("secret")))
        ttk.Checkbutton(body, text="Valor secreto (mascarar na tela)", variable=self.secret,
                        command=self._apply_mask).grid(row=2, column=1, sticky="w", pady=4)
        buttons = ttk.Frame(body)
        buttons.grid(row=3, column=0, columnspan=2, sticky="e", pady=(10, 0))
        ttk.Button(buttons, text="Cancelar", command=self.destroy).pack(side="right")
        ttk.Button(buttons, text="OK", command=self.ok).pack(side="right", padx=(0, 6))
        self._apply_mask()
        self.bind("<Return>", lambda e: self.ok())
        self.bind("<Escape>", lambda e: self.destroy())
        center_on(self, parent)
        self.grab_set()
        self.key.focus_set()
        self.wait_window()
        if parent.winfo_exists():
            parent.grab_set()

    def _apply_mask(self) -> None:
        self.value.config(show="•" if self.secret.get() else "")

    def ok(self) -> None:
        if not self.key.get().strip():
            messagebox.showerror("Campo extra", "Informe o nome do campo.", parent=self)
            return
        self.result = {"key": self.key.get().strip(), "value": self.value.get(),
                       "secret": self.secret.get()}
        self.destroy()


class GeneratorDialog(tk.Toplevel):
    def __init__(self, app: App):
        super().__init__(app)
        self.app = app
        self.title("Gerador de senhas")
        self.transient(app)
        self.resizable(False, False)
        body = ttk.Frame(self, padding=18)
        body.pack(fill="both", expand=True)
        self.output = ttk.Entry(body, width=44, font=(MONO, 12), exportselection=False)
        self.output.grid(row=0, column=0, columnspan=4, sticky="ew")
        self.strength = ttk.Label(body, font=(FONT, 9))
        self.strength.grid(row=1, column=0, columnspan=4, sticky="w", pady=(4, 10))
        ttk.Label(body, text="Tamanho").grid(row=2, column=0, sticky="w")
        self.length = tk.IntVar(value=24)
        ttk.Spinbox(body, from_=8, to=128, textvariable=self.length, width=5,
                    command=self.generate).grid(row=2, column=1, sticky="w", padx=(6, 16))
        self.symbols = tk.BooleanVar(value=True)
        ttk.Checkbutton(body, text="Incluir símbolos", variable=self.symbols,
                        command=self.generate).grid(row=2, column=2, sticky="w")
        buttons = ttk.Frame(body)
        buttons.grid(row=3, column=0, columnspan=4, sticky="e", pady=(14, 0))
        ttk.Button(buttons, text="Fechar", command=self.destroy).pack(side="right")
        ttk.Button(buttons, text="Copiar", command=self.copy).pack(side="right", padx=6)
        ttk.Button(buttons, text="Gerar outra", command=self.generate).pack(side="right")
        self.bind("<Escape>", lambda e: self.destroy())
        self.generate()
        center_on(self, app)

    def generate(self) -> None:
        try:
            length = max(8, min(128, int(self.length.get())))
        except (tk.TclError, ValueError):
            length = 24
        pw = generate_password(length, self.symbols.get())
        self.output.delete(0, "end")
        self.output.insert(0, pw)
        text, color = password_strength(pw)
        self.strength.config(text=text, foreground=color)

    def copy(self) -> None:
        self.app.copy_to_clipboard(self.output.get(), "Senha gerada")


class ChangePasswordDialog(tk.Toplevel):
    def __init__(self, app: App):
        super().__init__(app)
        self.app = app
        self.title("Trocar senha mestra")
        self.transient(app)
        self.resizable(False, False)
        body = ttk.Frame(self, padding=18)
        body.pack(fill="both", expand=True)
        self.fields = []
        for i, label in enumerate(("Senha mestra atual", "Nova senha mestra", "Confirme a nova senha")):
            ttk.Label(body, text=label, style="Field.TLabel").grid(row=i * 2, column=0, sticky="w",
                                                                  pady=(8 if i else 0, 0))
            ent = ttk.Entry(body, show="•", width=44)
            ent.grid(row=i * 2 + 1, column=0, sticky="ew", ipady=2)
            ent.bind("<Return>", lambda e: self.ok())
            self.fields.append(ent)
        self.fields[1].bind("<KeyRelease>", self._update_strength)
        self.strength = ttk.Label(body, font=(FONT, 9))
        self.strength.grid(row=6, column=0, sticky="w", pady=(4, 0))
        ttk.Label(body, style="Muted.TLabel", wraplength=380, justify="left",
                  text="Todo o cofre será recriptografado com uma chave nova. Backups feitos "
                       "antes continuam abrindo apenas com a senha antiga."
                  ).grid(row=7, column=0, sticky="w", pady=(10, 0))
        self.msg = ttk.Label(body, style="Error.TLabel", wraplength=380)
        self.msg.grid(row=8, column=0, sticky="w", pady=(6, 0))
        buttons = ttk.Frame(body)
        buttons.grid(row=9, column=0, sticky="e", pady=(12, 0))
        ttk.Button(buttons, text="Cancelar", command=self.destroy).pack(side="right")
        ttk.Button(buttons, text="Trocar senha", command=self.ok).pack(side="right", padx=(0, 6))
        self.bind("<Escape>", lambda e: self.destroy())
        center_on(self, app)
        self.grab_set()
        self.fields[0].focus_set()

    def _update_strength(self, _event=None) -> None:
        text, color = password_strength(self.fields[1].get())
        self.strength.config(text=text, foreground=color)

    def ok(self) -> None:
        old, new, confirm = (f.get() for f in self.fields)
        if new != confirm:
            self.msg.config(text="A nova senha e a confirmação não conferem.")
            return
        if self.app.vault is None:
            return
        self.config(cursor="watch")
        self.update_idletasks()
        try:
            self.app.vault.change_master_password(old, new)
        except VaultError as exc:
            self.msg.config(text=str(exc))
            return
        finally:
            if self.winfo_exists():
                self.config(cursor="")
        self.destroy()
        messagebox.showinfo(APP_NAME, "Senha mestra alterada e cofre recriptografado.",
                            parent=self.app)


def main() -> None:
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)  # texto nítido em telas HiDPI
        except Exception:
            pass
    App(sys.argv[1] if len(sys.argv) > 1 else None).mainloop()


if __name__ == "__main__":
    main()
