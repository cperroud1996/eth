import json
import os
import string
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from eth_account import Account
from eth_account.messages import encode_defunct

Account.enable_unaudited_hdwallet_features()

REVEAL_DURATION_MS = 15_000
MIN_KEYSTORE_PASSWORD_LENGTH = 12
MAX_SIGNING_MESSAGE_LENGTH = 4_096

active_account = None
root = None
address_var = None
private_key_entry = None
private_key_display = None
output_text = None
status_label = None
reveal_timer_id = None


def set_status(message, color="#1f2937"):
    status_label.config(text=message, foreground=color)


def write_activity(message, replace=False):
    output_text.config(state="normal")
    if replace:
        output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"{message}\n")
    output_text.config(state="disabled")


def normalize_private_key(value):
    candidate = value.strip()
    if candidate.lower().startswith("0x"):
        candidate = candidate[2:]

    if len(candidate) != 64 or any(character not in string.hexdigits for character in candidate):
        raise ValueError("A private key must contain exactly 64 hexadecimal characters.")

    return bytes.fromhex(candidate)


def validate_private_key_input(proposed):
    if not proposed:
        return True
    if len(proposed) > 66:
        return False

    if proposed.lower().startswith("0x"):
        proposed = proposed[2:]

    return all(character in string.hexdigits for character in proposed)


def hide_private_key():
    global reveal_timer_id
    if root is not None and reveal_timer_id is not None:
        try:
            root.after_cancel(reveal_timer_id)
        except tk.TclError:
            pass
        reveal_timer_id = None

    private_key_display.config(state="normal", show="")
    private_key_display.delete(0, tk.END)
    private_key_display.config(state="readonly", show="")


def set_wallet_info(account):
    address_var.set(account.address)
    hide_private_key()
    set_status("Wallet ready. The private key remains hidden.", "#0f766e")


def create_new_wallet():
    global active_account
    active_account = Account.create()
    set_wallet_info(active_account)
    write_activity(
        "New wallet created. Export an encrypted keystore before closing the app.",
        replace=True,
    )


def import_wallet():
    global active_account
    try:
        key_bytes = normalize_private_key(private_key_entry.get())
        active_account = Account.from_key(key_bytes)
    except ValueError:
        messagebox.showerror(
            "Import Wallet",
            "Enter a valid 32-byte hexadecimal private key.",
        )
        return

    private_key_entry.delete(0, tk.END)
    set_wallet_info(active_account)
    write_activity("Wallet imported. The supplied private key was cleared from the input field.", replace=True)


def clear_wallet():
    global active_account
    active_account = None
    address_var.set("")
    private_key_entry.delete(0, tk.END)
    hide_private_key()
    write_activity("Wallet cleared from this session.", replace=True)
    set_status("No wallet loaded.")


def reveal_private_key():
    global reveal_timer_id
    if not active_account:
        messagebox.showwarning("Reveal Private Key", "Create or import a wallet first.")
        return

    confirmed = messagebox.askyesno(
        "Reveal Private Key",
        "Anyone who sees this key can control the wallet. Reveal it for 15 seconds?",
        icon="warning",
    )
    if not confirmed:
        return

    private_key_display.config(state="normal", show="")
    private_key_display.delete(0, tk.END)
    private_key_display.insert(0, active_account.key.hex())
    private_key_display.config(state="readonly")
    set_status("Private key shown temporarily; it will be hidden in 15 seconds.", "#b45309")
    if reveal_timer_id is not None:
        try:
            root.after_cancel(reveal_timer_id)
        except tk.TclError:
            pass
    reveal_timer_id = root.after(REVEAL_DURATION_MS, hide_private_key)


def export_keystore():
    if not active_account:
        messagebox.showwarning("Export Keystore", "Create or import a wallet first.")
        return

    password = simpledialog.askstring(
        "Keystore Password",
        f"Create an encryption password (at least {MIN_KEYSTORE_PASSWORD_LENGTH} characters):",
        show="*",
    )
    if password is None:
        return
    if len(password) < MIN_KEYSTORE_PASSWORD_LENGTH:
        messagebox.showwarning(
            "Keystore Password",
            f"Use at least {MIN_KEYSTORE_PASSWORD_LENGTH} characters to encrypt the keystore.",
        )
        return

    confirmation = simpledialog.askstring(
        "Confirm Keystore Password",
        "Enter the encryption password again:",
        show="*",
    )
    if confirmation is None:
        return
    if password != confirmation:
        messagebox.showerror("Keystore Password", "The passwords do not match.")
        return

    try:
        keystore = Account.encrypt(active_account.key, password)
    except Exception as exc:
        messagebox.showerror("Export Keystore", f"Failed to encrypt keystore: {exc}")
        return

    default_name = f"keystore-{active_account.address}.json"
    file_path = filedialog.asksaveasfilename(
        title="Save encrypted keystore locally",
        defaultextension=".json",
        filetypes=[("JSON files", "*.json")],
        initialfile=default_name,
    )
    if not file_path:
        return

    try:
        file_descriptor = os.open(
            Path(file_path),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as keystore_file:
            json.dump(keystore, keystore_file, indent=2)
    except FileExistsError:
        messagebox.showerror(
            "Save Keystore",
            "That file already exists. Choose a new filename to avoid overwriting it.",
        )
        return
    except OSError as exc:
        messagebox.showerror("Save Keystore", f"Failed to save keystore: {exc}")
        return

    write_activity("Encrypted keystore saved locally.")
    set_status("Encrypted keystore exported locally.", "#0f766e")


def sign_message():
    if not active_account:
        messagebox.showwarning("Sign Message", "Create or import a wallet first.")
        return

    message = simpledialog.askstring("Sign Message", "Enter the text message to sign:")
    if message is None or not message.strip():
        return
    if len(message) > MAX_SIGNING_MESSAGE_LENGTH:
        messagebox.showerror(
            "Sign Message",
            f"Messages must be {MAX_SIGNING_MESSAGE_LENGTH:,} characters or fewer.",
        )
        return

    try:
        signed = Account.sign_message(encode_defunct(text=message), active_account.key)
        message_hash = getattr(signed, "message_hash", None)
        if message_hash is None:
            message_hash = signed.messageHash
    except Exception as exc:
        messagebox.showerror("Sign Message", f"Failed to sign message: {exc}")
        return

    write_activity(
        f"Message signed.\nSignature: {signed.signature.hex()}\nMessage hash: {message_hash.hex()}",
        replace=True,
    )
    set_status("Message signed locally.", "#0f766e")


def copy_address():
    if not active_account:
        messagebox.showwarning("Copy Address", "Create or import a wallet first.")
        return

    root.clipboard_clear()
    root.clipboard_append(active_account.address)
    set_status("Wallet address copied to clipboard.", "#0f766e")


def build_app():
    global root, address_var, private_key_entry, private_key_display, output_text, status_label

    root = tk.Tk()
    root.title("Ethereum Wallet Creator")
    root.configure(background="#eef2f7")

    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("App.TFrame", background="#eef2f7")
    style.configure("Card.TFrame", background="#ffffff")
    style.configure("Title.TLabel", background="#11243a", foreground="#ffffff", font=("Segoe UI", 24, "bold"))
    style.configure("Subtitle.TLabel", background="#11243a", foreground="#bfdbfe", font=("Segoe UI", 11))
    style.configure("Section.TLabel", background="#ffffff", foreground="#11243a", font=("Segoe UI", 12, "bold"))
    style.configure("Hint.TLabel", background="#ffffff", foreground="#52616b", font=("Segoe UI", 10))
    style.configure("Status.TLabel", background="#eef2f7", font=("Segoe UI", 10))
    style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"), padding=(14, 9))
    style.configure("Secondary.TButton", font=("Segoe UI", 10), padding=(14, 9))
    style.map("Primary.TButton", background=[("active", "#0f766e"), ("!active", "#0f766e")], foreground=[("!disabled", "white")])

    address_var = tk.StringVar()

    shell = ttk.Frame(root, style="App.TFrame", padding=20)
    shell.pack(fill=tk.BOTH, expand=True)

    header = ttk.Frame(shell, style="Card.TFrame", padding=0)
    header.pack(fill=tk.X)
    header.configure(style="Card.TFrame")
    header_canvas = tk.Frame(header, background="#11243a", padx=24, pady=20)
    header_canvas.pack(fill=tk.X)
    ttk.Label(header_canvas, text="Ethereum Wallet Creator", style="Title.TLabel").pack(anchor="w")
    ttk.Label(
        header_canvas,
        text="A local desktop utility for wallet creation, encrypted backups, and message signing.",
        style="Subtitle.TLabel",
    ).pack(anchor="w", pady=(4, 0))

    content = ttk.Frame(shell, style="App.TFrame")
    content.pack(fill=tk.BOTH, expand=True, pady=(16, 0))
    content.columnconfigure(0, weight=3)
    content.columnconfigure(1, weight=2)
    content.rowconfigure(0, weight=1)

    wallet_card = ttk.Frame(content, style="Card.TFrame", padding=22)
    wallet_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
    wallet_card.columnconfigure(0, weight=1)

    ttk.Label(wallet_card, text="Wallet", style="Section.TLabel").grid(row=0, column=0, sticky="w")
    ttk.Label(
        wallet_card,
        text="Private keys are never sent anywhere by this application.",
        style="Hint.TLabel",
    ).grid(row=1, column=0, sticky="w", pady=(4, 16))

    actions = ttk.Frame(wallet_card, style="Card.TFrame")
    actions.grid(row=2, column=0, sticky="ew", pady=(0, 20))
    actions.columnconfigure((0, 1), weight=1)
    ttk.Button(actions, text="Create New Wallet", command=create_new_wallet, style="Primary.TButton").grid(row=0, column=0, sticky="ew", padx=(0, 6), pady=4)
    ttk.Button(actions, text="Import Private Key", command=import_wallet, style="Secondary.TButton").grid(row=0, column=1, sticky="ew", padx=(6, 0), pady=4)
    ttk.Button(actions, text="Export Encrypted Keystore", command=export_keystore, style="Secondary.TButton").grid(row=1, column=0, sticky="ew", padx=(0, 6), pady=4)
    ttk.Button(actions, text="Sign Message", command=sign_message, style="Secondary.TButton").grid(row=1, column=1, sticky="ew", padx=(6, 0), pady=4)

    ttk.Label(wallet_card, text="Private key to import", style="Section.TLabel").grid(row=3, column=0, sticky="w")
    ttk.Label(
        wallet_card,
        text="Only a 64-character hexadecimal key (optionally prefixed with 0x) is accepted.",
        style="Hint.TLabel",
    ).grid(row=4, column=0, sticky="w", pady=(4, 6))
    validation_command = (root.register(validate_private_key_input), "%P")
    private_key_entry = ttk.Entry(wallet_card, show="•", validate="key", validatecommand=validation_command)
    private_key_entry.grid(row=5, column=0, sticky="ew", pady=(0, 20))

    ttk.Label(wallet_card, text="Wallet address", style="Section.TLabel").grid(row=6, column=0, sticky="w")
    address_row = ttk.Frame(wallet_card, style="Card.TFrame")
    address_row.grid(row=7, column=0, sticky="ew", pady=(6, 14))
    address_row.columnconfigure(0, weight=1)
    ttk.Entry(address_row, textvariable=address_var, state="readonly").grid(row=0, column=0, sticky="ew", padx=(0, 8))
    ttk.Button(address_row, text="Copy Address", command=copy_address, style="Secondary.TButton").grid(row=0, column=1)

    ttk.Label(wallet_card, text="Private key", style="Section.TLabel").grid(row=8, column=0, sticky="w")
    key_row = ttk.Frame(wallet_card, style="Card.TFrame")
    key_row.grid(row=9, column=0, sticky="ew", pady=(6, 0))
    key_row.columnconfigure(0, weight=1)
    private_key_display = ttk.Entry(key_row, state="readonly")
    private_key_display.grid(row=0, column=0, sticky="ew", padx=(0, 8))
    ttk.Button(key_row, text="Reveal for 15s", command=reveal_private_key, style="Secondary.TButton").grid(row=0, column=1)

    activity_card = ttk.Frame(content, style="Card.TFrame", padding=22)
    activity_card.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
    activity_card.columnconfigure(0, weight=1)
    activity_card.rowconfigure(2, weight=1)
    ttk.Label(activity_card, text="Activity", style="Section.TLabel").grid(row=0, column=0, sticky="w")
    ttk.Label(
        activity_card,
        text="Only non-secret status and signing results appear here.",
        style="Hint.TLabel",
    ).grid(row=1, column=0, sticky="w", pady=(4, 12))
    output_text = tk.Text(
        activity_card,
        height=16,
        wrap=tk.WORD,
        state="disabled",
        background="#f8fafc",
        foreground="#1f2937",
        relief=tk.FLAT,
        padx=12,
        pady=12,
        font=("Consolas", 10),
    )
    output_text.grid(row=2, column=0, sticky="nsew")
    ttk.Button(activity_card, text="Clear Session", command=clear_wallet, style="Secondary.TButton").grid(row=3, column=0, sticky="ew", pady=(14, 0))

    status_label = tk.Label(
        shell,
        text="No wallet loaded.",
        background="#eef2f7",
        foreground="#1f2937",
        anchor="w",
        font=("Segoe UI", 10),
    )
    status_label.pack(fill=tk.X, pady=(14, 0))

    root.update_idletasks()
    required_width = root.winfo_reqwidth()
    required_height = root.winfo_reqheight()
    root.minsize(required_width, required_height)
    root.geometry(f"{max(920, required_width)}x{max(670, required_height)}")
    return root


def main():
    app = build_app()
    app.mainloop()


if __name__ == "__main__":
    main()
