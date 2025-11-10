import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext
import vault  # make sure vault.py is in the same folder


# ---------- Helper ----------
def ask_shares(threshold):
    """GUI popup for pasting shares (one per line)."""
    root = tk.Toplevel()
    root.title("Enter Shares")

    tk.Label(root, text=f"Paste at least {threshold} shares (one per line):").pack(pady=5)
    txt = scrolledtext.ScrolledText(root, width=60, height=10)
    txt.pack(padx=10, pady=10)

    result = []

    def on_ok():
        shares = txt.get("1.0", tk.END).strip().splitlines()
        if len(shares) < threshold:
            messagebox.showerror("Error", f"You must enter at least {threshold} shares.")
            return

        unwrapped = []
        for s in shares:
            try:
                def gui_prompt():
                    return simpledialog.askstring(
                        "Passphrase Required",
                        "Enter passphrase for this wrapped share:",
                        show="*"
                    )
                unwrapped.append(vault.unwrap_share_if_needed(s, gui_prompt))
            except Exception as e:
                messagebox.showerror("Error", f"Failed to unwrap share: {e}")
                return
        result.extend(unwrapped)
        root.destroy()

    tk.Button(root, text="OK", command=on_ok).pack(pady=5)
    root.wait_window()
    return result



# ---------- Actions ----------
def init_vault():
    threshold = simpledialog.askinteger("Init Vault", "Threshold (e.g., 2):", minvalue=1)
    total = simpledialog.askinteger("Init Vault", "Total shares (e.g., 3):", minvalue=threshold)
    if threshold and total:
        wrap = messagebox.askyesno("Wrap Shares", "Protect each share with passphrases?")
        try:
            vault.create_vault(threshold, total, wrap)
            messagebox.showinfo(
                "Success",
                f"Vault created with {threshold}-of-{total} shares.\n\n"
                f"Shares are printed in the Run console — copy them out securely."
            )
        except Exception as e:
            messagebox.showerror("Error", str(e))


def add_entry():
    meta = vault.load_meta()
    shares = ask_shares(meta["threshold"])
    site = simpledialog.askstring("Add Entry", "Site:")
    username = simpledialog.askstring("Add Entry", "Username:")
    password = simpledialog.askstring("Add Entry", "Password (leave blank to auto-generate):")

    try:
        master_key, data = vault.unlock_with_shares(shares)

        if not password:
            # auto-generate using vault’s generator
            password = vault.generate_password(20, "mixed")

        entry = {
            "site": site,
            "username": username,
            "password": password,
            "created": vault.now_iso()
        }
        data["entries"].append(entry)

        # save vault again
        vault.save_vault(master_key, data)
        vault.audit("add_entry", {"site": site, "username": username})

        messagebox.showinfo("Success", f"Added entry for {site}.")

    except Exception as e:
        messagebox.showerror("Error", str(e))




def list_entries():
    meta = vault.load_meta()
    shares = ask_shares(meta["threshold"])
    try:
        master_key, data = vault.unlock_with_shares(shares)
        entries = data.get("entries", [])
        if not entries:
            messagebox.showinfo("Entries", "Vault is empty.")
        else:
            msg = "\n".join([f"{i+1}. {e['site']} — {e['username']}" for i, e in enumerate(entries)])
            messagebox.showinfo("Entries", msg)
    except Exception as e:
        messagebox.showerror("Error", str(e))


def show_entry():
    meta = vault.load_meta()
    shares = ask_shares(meta["threshold"])
    try:
        master_key, data = vault.unlock_with_shares(shares)
        entries = data.get("entries", [])
        if not entries:
            messagebox.showinfo("Show Entry", "Vault is empty.")
            return

        # Create selection window
        top = tk.Toplevel()
        top.title("Select Entry")

        tk.Label(top, text="Choose a site to reveal:").pack(pady=5)

        # Build mapping: label -> entry dict
        labels = [f"{i+1}. {e['site']} — {e['username']}" for i, e in enumerate(entries)]
        label_to_entry = dict(zip(labels, entries))

        selected = tk.StringVar(top)
        selected.set(labels[0])  # default first

        dropdown = tk.OptionMenu(top, selected, *labels)
        dropdown.pack(pady=10)

        def on_select():
            e = label_to_entry[selected.get()]
            messagebox.showinfo(
                "Password",
                f"Site: {e['site']}\nUser: {e['username']}\nPassword: {e['password']}"
            )
            top.destroy()

        tk.Button(top, text="Reveal", command=on_select).pack(pady=10)

    except Exception as e:
        messagebox.showerror("Error", str(e))


def rotate_shares():
    meta = vault.load_meta()
    shares = ask_shares(meta["threshold"])  # GUI prompt for shares
    threshold = simpledialog.askinteger("Rotate Shares", "New threshold:")
    total = simpledialog.askinteger("Rotate Shares", "New total shares:")

    if threshold and total:
        wrap = messagebox.askyesno("Wrap Shares", "Protect new shares with passphrases?")
        passphrases = []

        if wrap:
            messagebox.showinfo(
                "Passphrases",
                f"You’ll now be asked to set passphrases for {total} new shares."
            )
            for i in range(total):
                pw = simpledialog.askstring(
                    "Share Passphrase",
                    f"Set passphrase for new Share #{i + 1} (leave blank to skip):",
                    show="*"
                )
                passphrases.append(pw or "")

        try:
            vault.unlock_with_shares(shares)  # Confirm old shares are valid

            # ✅ Pass the shares from GUI into vault backend
            new_shares = vault.rotate_shares(
                threshold, total, wrap,
                passphrases,
                existing_shares=shares
            )

            # Display new shares in a scrollable window
            txt_window = tk.Toplevel()
            txt_window.title("New Shares")
            tk.Label(txt_window, text="Distribute the following new shares securely:").pack(pady=5)
            box = scrolledtext.ScrolledText(txt_window, width=80, height=20)
            box.pack(padx=10, pady=10)
            box.insert(tk.END, "\n".join(new_shares))
            box.configure(state="disabled")

            messagebox.showinfo(
                "Success",
                f"Shares rotated to {threshold}-of-{total}.\n\n"
                f"New shares are shown in a new window."
            )

        except Exception as e:
            messagebox.showerror("Error", str(e))



# ---------- Main Window ----------
root = tk.Tk()
root.title("Shared-Key Password Vault")
root.geometry("400x350")

tk.Label(root, text="Password Vault", font=("Arial", 16, "bold")).pack(pady=10)

btns = [
    ("Init Vault", init_vault),
    ("Add Entry", add_entry),
    ("List Entries", list_entries),
    ("Show Entry", show_entry),
    ("Rotate Shares", rotate_shares),
]

for text, cmd in btns:
    tk.Button(root, text=text, command=cmd, width=20).pack(pady=5)

tk.Button(root, text="Exit", command=root.quit, width=20).pack(pady=20)

root.mainloop()