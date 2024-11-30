import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import random
import string
import hashlib
import requests
import pyperclip
from datetime import datetime

class ModernPasswordManagementTool:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Modern Password Management System")
        self.root.geometry("1200x800")
        self.generated_password = ""
        self.password_history = []

        # UI Styling
        self.setup_ui_style()

        # Notebook for Tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        # Add Tabs
        self.add_password_generator_tab()
        self.add_compromise_checker_tab()
        self.add_strength_checker_tab()
        self.add_password_log_tab()

        # Status Bar
        self.status_var = tk.StringVar(value="Welcome to Modern Password Management System!")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def setup_ui_style(self):
        """Setup the style and theme for the UI."""
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TLabel", font=("Segoe UI", 12))
        style.configure("TButton", font=("Segoe UI", 12, "bold"))
        style.configure("TEntry", font=("Segoe UI", 12))

    def add_password_generator_tab(self):
        """Create the Password Generator tab."""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="🔑 Password Generator")

        ttk.Label(frame, text="Password Generator", font=("Segoe UI", 14, "bold")).grid(row=0, column=0, columnspan=2, pady=10)

        labels = ["First Name", "Last Name", "Hobby", "Age"]
        self.entries = {}
        for i, text in enumerate(labels):
            ttk.Label(frame, text=f"{text}:").grid(row=i+1, column=0, sticky=tk.W, padx=10, pady=5)
            entry = ttk.Entry(frame)
            entry.grid(row=i+1, column=1, sticky=tk.EW, padx=10, pady=5)
            self.entries[text.lower()] = entry

        btn_generate = ttk.Button(frame, text="Generate Password", command=self.generate_password)
        btn_generate.grid(row=len(labels)+1, column=0, pady=10, padx=10)
        btn_generate_strong = ttk.Button(frame, text="Generate Strong Password", command=self.generate_strong_password)
        btn_generate_strong.grid(row=len(labels)+1, column=1, pady=10, padx=10)

        self.generated_password_label = ttk.Label(frame, text="", font=("Segoe UI", 12, "bold"), foreground="blue")
        self.generated_password_label.grid(row=len(labels)+2, column=0, columnspan=2, pady=10)

        self.copy_button = ttk.Button(frame, text="Copy to Clipboard", command=self.copy_to_clipboard, state=tk.DISABLED)
        self.copy_button.grid(row=len(labels)+3, column=0, pady=10)

        clear_button = ttk.Button(frame, text="Clear", command=self.clear_password_generator)
        clear_button.grid(row=len(labels)+3, column=1, pady=10)

    def add_compromise_checker_tab(self):
        """Create the Password Compromise Checker tab."""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="🕵️ Compromise Checker")

        ttk.Label(frame, text="Password Compromise Checker", font=("Segoe UI", 14, "bold")).pack(pady=10)

        ttk.Label(frame, text="Enter your password:").pack(pady=5)
        self.compromise_entry = ttk.Entry(frame, show="")
        self.compromise_entry.pack(pady=5)

        btn_check = ttk.Button(frame, text="Check Compromise", command=self.check_password_compromised)
        btn_check.pack(pady=10)

        clear_button = ttk.Button(frame, text="Clear", command=self.clear_compromise_checker)
        clear_button.pack(pady=10)

        self.compromise_result = ttk.Label(frame, text="")
        self.compromise_result.pack(pady=10)

    def add_strength_checker_tab(self):
        """Create the Password Strength Checker tab."""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="💪 Strength Checker")

        ttk.Label(frame, text="Password Strength Checker", font=("Segoe UI", 14, "bold")).pack(pady=10)

        ttk.Label(frame, text="Enter your password:").pack(pady=5)
        self.strength_entry = ttk.Entry(frame, show="")
        self.strength_entry.pack(pady=5)

        btn_check = ttk.Button(frame, text="Check Strength", command=self.check_password_strength)
        btn_check.pack(pady=10)

        clear_button = ttk.Button(frame, text="Clear", command=self.clear_strength_checker)
        clear_button.pack(pady=10)

        self.strength_result = ttk.Label(frame, text="")
        self.strength_result.pack(pady=10)

    def add_password_log_tab(self):
        """Create the Password Log tab."""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="📋 Password Log")

        ttk.Label(frame, text="Password Generation History", font=("Segoe UI", 14, "bold")).pack(pady=10)

        self.history_tree = ttk.Treeview(frame, columns=("Timestamp", "Password"), show="headings")
        self.history_tree.heading("Timestamp", text="Timestamp")
        self.history_tree.heading("Password", text="Password")
        self.history_tree.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Clear History", command=self.clear_password_history).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Export History", command=self.export_password_history).pack(side=tk.LEFT, padx=5)

    def generate_password(self):
        """Generate a password based on user input."""
        first_name = self.entries["first name"].get()
        last_name = self.entries["last name"].get()
        hobby = self.entries["hobby"].get()
        age = self.entries["age"].get()

        if not (first_name and last_name and hobby and age.isdigit()):
            messagebox.showerror("Error", "Please fill out all fields correctly.")
            return

        self.generated_password = f"{first_name[:2]}{last_name[-2:]}{hobby[:3]}{age[::-1]}"
        self.update_generated_password("Basic Password")

    def generate_strong_password(self):
        """Generate a strong random password."""
        characters = string.ascii_letters + string.digits + string.punctuation
        self.generated_password = ''.join(random.choices(characters, k=16))
        self.update_generated_password("Strong Password")

    def update_generated_password(self, method):
        """Update the generated password on the UI and log it."""
        self.generated_password_label.config(text=self.generated_password)
        self.copy_button.config(state=tk.NORMAL)

        # Log the password
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.password_history.append((timestamp, method, self.generated_password))
        self.history_tree.insert("", "end", values=(timestamp, self.generated_password))

    def copy_to_clipboard(self):
        """Copy the generated password to the clipboard."""
        pyperclip.copy(self.generated_password)
        self.status_var.set("Password copied to clipboard!")

    def check_password_compromised(self):
        """Check if the password is compromised using the Have I Been Pwned API."""
        password = self.compromise_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return

        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"

        try:
            response = requests.get(url)
            if response.status_code == 200:
                breaches = {line.split(":")[0]: int(line.split(":")[1]) for line in response.text.splitlines()}
                if suffix in breaches:
                    self.compromise_result.config(
                        text=f"Your password has been found {breaches[suffix]} times!", foreground="red"
                    )
                else:
                    self.compromise_result.config(text="Your password is safe.", foreground="green")
            else:
                self.compromise_result.config(text="Error checking password.", foreground="red")
        except requests.RequestException:
            self.compromise_result.config(text="Network error. Try again later.", foreground="red")

    def check_password_strength(self):
        """Check the strength of a given password."""
        password = self.strength_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return

        length = len(password)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)

        if length >= 12 and has_upper and has_lower and has_digit and has_special:
            self.strength_result.config(text="Strong password!", foreground="green")
        elif length >= 8 and has_upper and has_lower and (has_digit or has_special):
            self.strength_result.config(text="Moderate password.", foreground="orange")
        else:
            self.strength_result.config(text="Weak password.", foreground="red")

    def clear_password_generator(self):
        """Clear all input fields and reset labels in the Password Generator tab."""
        for entry in self.entries.values():
            entry.delete(0, tk.END)
        self.generated_password_label.config(text="")
        self.copy_button.config(state=tk.DISABLED)

    def clear_compromise_checker(self):
        """Clear the password compromise checker fields."""
        self.compromise_entry.delete(0, tk.END)
        self.compromise_result.config(text="")

    def clear_strength_checker(self):
        """Clear the password strength checker fields."""
        self.strength_entry.delete(0, tk.END)
        self.strength_result.config(text="")

    def clear_password_history(self):
        """Clear the password history."""
        self.password_history.clear()
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        self.status_var.set("Password history cleared.")

    def export_password_history(self):
        """Export the password history to a file."""
        if not self.password_history:
            messagebox.showinfo("Info", "No password history to export.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if not file_path:
            return

        with open(file_path, "w") as file:
            file.write("Timestamp\tMethod\tPassword\n")
            for record in self.password_history:
                file.write("\t".join(record) + "\n")

        messagebox.showinfo("Success", "Password history exported successfully.")
        self.status_var.set("Password history exported.")

if __name__ == "__main__":
    root = tk.Tk()
    app = ModernPasswordManagementTool(root)
    root.mainloop()
