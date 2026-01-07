import customtkinter as ctk
from tkinter import filedialog, messagebox
from pathlib import Path
from .core import CipherVaultCore
import threading
import os

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class SmartCipherApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("CipherVault")
        self.geometry("600x750")
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure((0, 1, 2, 3), weight=1)

        self.core = CipherVaultCore()
        self.current_file = None
        self.mode = None # "encrypt" or "decrypt"

        # --- Header ---
        self.header_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.header_frame.pack(pady=(40, 20), padx=20, fill="x")
        
        self.lbl_title = ctk.CTkLabel(self.header_frame, text="CipherVault", font=("Roboto Medium", 32))
        self.lbl_title.pack()
        
        self.lbl_subtitle = ctk.CTkLabel(self.header_frame, text="Secure. Simple. Private.", font=("Roboto", 14), text_color="gray")
        self.lbl_subtitle.pack()

        # --- File Selection Area ---
        self.file_frame = ctk.CTkFrame(self, fg_color=("#EBEBEB", "#2B2B2B"), corner_radius=15, border_width=2, border_color="#3B8ED0")
        self.file_frame.pack(pady=20, padx=40, fill="x")

        self.lbl_file_instructions = ctk.CTkLabel(self.file_frame, text="Select a file to start", font=("Roboto", 18))
        self.lbl_file_instructions.pack(pady=(30, 10))

        self.btn_select = ctk.CTkButton(self.file_frame, text="Browse Files", command=self.select_file, height=40, font=("Roboto", 14))
        self.btn_select.pack(pady=(0, 30))

        self.lbl_selected_file = ctk.CTkLabel(self.file_frame, text="", font=("Roboto", 12), text_color="#3B8ED0")
        self.lbl_selected_file.pack(pady=(0, 5))

        # Output Path Display
        self.output_frame = ctk.CTkFrame(self.file_frame, fg_color="transparent")
        self.output_frame.pack(pady=(0, 10))
        
        self.lbl_output_path = ctk.CTkLabel(self.output_frame, text="", font=("Roboto", 10), text_color="gray")
        self.lbl_output_path.pack(side="left", padx=(0, 10))
        
        self.btn_change_output = ctk.CTkButton(self.output_frame, text="Change Output", command=self.change_output, width=80, height=20, font=("Roboto", 10))
        self.btn_change_output.pack(side="left")
        self.output_frame.pack_forget() # Hide initially

        # --- Options Area (Hidden initially) ---
        self.options_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.options_frame.pack(pady=10, padx=40, fill="x")

        self.lbl_password = ctk.CTkLabel(self.options_frame, text="Password (Recommended)", anchor="w")
        
        self.entry_password = ctk.CTkEntry(self.options_frame, placeholder_text="Enter a strong password", show="*", height=35)
        
        self.switch_show_pass = ctk.CTkSwitch(self.options_frame, text="Show", command=self.toggle_password, width=50)

        # Key file option (Advanced)
        self.check_keyfile_var = ctk.BooleanVar(value=False)
        self.check_keyfile = ctk.CTkCheckBox(self.options_frame, text="Use Key File instead", command=self.toggle_key_mode, variable=self.check_keyfile_var)

        # --- Action ---
        self.btn_action = ctk.CTkButton(self, text="START", command=self.perform_action, height=80, 
                                        font=("Roboto Medium", 20), state="disabled", fg_color="gray")
        self.btn_action.pack(pady=30, padx=40, fill="x")

        self.lbl_status = ctk.CTkLabel(self, text="", text_color="gray")
        self.lbl_status.pack(pady=(0, 20))

    def select_file(self):
        filename = filedialog.askopenfilename()
        if not filename:
            return

        self.current_file = Path(filename)
        self.lbl_selected_file.configure(text=f"Selected: {self.current_file.name}")
        self.lbl_file_instructions.configure(text="File Ready")

        # Auto-detect mode
        if self.current_file.suffix == ".enc":
            self.mode = "decrypt"
            self.lbl_title.configure(text="Unlock File", text_color="#D35B58")
            self.file_frame.configure(border_color="#D35B58") # Red-ish for unlock
            self.btn_action.configure(text="UNLOCK NOW", fg_color="#D35B58", hover_color="#C72C41", state="normal")
            self.lbl_password.configure(text="Enter Password to Decrypt")
            
            # Default Output
            # User wants "filename - Decrypted.ext"
            base_path = self.current_file.with_suffix("")
            self.current_output = base_path.with_name(f"{base_path.stem} - Decrypted{base_path.suffix}")
            
        else:
            self.mode = "encrypt"
            self.lbl_title.configure(text="Secure File", text_color="#2CC985")
            self.file_frame.configure(border_color="#2CC985") # Green for lock
            self.btn_action.configure(text="LOCK NOW", fg_color="#2CC985", hover_color="#24A36B", state="normal")
            self.lbl_password.configure(text="Create Password (Optional but Recommended)")
            
            # Default Output
            self.current_output = self.current_file.parent / (self.current_file.name + ".enc")

        self.lbl_output_path.configure(text=f"Save to: {self.current_output.name}")
        self.output_frame.pack(pady=(0, 10))

        # Show options
        self.lbl_password.pack(fill="x", pady=(0, 5))
        self.entry_password.pack(fill="x", pady=(0, 5))
        self.switch_show_pass.pack(pady=(0, 15), anchor="w")
        # Advanced options usually hidden to keep it simple, but we show checkbox for keyfile
        self.check_keyfile.pack(anchor="w")


    def change_output(self):
        if not self.current_file:
            return
            
        # Determine strict filetypes/defaultextension
        if self.mode == "encrypt":
            new_path = filedialog.asksaveasfilename(defaultextension=".enc", initialfile=self.current_output.name)
        else:
            new_path = filedialog.asksaveasfilename(initialfile=self.current_output.name)
            
        if new_path:
            self.current_output = Path(new_path)
            self.lbl_output_path.configure(text=f"Save to: {self.current_output.name}")

    def toggle_password(self):
        if self.switch_show_pass.get() == 1:
            self.entry_password.configure(show="")
        else:
            self.entry_password.configure(show="*")

    def toggle_key_mode(self):
        if self.check_keyfile_var.get():
            self.entry_password.configure(state="disabled", placeholder_text="Using Key File...")
            self.switch_show_pass.configure(state="disabled")
        else:
            self.entry_password.configure(state="normal", placeholder_text="Enter a strong password")
            self.switch_show_pass.configure(state="normal")

    def perform_action(self):
        password = self.entry_password.get()
        use_keyfile = self.check_keyfile_var.get()

        def run():
            try:
                self.btn_action.configure(state="disabled", text="Processing...")
                
                if self.mode == "encrypt":
                    self._run_encrypt(password, use_keyfile)
                else:
                    self._run_decrypt(password, use_keyfile)

                self.lbl_status.configure(text="Operation Successful!", text_color="#2CC985")
                self.after(2000, lambda: self.lbl_status.configure(text=""))
                
            except Exception as e:
                self.lbl_status.configure(text=f"Error: {str(e)}", text_color="#D35B58")
                messagebox.showerror("Error", str(e))
            finally:
                # Reset button state
                if self.mode == "encrypt":
                    self.btn_action.configure(state="normal", text="LOCK NOW")
                else:
                    self.btn_action.configure(state="normal", text="UNLOCK NOW")

        threading.Thread(target=run).start()

    def _run_encrypt(self, password, use_keyfile):
        output_path = self.current_output
        
        if use_keyfile:
             key = self.core.generate_key()
             key_path = self.current_file.parent / (self.current_file.stem + ".key")
             with open(key_path, 'wb') as f:
                 f.write(key)
             self.core.encrypt_file(str(self.current_file), str(output_path), key)
             self.after(0, lambda: messagebox.showinfo("Encrypted", f"Key saved to: {key_path.name}\nFile saved to: {output_path.name}"))
        
        elif password:
            key, salt = self.core.derive_key_from_password(password)
            with open(self.current_file, 'rb') as f:
                data = f.read()
            encrypted_data = self.core.encrypt_data(data, key)
            with open(output_path, 'wb') as f:
                f.write(salt)
                f.write(encrypted_data)
            self.after(0, lambda: messagebox.showinfo("Encrypted", f"File saved to: {output_path.name}"))
        
        else:
            # No password, no keyfile -> Generate simple key
            key = self.core.generate_key()
            key_path = self.current_file.parent / (self.current_file.stem + ".key")
            with open(key_path, 'wb') as f:
                f.write(key)
            self.core.encrypt_file(str(self.current_file), str(output_path), key)
            self.after(0, lambda: messagebox.showinfo("Encrypted", f"WARNING: No password used.\nKey saved to: {key_path.name}\nFile saved to: {output_path.name}"))

    def _run_decrypt(self, password, use_keyfile):
        input_path = self.current_file
        output_path = self.current_output

        if use_keyfile:
            key_filename = filedialog.askopenfilename(title="Select Key File", filetypes=[("Key Files", "*.key"), ("All Files", "*.*")])
            if not key_filename:
                raise ValueError("No key file selected.")
            with open(key_filename, "rb") as f:
                key = f.read().strip()
            
            self.core.decrypt_file(str(input_path), str(output_path), key)
            
        elif password:
            # Assume Salt is at start
            with open(input_path, 'rb') as f:
                salt = f.read(16)
                encrypted_data = f.read()
            
            key, _ = self.core.derive_key_from_password(password, salt)
            decrypted_data = self.core.decrypt_data(encrypted_data, key)
            
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
        else:
            raise ValueError("Please enter a password or select a key file.")

        self.after(0, lambda: messagebox.showinfo("Decrypted", f"File saved to: {output_path.name}"))

def main():
    app = SmartCipherApp()
    app.mainloop()

if __name__ == "__main__":
    main()
