import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext
import random
import string
import qrcode
from PIL import Image, ImageTk
import time
import json
import os

# Função para cifra de César
def caesar_encrypt(text, shift):
    result = []
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base + shift) % 26 + base))
        else:
            result.append(char)
    return ''.join(result)

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# Função para gerar senha forte
def generate_password(length=12):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

DATA_FILE = "data.json"

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Gerenciador de Senhas e Textos Criptografados")
        self.root.geometry("500x600")
        self.root.resizable(False, False)
        self.data = {}  # {nome: (texto_criptografado, camadas, tipo)}
        self.master_key = None
        self.key_expiry = None

        self.load_data()

        # Definir cores e fontes
        self.bg_color = "#2E3440"  # fundo escuro
        self.fg_color = "#D8DEE9"  # texto claro
        self.accent_color = "#88C0D0"  # azul claro para botões
        self.error_color = "#BF616A"  # vermelho para erros
        self.font_title = ("Segoe UI", 16, "bold")
        self.font_label = ("Segoe UI", 11)
        self.font_entry = ("Segoe UI", 11)
        self.font_button = ("Segoe UI", 11, "bold")


        self.root.configure(bg=self.bg_color)

        # Canvas e Scrollbar para rolagem
        self.canvas = tk.Canvas(root, bg=self.bg_color, highlightthickness=0)
        self.scrollbar = tk.Scrollbar(root, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg=self.bg_color)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(
                scrollregion=self.canvas.bbox("all")
            )
        )

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Título
        self.title_label = tk.Label(self.scrollable_frame, text="Gerenciador de Senhas e Textos", font=self.font_title, fg=self.accent_color, bg=self.bg_color)
        self.title_label.grid(row=0, column=0, columnspan=2, pady=(0, 15))

        # Botão gerar chave mestre
        self.btn_master_key = tk.Button(self.scrollable_frame, text="Gerar Chave Mestre (QR)", command=self.generate_master_key,
            bg=self.accent_color, fg=self.bg_color, font=self.font_button, relief="flat", activebackground="#81A1C1")
        self.btn_master_key.grid(row=1, column=0, columnspan=2, pady=10, sticky="ew")

        # Nome
        tk.Label(self.scrollable_frame, text="Nome (senha/texto):", font=self.font_label, fg=self.fg_color, bg=self.bg_color).grid(row=2, column=0, sticky="e", pady=5, padx=(0,10))
        self.name_entry = tk.Entry(self.scrollable_frame, width=30, font=self.font_entry, bg="#3B4252", fg=self.fg_color, insertbackground=self.fg_color, relief="flat")
        self.name_entry.grid(row=2, column=1, pady=5, sticky="w")

        # Texto para criptografar
        tk.Label(self.scrollable_frame, text="Texto para criptografar:", font=self.font_label, fg=self.fg_color, bg=self.bg_color).grid(row=3, column=0, sticky="ne", pady=5, padx=(0,10))
        self.text_entry = scrolledtext.ScrolledText(self.scrollable_frame, width=35, height=6, font=self.font_entry, bg="#3B4252", fg=self.fg_color, insertbackground=self.fg_color, relief="flat")
        self.text_entry.grid(row=3, column=1, pady=5, sticky="w")

        # Camadas
        tk.Label(self.scrollable_frame, text="Camadas de criptografia (1-10):", font=self.font_label, fg=self.fg_color, bg=self.bg_color).grid(row=4, column=0, sticky="e", pady=5, padx=(0,10))
        self.layers_entry = tk.Entry(self.scrollable_frame, width=5, font=self.font_entry, bg="#3B4252", fg=self.fg_color, insertbackground=self.fg_color, relief="flat")
        self.layers_entry.grid(row=4, column=1, sticky="w", pady=5)
        self.layers_entry.insert(0, "1")

        # Botões adicionar senha e texto lado a lado
        self.btn_add_password = tk.Button(self.scrollable_frame, text="Adicionar Senha Forte", command=self.add_password,
            bg=self.accent_color, fg=self.bg_color, font=self.font_button, relief="flat", activebackground="#81A1C1")
        self.btn_add_password.grid(row=5, column=0, pady=10, sticky="ew", padx=(0,5))

        self.btn_add_text = tk.Button(self.scrollable_frame, text="Adicionar Texto", command=self.add_text,
            bg=self.accent_color, fg=self.bg_color, font=self.font_button, relief="flat", activebackground="#81A1C1")
        self.btn_add_text.grid(row=5, column=1, pady=10, sticky="ew", padx=(5,0))

        # Botão ver dados
        self.btn_view_data = tk.Button(self.scrollable_frame, text="Ver Dados", command=self.view_data,
            bg=self.accent_color, fg=self.bg_color, font=self.font_button, relief="flat", activebackground="#81A1C1")
        self.btn_view_data.grid(row=6, column=0, columnspan=2, pady=15, sticky="ew")

        # Área para mostrar QR code
        self.qr_label = tk.Label(self.scrollable_frame, bg=self.bg_color)
        self.qr_label.grid(row=7, column=0, columnspan=2, pady=10)

        # Label para mostrar tempo restante da chave
        self.timer_label = tk.Label(self.scrollable_frame, text="", font=self.font_label, fg=self.accent_color, bg=self.bg_color)
        self.timer_label.grid(row=8, column=0, columnspan=2)

        # Ajustar colunas para expandir botões e entradas
        self.scrollable_frame.grid_columnconfigure(0, weight=1)
        self.scrollable_frame.grid_columnconfigure(1, weight=1)

    def load_data(self):
        if os.path.exists(DATA_FILE):
            try:
                with open(DATA_FILE, "r", encoding="utf-8") as f:
                    self.data = json.load(f)
            except Exception as e:
                messagebox.showerror("Erro", f"Falha ao carregar dados: {e}")
                self.data = {}
        else:
            self.data = {}

    def save_data(self):
        try:
            with open(DATA_FILE, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao salvar dados: {e}")


    def generate_master_key(self):
        self.master_key = ''.join(random.choices(string.digits, k=6))
        self.key_expiry = time.time() + 60  # 1 minuto
        qr = qrcode.make(self.master_key)
        qr = qr.resize((250, 250))  # Tamanho maior para evitar cortes
        self.qr_img = ImageTk.PhotoImage(qr)
        self.qr_label.config(image=self.qr_img, width=250, height=250)  # Define tamanho fixo do QR
        self.update_timer()

    def update_timer(self):
        if self.key_expiry:
            remaining = int(self.key_expiry - time.time())
            if remaining > 0:
                self.timer_label.config(text=f"Chave mestre expira em {remaining} segundos")
                self.root.after(1000, self.update_timer)
            else:
                self.master_key = None
                self.key_expiry = None
                self.qr_label.config(image='')
                self.timer_label.config(text="Chave mestre expirada. Gere uma nova.")
        else:
            self.timer_label.config(text="")

    def check_master_key(self):
        if not self.master_key or time.time() > self.key_expiry:
            messagebox.showerror("Erro", "Chave mestre inválida ou expirada. Gere uma nova.")
            return False
        key = simpledialog.askstring("Chave Mestre", "Digite a chave mestre (6 dígitos):")
        if key != self.master_key:
            messagebox.showerror("Erro", "Chave mestre incorreta.")
            return False
        return True

    def add_password(self):
        if not self.check_master_key():
            return
        name = self.name_entry.get().strip()
        if not name:
            messagebox.showerror("Erro", "Digite um nome para a senha.")
            return
        length = simpledialog.askinteger("Tamanho da Senha", "Digite o tamanho da senha (mínimo 8):", minvalue=8, maxvalue=64)
        if not length:
            return
        layers = self.get_layers()
        if layers is None:
            return
        password = generate_password(length)
        encrypted = password
        for _ in range(layers):
            encrypted = caesar_encrypt(encrypted, shift=3)
        self.data[name] = [encrypted, layers, 'senha']
        self.save_data()
        messagebox.showinfo("Senha Gerada", f"Senha '{name}' gerada e armazenada.\nSenha original:\n{password}")
        self.clear_inputs()

    def add_text(self):
        if not self.check_master_key():
            return
        name = self.name_entry.get().strip()
        if not name:
            messagebox.showerror("Erro", "Digite um nome para o texto.")
            return
        text = self.text_entry.get("1.0", tk.END).strip()
        if not text:
            messagebox.showerror("Erro", "Digite o texto para criptografar.")
            return
        layers = self.get_layers()
        if layers is None:
            return
        encrypted = text
        for _ in range(layers):
            encrypted = caesar_encrypt(encrypted, shift=3)
        self.data[name] = [encrypted, layers, 'texto']
        self.save_data()
        messagebox.showinfo("Texto Armazenado", f"Texto '{name}' armazenado com criptografia.")
        self.clear_inputs()

    def get_layers(self):
        try:
            layers = int(self.layers_entry.get())
            if not (1 <= layers <= 10):
                raise ValueError
            return layers
        except:
            messagebox.showerror("Erro", "Camadas de criptografia devem ser um número entre 1 e 10.")
            return None

    def clear_inputs(self):
        self.name_entry.delete(0, tk.END)
        self.text_entry.delete("1.0", tk.END)
        self.layers_entry.delete(0, tk.END)
        self.layers_entry.insert(0, "1")

    def view_data(self):
        if not self.check_master_key():
            return
        if not self.data:
            messagebox.showinfo("Sem Dados", "Nenhuma senha ou texto armazenado.")
            return
        names = list(self.data.keys())
        name = simpledialog.askstring("Ver Dados", f"Digite o nome para visualizar:\n{', '.join(names)}")
        if not name or name not in self.data:
            messagebox.showerror("Erro", "Nome inválido.")
            return
        encrypted, layers, tipo = self.data[name]
        decrypted = encrypted
        for _ in range(layers):
            decrypted = caesar_decrypt(decrypted, shift=3)
        messagebox.showinfo(f"{tipo.capitalize()} '{name}'",
                            f"Criptografado:\n{encrypted}\n\nDescriptografado:\n{decrypted}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()