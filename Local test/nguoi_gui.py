import os
import base64
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime
from Crypto.Cipher import DES3, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512
from Crypto.Util.Padding import pad, unpad

# Hàm xử lý mã hóa và ký số
def tao_session_key():
    return DES3.adjust_key_parity(get_random_bytes(24))

def ma_hoa_3des(data, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_data = pad(data, DES3.block_size)
    return cipher.encrypt(padded_data)

def ky_so(private_key, data):
    h = SHA512.new(data)
    rsa_key = RSA.import_key(private_key)
    return pkcs1_15.new(rsa_key).sign(h)

def ma_hoa_session_key(session_key, pub_key):
    rsa_key = RSA.import_key(pub_key)
    cipher_rsa = PKCS1_v1_5.new(rsa_key)
    return cipher_rsa.encrypt(session_key)

def chia_file(data):
    size = len(data)
    return [data[:size//3], data[size//3:2*size//3], data[2*size//3:]]

class GuiNguoiGui:
    def __init__(self, root):
        self.root = root
        self.root.title("Người Gửi - Ứng Dụng Bảo Mật File")
        self.root.geometry("500x400")
        self.root.configure(bg="#f0f0f0")

        # Style
        style = ttk.Style()
        style.configure("TButton", font=("Arial", 10), padding=6)
        style.configure("TLabel", font=("Arial", 10), background="#f0f0f0")
        style.configure("TFrame", background="#f0f0f0")

        # Frame chính
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.pack(fill="both", expand=True)

        # Tiêu đề
        self.title_label = ttk.Label(self.main_frame, text="Người Gửi - Mã Hóa File", font=("Arial", 14, "bold"), foreground="#2c3e50")
        self.title_label.pack(pady=10)

        # Chọn file
        self.select_frame = ttk.LabelFrame(self.main_frame, text="Chọn File Hợp Đồng", padding="10")
        self.select_frame.pack(fill="x", pady=5)

        self.select_file_btn = ttk.Button(self.select_frame, text="Chọn File (contract.txt)", command=self.select_file)
        self.select_file_btn.pack(pady=5)

        self.file_label = ttk.Label(self.select_frame, text="Chưa chọn file", wraplength=350)
        self.file_label.pack(pady=5)

        # Mã hóa và tạo file
        self.action_frame = ttk.LabelFrame(self.main_frame, text="Thao Tác", padding="10")
        self.action_frame.pack(fill="x", pady=5)

        self.send_btn = ttk.Button(self.action_frame, text="Mã Hóa và Tạo outbox.json", command=self.send_file, state="disabled")
        self.send_btn.pack(pady=5)

        self.status_label = ttk.Label(self.action_frame, text="", foreground="green")
        self.status_label.pack(pady=5)

        # Hướng dẫn
        self.instruction_label = ttk.Label(self.main_frame, text="Sau khi tạo, hãy chuyển file outbox.json cho người nhận.", foreground="#7f8c8d")
        self.instruction_label.pack(pady=10)

        # Biến lưu trữ
        self.file_path = ""

    def select_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if self.file_path:
            self.file_label.config(text=f"File đã chọn: {os.path.basename(self.file_path)}")
            self.send_btn.config(state="normal")
        else:
            self.file_label.config(text="Chưa chọn file")

    def send_file(self):
        try:
            priv_sender = RSA.import_key(open("priv_sender.pem", "rb").read())
            pub_receiver = RSA.import_key(open("pub_receiver.pem", "rb").read())

            with open(self.file_path, "rb") as f:
                data = f.read()

            session_key = tao_session_key()
            enc_session_key = ma_hoa_session_key(session_key, pub_receiver.export_key())
            
            metadata = f"{os.path.basename(self.file_path)}|{datetime.utcnow()}|{len(data)}".encode()
            sig_metadata = ky_so(priv_sender.export_key(), metadata)

            packets = []
            parts = chia_file(data)
            for part in parts:
                iv = get_random_bytes(8)
                cipher = ma_hoa_3des(part, session_key, iv)
                sig = ky_so(priv_sender.export_key(), cipher)
                hash_val = SHA512.new(iv + cipher).hexdigest()
                packets.append({
                    'iv': base64.b64encode(iv).decode(),
                    'cipher': base64.b64encode(cipher).decode(),
                    'hash': hash_val,
                    'sig': base64.b64encode(sig).decode()
                })

            out = {
                'enc_session_key': base64.b64encode(enc_session_key).decode(),
                'metadata': base64.b64encode(metadata).decode(),
                'sig_metadata': base64.b64encode(sig_metadata).decode(),
                'packets': packets
            }

            with open("outbox.json", "w") as f:
                json.dump(out, f)

            self.status_label.config(text="✅ Mã hóa và tạo outbox.json thành công!")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Lỗi khi mã hóa: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = GuiNguoiGui(root)
    root.mainloop()