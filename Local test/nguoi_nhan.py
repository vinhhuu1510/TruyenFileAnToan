import os
import base64
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from Crypto.Cipher import DES3, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Util.Padding import pad, unpad

# Hàm xử lý giải mã và xác thực
def giai_ma_session_key(enc_key, priv_key):
    rsa_key = RSA.import_key(priv_key)
    cipher_rsa = PKCS1_v1_5.new(rsa_key)
    return cipher_rsa.decrypt(enc_key, None)

def giai_ma_3des(data, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_data = cipher.decrypt(data)
    return unpad(padded_data, DES3.block_size)

def xac_thuc(pub_key, data, sig):
    h = SHA512.new(data)
    rsa_key = RSA.import_key(pub_key)
    try:
        pkcs1_15.new(rsa_key).verify(h, sig)
        return True
    except (ValueError, TypeError):
        return False

class GuiNguoiNhan:
    def __init__(self, root):
        self.root = root
        self.root.title("Người Nhận - Ứng Dụng Bảo Mật File")
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
        self.title_label = ttk.Label(self.main_frame, text="Người Nhận - Giải Mã File", font=("Arial", 14, "bold"), foreground="#2c3e50")
        self.title_label.pack(pady=10)

        # Chọn file outbox
        self.select_frame = ttk.LabelFrame(self.main_frame, text="Chọn File outbox.json", padding="10")
        self.select_frame.pack(fill="x", pady=5)

        self.select_file_btn = ttk.Button(self.select_frame, text="Chọn outbox.json", command=self.select_file)
        self.select_file_btn.pack(pady=5)

        self.file_label = ttk.Label(self.select_frame, text="Chưa chọn file", wraplength=350)
        self.file_label.pack(pady=5)

        # Giải mã và nhận file
        self.action_frame = ttk.LabelFrame(self.main_frame, text="Thao Tác", padding="10")
        self.action_frame.pack(fill="x", pady=5)

        self.receive_btn = ttk.Button(self.action_frame, text="Giải Mã và Nhận File", command=self.receive_file, state="disabled")
        self.receive_btn.pack(pady=5)

        self.status_label = ttk.Label(self.action_frame, text="", foreground="green")
        self.status_label.pack(pady=5)

        # Biến lưu trữ
        self.file_path = ""

    def select_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if self.file_path:
            self.file_label.config(text=f"File đã chọn: {os.path.basename(self.file_path)}")
            self.receive_btn.config(state="normal")
        else:
            self.file_label.config(text="Chưa chọn file")

    def receive_file(self):
        try:
            priv_receiver = RSA.import_key(open("priv_receiver.pem", "rb").read())
            pub_sender = RSA.import_key(open("pub_sender.pem", "rb").read())

            with open(self.file_path, "r") as f:
                inbox = json.load(f)

            enc_session_key = base64.b64decode(inbox['enc_session_key'])
            metadata = base64.b64decode(inbox['metadata'])
            sig_metadata = base64.b64decode(inbox['sig_metadata'])

            session_key = giai_ma_session_key(enc_session_key, priv_receiver.export_key())

            if not xac_thuc(pub_sender.export_key(), metadata, sig_metadata):
                self.status_label.config(text="❌ Chữ ký metadata không hợp lệ!")
                return

            result = b''
            for pkt in inbox['packets']:
                iv = base64.b64decode(pkt['iv'])
                cipher = base64.b64decode(pkt['cipher'])
                sig = base64.b64decode(pkt['sig'])
                hash_val = SHA512.new(iv + cipher).hexdigest()

                if hash_val != pkt['hash']:
                    self.status_label.config(text="❌ Hash mismatch!")
                    return

                if not xac_thuc(pub_sender.export_key(), cipher, sig):
                    self.status_label.config(text="❌ Chữ ký phần dữ liệu không hợp lệ!")
                    return

                part = giai_ma_3des(cipher, session_key, iv)
                result += part

            with open("contract_received.txt", "wb") as f:
                f.write(result)
            self.status_label.config(text="✅ Giải mã và nhận file thành công!")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Lỗi khi giải mã: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = GuiNguoiNhan(root)
    root.mainloop()