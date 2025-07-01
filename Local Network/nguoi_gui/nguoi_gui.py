import os
import base64
import json
import socket
import tkinter as tk
from tkinter import filedialog, messagebox
from datetime import datetime
import struct
from utils_crypto import *

class GuiNguoiGui:
    def __init__(self, root):
        self.root = root
        self.root.title("Người Gửi - Ứng Dụng Bảo Mật File")
        self.root.geometry("600x550")
        self.root.configure(bg="#f0f4f8")

        self.title_label = tk.Label(root, text="Người Gửi - Mã Hóa và Gửi File", 
                                   font=("Arial", 16, "bold"), fg="#1a3c6e", bg="#f0f4f8")
        self.title_label.pack(pady=10)

        self.step1_frame = tk.LabelFrame(root, text="Bước 1: Chọn File Hợp Đồng", 
                                        font=("Arial", 10, "bold"), fg="#1a3c6e", bg="#f0f4f8", 
                                        padx=10, pady=10)
        self.step1_frame.pack(fill="x", padx=20, pady=10)

        self.select_btn = tk.Button(self.step1_frame, text="Chọn File (contract.txt)", 
                                   command=self.select_file, bg="#4a90e2", fg="white", 
                                   font=("Arial", 10), activebackground="#357abd")
        self.select_btn.pack(pady=5)

        self.file_label = tk.Label(self.step1_frame, text="Chưa chọn file", 
                                  fg="#34495e", bg="#f0f4f8", font=("Arial", 10))
        self.file_label.pack(pady=5)

        self.step2_frame = tk.LabelFrame(root, text="Bước 2: Nhập IP Máy Nhận", 
                                        font=("Arial", 10, "bold"), fg="#1a3c6e", bg="#f0f4f8", 
                                        padx=10, pady=10)
        self.step2_frame.pack(fill="x", padx=20, pady=10)

        self.ip_label = tk.Label(self.step2_frame, text="IP Máy Nhận:", 
                                fg="#34495e", bg="#f0f4f8", font=("Arial", 10))
        self.ip_label.pack(side="left", padx=5)

        self.ip_entry = tk.Entry(self.step2_frame, width=30, font=("Arial", 10))
        self.ip_entry.pack(side="left", padx=5)

        self.step3_frame = tk.LabelFrame(root, text="Bước 3: Gửi File", 
                                        font=("Arial", 10, "bold"), fg="#1a3c6e", bg="#f0f4f8", 
                                        padx=10, pady=10)
        self.step3_frame.pack(fill="x", padx=20, pady=10)

        self.progress = tk.Scale(self.step3_frame, from_=0, to=100, orient="horizontal", 
                                length=400, showvalue=1, bg="#f0f4f8", fg="#1a3c6e", 
                                troughcolor="#d3e0ea", activebackground="#4a90e2")
        self.progress.pack(pady=5)

        self.send_btn = tk.Button(self.step3_frame, text="Gửi File", 
                                 command=self.send_file, bg="#4a90e2", fg="white", 
                                 font=("Arial", 10), state="disabled", activebackground="#357abd")
        self.send_btn.pack(pady=10)

        self.status_label = tk.Label(self.step3_frame, text="", 
                                    fg="#27ae60", bg="#f0f4f8", font=("Arial", 10, "bold"))
        self.status_label.pack(pady=5)

        self.guide_label = tk.Label(root, text="Lưu ý: Đảm bảo máy nhận đang chạy và cổng 9999 mở.", 
                                   fg="#7f8c8d", bg="#f0f4f8", font=("Arial", 9, "italic"))
        self.guide_label.pack(pady=10)

        self.file_path = ""
        self.client = None

    def select_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if self.file_path:
            self.file_label.config(text=f"File đã chọn: {os.path.basename(self.file_path)}")
            self.send_btn.config(state="normal")
        else:
            self.file_label.config(text="Chưa chọn file")

    def send_file(self):
        if not self.ip_entry.get():
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập IP máy nhận!")
            return
        if messagebox.askyesno("Xác nhận", "Bạn có muốn gửi file không?"):
            self.progress.set(0)
            try:
                priv_sender = load_key("priv_sender.pem")
                pub_receiver = load_key("pub_receiver.pem")
                self.progress.set(10)
                self.root.update()
                with open(self.file_path, "rb") as f:
                    data = f.read()

                metadata = f"contract.txt|{datetime.utcnow()}|{len(data)}".encode()
                sig_metadata = sign_data(metadata, priv_sender)

                session_key = generate_session_key()
                enc_session_key = encrypt_session_key(session_key, pub_receiver)

                chunk_size = len(data) // 3
                parts = [data[i * chunk_size:(i + 1) * chunk_size] for i in range(3)]
                parts[-1] += data[3 * chunk_size:]  # Thêm phần dư

                packets = []
                for i, part in enumerate(parts):
                    self.progress.set(10 + (i + 1) * 30)  # 10% khởi tạo, 90% xử lý 3 phần
                    self.root.update()
                    iv = get_random_bytes(8)
                    cipher = encrypt_3des(part, session_key, iv)
                    sig = sign_data(cipher, priv_sender)
                    hash_val = SHA512.new(iv + cipher).hexdigest()
                    packets.append({
                        "iv": base64.b64encode(iv).decode(),
                        "cipher": base64.b64encode(cipher).decode(),
                        "hash": hash_val,
                        "sig": base64.b64encode(sig).decode()
                    })

                outbox = {
                    "enc_session_key": base64.b64encode(enc_session_key).decode(),
                    "metadata": base64.b64encode(metadata).decode(),
                    "sig_metadata": base64.b64encode(sig_metadata).decode(),
                    "packets": packets
                }

                data_str = json.dumps(outbox).encode()
                data_len = len(data_str)
                host = self.ip_entry.get()
                self.client = socket.socket()
                self.client.connect((host, 9999))
                self.client.send(struct.pack('!I', data_len))  # Gửi độ dài
                self.client.sendall(data_str)  # Gửi dữ liệu
                self.client.close()

                self.status_label.config(text="✅ File đã được gửi đi an toàn!")
                self.progress.set(100)
                self.send_btn.config(state="disabled")
            except Exception as e:
                self.status_label.config(text=f"❌ Lỗi: {str(e)}")
                if self.client:
                    self.client.close()
            except FileNotFoundError:
                messagebox.showerror("Lỗi", "Không tìm thấy file khóa!")
                if self.client:
                    self.client.close()        

if __name__ == "__main__":
    root = tk.Tk()
    app = GuiNguoiGui(root)
    root.mainloop()