import socket
import json
import base64
import tkinter as tk
from tkinter import messagebox
import struct
from utils_crypto import *

class GuiNguoiNhan:
    def __init__(self, root):
        self.root = root
        self.root.title("Người Nhận - Ứng Dụng Bảo Mật File")
        self.root.geometry("600x500")
        self.root.configure(bg="#f0f4f8")

        self.title_label = tk.Label(root, text="Người Nhận - Nhận và Giải Mã File", 
                                   font=("Arial", 16, "bold"), fg="#1a3c6e", bg="#f0f4f8")
        self.title_label.pack(pady=10)

        self.step1_frame = tk.LabelFrame(root, text="Bước 1: Khởi Động Server", 
                                        font=("Arial", 10, "bold"), fg="#1a3c6e", bg="#f0f4f8", 
                                        padx=10, pady=10)
        self.step1_frame.pack(fill="x", padx=20, pady=10)

        self.start_btn = tk.Button(self.step1_frame, text="Khởi Động Server (Cổng 9999)", 
                                  command=self.start_server, bg="#4a90e2", fg="white", 
                                  font=("Arial", 10), activebackground="#357abd")
        self.start_btn.pack(pady=10)

        self.status_label1 = tk.Label(self.step1_frame, text="Chưa khởi động", 
                                     fg="#34495e", bg="#f0f4f8", font=("Arial", 10))
        self.status_label1.pack(pady=5)

        self.step2_frame = tk.LabelFrame(root, text="Bước 2: Chờ Kết Nối", 
                                        font=("Arial", 10, "bold"), fg="#1a3c6e", bg="#f0f4f8", 
                                        padx=10, pady=10)
        self.step2_frame.pack(fill="x", padx=20, pady=10)

        self.connection_label = tk.Label(self.step2_frame, text="Chờ kết nối...", 
                                        fg="#34495e", bg="#f0f4f8", font=("Arial", 10))
        self.connection_label.pack(pady=5)

        self.step3_frame = tk.LabelFrame(root, text="Bước 3: Giải Mã và Lưu File", 
                                        font=("Arial", 10, "bold"), fg="#1a3c6e", bg="#f0f4f8", 
                                        padx=10, pady=10)
        self.step3_frame.pack(fill="x", padx=20, pady=10)

        self.progress = tk.Scale(self.step3_frame, from_=0, to=100, orient="horizontal", 
                                length=400, showvalue=1, bg="#f0f4f8", fg="#1a3c6e", 
                                troughcolor="#d3e0ea", activebackground="#4a90e2")
        self.progress.pack(pady=5)

        self.status_label2 = tk.Label(self.step3_frame, text="", 
                                     fg="#27ae60", bg="#f0f4f8", font=("Arial", 10, "bold"))
        self.status_label2.pack(pady=5)

        self.guide_label = tk.Label(root, text="Lưu ý: Đảm bảo cổng 9999 không bị chặn bởi firewall.", 
                                   fg="#7f8c8d", bg="#f0f4f8", font=("Arial", 9, "italic"))
        self.guide_label.pack(pady=10)

        self.server = None
        self.conn = None
        self.waiting = False

    def start_server(self):
        if self.server:
            self.status_label1.config(text="Server đã khởi động!")
            return
        try:
            self.server = socket.socket()
            self.server.bind(("0.0.0.0", 9999))
            self.server.listen(1)
            self.status_label1.config(text="✅ Server khởi động thành công!")
            self.start_btn.config(state="disabled")
            self.waiting = True
            self.root.after(100, self.wait_for_connection)
        except Exception as e:
            self.status_label1.config(text=f"❌ Lỗi: {str(e)}")

    def wait_for_connection(self):
        if self.waiting and not self.conn:
            try:
                self.conn, addr = self.server.accept()
                self.connection_label.config(text=f"✅ Nhận kết nối từ {addr}")
                self.waiting = False
                self.root.after(100, self.receive_and_decrypt)
            except:
                self.root.after(100, self.wait_for_connection)

    def receive_and_decrypt(self):
        if self.conn:
            try:
                raw_size = self.conn.recv(4)
                data_len = struct.unpack('!I', raw_size)[0]
                raw = b""
                while len(raw) < data_len:
                    packet = self.conn.recv(data_len - len(raw))
                    if not packet:
                        break
                    raw += packet
                data = json.loads(raw.decode())

                priv_receiver = load_key("priv_receiver.pem")
                pub_sender = load_key("pub_sender.pem")

                session_key = decrypt_session_key(base64.b64decode(data['enc_session_key']), priv_receiver)
                metadata = base64.b64decode(data['metadata'])
                sig_metadata = base64.b64decode(data['sig_metadata'])

                if not verify_signature(metadata, sig_metadata, pub_sender):
                    self.status_label2.config(text="❌ Chữ ký metadata không hợp lệ!")
                    self.conn.close()
                    if self.server:
                        self.server.close()
                    return

                result = b''
                for i, pkt in enumerate(data['packets']):
                    self.progress.set((i + 1) * 100 / len(data['packets']))
                    self.root.update()
                    iv = base64.b64decode(pkt['iv'])
                    cipher = base64.b64decode(pkt['cipher'])
                    sig = base64.b64decode(pkt['sig'])
                    hash_val = SHA512.new(iv + cipher).hexdigest()
                    if hash_val != pkt['hash']:
                        self.status_label2.config(text="❌ Hash sai!")
                        self.conn.close()
                        if self.server:
                            self.server.close()
                        return
                    if not verify_signature(cipher, sig, pub_sender):
                        self.status_label2.config(text="❌ Chữ ký phần dữ liệu sai!")
                        self.conn.close()
                        if self.server:
                            self.server.close()
                        return
                    result += decrypt_3des(cipher, session_key, iv)

                with open("contract_received.txt", "wb") as f:
                    f.write(result)
                self.status_label2.config(text="✅ Nhận và giải mã thành công!")
                self.conn.close()
                if self.server:
                    self.server.close()
            except Exception as e:
                self.status_label2.config(text=f"❌ Lỗi: {str(e)}")
                if self.conn:
                    self.conn.close()
                if self.server:
                    self.server.close()

if __name__ == "__main__":
    root = tk.Tk()
    app = GuiNguoiNhan(root)
    root.mainloop()