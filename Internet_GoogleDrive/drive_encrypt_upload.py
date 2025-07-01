import os
import pickle
import json
import base64
import tkinter as tk
from tkinter import filedialog, messagebox
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from utils_crypto import aes_encrypt
from Crypto.Random import get_random_bytes

SCOPES = ['https://www.googleapis.com/auth/drive.file']

class GuiEncryptUpload:
    def __init__(self, root):
        self.root = root
        self.root.title("Mã Hóa và Tải Lên Google Drive")
        self.root.geometry("600x550")
        self.root.configure(bg="#f0f4f8")

        self.title_label = tk.Label(root, text="Mã Hóa và Tải Lên File", 
                                   font=("Arial", 16, "bold"), fg="#1a3c6e", bg="#f0f4f8")
        self.title_label.pack(pady=10)

        # Bước 1: Chọn File
        self.step1_frame = tk.LabelFrame(root, text="Bước 1: Chọn File", 
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

        # Bước 2: Xác thực Google Drive
        self.step2_frame = tk.LabelFrame(root, text="Bước 2: Xác Thực Google Drive", 
                                        font=("Arial", 10, "bold"), fg="#1a3c6e", bg="#f0f4f8", 
                                        padx=10, pady=10)
        self.step2_frame.pack(fill="x", padx=20, pady=10)

        self.auth_btn = tk.Button(self.step2_frame, text="Xác Thực Google Drive", 
                                 command=self.authenticate, bg="#4a90e2", fg="white", 
                                 font=("Arial", 10), activebackground="#357abd")
        self.auth_btn.pack(pady=5)

        self.auth_status = tk.Label(self.step2_frame, text="Chưa xác thực", 
                                   fg="#34495e", bg="#f0f4f8", font=("Arial", 10))
        self.auth_status.pack(pady=5)

        # Bước 3: Mã hóa và Tải lên
        self.step3_frame = tk.LabelFrame(root, text="Bước 3: Mã Hóa và Tải Lên", 
                                        font=("Arial", 10, "bold"), fg="#1a3c6e", bg="#f0f4f8", 
                                        padx=10, pady=10)
        self.step3_frame.pack(fill="x", padx=20, pady=10)

        self.progress = tk.Scale(self.step3_frame, from_=0, to=100, orient="horizontal", 
                                length=400, showvalue=1, bg="#f0f4f8", fg="#1a3c6e", 
                                troughcolor="#d3e0ea", activebackground="#357abd")
        self.progress.pack(pady=5)

        self.upload_btn = tk.Button(self.step3_frame, text="Mã Hóa và Tải Lên", 
                                   command=self.upload_encrypted_file, bg="#4a90e2", fg="white", 
                                   font=("Arial", 10), state="disabled", activebackground="#357abd")
        self.upload_btn.pack(pady=5)

        self.status_label = tk.Label(self.step3_frame, text="", 
                                    fg="#27ae60", bg="#f0f4f8", font=("Arial", 10, "bold"))
        self.status_label.pack(pady=5)

        self.guide_label = tk.Label(root, text="Lưu ý: ID file sẽ hiển thị ở terminal sau khi tải lên thành công. Đảm bảo file credentials.json tồn tại.", 
                                   fg="#7f8c8d", bg="#f0f4f8", font=("Arial", 9, "italic"))
        self.guide_label.pack(pady=10)

        self.file_path = ""
        self.creds = None

    def select_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if self.file_path:
            self.file_label.config(text=f"File đã chọn: {os.path.basename(self.file_path)}")
            if self.creds:
                self.upload_btn.config(state="normal")
        else:
            self.file_label.config(text="Chưa chọn file")

    def authenticate(self):
        try:
            if os.path.exists('token.json'):
                with open('token.json', 'rb') as token:
                    self.creds = pickle.load(token)
            if not self.creds or not self.creds.valid:
                if self.creds and self.creds.expired and self.creds.refresh_token:
                    self.creds.refresh(Request())
                else:
                    flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
                    self.creds = flow.run_local_server(port=0)
                with open('token.json', 'wb') as token:
                    pickle.dump(self.creds, token)
            self.auth_status.config(text="✅ Xác thực thành công!")
            if self.file_path:
                self.upload_btn.config(state="normal")
        except Exception as e:
            self.auth_status.config(text=f"❌ Lỗi xác thực: {str(e)}")
            messagebox.showerror("Lỗi", f"Xác thực thất bại: {str(e)}")

    def upload_encrypted_file(self):
        if not self.file_path:
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn file trước!")
            return
        if not self.creds:
            messagebox.showwarning("Cảnh báo", "Vui lòng xác thực Google Drive trước!")
            return
        try:
            self.progress.set(0)
            self.status_label.config(text="Đang mã hóa...")
            self.root.update()

            key = get_random_bytes(16)
            iv = get_random_bytes(16)
            with open(self.file_path, 'rb') as f:
                plaintext = f.read()
            ciphertext = aes_encrypt(plaintext, key, iv)
            self.progress.set(50)
            self.root.update()

            package = {
                'filename': os.path.basename(self.file_path),
                'cipher': base64.b64encode(ciphertext).decode(),
                'key': base64.b64encode(key).decode(),
                'iv': base64.b64encode(iv).decode()
            }

            with open('upload_data.json', 'w') as f:
                json.dump(package, f)

            self.status_label.config(text="Đang tải lên Google Drive...")
            self.root.update()

            service = build('drive', 'v3', credentials=self.creds)
            file_metadata = {'name': 'upload_data.json'}
            media = MediaFileUpload('upload_data.json', mimetype='application/json')
            file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()

            file_id = file.get('id')
            print(f"✅ Tải lên thành công! ID File trên Drive: {file_id}")

            self.progress.set(100)
            self.status_label.config(text="✅ Tải lên thành công! (Xem ID ở terminal)")
            self.upload_btn.config(state="disabled")
        except Exception as e:
            self.status_label.config(text=f"❌ Lỗi: {str(e)}")
            messagebox.showerror("Lỗi", f"Mã hóa/tải lên thất bại: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = GuiEncryptUpload(root)
    root.mainloop()