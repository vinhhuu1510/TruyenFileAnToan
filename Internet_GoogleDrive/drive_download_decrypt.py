import os
import pickle
import json
import base64
import tkinter as tk
from tkinter import filedialog, messagebox
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
import io
from utils_crypto import aes_decrypt

SCOPES = ['https://www.googleapis.com/auth/drive.file']

class GuiDownloadDecrypt:
    def __init__(self, root):
        self.root = root
        self.root.title("Tải Xuống và Giải Mã File")
        self.root.geometry("600x650")
        self.root.configure(bg="#f0f4f8")

        self.title_label = tk.Label(root, text="Tải Xuống và Giải Mã File từ Google Drive", 
                                   font=("Arial", 16, "bold"), fg="#1a3c6e", bg="#f0f4f8")
        self.title_label.pack(pady=10)

        # Bước 1: Xác thực Google Drive
        self.step1_frame = tk.LabelFrame(root, text="Bước 1: Xác Thực Google Drive", 
                                        font=("Arial", 10, "bold"), fg="#1a3c6e", bg="#f0f4f8", 
                                        padx=10, pady=10)
        self.step1_frame.pack(fill="x", padx=20, pady=10)

        self.auth_btn = tk.Button(self.step1_frame, text="Xác Thực Google Drive", 
                                 command=self.authenticate, bg="#4a90e2", fg="white", 
                                 font=("Arial", 10), activebackground="#357abd")
        self.auth_btn.pack(pady=5)

        self.auth_status = tk.Label(self.step1_frame, text="Chưa xác thực", 
                                   fg="#34495e", bg="#f0f4f8", font=("Arial", 10))
        self.auth_status.pack(pady=5)

        # Bước 2: Nhập File ID
        self.step2_frame = tk.LabelFrame(root, text="Bước 2: Nhập File ID", 
                                        font=("Arial", 10, "bold"), fg="#1a3c6e", bg="#f0f4f8", 
                                        padx=10, pady=10)
        self.step2_frame.pack(fill="x", padx=20, pady=10)

        self.file_id_label = tk.Label(self.step2_frame, text="File ID:", 
                                     fg="#34495e", bg="#f0f4f8", font=("Arial", 10))
        self.file_id_label.pack(side="left", padx=5)

        self.file_id_entry = tk.Entry(self.step2_frame, width=40, font=("Arial", 10))
        self.file_id_entry.pack(side="left", padx=5)

        self.search_btn = tk.Button(self.step2_frame, text="Tìm File", 
                                   command=self.search_files, bg="#4a90e2", fg="white", 
                                   font=("Arial", 10), activebackground="#357abd")
        self.search_btn.pack(side="left", padx=5)

        self.file_list_label = tk.Label(self.step2_frame, text="Chưa tìm thấy file", 
                                       fg="#34495e", bg="#f0f4f8", font=("Arial", 10))
        self.file_list_label.pack(pady=5)

        # Bước 3: Tải xuống và Giải mã
        self.step3_frame = tk.LabelFrame(root, text="Bước 3: Tải Xuống và Giải Mã", 
                                        font=("Arial", 10, "bold"), fg="#1a3c6e", bg="#f0f4f8", 
                                        padx=10, pady=10)
        self.step3_frame.pack(fill="x", padx=20, pady=10)

        self.progress = tk.Scale(self.step3_frame, from_=0, to=100, orient="horizontal", 
                                length=400, showvalue=1, bg="#f0f4f8", fg="#1a3c6e", 
                                troughcolor="#d3e0ea", activebackground="#4a90e2")
        self.progress.pack(pady=5)

        self.download_btn = tk.Button(self.step3_frame, text="Tải Xuống và Giải Mã", 
                                     command=self.download_and_decrypt, bg="#4a90e2", fg="white", 
                                     font=("Arial", 10), state="disabled", activebackground="#357abd")
        self.download_btn.pack(pady=5)

        self.status_label = tk.Label(self.step3_frame, text="", 
                                    fg="#27ae60", bg="#f0f4f8", font=("Arial", 10, "bold"))
        self.status_label.pack(pady=5)

        self.guide_label = tk.Label(root, text="Lưu ý: Đảm bảo file credentials.json tồn tại và File ID hợp lệ.", 
                                   fg="#7f8c8d", bg="#f0f4f8", font=("Arial", 9, "italic"))
        self.guide_label.pack(pady=10)

        self.creds = None

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
            self.download_btn.config(state="normal")
        except Exception as e:
            self.auth_status.config(text=f"❌ Lỗi xác thực: {str(e)}")
            messagebox.showerror("Lỗi", f"Xác thực thất bại: {str(e)}")

    def search_files(self):
        if not self.creds:
            messagebox.showwarning("Cảnh báo", "Vui lòng xác thực Google Drive trước!")
            return
        try:
            service = build('drive', 'v3', credentials=self.creds)
            results = service.files().list(q="name='upload_data.json'", fields="files(id, name)").execute()
            items = results.get('files', [])
            if not items:
                self.file_list_label.config(text="❌ Không tìm thấy file nào!")
            else:
                file_info = "\n".join([f"ID: {item['id']}, Name: {item['name']}" for item in items])
                self.file_list_label.config(text=f"Tìm thấy:\n{file_info}")
                if len(items) == 1:
                    self.file_id_entry.delete(0, tk.END)
                    self.file_id_entry.insert(0, items[0]['id'])
        except Exception as e:
            self.file_list_label.config(text=f"❌ Lỗi: {str(e)}")
            messagebox.showerror("Lỗi", f"Tìm file thất bại: {str(e)}")

    def download_and_decrypt(self):
        file_id = self.file_id_entry.get()
        if not file_id:
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập File ID!")
            return
        if not self.creds:
            messagebox.showwarning("Cảnh báo", "Vui lòng xác thực Google Drive trước!")
            return
        try:
            self.progress.set(0)
            self.status_label.config(text="Đang tải xuống...")
            self.root.update()

            service = build('drive', 'v3', credentials=self.creds)
            request = service.files().get_media(fileId=file_id)
            fh = io.BytesIO()
            downloader = MediaIoBaseDownload(fh, request)
            done = False
            while not done:
                status, done = downloader.next_chunk()
                self.progress.set(int(status.progress() * 50))  # 50% cho tải xuống
            fh.seek(0)

            self.status_label.config(text="Đang giải mã...")
            self.root.update()

            data = json.loads(fh.getvalue().decode())
            ciphertext = base64.b64decode(data['cipher'])
            key = base64.b64decode(data['key'])
            iv = base64.b64decode(data['iv'])

            plaintext = aes_decrypt(ciphertext, key, iv)
            save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
            if save_path:
                with open(save_path, 'wb') as f:
                    f.write(plaintext)
                self.progress.set(100)
                self.status_label.config(text=f"✅ Lưu file tại {save_path}")
            else:
                self.status_label.config(text="❌ Hủy lưu file")
        except Exception as e:
            self.status_label.config(text=f"❌ Lỗi: {str(e)}")
            messagebox.showerror("Lỗi", f"Tải xuống/giải mã thất bại: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = GuiDownloadDecrypt(root)
    root.mainloop()