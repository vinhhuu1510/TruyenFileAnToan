**Ứng Dụng Gửi Hợp Đồng Bảo Mật Với Chữ Ký Số Riêng**

*Đề tài tập trung vào việc xây dựng hệ thống gửi tệp hợp đồng điện tử có tính bảo mật, toàn vẹn và xác thực bằng cách sử dụng các thuật toán mã hóa hiện đại như Triple DES, RSA và SHA-512.*

---

### 🌟 **Giới thiệu**

* **Bảo mật hợp đồng:** Nội dung hợp đồng được mã hóa bằng thuật toán đối xứng Triple DES, đảm bảo dữ liệu không bị đọc trộm trong quá trình truyền tải.

* **Chữ ký số RSA:** Xác thực danh tính người gửi và đảm bảo không thể chối bỏ bằng chữ ký số sử dụng khóa riêng RSA.

* **Toàn vẹn dữ liệu:** Tính toàn vẹn được đảm bảo thông qua hàm băm SHA-512, giúp phát hiện mọi thay đổi trên dữ liệu.

* **Ứng dụng:** Hệ thống được triển khai ở 3 cấp độ: kiểm tra nội bộ trên 1 máy, truyền file giữa 2 máy trong mạng LAN, và truyền file qua Internet sử dụng Google Drive.



### 🛠️ **Công nghệ sử dụng**

#### 🖥️ Phần mềm:

* **Python 3.10+**
* **Thư viện PyCryptodome** – triển khai Triple DES, RSA, SHA-512
* **Google API Client** – giao tiếp với Google Drive thông qua OAuth 2.0
* **Tkinter** – xây dựng giao diện người dùng

#### 📦 Yêu cầu thư viện:

```bash
pip install pycryptodome
pip install google-api-python-client google-auth google-auth-oauthlib google-auth-httplib2
```

---

### 🧮 **Giải thuật sử dụng**

1. **Mã hóa dữ liệu (Triple DES)**

   * Chia file `contract.txt` thành 3 phần bằng nhau
   * Sinh IV ngẫu nhiên và mã hóa từng phần bằng Triple DES (chế độ CBC)

2. **Kiểm tra toàn vẹn (SHA-512)**

   * Tính băm SHA-512 của chuỗi `IV || ciphertext`

3. **Chữ ký số (RSA 2048-bit)**

   * Ký từng hash bằng khóa riêng của người gửi
   * Ký metadata (tên file, timestamp, kích thước) bằng RSA
   * Mã hóa session key Triple DES bằng khóa công khai người nhận (PKCS#1 v1.5)

4. **Truyền file**

   * Tạo JSON chứa `enc_session_key`, `metadata`, `sig_metadata`, `packets`
   * Gửi JSON cho người nhận hoặc lưu lên Drive

5. **Giải mã & kiểm tra (Người nhận)**

   * Kiểm tra hash, chữ ký
   * Giải mã từng phần nếu hợp lệ
   * Ghép lại thành `contract_received.txt`

---

### 🚀 **Hướng dẫn chạy thử**

#### 🔁 **Mức 1 – Kiểm tra nội bộ (1 máy):**

```bash
python nguoi_gui.py
```
```bash
python nguoi_nhan.py
```

#### 🌐 **Mức 2 – Gửi qua mạng LAN (2 máy):**

* Máy gửi:

```bash
python nguoi_gui.py
```

* Máy nhận:

```bash
python nguoi_nhan.py
```

#### ☁️ **Mức 3 – Gửi file qua Internet (Google Drive):**

* Mã hóa và upload:

```bash
python drive_encrypt_upload.py
```

* Download và giải mã:

```bash
python drive_download_decrypt.py
```

---

### 📌 **Lưu ý bảo mật**

* File `credentials.json` chỉ dùng để xác thực OAuth 2.0 với Google – không chia sẻ công khai.
* Khóa riêng RSA được lưu cục bộ trên máy gửi – không được gửi kèm hoặc upload.
* Tất cả nội dung upload lên Drive đã được mã hóa hoàn toàn.

---

### 🤝 **Đóng góp nhóm**

| Họ và Tên          | Vai trò                                                                    |
| ------------       | ---------------------------------------------------------------------------|
| Trương Hữu Vinh    | Thiết kế thuật toán và xử lý mã hóa, xây dựng mã nguồn sender/receiver     |
| Đinh Thị Ngọc Bích | Tích hợp GUI, viết phần giao tiếp Google Drive và xử lý xác thực OAuth     |
| Trịnh Minh Quân    | Viết báo cáo, trình bày, kiểm thử hệ thống và tổng hợp hướng dẫn người dùng|

---

© 2025 NHÓM 5, GỬI HỢP ĐỒNG VỚI CHỮ KÝ SỐ RIÊNG – NHẬP MÔN AN TOÀN BẢO MẬT THÔNG TIN – TRƯỜNG ĐẠI HỌC ĐẠI NAM
