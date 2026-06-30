# Semgrep Python Security Demo

## Báo cáo demo bảo mật mã nguồn

**Đề tài:** Ứng dụng Semgrep để phát hiện lỗi bảo mật trong mã nguồn Python  
**Sinh viên:** Nguyễn Thành Nhân  
**Môn:** Lập trình Python  
**GVHD:** Nguyễn Hải Sơn  

---

## 1. Bối cảnh

Python là ngôn ngữ phổ biến, dễ viết và dễ sử dụng. Tuy nhiên, nếu xử lý dữ liệu đầu vào không cẩn thận, chương trình Python có thể mắc các lỗi bảo mật phổ biến.

Trong project này, em demo 3 lỗi chính:

| Lỗi bảo mật | Mô tả |
|---|---|
| Hardcoded Password | Mật khẩu bị ghi cứng trực tiếp trong source code |
| SQL Injection | Câu lệnh SQL bị tạo bằng cách nối chuỗi với dữ liệu người dùng |
| Command Injection | Lệnh hệ thống thực thi trực tiếp dữ liệu đầu vào không kiểm soát |

**Mục tiêu:** Dùng Semgrep để phát hiện lỗi ngay trong mã nguồn trước khi triển khai thực tế.

---

## 2. Semgrep là gì?

Semgrep là công cụ phân tích mã nguồn tĩnh.

```text
SAST = Static Application Security Testing
```

Semgrep có thể:

- Quét trực tiếp source code.
- Không cần chạy chương trình.
- Phát hiện lỗi bảo mật, bug hoặc coding issue.
- Dùng rule có sẵn hoặc tự viết custom rule.

Mô hình hoạt động:

```text
Source Code  →  Semgrep  →  Findings
```

---

## 3. Mục tiêu demo

Quy trình demo trong project:

```text
1. Viết chương trình Python có lỗi bảo mật
2. Tạo custom rule cho Semgrep
3. Dùng Semgrep quét và phát hiện lỗi
4. Sửa code an toàn hơn
5. Quét lại để kiểm chứng
```

Luồng kiểm tra:

```text
vulnerable_app.py
        ↓
Semgrep scan
        ↓
3 findings
        ↓
secure_app.py
        ↓
Semgrep scan
        ↓
0 findings
```

---

## 4. Cấu trúc project

```text
semgrep-python-demo/
├── .gitignore
├── README.md
├── rules/
│   └── python-security.yml
└── src/
    ├── data/
    │   └── report.txt
    ├── secure_app.py
    └── vulnerable_app.py
```

Ý nghĩa các file:

| File | Chức năng |
|---|---|
| `rules/python-security.yml` | Custom rule cho Semgrep |
| `src/vulnerable_app.py` | Code Python có lỗi bảo mật |
| `src/secure_app.py` | Code Python đã sửa an toàn hơn |
| `src/data/report.txt` | File dữ liệu demo |
| `README.md` | Hướng dẫn chạy project |

---

## 5. Phiên bản code có lỗi: vulnerable_app.py

Trong file `vulnerable_app.py`, có 3 lỗi bảo mật được cài đặt có chủ đích.

### Lỗi 1: Hardcoded Password

```python
PASSWORD = "admin123"
```

Mật khẩu bị ghi trực tiếp trong source code. Nếu source code bị public lên GitHub, mật khẩu có thể bị lộ.

### Lỗi 2: SQL Injection

```python
query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
```

Câu SQL được tạo bằng cách nối chuỗi trực tiếp với dữ liệu người dùng nhập vào. Người dùng có thể nhập dữ liệu độc hại để thay đổi ý nghĩa câu SQL.

### Lỗi 3: Command Injection

```python
os.system("cat " + filename)
```

Chương trình gọi lệnh hệ điều hành bằng dữ liệu người dùng nhập. Nếu người dùng chèn thêm lệnh khác, hệ thống có thể thực thi lệnh ngoài ý muốn.

---

## 6. Custom rule Semgrep

File rule nằm tại:

```text
rules/python-security.yml
```

Project sử dụng 3 rule chính:

| Rule ID | Mục đích |
|---|---|
| `python-hardcoded-password` | Phát hiện password hoặc secret bị hardcode |
| `python-sql-query-string-concat` | Phát hiện SQL query tạo bằng nối chuỗi |
| `python-dangerous-os-system` | Phát hiện việc sử dụng `os.system()` |

Mục tiêu chung của các rule là phát hiện sớm 3 nhóm lỗi bảo mật phổ biến trong mã nguồn Python.

---

## 7. Kết quả scan file có lỗi

Lệnh quét file có lỗi:

```bash
semgrep scan --config rules/python-security.yml src/vulnerable_app.py
```

Kết quả mong muốn:

```text
3 Code Findings
Findings: 3
Rules run: 3
Targets scanned: 1
```

Semgrep phát hiện 3 lỗi:

```text
1. Hardcoded Password
2. SQL Injection
3. Command Injection
```

---

## 8. Phiên bản đã sửa: secure_app.py

Trong file `secure_app.py`, các lỗi được sửa như sau:

| Lỗi ban đầu | Cách sửa |
|---|---|
| Hardcoded Password | Dùng biến môi trường `DEMO_PASSWORD` |
| SQL Injection | Dùng parameterized query |
| Command Injection | Dùng `pathlib` và `read_text()` |

### Sửa Hardcoded Password

```python
demo_password = get_required_env("DEMO_PASSWORD")
```

Mật khẩu không còn ghi trực tiếp trong source code mà lấy từ biến môi trường.

### Sửa SQL Injection

```python
cursor = conn.execute(
    "SELECT id FROM users WHERE username = ? AND password = ?",
    (username, password),
)
```

Dữ liệu người dùng được truyền riêng qua tham số, không nối trực tiếp vào câu SQL.

### Sửa Command Injection

```python
return target_file.read_text(encoding="utf-8")
```

Chương trình đọc file bằng Python thay vì gọi lệnh hệ điều hành bằng `os.system()`.

---

## 9. Chạy chương trình đã sửa

Cấu hình mật khẩu demo:

```bash
export DEMO_PASSWORD="Nhan@123"
```

Chạy chương trình:

```bash
python3 src/secure_app.py
```

Thông tin đăng nhập demo:

```text
Username: admin
Password: Nhan@123
File: report.txt
```

Kết quả mong muốn:

```text
Đăng nhập thành công

Nội dung file:
Đây là file báo cáo demo cho bài Python + Semgrep.
```

---

## 10. Kết quả scan sau khi sửa

Lệnh quét file đã sửa:

```bash
semgrep scan --config rules/python-security.yml src/secure_app.py
```

Kết quả mong muốn:

```text
Findings: 0
Rules run: 3
Targets scanned: 1
Ran 3 rules on 1 file: 0 findings.
```

So sánh kết quả:

| Giai đoạn | Kết quả |
|---|---|
| Trước khi sửa | 3 findings |
| Sau khi sửa | 0 findings |

---

## 11. Kết luận

Semgrep giúp phát hiện sớm lỗi bảo mật trong mã nguồn Python ngay từ giai đoạn lập trình.

Qua demo, Semgrep đã phát hiện được 3 lỗi trong phiên bản `vulnerable_app.py`. Sau khi sửa code thành `secure_app.py`, kết quả quét giảm từ **3 findings xuống 0 findings**.

Hướng phát triển tiếp theo:

- Tích hợp Semgrep vào GitHub Actions.
- Tự động quét code mỗi khi push lên GitHub.
- Kết hợp thêm Docker và Trivy để mở rộng thành pipeline DevSecOps.

