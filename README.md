# Semgrep + Mini SAST Python Security Demo

## Giới thiệu

Đây là project demo sử dụng **Semgrep** và một công cụ **Mini SAST tự viết bằng Python** để phát hiện lỗi bảo mật trong mã nguồn Python.

Project gồm hai hướng kiểm tra bảo mật:

1. Dùng **Semgrep** với custom rule.
2. Dùng **Mini SAST Python** tự viết để mô phỏng cách công cụ SAST hoạt động.

Mục tiêu chính của project là phát hiện một số lỗi bảo mật phổ biến trong mã nguồn Python, sau đó sửa code và quét lại để kiểm chứng kết quả.

---

## Thông tin đề tài

**Tên đề tài:** Ứng dụng Semgrep và Python để phát hiện lỗi bảo mật trong mã nguồn Python
**Sinh viên:** Nguyễn Thành Nhân
**Môn:** Lập trình Python
**GVHD:** Nguyễn Hải Sơn

---

## Các lỗi bảo mật được demo

Project phát hiện 3 lỗi bảo mật chính:

1. **Hardcoded Password**
   Mật khẩu bị ghi trực tiếp trong source code.

2. **SQL Injection**
   Câu lệnh SQL được tạo bằng cách nối chuỗi với dữ liệu người dùng nhập.

3. **Command Injection**
   Chương trình thực thi lệnh hệ điều hành bằng dữ liệu đầu vào không kiểm soát.

---

## Cấu trúc project

```text
semgrep-python-demo/
├── .gitignore
├── README.md
├── rules/
│   └── python-security.yml
├── src/
│   ├── data/
│   │   └── report.txt
│   ├── secure_app.py
│   └── vulnerable_app.py
└── tools/
    └── mini_sast.py
```

---

## Ý nghĩa các file

| File                        | Chức năng                                  |
| --------------------------- | ------------------------------------------ |
| `src/vulnerable_app.py`     | Phiên bản code Python có lỗi bảo mật       |
| `src/secure_app.py`         | Phiên bản code Python đã sửa an toàn hơn   |
| `src/data/report.txt`       | File dữ liệu demo                          |
| `rules/python-security.yml` | Custom rule cho Semgrep                    |
| `tools/mini_sast.py`        | Công cụ Mini SAST tự viết bằng Python      |
| `.gitignore`                | Loại bỏ các file không cần push lên GitHub |
| `README.md`                 | Mô tả project và hướng dẫn chạy            |

---

## Quy trình demo

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

Ngoài Semgrep, project còn có công cụ Mini SAST tự viết bằng Python:

```text
vulnerable_app.py
        ↓
Mini SAST Python scan
        ↓
3 findings
        ↓
secure_app.py
        ↓
Mini SAST Python scan
        ↓
0 findings
```

---

## Phiên bản code có lỗi: vulnerable_app.py

Trong file `src/vulnerable_app.py`, có 3 lỗi bảo mật được tạo có chủ đích.

### 1. Hardcoded Password

```python
PASSWORD = "admin123"
```

Lỗi này xảy ra khi mật khẩu bị ghi trực tiếp trong source code. Nếu source code bị public lên GitHub, mật khẩu có thể bị lộ.

### 2. SQL Injection

```python
query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
```

Lỗi này xảy ra do câu SQL được tạo bằng cách nối chuỗi trực tiếp với dữ liệu người dùng nhập.

### 3. Command Injection

```python
os.system("cat " + filename)
```

Lỗi này xảy ra khi chương trình gọi lệnh hệ điều hành bằng dữ liệu người dùng nhập vào.

---

## Phiên bản đã sửa: secure_app.py

Trong file `src/secure_app.py`, các lỗi được sửa như sau:

| Lỗi ban đầu        | Cách sửa                             |
| ------------------ | ------------------------------------ |
| Hardcoded Password | Dùng biến môi trường `DEMO_PASSWORD` |
| SQL Injection      | Dùng parameterized query             |
| Command Injection  | Dùng `pathlib` và `read_text()`      |

### Sửa Hardcoded Password

```python
demo_password = get_required_env("DEMO_PASSWORD")
```

Mật khẩu không còn ghi trực tiếp trong source code mà được lấy từ biến môi trường.

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

## Custom rule Semgrep

File rule nằm tại:

```text
rules/python-security.yml
```

Project sử dụng 3 rule chính:

| Rule ID                          | Mục đích                                   |
| -------------------------------- | ------------------------------------------ |
| `python-hardcoded-password`      | Phát hiện password hoặc secret bị hardcode |
| `python-sql-query-string-concat` | Phát hiện SQL query tạo bằng nối chuỗi     |
| `python-dangerous-os-system`     | Phát hiện việc sử dụng `os.system()`       |

---

## Quét bằng Semgrep

### Quét file có lỗi

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

Các lỗi được phát hiện:

```text
1. Hardcoded Password
2. SQL Injection
3. Command Injection
```

### Quét file đã sửa

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

---

## Mini SAST bằng Python

Ngoài Semgrep, project còn có công cụ `tools/mini_sast.py` được viết bằng Python.

Công cụ này sử dụng thư viện `ast` để phân tích mã nguồn Python.

```text
AST = Abstract Syntax Tree
```

AST giúp chương trình hiểu cấu trúc source code Python, ví dụ:

* Đâu là biến.
* Đâu là phép gán.
* Đâu là lời gọi hàm.
* Đâu là biểu thức nối chuỗi.

Mini SAST Python phát hiện 3 lỗi:

1. Hardcoded Password.
2. SQL query nối chuỗi.
3. Sử dụng `os.system()`.

---

## Quét bằng Mini SAST Python

### Quét file có lỗi

```bash
python3 tools/mini_sast.py src/vulnerable_app.py
```

Kết quả mong muốn:

```text
3 finding(s)
```

Các rule được phát hiện:

```text
python-hardcoded-password
python-sql-query-string-concat
python-dangerous-os-system
```

### Quét file đã sửa

```bash
python3 tools/mini_sast.py src/secure_app.py
```

Kết quả mong muốn:

```text
Findings: 0
```

---

## Chạy chương trình đã sửa

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
BÁO CÁO DEMO PYTHON + SEMGREP
...
```

---

## So sánh kết quả

| Công cụ          | vulnerable_app.py | secure_app.py |
| ---------------- | ----------------: | ------------: |
| Semgrep          |        3 findings |    0 findings |
| Mini SAST Python |        3 findings |    0 findings |

---

## Kết luận

Project cho thấy có thể phát hiện lỗi bảo mật trong mã nguồn Python bằng hai cách:

1. Sử dụng công cụ chuyên nghiệp là **Semgrep**.
2. Tự xây dựng một công cụ **Mini SAST bằng Python** để mô phỏng cách phân tích mã nguồn hoạt động.

Kết quả demo cho thấy:

* File `vulnerable_app.py` có 3 lỗi bảo mật.
* Sau khi sửa thành `secure_app.py`, kết quả quét giảm xuống 0 findings.

Semgrep phù hợp với môi trường thực tế vì có nhiều rule, hỗ trợ CI/CD và có thể tích hợp vào DevSecOps pipeline.
Mini SAST Python phù hợp cho mục tiêu học tập vì giúp hiểu rõ hơn cách công cụ phân tích mã nguồn hoạt động.

Hướng phát triển tiếp theo:

* Tích hợp Semgrep vào GitHub Actions.
* Tự động quét code mỗi khi push lên GitHub.
* Kết hợp thêm Docker và Trivy để mở rộng thành pipeline DevSecOps.
