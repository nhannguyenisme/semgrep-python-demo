# Semgrep Python Security Demo

Đây là project demo sử dụng Semgrep để phát hiện lỗi bảo mật trong mã nguồn Python.

## Các file chính

- `src/vulnerable_app.py`: code Python có lỗi bảo mật.
- `src/secure_app.py`: code Python đã sửa an toàn hơn.
- `rules/python-security.yml`: custom rule Semgrep.
- `src/data/report.txt`: file dữ liệu demo.

## Lỗi bảo mật được demo

1. Hardcoded Password
2. SQL Injection
3. Command Injection

## Chạy chương trình đã sửa

```bash
export DEMO_PASSWORD="Nhan@123"
python3 src/secure_app.py

