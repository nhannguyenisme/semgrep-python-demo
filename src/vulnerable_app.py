# ============================================================
# File: vulnerable_app.py
# Mục đích:
#   Phiên bản chương trình Python CÓ LỖI BẢO MẬT.
#   File này dùng để demo Semgrep phát hiện lỗi.
#
# Lỗi cố tình tạo:
#   1. Hardcoded Password
#   2. SQL Injection
#   3. Command Injection
# ============================================================

import os
import sqlite3


# LỖI 1: Hardcoded Password
# Mật khẩu bị ghi trực tiếp trong source code.
PASSWORD = "admin123"


def login():
    # Nhận username từ bàn phím.
    username = input("Username: ")

    # Nhận password từ bàn phím.
    password = input("Password: ")

    # Kết nối đến database SQLite.
    conn = sqlite3.connect("demo.db")

    # LỖI 2: SQL Injection
    # Câu SQL được tạo bằng cách nối chuỗi trực tiếp với input người dùng.
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"

    # Thực thi câu SQL.
    result = conn.execute(query).fetchone()

    if result:
        print("Đăng nhập thành công")
    else:
        print("Sai tài khoản hoặc mật khẩu")


def read_report_file():
    # Nhận tên file từ người dùng.
    filename = input("Nhập tên file cần đọc: ")

    # LỖI 3: Command Injection
    # os.system() thực thi lệnh hệ điều hành với dữ liệu người dùng nhập.
    os.system("cat " + filename)


def main():
    login()
    read_report_file()


main()
