# ============================================================
# File: secure_app.py
# Mục đích:
#   Phiên bản chương trình Python đã được sửa an toàn hơn.
#
# Chức năng:
#   1. Khởi tạo database SQLite.
#   2. Tạo tài khoản admin demo.
#   3. Cho người dùng đăng nhập.
#   4. Cho phép đọc file báo cáo trong thư mục data.
#
# Cách sửa:
#   1. Không hardcode password.
#   2. Dùng parameterized query để tránh SQL Injection.
#   3. Không dùng os.system(), thay bằng pathlib và read_text().
# ============================================================

import os
import sqlite3
from getpass import getpass
from pathlib import Path


# Thư mục chứa file secure_app.py.
BASE_DIR = Path(__file__).resolve().parent

# Thư mục data chứa file được phép đọc.
DATA_DIR = (BASE_DIR / "data").resolve()

# Đường dẫn database SQLite.
DB_PATH = BASE_DIR / "demo.db"


def get_required_env(name: str) -> str:
    """
    Lấy biến môi trường bắt buộc.
    Dùng để tránh ghi mật khẩu trực tiếp trong source code.
    """

    value = os.environ.get(name)

    if not value:
        raise RuntimeError(f"Thiếu biến môi trường bắt buộc: {name}")

    return value


def get_database_connection() -> sqlite3.Connection:
    """
    Tạo kết nối đến database SQLite.
    """

    return sqlite3.connect(DB_PATH)


def initialize_database() -> None:
    """
    Tạo bảng users và thêm tài khoản admin demo.
    """

    # Lấy mật khẩu từ biến môi trường.
    demo_password = get_required_env("DEMO_PASSWORD")

    with get_database_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
            """
        )

        # Dùng dấu ? để truyền tham số an toàn.
        # Đây là parameterized query, giúp tránh SQL Injection.
        conn.execute(
            "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
            ("admin", demo_password),
        )


def authenticate_user(username: str, password: str) -> bool:
    """
    Kiểm tra username/password có đúng hay không.
    """

    with get_database_connection() as conn:
        # Không nối chuỗi SQL.
        # Dữ liệu username/password được truyền riêng qua tuple.
        cursor = conn.execute(
            "SELECT id FROM users WHERE username = ? AND password = ?",
            (username, password),
        )

        return cursor.fetchone() is not None


def read_report_file(filename: str) -> str:
    """
    Đọc file trong thư mục data.
    Không cho phép đọc file bên ngoài thư mục data.
    """

    # Ghép tên file người dùng nhập với thư mục data.
    target_file = (DATA_DIR / filename).resolve()

    # Kiểm tra file có nằm trong thư mục data hay không.
    try:
        target_file.relative_to(DATA_DIR)
    except ValueError as exc:
        raise ValueError("Không được truy cập file bên ngoài thư mục data") from exc

    if not target_file.is_file():
        raise FileNotFoundError("File không tồn tại")

    # Đọc file bằng Python, không dùng os.system().
    return target_file.read_text(encoding="utf-8")


def main() -> None:
    """
    Hàm chính điều khiển chương trình.
    """

    initialize_database()

    username = input("Username: ").strip()
    password = getpass("Password: ")

    if not authenticate_user(username, password):
        print("Sai tài khoản hoặc mật khẩu")
        return

    print("Đăng nhập thành công")

    filename = input("Nhập tên file báo cáo cần đọc: ").strip()

    try:
        content = read_report_file(filename)
    except (ValueError, FileNotFoundError) as error:
        print(f"Lỗi: {error}")
        return

    print("\nNội dung file:")
    print(content)


if __name__ == "__main__":
    main()
