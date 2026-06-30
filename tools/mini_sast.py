# ============================================================
# File: mini_sast.py
# Mục đích:
#   Đây là công cụ Mini SAST được viết bằng Python.
#   Công cụ này dùng để thay thế Semgrep trong phạm vi demo.
#
# Chức năng:
#   1. Đọc source code Python.
#   2. Phân tích code bằng AST.
#   3. Phát hiện một số lỗi bảo mật phổ biến:
#      - Hardcoded Password
#      - SQL query nối chuỗi
#      - os.system()
#
# Lưu ý:
#   Đây là bản demo học thuật, không mạnh bằng Semgrep thật.
# ============================================================

import ast
import sys
from dataclasses import dataclass
from pathlib import Path


# Danh sách từ khóa thường xuất hiện trong tên biến nhạy cảm.
# Ví dụ: PASSWORD, db_password, secret_key, pwd...
SENSITIVE_NAMES = ("password", "passwd", "pwd", "secret")


# Danh sách từ khóa SQL phổ biến.
# Nếu một chuỗi có các từ này và được nối bằng dấu +,
# ta xem đó là dấu hiệu có thể gây SQL Injection.
SQL_KEYWORDS = ("select", "insert", "update", "delete")


@dataclass
class Finding:
    """
    Lớp Finding dùng để lưu thông tin một lỗi bảo mật được phát hiện.

    Thuộc tính:
        rule_id: mã rule phát hiện lỗi.
        severity: mức độ nghiêm trọng.
        message: mô tả lỗi.
        file_path: đường dẫn file bị lỗi.
        line: dòng bị lỗi.
        code: đoạn code liên quan.
    """

    rule_id: str
    severity: str
    message: str
    file_path: Path
    line: int
    code: str


class SecurityVisitor(ast.NodeVisitor):
    """
    SecurityVisitor là class duyệt cây AST của Python.

    AST = Abstract Syntax Tree.
    Đây là cây biểu diễn cấu trúc source code Python.

    Thay vì quét text đơn thuần, AST giúp ta hiểu code tốt hơn.
    Ví dụ:
        - Biết đâu là biến.
        - Biết đâu là lời gọi hàm.
        - Biết đâu là biểu thức nối chuỗi.
    """

    def __init__(self, file_path: Path, source_code: str):
        # Lưu đường dẫn file đang quét.
        self.file_path = file_path

        # Lưu toàn bộ source code để lấy lại đoạn code ở dòng bị lỗi.
        self.source_code = source_code

        # Danh sách findings phát hiện được.
        self.findings: list[Finding] = []

        # Dùng set để tránh báo trùng một rule trên cùng một dòng.
        self.reported: set[tuple[str, int]] = set()

    def add_finding(
        self,
        rule_id: str,
        severity: str,
        message: str,
        node: ast.AST,
    ) -> None:
        """
        Hàm thêm một finding vào danh sách kết quả.

        node là vị trí AST đang bị phát hiện lỗi.
        """

        # Lấy số dòng của node.
        line = getattr(node, "lineno", 0)

        # Tránh báo trùng cùng một rule trên cùng một dòng.
        key = (rule_id, line)
        if key in self.reported:
            return

        self.reported.add(key)

        # Lấy đoạn source code tương ứng với node.
        code = ast.get_source_segment(self.source_code, node)

        # Nếu không lấy được source segment thì để chuỗi rỗng.
        if code is None:
            code = ""

        self.findings.append(
            Finding(
                rule_id=rule_id,
                severity=severity,
                message=message,
                file_path=self.file_path,
                line=line,
                code=code.strip(),
            )
        )

    def visit_Assign(self, node: ast.Assign) -> None:
        """
        Hàm này được gọi khi AST gặp phép gán biến.

        Ví dụ:
            PASSWORD = "admin123"

        Mục tiêu:
            Phát hiện hardcoded password/secret.
        """

        # Duyệt qua các biến ở bên trái dấu =
        for target in node.targets:

            # Chỉ kiểm tra biến dạng Name.
            # Ví dụ: PASSWORD = "admin123"
            if not isinstance(target, ast.Name):
                continue

            variable_name = target.id.lower()

            # Kiểm tra tên biến có chứa password/passwd/pwd/secret hay không.
            is_sensitive_name = any(
                keyword in variable_name for keyword in SENSITIVE_NAMES
            )

            # Kiểm tra giá trị gán có phải chuỗi cố định hay không.
            is_string_literal = isinstance(node.value, ast.Constant) and isinstance(
                node.value.value, str
            )

            if is_sensitive_name and is_string_literal:
                self.add_finding(
                    rule_id="python-hardcoded-password",
                    severity="WARNING",
                    message="Phát hiện password/secret được hardcode trong source code.",
                    node=node,
                )

        # Tiếp tục duyệt các node con.
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """
        Hàm này được gọi khi AST gặp lời gọi hàm.

        Ví dụ:
            os.system("cat " + filename)

        Mục tiêu:
            Phát hiện việc sử dụng os.system().
        """

        # Kiểm tra lời gọi có dạng module.function() hay không.
        # Ví dụ: os.system()
        if isinstance(node.func, ast.Attribute):

            # Kiểm tra tên hàm có phải system hay không.
            is_system_call = node.func.attr == "system"

            # Kiểm tra phần module có phải os hay không.
            is_os_module = isinstance(node.func.value, ast.Name) and node.func.value.id == "os"

            if is_os_module and is_system_call:
                self.add_finding(
                    rule_id="python-dangerous-os-system",
                    severity="ERROR",
                    message="Không nên dùng os.system() với input người dùng vì có nguy cơ Command Injection.",
                    node=node,
                )

        # Tiếp tục duyệt các node con.
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        """
        Hàm này được gọi khi AST gặp biểu thức toán tử.

        Ví dụ:
            "SELECT ..." + username

        Mục tiêu:
            Phát hiện SQL query được tạo bằng cách nối chuỗi.
        """

        # Chỉ quan tâm phép cộng chuỗi bằng dấu +
        if isinstance(node.op, ast.Add):

            # Lấy đoạn source code của biểu thức.
            code = ast.get_source_segment(self.source_code, node)

            if code:
                code_lower = code.lower()

                # Kiểm tra có từ khóa SQL trong đoạn code hay không.
                has_sql_keyword = any(keyword in code_lower for keyword in SQL_KEYWORDS)

                # Kiểm tra có dấu + để nối chuỗi hay không.
                has_string_concat = "+" in code

                if has_sql_keyword and has_string_concat:
                    self.add_finding(
                        rule_id="python-sql-query-string-concat",
                        severity="ERROR",
                        message="Có dấu hiệu nối chuỗi khi tạo câu SQL. Nên dùng parameterized query để tránh SQL Injection.",
                        node=node,
                    )

        # Tiếp tục duyệt các node con.
        self.generic_visit(node)


def scan_file(file_path: Path) -> list[Finding]:
    """
    Hàm quét một file Python.

    Tham số:
        file_path: đường dẫn file Python cần quét.

    Trả về:
        Danh sách findings tìm được.
    """

    # Đọc nội dung source code.
    source_code = file_path.read_text(encoding="utf-8")

    try:
        # Chuyển source code thành AST.
        tree = ast.parse(source_code)

    except SyntaxError as error:
        # Nếu file Python bị lỗi cú pháp, báo lỗi và bỏ qua.
        print(f"[ERROR] Không parse được file {file_path}: {error}")
        return []

    # Tạo visitor để duyệt AST.
    visitor = SecurityVisitor(file_path=file_path, source_code=source_code)

    # Bắt đầu duyệt AST.
    visitor.visit(tree)

    # Trả về danh sách findings.
    return visitor.findings


def collect_python_files(paths: list[str]) -> list[Path]:
    """
    Hàm thu thập danh sách file Python cần quét.

    Người dùng có thể truyền vào:
        - Một file .py
        - Một thư mục chứa nhiều file .py
    """

    python_files: list[Path] = []

    for raw_path in paths:
        path = Path(raw_path)

        # Nếu là file Python thì thêm trực tiếp.
        if path.is_file() and path.suffix == ".py":
            python_files.append(path)

        # Nếu là thư mục thì tìm toàn bộ file .py bên trong.
        elif path.is_dir():
            python_files.extend(path.rglob("*.py"))

    return python_files


def print_report(findings: list[Finding]) -> None:
    """
    Hàm in kết quả quét ra terminal.
    """

    print()
    print("┌──────────────────────────────┐")
    print("│ Mini Python Security Scanner │")
    print("└──────────────────────────────┘")
    print()

    if not findings:
        print("✅ Scan completed successfully.")
        print(" • Findings: 0")
        print(" • Không phát hiện lỗi theo rule hiện tại.")
        return

    print(f"❌ Scan completed with {len(findings)} finding(s).")
    print()

    for finding in findings:
        print(f"{finding.file_path}:{finding.line}")
        print(f"  [{finding.severity}] {finding.rule_id}")
        print(f"  {finding.message}")

        if finding.code:
            print(f"  Code: {finding.code}")

        print()


def main() -> int:
    """
    Hàm main của chương trình scanner.

    Cách chạy:
        python3 tools/mini_sast.py src/vulnerable_app.py
        python3 tools/mini_sast.py src/secure_app.py
    """

    # Lấy danh sách đường dẫn từ command line.
    paths = sys.argv[1:]

    # Nếu người dùng không truyền file/thư mục, hiển thị hướng dẫn.
    if not paths:
        print("Cách dùng:")
        print("  python3 tools/mini_sast.py <file-hoặc-thư-mục>")
        return 2

    # Thu thập các file Python cần quét.
    python_files = collect_python_files(paths)

    if not python_files:
        print("Không tìm thấy file Python để quét.")
        return 2

    all_findings: list[Finding] = []

    # Quét từng file Python.
    for file_path in python_files:
        findings = scan_file(file_path)
        all_findings.extend(findings)

    # In báo cáo kết quả.
    print_report(all_findings)

    # Trả về exit code:
    #   0 = không có lỗi
    #   1 = có finding
    return 1 if all_findings else 0


if __name__ == "__main__":
    raise SystemExit(main())

