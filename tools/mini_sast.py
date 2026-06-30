# ============================================================
# File: mini_sast.py
# Mục đích:
#   Công cụ Mini SAST viết bằng Python.
#   Dùng để mô phỏng cách công cụ như Semgrep phát hiện lỗi bảo mật.
#
# Phát hiện 3 lỗi:
#   1. Hardcoded Password
#   2. SQL query nối chuỗi
#   3. os.system()
# ============================================================

import ast
import sys
from dataclasses import dataclass
from pathlib import Path


SENSITIVE_NAMES = ("password", "passwd", "pwd", "secret")
SQL_KEYWORDS = ("select", "insert", "update", "delete")


@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    file_path: Path
    line: int
    code: str


class SecurityVisitor(ast.NodeVisitor):
    def __init__(self, file_path: Path, source_code: str):
        self.file_path = file_path
        self.source_code = source_code
        self.findings: list[Finding] = []
        self.reported: set[tuple[str, int]] = set()

    def add_finding(self, rule_id: str, severity: str, message: str, node: ast.AST) -> None:
        line = getattr(node, "lineno", 0)
        key = (rule_id, line)

        if key in self.reported:
            return

        self.reported.add(key)

        code = ast.get_source_segment(self.source_code, node)
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
        Phát hiện hardcoded password.

        Ví dụ:
            PASSWORD = "admin123"
        """

        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue

            variable_name = target.id.lower()

            is_sensitive_name = any(
                keyword in variable_name for keyword in SENSITIVE_NAMES
            )

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

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """
        Phát hiện os.system().

        Ví dụ:
            os.system("cat " + filename)
        """

        if isinstance(node.func, ast.Attribute):
            is_system_call = node.func.attr == "system"
            is_os_module = isinstance(node.func.value, ast.Name) and node.func.value.id == "os"

            if is_os_module and is_system_call:
                self.add_finding(
                    rule_id="python-dangerous-os-system",
                    severity="ERROR",
                    message="Không nên dùng os.system() với input người dùng vì có nguy cơ Command Injection.",
                    node=node,
                )

        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        """
        Phát hiện SQL query nối chuỗi.

        Ví dụ:
            "SELECT ..." + username
        """

        if isinstance(node.op, ast.Add):
            code = ast.get_source_segment(self.source_code, node)

            if code:
                code_lower = code.lower()
                has_sql_keyword = any(keyword in code_lower for keyword in SQL_KEYWORDS)
                has_concat = "+" in code

                if has_sql_keyword and has_concat:
                    self.add_finding(
                        rule_id="python-sql-query-string-concat",
                        severity="ERROR",
                        message="Có dấu hiệu nối chuỗi khi tạo câu SQL. Nên dùng parameterized query để tránh SQL Injection.",
                        node=node,
                    )

        self.generic_visit(node)


def scan_file(file_path: Path) -> list[Finding]:
    source_code = file_path.read_text(encoding="utf-8")

    try:
        tree = ast.parse(source_code)
    except SyntaxError as error:
        print(f"[ERROR] Không parse được file {file_path}: {error}")
        return []

    visitor = SecurityVisitor(file_path=file_path, source_code=source_code)
    visitor.visit(tree)

    return visitor.findings


def print_report(findings: list[Finding]) -> None:
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
    if len(sys.argv) != 2:
        print("Cách dùng:")
        print("  python3 tools/mini_sast.py <file-python>")
        return 2

    file_path = Path(sys.argv[1])

    if not file_path.is_file():
        print(f"Không tìm thấy file: {file_path}")
        return 2

    findings = scan_file(file_path)
    print_report(findings)

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())

