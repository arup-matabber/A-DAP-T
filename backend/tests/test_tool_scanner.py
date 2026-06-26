"""
Unit tests for Tool_Scanner.

Covers:
  - Critical-tier risky function detection (.py, .js, .ts)
  - High-tier risky function detection
  - Data-access functions without masking → Data Exposure Risk
  - Data-access functions with masking in window → suppressed
  - Sensitive JSON key detection
  - No findings for clean files
  - Correct field population on findings
"""

import pytest

from app.scanners.tool_scanner import run


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def findings_by_category(findings, category):
    return [f for f in findings if f.category == category]


def findings_by_file(findings, filepath):
    return [f for f in findings if f.file == filepath]


# ---------------------------------------------------------------------------
# Requirement 7.2 — Critical-tier tool detection
# ---------------------------------------------------------------------------


class TestCriticalTierDetection:
    def test_refund_py(self):
        files = {"tools.py": "def process_refund(order_id):\n    pass\n"}
        findings = run(files)
        tool_findings = findings_by_category(findings, "Tool Permission Risk")
        assert len(tool_findings) == 1
        f = tool_findings[0]
        assert f.severity == "Critical"
        assert f.line == 1
        assert "refund" in f.title.lower() or "process_refund" in f.title

    def test_payment_py(self):
        files = {"billing.py": "def charge_payment(amount):\n    pass\n"}
        findings = run(files)
        tool = findings_by_category(findings, "Tool Permission Risk")
        assert any(f.severity == "Critical" for f in tool)

    def test_delete_py(self):
        files = {"ops.py": "def delete_record(id):\n    ...\n"}
        findings = run(files)
        tool = findings_by_category(findings, "Tool Permission Risk")
        assert any(f.severity == "Critical" for f in tool)

    def test_admin_py(self):
        files = {"admin.py": "def admin_reset(user):\n    pass\n"}
        findings = run(files)
        tool = findings_by_category(findings, "Tool Permission Risk")
        assert any(f.severity == "Critical" for f in tool)

    def test_execute_py(self):
        files = {"runner.py": "def execute_command(cmd):\n    pass\n"}
        findings = run(files)
        tool = findings_by_category(findings, "Tool Permission Risk")
        assert any(f.severity == "Critical" for f in tool)

    def test_shell_py(self):
        files = {"utils.py": "def run_shell(args):\n    pass\n"}
        findings = run(files)
        tool = findings_by_category(findings, "Tool Permission Risk")
        assert any(f.severity == "Critical" for f in tool)

    def test_run_command_py(self):
        files = {"exec.py": "def run_command(cmd):\n    pass\n"}
        findings = run(files)
        tool = findings_by_category(findings, "Tool Permission Risk")
        assert any(f.severity == "Critical" for f in tool)

    def test_write_file_py(self):
        files = {"io.py": "def write_file(path, data):\n    pass\n"}
        findings = run(files)
        tool = findings_by_category(findings, "Tool Permission Risk")
        assert any(f.severity == "Critical" for f in tool)

    def test_drop_table_py(self):
        files = {"db.py": "def drop_table(name):\n    pass\n"}
        findings = run(files)
        tool = findings_by_category(findings, "Tool Permission Risk")
        assert any(f.severity == "Critical" for f in tool)

    def test_critical_keyword_in_js(self):
        files = {"tools.js": "function deleteUser(id) {\n  return id;\n}\n"}
        findings = run(files)
        tool = findings_by_category(findings, "Tool Permission Risk")
        assert len(tool) == 1
        assert tool[0].severity == "Critical"

    def test_critical_keyword_in_ts(self):
        files = {"tools.ts": "function adminOverride(config) {\n  return config;\n}\n"}
        findings = run(files)
        tool = findings_by_category(findings, "Tool Permission Risk")
        assert len(tool) == 1
        assert tool[0].severity == "Critical"

    def test_case_insensitive_match(self):
        # Function name uses mixed case — still a substring match
        files = {"tools.py": "def ProcessRefund(order):\n    pass\n"}
        findings = run(files)
        tool = findings_by_category(findings, "Tool Permission Risk")
        assert any(f.severity == "Critical" for f in tool)


# ---------------------------------------------------------------------------
# Requirement 7.3 — High-tier tool detection
# ---------------------------------------------------------------------------


class TestHighTierDetection:
    def test_send_email_py(self):
        files = {"notify.py": "def send_email(to, body):\n    pass\n"}
        findings = run(files)
        tool = findings_by_category(findings, "Tool Permission Risk")
        assert len(tool) == 1
        assert tool[0].severity == "High"

    def test_customer_py(self):
        files = {"crm.py": "def get_customer_info(cid):\n    pass\n"}
        findings = run(files)
        # get_customer_info matches HIGH keyword "customer"
        tool = findings_by_category(findings, "Tool Permission Risk")
        assert any(f.severity == "High" for f in tool)

    def test_database_py(self):
        files = {"db.py": "def query_database(sql):\n    pass\n"}
        findings = run(files)
        tool = findings_by_category(findings, "Tool Permission Risk")
        assert any(f.severity == "High" for f in tool)

    def test_read_file_py(self):
        files = {"io.py": "def read_file(path):\n    pass\n"}
        findings = run(files)
        tool = findings_by_category(findings, "Tool Permission Risk")
        assert len(tool) == 1
        assert tool[0].severity == "High"

    def test_update_user_py(self):
        files = {"user.py": "def update_user(uid, data):\n    pass\n"}
        findings = run(files)
        tool = findings_by_category(findings, "Tool Permission Risk")
        assert any(f.severity == "High" for f in tool)

    def test_crm_py(self):
        files = {"crm.py": "def sync_crm_record(record):\n    pass\n"}
        findings = run(files)
        tool = findings_by_category(findings, "Tool Permission Risk")
        assert any(f.severity == "High" for f in tool)

    def test_high_keyword_in_ts(self):
        # Function name must contain the literal substring (with underscore)
        # because the keyword list uses snake_case substrings.
        files = {"service.ts": "function send_email(address, msg) {\n  return null;\n}\n"}
        findings = run(files)
        tool = findings_by_category(findings, "Tool Permission Risk")
        assert len(tool) == 1
        assert tool[0].severity == "High"


# ---------------------------------------------------------------------------
# Requirement 7.4 — Function definition pattern matching
# ---------------------------------------------------------------------------


class TestFunctionDefinitionPatterns:
    def test_py_def_keyword_required(self):
        # A call (not a definition) should not be flagged
        files = {"script.py": "result = delete_record(id)\n"}
        findings = run(files)
        tool = findings_by_category(findings, "Tool Permission Risk")
        assert len(tool) == 0

    def test_js_arrow_function_matches(self):
        # V2 scans arrow functions because JS/TS agent tools are often exported this way.
        files = {"script.js": "const deleteItem = (id) => {};\n"}
        findings = run(files)
        tool = findings_by_category(findings, "Tool Permission Risk")
        assert len(tool) == 1

    def test_py_def_matches(self):
        files = {"tools.py": "def delete_item(id):\n    pass\n"}
        findings = run(files)
        tool = findings_by_category(findings, "Tool Permission Risk")
        assert len(tool) == 1

    def test_js_function_keyword_matches(self):
        files = {"tools.js": "function deleteItem(id) {}\n"}
        findings = run(files)
        tool = findings_by_category(findings, "Tool Permission Risk")
        assert len(tool) == 1

    def test_ts_function_keyword_matches(self):
        files = {"tools.ts": "function deleteItem(id: string): void {}\n"}
        findings = run(files)
        tool = findings_by_category(findings, "Tool Permission Risk")
        assert len(tool) == 1

    def test_jsx_extension_is_scanned(self):
        # V2 supports JS/TS frontend-heavy agent repos, including JSX/TSX files.
        files = {"tools.jsx": "function deleteItem(id) {}\n"}
        findings = run(files)
        tool = findings_by_category(findings, "Tool Permission Risk")
        assert len(tool) == 1


# ---------------------------------------------------------------------------
# Requirement 7.5 — Finding field population
# ---------------------------------------------------------------------------


class TestFindingFields:
    def test_required_fields_present(self):
        files = {"tools.py": "def process_refund(order):\n    pass\n"}
        findings = run(files)
        tool = findings_by_category(findings, "Tool Permission Risk")
        assert len(tool) == 1
        f = tool[0]
        assert f.title
        assert f.severity in {"Critical", "High"}
        assert f.category == "Tool Permission Risk"
        assert f.file == "tools.py"
        assert f.line == 1
        assert f.why_it_matters
        assert f.suggested_fix

    def test_line_number_is_correct(self):
        code = "# header comment\n\ndef process_refund(order):\n    pass\n"
        files = {"tools.py": code}
        findings = run(files)
        tool = findings_by_category(findings, "Tool Permission Risk")
        assert tool[0].line == 3


# ---------------------------------------------------------------------------
# Requirement 7.6 — No findings for clean files
# ---------------------------------------------------------------------------


class TestNoFindingsCleanFiles:
    def test_clean_py_no_findings(self):
        files = {"safe.py": "def greet(name):\n    return f'Hello {name}'\n"}
        findings = run(files)
        assert len(findings) == 0

    def test_clean_js_no_findings(self):
        files = {"safe.js": "function greet(name) { return 'Hello ' + name; }\n"}
        findings = run(files)
        assert len(findings) == 0

    def test_empty_file_no_findings(self):
        files = {"empty.py": ""}
        findings = run(files)
        assert len(findings) == 0

    def test_non_code_extension_skipped(self):
        files = {"readme.md": "def delete_everything():\n    pass\n"}
        findings = run(files)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Requirement 17.1 / 17.2 — Data Exposure Risk: data-access without masking
# ---------------------------------------------------------------------------


class TestDataExposureNoMasking:
    def test_get_customer_no_masking(self):
        files = {"data.py": "def get_customer(cid):\n    return db.find(cid)\n"}
        findings = run(files)
        de = findings_by_category(findings, "Data Exposure Risk")
        assert len(de) == 1
        assert de[0].severity == "High"
        assert de[0].file == "data.py"

    def test_read_internal_no_masking(self):
        files = {"data.py": "def read_internal(key):\n    return store[key]\n"}
        findings = run(files)
        de = findings_by_category(findings, "Data Exposure Risk")
        assert len(de) == 1

    def test_get_user_data_no_masking(self):
        files = {"data.py": "def get_user_data(uid):\n    return users[uid]\n"}
        findings = run(files)
        de = findings_by_category(findings, "Data Exposure Risk")
        assert len(de) == 1

    def test_fetch_record_no_masking(self):
        files = {"data.py": "def fetch_record(rid):\n    return records[rid]\n"}
        findings = run(files)
        de = findings_by_category(findings, "Data Exposure Risk")
        assert len(de) == 1

    def test_get_record_no_masking(self):
        files = {"data.py": "def get_record(rid):\n    return repo.get(rid)\n"}
        findings = run(files)
        de = findings_by_category(findings, "Data Exposure Risk")
        assert len(de) == 1

    def test_data_access_in_js_no_masking(self):
        # JS data-access function name must contain the literal substring
        # (with underscore) to match the DATA_ACCESS_KEYWORDS list.
        files = {"data.js": "function get_customer(id) {\n  return db.find(id);\n}\n"}
        findings = run(files)
        de = findings_by_category(findings, "Data Exposure Risk")
        assert len(de) == 1
        assert de[0].severity == "High"


class TestDataExposureWithMasking:
    def test_mask_keyword_within_window_suppresses_finding(self):
        code = (
            "def mask_email(val):\n"
            "    return val[:2] + '***'\n"
            "\n"
            "def get_customer(cid):\n"
            "    data = db.find(cid)\n"
            "    return data\n"
        )
        files = {"data.py": code}
        findings = run(files)
        de = findings_by_category(findings, "Data Exposure Risk")
        # mask_ appears within 10 lines of get_customer definition (line 4)
        assert len(de) == 0

    def test_redact_keyword_within_window_suppresses_finding(self):
        code = (
            "def get_user_data(uid):\n"
            "    data = users[uid]\n"
            "    return redact_pii(data)\n"
        )
        files = {"data.py": code}
        findings = run(files)
        de = findings_by_category(findings, "Data Exposure Risk")
        assert len(de) == 0

    def test_anonymize_keyword_suppresses_finding(self):
        code = (
            "def fetch_record(rid):\n"
            "    rec = records[rid]\n"
            "    return anonymize(rec)\n"
        )
        files = {"data.py": code}
        findings = run(files)
        de = findings_by_category(findings, "Data Exposure Risk")
        assert len(de) == 0

    def test_sanitize_keyword_suppresses_finding(self):
        code = (
            "def get_record(rid):\n"
            "    rec = repo.get(rid)\n"
            "    sanitize(rec)\n"
            "    return rec\n"
        )
        files = {"data.py": code}
        findings = run(files)
        de = findings_by_category(findings, "Data Exposure Risk")
        assert len(de) == 0

    def test_masking_just_outside_window_does_not_suppress(self):
        # 11 lines of filler between mask call and data-access definition
        filler = "\n".join(f"# line {i}" for i in range(12))
        code = f"def mask_result():\n    pass\n{filler}\ndef get_customer(cid):\n    return db.find(cid)\n"
        files = {"data.py": code}
        findings = run(files)
        de = findings_by_category(findings, "Data Exposure Risk")
        # masking is > 10 lines away, so finding is expected
        assert len(de) == 1

    def test_masking_at_exactly_10_lines_above_suppresses(self):
        # mask_ keyword is exactly 10 lines above the data-access function definition.
        # Window formula: start = max(0, line_number - 1 - 10)
        # If get_customer is at line 12 (0-indexed: 11), then start = max(0, 11-10) = 1
        # Line 1 (0-indexed) = line 2 (1-based), which is "    mask_data = None"
        # But we need the mask keyword at exactly line_number-10, i.e. 10 lines above.
        # get_customer on line 12: 10 lines above is line 2.
        # Build: line1="# padding", line2="  mask_result = None", lines3-11="# filler x8", line12=def get_customer
        lines = ["# padding"]                        # line 1
        lines.append("  mask_result = None")          # line 2  (10 lines above line 12)
        for i in range(9):                            # lines 3-11
            lines.append(f"# filler {i}")
        lines.append("def get_customer(cid):")        # line 12
        lines.append("    return db.find(cid)")       # line 13
        code = "\n".join(lines) + "\n"
        files = {"data.py": code}
        findings = run(files)
        de = findings_by_category(findings, "Data Exposure Risk")
        # mask_ is exactly at boundary (10 lines above) → window includes it → suppressed
        assert len(de) == 0

    def test_masking_at_exactly_11_lines_above_does_not_suppress(self):
        # mask_ keyword is exactly 11 lines above the data-access function — outside the window.
        # get_customer on line 13: 11 lines above is line 2.
        # Window start = max(0, 13-1-10) = 2 (0-indexed) = line 3 (1-based).
        # Line 2 (0-indexed = line 2, 1-based) is NOT in the window → not suppressed.
        lines = ["# padding"]                        # line 1
        lines.append("  mask_result = None")          # line 2  (11 lines above line 13)
        for i in range(10):                           # lines 3-12
            lines.append(f"# filler {i}")
        lines.append("def get_customer(cid):")        # line 13
        lines.append("    return db.find(cid)")       # line 14
        code = "\n".join(lines) + "\n"
        files = {"data.py": code}
        findings = run(files)
        de = findings_by_category(findings, "Data Exposure Risk")
        # mask_ is 11 lines above — outside the ±10 window → finding expected
        assert len(de) == 1

    def test_masking_at_exactly_10_lines_below_suppresses(self):
        # mask_ keyword is exactly 10 lines below the data-access function.
        # get_customer on line 1: end = min(len, 1+10) = 11.
        # Line at 0-indexed 10 = line 11 (1-based) is included → suppressed.
        lines = ["def get_customer(cid):"]            # line 1
        lines.append("    return db.find(cid)")       # line 2
        for i in range(8):                            # lines 3-10
            lines.append(f"# filler {i}")
        lines.append("  mask_result = None")          # line 11 (10 lines below line 1)
        code = "\n".join(lines) + "\n"
        files = {"data.py": code}
        findings = run(files)
        de = findings_by_category(findings, "Data Exposure Risk")
        # mask_ is exactly 10 lines below → window includes it → suppressed
        assert len(de) == 0

    def test_masking_at_exactly_11_lines_below_does_not_suppress(self):
        # mask_ keyword is exactly 11 lines below the data-access function — outside window.
        # get_customer on line 1: end = min(len, 1+10) = 11.
        # Line at 0-indexed 11 = line 12 (1-based) is NOT in the window.
        lines = ["def get_customer(cid):"]            # line 1
        lines.append("    return db.find(cid)")       # line 2
        for i in range(9):                            # lines 3-11
            lines.append(f"# filler {i}")
        lines.append("  mask_result = None")          # line 12 (11 lines below line 1)
        code = "\n".join(lines) + "\n"
        files = {"data.py": code}
        findings = run(files)
        de = findings_by_category(findings, "Data Exposure Risk")
        # mask_ is 11 lines below → outside ±10 window → finding expected
        assert len(de) == 1


# ---------------------------------------------------------------------------
# Requirement 17.3 / 17.4 — Sensitive JSON key detection
# ---------------------------------------------------------------------------


class TestSensitiveJsonKeys:
    def test_email_key_detected(self):
        files = {"config.json": '{"email": "test@example.com"}'}
        findings = run(files)
        de = findings_by_category(findings, "Data Exposure Risk")
        assert len(de) == 1
        assert de[0].severity == "Medium"
        assert de[0].file == "config.json"
        assert de[0].line == 1

    def test_phone_key_detected(self):
        files = {"data.json": '{"phone": "555-1234"}'}
        findings = run(files)
        de = findings_by_category(findings, "Data Exposure Risk")
        assert len(de) == 1

    def test_ssn_key_detected(self):
        files = {"record.json": '{"ssn": "123-45-6789"}'}
        findings = run(files)
        de = findings_by_category(findings, "Data Exposure Risk")
        assert len(de) == 1

    def test_credit_card_key_detected(self):
        files = {"payment.json": '{"credit_card": "4111111111111111"}'}
        findings = run(files)
        de = findings_by_category(findings, "Data Exposure Risk")
        assert len(de) == 1

    def test_password_key_detected(self):
        files = {"auth.json": '{"password": "secret"}'}
        findings = run(files)
        de = findings_by_category(findings, "Data Exposure Risk")
        assert len(de) == 1

    def test_nested_sensitive_key_detected(self):
        files = {"users.json": '{"user": {"email": "a@b.com", "name": "Alice"}}'}
        findings = run(files)
        de = findings_by_category(findings, "Data Exposure Risk")
        assert len(de) == 1

    def test_multiple_sensitive_keys_one_finding_per_file(self):
        files = {"big.json": '{"email": "a@b.com", "phone": "555", "ssn": "123"}'}
        findings = run(files)
        de = findings_by_category(findings, "Data Exposure Risk")
        # Only one finding per file regardless of how many keys matched
        assert len(de) == 1

    def test_clean_json_no_findings(self):
        files = {"settings.json": '{"timeout": 30, "retries": 3}'}
        findings = run(files)
        de = findings_by_category(findings, "Data Exposure Risk")
        assert len(de) == 0

    def test_invalid_json_no_error(self):
        files = {"bad.json": '{"email": broken json'}
        findings = run(files)
        # Should not raise; invalid JSON yields no findings
        assert len(findings) == 0

    def test_json_finding_required_fields(self):
        files = {"data.json": '{"password": "hunter2"}'}
        findings = run(files)
        de = findings_by_category(findings, "Data Exposure Risk")
        assert len(de) == 1
        f = de[0]
        assert f.title
        assert f.severity == "Medium"
        assert f.category == "Data Exposure Risk"
        assert f.file == "data.json"
        assert f.line == 1
        assert f.why_it_matters
        assert f.suggested_fix


# ---------------------------------------------------------------------------
# Multiple findings in one file
# ---------------------------------------------------------------------------


class TestMultipleFindings:
    def test_multiple_risky_functions_in_one_file(self):
        code = (
            "def process_refund(oid):\n"
            "    pass\n"
            "\n"
            "def send_email(to, body):\n"
            "    pass\n"
        )
        files = {"tools.py": code}
        findings = run(files)
        tool = findings_by_category(findings, "Tool Permission Risk")
        assert len(tool) == 2
        severities = {f.severity for f in tool}
        assert "Critical" in severities
        assert "High" in severities

    def test_tool_risk_and_data_exposure_same_file(self):
        code = (
            "def delete_record(rid):\n"
            "    pass\n"
            "\n"
            "def get_customer(cid):\n"
            "    return db.find(cid)\n"
        )
        files = {"ops.py": code}
        findings = run(files)
        tool = findings_by_category(findings, "Tool Permission Risk")
        de = findings_by_category(findings, "Data Exposure Risk")
        # delete_record → Critical Tool Permission Risk
        # get_customer → High Tool Permission Risk (contains "customer")
        #              → High Data Exposure Risk (contains "get_customer", no masking)
        assert len(tool) == 2
        assert any(f.severity == "Critical" for f in tool)
        assert len(de) == 1
        assert de[0].severity == "High"

    def test_files_dict_with_multiple_files(self):
        files = {
            "a.py": "def refund_order(oid):\n    pass\n",
            "b.js": "function adminPanel() {}\n",
            "c.json": '{"email": "test@test.com"}',
        }
        findings = run(files)
        assert len(findings_by_file(findings, "a.py")) >= 1
        assert len(findings_by_file(findings, "b.js")) >= 1
        assert len(findings_by_file(findings, "c.json")) >= 1
