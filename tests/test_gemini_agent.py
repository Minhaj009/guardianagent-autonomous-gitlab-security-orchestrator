# test_gemini_agent.py
import unittest
from unittest.mock import MagicMock, patch
from pydantic import ValidationError

# Import schemas and functions from guardian
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from guardian import (
    SecurityFinding,
    FindingsList,
    call_gemini_model,
    generate_remediation_patch,
    extract_json,
    validate_patch_ast_and_safety
)

class TestGeminiAgent(unittest.TestCase):

    def test_security_finding_schema_valid(self):
        """Verify that valid input correctly instantiates the SecurityFinding schema."""
        finding = SecurityFinding(
            file="vulnerable_service.py",
            line=7,
            vulnerability="Hardcoded Secret",
            severity="High",
            description="Exposed AWS Access Key ID."
        )
        self.assertEqual(finding.file, "vulnerable_service.py")
        self.assertEqual(finding.line, 7)
        self.assertEqual(finding.vulnerability, "Hardcoded Secret")
        self.assertEqual(finding.severity, "High")

    def test_security_finding_schema_invalid(self):
        """Verify that invalid line types raise Pydantic validation errors."""
        with self.assertRaises(ValidationError):
            # line must be an integer, passing string should raise validation or coerce error depending on strictness
            # passing a non-coercible type
            SecurityFinding(
                file="vulnerable_service.py",
                line="not_an_int",
                vulnerability="Hardcoded Secret",
                severity="High",
                description="Exposed AWS Access Key ID."
            )

    def test_extract_json_standard_block(self):
        """Verify that JSON content is successfully extracted from markdown code fences."""
        raw_text = """
        Here is the finding:
        ```json
        {
            "findings": [
                {
                    "file": "vulnerable_service.py",
                    "line": 7,
                    "vulnerability": "Hardcoded Cloud Secret",
                    "severity": "High",
                    "description": "Exposed AWS Access Key ID."
                }
            ]
        }
        ```
        """
        extracted = extract_json(raw_text)
        self.assertEqual(len(extracted), 1)
        self.assertEqual(extracted[0]["file"], "vulnerable_service.py")
        self.assertEqual(extracted[0]["line"], 7)

    @patch('google.genai.Client')
    def test_call_gemini_model_retry_success(self, mock_client_cls):
        """Verify that call_gemini_model retries on failure and eventually succeeds."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.text = '{"findings": []}'
        
        # Configure side effect: raise an exception twice, then succeed
        mock_client.models.generate_content.side_effect = [
            Exception("API Rate Limit Exceeded (429)"),
            Exception("Service Unavailable (503)"),
            mock_response
        ]
        
        # Execute call
        result = call_gemini_model(
            client=mock_client,
            model_name="gemini-2.5-flash",
            diff_content="File: app.py\nDiff: ...",
            temperature=0.1,
            system_prompt="Test Prompt"
        )
        
        # Verify result and call count
        self.assertEqual(result, '{"findings": []}')
        self.assertEqual(mock_client.models.generate_content.call_count, 3)

    def test_validate_patch_ast_and_safety(self):
        """Verify AST parsing and safety guardrails checker for Python patches."""
        # 1. Clean valid Python code should pass (return None)
        valid_code = "def add(a, b):\n    return a + b\n"
        self.assertIsNone(validate_patch_ast_and_safety(valid_code, "math_utils.py"))

        # 2. Syntax-broken Python code should fail AST check
        invalid_code = "def add(a, b)\n    return a + b\n"
        error = validate_patch_ast_and_safety(invalid_code, "math_utils.py")
        self.assertIsNotNone(error)
        self.assertIn("Syntax error", error)

        # 3. Code containing forbidden terms should fail safety guardrail check
        insecure_code = "def exec_input(user_input):\n    eval(user_input)\n"
        error2 = validate_patch_ast_and_safety(insecure_code, "helpers.py")
        self.assertIsNotNone(error2)
        self.assertIn("Insecure call", error2)

        # 4. Non-Python files should skip AST syntax check but still verify safety guardrails
        js_insecure_code = "const val = eval(input);"
        error3 = validate_patch_ast_and_safety(js_insecure_code, "script.js")
        self.assertIsNotNone(error3)
        self.assertIn("Insecure call", error3)

        js_secure_code = "const val = JSON.parse(input);"
        self.assertIsNone(validate_patch_ast_and_safety(js_secure_code, "script.js"))

if __name__ == "__main__":
    unittest.main()
