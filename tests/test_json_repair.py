import unittest

from app.analyzer import repair_json_response


class JsonRepairTests(unittest.TestCase):
    def test_repairs_fenced_json_with_trailing_comma(self):
        source = '''```json
        {"findings": [{"attack_type": "scan", "severity": "low",}]}
        ```'''
        self.assertEqual(repair_json_response(source), {"findings": [{"attack_type": "scan", "severity": "low"}]})

    def test_rejects_output_without_findings_array(self):
        with self.assertRaisesRegex(ValueError, "findings array"):
            repair_json_response('{"summary":"none"}')

    def test_repairs_unquoted_model_keys(self):
        result = repair_json_response('{findings: []}')
        self.assertEqual(result, {"findings": []})


if __name__ == "__main__":
    unittest.main()
