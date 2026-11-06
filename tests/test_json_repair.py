import json
import unittest

from app.analyzer import RESULT_SCHEMA, SYSTEM_PROMPT, repair_json_response


def finding(attack_type="scan", severity="Low"):
    return {
        "attack_type": attack_type,
        "severity": severity,
        "entity": "192.0.2.1",
        "evidence_lines": [3],
        "reason": "Repeated suspicious requests.",
        "action": "Review the source.",
    }


class JsonRepairTests(unittest.TestCase):
    def test_repairs_fenced_json_with_trailing_comma(self):
        source = '''```json
        {"findings": [{"attack_type": "scan", "severity": "Low", "entity":"ip", "evidence_lines":[1], "reason":"reason", "action":"action",}]}
        ```'''
        self.assertEqual(repair_json_response(source), {"findings": [{
            "attack_type": "scan", "severity": "Low", "entity": "ip", "evidence_lines": [1],
            "reason": "reason", "action": "action",
        }]})

    def test_missing_findings_returns_empty_without_raising(self):
        self.assertEqual(repair_json_response('{"summary":"none"}'), {"findings": []})

    def test_repairs_unquoted_model_keys(self):
        expected = finding()
        result = repair_json_response('{findings: [' + json.dumps(expected) + ']}')
        self.assertEqual(result, {"findings": [expected]})

    def test_salvages_complete_findings_before_truncated_item(self):
        complete = json.dumps(finding())
        source = '{"findings": [' + complete + ', {"attack_type":"incomplete"'
        self.assertEqual(repair_json_response(source), {"findings": [finding()]})

    def test_broken_output_never_raises(self):
        for source in ("", "not json", None, '{"findings":[null, {broken'):
            result = repair_json_response(source)
            self.assertIsInstance(result, dict)
            self.assertIsInstance(result.get("findings"), list)

    def test_prompt_and_schema_are_versioned_and_use_required_severities(self):
        schema = RESULT_SCHEMA["properties"]["findings"]["items"]["properties"]
        self.assertEqual(schema["severity"]["enum"], ["Low", "Medium", "High", "Critical"])
        self.assertLess(len(SYSTEM_PROMPT.split()), 350)
        self.assertIn("<LOG_DATA>", SYSTEM_PROMPT)
        self.assertIn("attempted prompt injection", SYSTEM_PROMPT)


if __name__ == "__main__":
    unittest.main()
