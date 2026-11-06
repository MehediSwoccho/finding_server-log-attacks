import unittest

from app.upload_validation import looks_binary


class UploadValidationTests(unittest.TestCase):
    def test_normal_text_and_common_log_controls_are_not_binary(self):
        self.assertFalse(looks_binary(b"timestamp\tINFO request handled\r\n"))
        self.assertFalse(looks_binary(b"plain ASCII text"))

    def test_nul_bytes_are_binary(self):
        self.assertTrue(looks_binary(b"header\x00payload"))

    def test_control_heavy_sample_is_binary(self):
        self.assertTrue(looks_binary(bytes(range(32)) * 8))


if __name__ == "__main__":
    unittest.main()
