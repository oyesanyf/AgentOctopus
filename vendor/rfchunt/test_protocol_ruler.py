"""
End-to-End Verification Test for Protocol Ruler Engine:
Validates real socket connections, binary search boundary calibration,
and differential expansion detection (James Kettle technique).
Zero mocks; executes against live test socket server.
"""

import time
import unittest
from test_lab_server import TestLabServer
from protocol_ruler import ProtocolRuler


class TestProtocolRuler(unittest.TestCase):
    SERVER_PORT = 8092
    MAX_LIMIT = 64040

    @classmethod
    def setUpClass(cls):
        cls.server = TestLabServer(host="127.0.0.1", port=cls.SERVER_PORT, max_header_limit=cls.MAX_LIMIT)
        cls.server.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def setUp(self):
        self.ruler = ProtocolRuler(host="127.0.0.1", port=self.SERVER_PORT, timeout=3.0)

    def test_01_calibrate_baseline_limit(self):
        """Validates that baseline calibration pinpoints the exact 64,040 byte limit."""
        limit = self.ruler.calibrate_baseline_limit(min_size=1024, max_size=70000)
        self.assertIsNotNone(limit)
        self.assertEqual(limit, 64040)

    def test_02_detect_c0_8a_expansion(self):
        """Validates that Kettle's overlong c0 8a sequence is detected expanding by 10 bytes."""
        limit = 64040
        result = self.ruler.measure_sequence_transformation("Kettle Overlong UTF-8", b"\xc0\x8a", limit)
        self.assertEqual(result["delta_bytes"], 10)
        self.assertEqual(result["classification"], "EXPANSION")
        self.assertEqual(result["mutated_limit"], 64030)

    def test_03_detect_verbatim_sequence(self):
        """Validates that standard bytes are detected as verbatim (delta = 0)."""
        limit = 64040
        result = self.ruler.measure_sequence_transformation("Standard Slash", b"/", limit)
        self.assertEqual(result["delta_bytes"], 0)
        self.assertEqual(result["classification"], "VERBATIM")
        self.assertEqual(result["mutated_limit"], 64040)

    def test_04_comprehensive_audit_run(self):
        """Validates that a full audit runs and detects high-value expansions."""
        report = self.ruler.run_comprehensive_audit(max_size=70000)
        self.assertTrue(report["success"])
        self.assertEqual(report["baseline_limit"], 64040)
        self.assertGreater(len(report["expansions"]), 0)
        self.assertTrue(any(exp["name"] == "Kettle Overlong UTF-8 (c0 8a)" for exp in report["expansions"]))


if __name__ == "__main__":
    unittest.main()
