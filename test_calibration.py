import math
import unittest

import tcp_server


class CalibrationMathTests(unittest.TestCase):
    def test_format_six_char_signed(self):
        self.assertEqual(tcp_server.format_six_char_signed(0), "000000")
        self.assertEqual(tcp_server.format_six_char_signed(2), "000002")
        self.assertEqual(tcp_server.format_six_char_signed(-12), "-00012")
        self.assertEqual(tcp_server.format_six_char_signed(999999), "999999")
        self.assertEqual(tcp_server.format_six_char_signed(-99999), "-99999")

    def test_format_six_char_signed_out_of_range(self):
        with self.assertRaises(ValueError):
            tcp_server.format_six_char_signed(1000000)
        with self.assertRaises(ValueError):
            tcp_server.format_six_char_signed(-100000)

    def test_example_numeric_flow(self):
        result = tcp_server.compute_calibration_offsets(
            [0.035, 0.035],
            [-0.012, -0.012],
        )
        self.assertEqual(result["pdoa_deg"], 2)
        self.assertEqual(result["rng_mm"], -12)
        self.assertEqual(tcp_server.format_six_char_signed(result["pdoa_deg"]), "000002")
        self.assertEqual(tcp_server.format_six_char_signed(result["rng_mm"]), "-00012")

    def test_sample_values_require_extended_report(self):
        with self.assertRaises(ValueError):
            tcp_server._calibration_sample_values(
                {"tag_uid": 1, "dist_cm": 300},
                3.0,
            )

    def test_sample_values_require_cleared_offsets(self):
        with self.assertRaises(ValueError):
            tcp_server._calibration_sample_values(
                {"tag_uid": 1, "dist_m": 3.0, "pdoa_deg": 1.0, "flags16": 0},
                3.0,
            )

    def test_sample_values_convert_units(self):
        phase_rad, range_err = tcp_server._calibration_sample_values(
            {"tag_uid": 1, "dist_m": 2.988, "pdoa_deg": 2.0, "flags16": 0xC000},
            3.0,
        )
        self.assertAlmostEqual(phase_rad, 2.0 * math.pi / 180.0)
        self.assertAlmostEqual(range_err, -0.012)


if __name__ == "__main__":
    unittest.main()
