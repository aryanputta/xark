from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from run import REJECTION, verified_samples


class VerifiedSampleTests(unittest.TestCase):
    def test_requires_the_expected_verified_samples(self):
        with TemporaryDirectory() as directory:
            log = Path(directory) / "worker.log"
            log.write_text(
                f"witness row checker: compiled\n{REJECTION}\n"
                "warm prove: xark-groth16 0.250000s\n"
                "warm prove: xark-groth16 0.125000s\n"
            )
            self.assertEqual(verified_samples(log, 2), [0.25, 0.125])
            with self.assertRaises(RuntimeError):
                verified_samples(log, 3)

    def test_rejects_timings_without_the_required_controls(self):
        with TemporaryDirectory() as directory:
            log = Path(directory) / "worker.log"
            timing = "warm prove: xark-groth16 0.125000s\n"
            for text in (
                f"witness row checker: compiled\n{timing}",
                f"{REJECTION}\n{timing}",
                f"witness row checker: compiled\n{REJECTION}\n"
                "warm prove: xark-groth16 0.000000s\n",
            ):
                with self.subTest(text=text):
                    log.write_text(text)
                    with self.assertRaises(RuntimeError):
                        verified_samples(log, 1)


if __name__ == "__main__":
    unittest.main()
