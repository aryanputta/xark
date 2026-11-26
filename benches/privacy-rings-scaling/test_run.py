from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from run import REJECTION, SHARED_VERIFIED, batch_completion_metrics, verified_samples


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
            with self.assertRaises(RuntimeError):
                verified_samples(log, 2, shared=True)
            log.write_text(log.read_text() + SHARED_VERIFIED + "\n")
            self.assertEqual(verified_samples(log, 2, shared=True), [0.25, 0.125])

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

    def test_batch_completion_includes_time_waiting_for_a_lane(self):
        with TemporaryDirectory() as directory:
            log = Path(directory) / "worker.log"
            # Logs are grouped by lane. The two earliest completions come
            # from different lanes, and nearest rank is computed across both.
            completions_ms = [*range(1, 20, 2), *range(2, 21, 2)]
            log.write_text(
                "".join(
                    f"warm batch completion: xark-groth16 {ms * 10**6} ns\n"
                    for ms in completions_ms
                )
            )
            self.assertEqual(
                batch_completion_metrics(log, 20),
                {"warm_batch_ms": 20.0, "warm_batch_completion_p95_ms": 19.0},
            )
            with self.assertRaises(RuntimeError):
                batch_completion_metrics(log, 21)


if __name__ == "__main__":
    unittest.main()
