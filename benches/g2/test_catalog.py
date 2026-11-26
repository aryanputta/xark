"""Check archive indexing without extracting or following paths."""

from pathlib import Path
import shutil
import tempfile
import unittest
import zipfile

from catalog import catalog


class CatalogTests(unittest.TestCase):
    def test_duplicate_archive_and_unsafe_member_are_reported(self):
        with tempfile.TemporaryDirectory() as scratch:
            directory = Path(scratch)
            first = directory / "xark-a.zip"
            with zipfile.ZipFile(first, "w") as archive:
                archive.writestr("run.log", "verified\n")
                archive.writestr("other.log", "verified\n")
                archive.writestr("../unexpected.log", "ignore")
            shutil.copyfile(first, directory / "xark-b.zip")
            result = catalog(directory)
            self.assertEqual(result["input_count"], 2)
            self.assertEqual(result["distinct_inputs"], 1)
            self.assertEqual(result["distinct_archived_text_members"], 1)
            self.assertEqual(result["inputs"][1]["identical_to"], "xark-a.zip")
            records = {item["name"]: item for item in result["inputs"][0]["members"]}
            self.assertFalse(records["../unexpected.log"]["safe_regular_file"])
            self.assertIsNone(records["../unexpected.log"]["text_sha256"])
            self.assertEqual(
                records["other.log"]["identical_text_to"], "xark-a.zip/run.log"
            )


if __name__ == "__main__":
    unittest.main()
