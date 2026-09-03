#!/usr/bin/env python3

import unittest

import publication_check


class PublicationPathTests(unittest.TestCase):
    def test_public_layout_is_allowed(self) -> None:
        self.assertTrue(publication_check.path_allowed("README.md"))
        self.assertTrue(publication_check.path_allowed("blog/index.html"))
        self.assertTrue(publication_check.path_allowed("patches/fix.patch"))
        self.assertTrue(publication_check.path_allowed("evidence/summary.csv"))
        self.assertTrue(
            publication_check.path_allowed("mitigations/99-gro-fraglist-off")
        )

    def test_private_and_generated_layout_is_rejected(self) -> None:
        self.assertFalse(publication_check.path_allowed("reports" + "/hourly.md"))
        self.assertFalse(publication_check.path_allowed("backlog" + "/task.md"))
        self.assertFalse(publication_check.path_allowed("tools/module.ko"))
        self.assertFalse(publication_check.path_allowed("capture.gz"))


class PublicationContentTests(unittest.TestCase):
    def test_clean_content_passes(self) -> None:
        self.assertEqual(
            publication_check.inspect_blob(
                "README.md",
                b"Allocator ownership is bounded.\n",
            ),
            [],
        )

    def test_network_and_identity_values_are_redacted(self) -> None:
        private_address = "192" + ".168.44.9"
        private_email = "person" + "@example.org"
        value = f"private endpoint {private_address} and {private_email}"
        failures = publication_check.scan_text("sample.txt", value)
        joined = "\n".join(failures)
        self.assertIn("private IPv4 address", joined)
        self.assertIn("email address", joined)
        self.assertNotIn(private_address, joined)
        self.assertNotIn(private_email, joined)

    def test_private_key_and_token_formats_are_rejected(self) -> None:
        text = (
            "-----BEGIN OPENSSH " + "PRIVATE KEY-----\n"
            "Authorization" + ": " + "Bearer" + " " + "abcdefghijklmnopqrstuvwxyz\n"
        )
        failures = publication_check.scan_text("sample.txt", text)
        labels = "\n".join(failures)
        self.assertIn("private key material", labels)
        self.assertIn("authorization header", labels)

    def test_binary_and_large_files_are_rejected(self) -> None:
        binary = publication_check.inspect_blob("tools/sample.c", b"a\0b")
        self.assertTrue(any("binary NUL" in item for item in binary))
        large = publication_check.inspect_blob(
            "evidence/large.csv",
            b"x" * (publication_check.MAX_FILE_BYTES + 1),
        )
        self.assertTrue(any("exceeds" in item for item in large))

    def test_raw_artifact_filename_is_rejected(self) -> None:
        failures = publication_check.inspect_blob(
            "evidence/router-capture.csv",
            b"cycle,value\none,1\n",
        )
        self.assertTrue(any("raw capture/trace" in item for item in failures))


if __name__ == "__main__":
    unittest.main()
