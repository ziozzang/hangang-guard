"""Release artifact contract tests without credentials or network access."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("prepare_release", Path(__file__).with_name("prepare_release.py"))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "repo"
        self.root.mkdir()
        (self.root / "Cargo.toml").write_text('[workspace.package]\nversion="0.3.0"\n')
        (self.root / "LICENSE").write_text("MIT fixture")
        self.patch_root = patch.object(release, "ROOT", self.root)
        self.patch_root.start()
        self.addCleanup(self.patch_root.stop)
        self.key = base64.b64encode(bytes(range(32))).decode()
        self.payloads = []
        self.seed = Path(self.temporary.name) / "private" / "seed"
        self.seed.parent.mkdir()
        self.seed.write_text("sensitive seed fixture")
        self.seed.chmod(0o600)
        self.output = Path(self.temporary.name) / "dist"
        for target in release.TARGETS:
            directory = self.root / "target" / target / "release"
            directory.mkdir(parents=True)
            for name in release.COMMON_BINARIES:
                path = directory / name
                path.write_bytes(b"#!/bin/sh\nexit 0\n")
                path.chmod(0o755)
        self.patch_run = patch.object(release, "run", side_effect=self.fake_run)
        self.patch_run.start()
        self.addCleanup(self.patch_run.stop)

    def fake_run(self, command):
        if command[1] == "--version":
            return f"{Path(command[0]).name} 0.3.0"
        if command[1] == "--public-key":
            return self.key
        payload = Path(command[1]).read_bytes()
        self.payloads.append(json.loads(payload))
        Path(command[3]).write_text(json.dumps({"payload": base64.b64encode(payload).decode(), "signature": "fixture"}))
        return ""

    def test_unsigned_assets_all_targets_have_only_expected_binaries(self):
        for target in release.TARGETS:
            with self.subTest(target=target):
                output = self.output / target
                release.prepare(None, output, target, unsigned=True)
                self.assertFalse((output / "release-public-key.txt").exists())
                self.assertFalse(list(output.glob("*.manifest.json")))
                artifact = output / f"hangang-guard-{target}"
                self.assertEqual(artifact.read_bytes(), b"#!/bin/sh\nexit 0\n")
                archive_path = next(output.glob("*.tar.gz"))
                with tarfile.open(archive_path) as archive:
                    self.assertEqual({Path(item.name).name for item in archive}, {"sumunjang", "hangang-guard", "guard-release-sign", "LICENSE"})
                    self.assertTrue(all(item.mtime == 0 and item.uid == 0 and item.gid == 0 for item in archive))
                for line in (output / "SHA256SUMS").read_text().splitlines():
                    expected, name = line.split("  ")
                    self.assertEqual(hashlib.sha256((output / name).read_bytes()).hexdigest(), expected)

    def test_signed_payload_binds_version_target_url_size_digest(self):
        (self.root / "release-public-key.txt").write_text(self.key + "\n")
        release.prepare(self.seed, self.output, release.TARGET)
        self.assertEqual(len(self.payloads), 2)
        payload = self.payloads[0]
        artifact = self.output / f"sumunjang-{release.TARGET}"
        self.assertEqual(payload["version"], "0.3.0")
        self.assertEqual(payload["target"], release.TARGET)
        self.assertEqual(payload["artifact_url"], f"https://github.com/ziozzang/sumunjang/releases/download/v0.3.0/sumunjang-{release.TARGET}")
        self.assertEqual(payload["size"], artifact.stat().st_size)
        self.assertEqual(payload["sha256"], hashlib.sha256(artifact.read_bytes()).hexdigest())
        self.assertFalse(list(self.output.glob(".release-payload-*")))
        self.assertNotIn(self.seed.read_bytes(), b"".join(p.read_bytes() for p in self.output.iterdir()))

    def test_wrong_pinned_key_and_output_containing_seed_are_rejected(self):
        (self.root / "release-public-key.txt").write_text(base64.b64encode(b"x" * 32).decode())
        with self.assertRaisesRegex(ValueError, "does not match"):
            release.prepare(self.seed, self.output, release.TARGET)
        self.assertFalse(self.output.exists())
        with self.assertRaisesRegex(ValueError, "separate"):
            release.prepare(self.seed, self.seed.parent, release.TARGET)

    def test_output_nonempty_invalid_version_missing_binary_and_unsigned_seed(self):
        self.output.mkdir()
        (self.output / "existing").write_text("preserve")
        with self.assertRaisesRegex(ValueError, "empty"):
            release.prepare(None, self.output, release.TARGET, unsigned=True)
        with self.assertRaisesRegex(ValueError, "must not use"):
            release.prepare(self.seed, self.output, release.TARGET, unsigned=True)
        output = self.output / "new"
        (self.root / "Cargo.toml").write_text('[workspace.package]\nversion="0.3.0-beta"\n')
        with self.assertRaisesRegex(ValueError, "stable"):
            release.prepare(None, output, release.TARGET, unsigned=True)
        (self.root / "Cargo.toml").write_text('[workspace.package]\nversion="0.3.0"\n')
        (self.root / "target" / release.TARGET / "release" / "hangang-guard").unlink()
        with self.assertRaisesRegex(ValueError, "missing executable"):
            release.prepare(None, output, release.TARGET, unsigned=True)

    def test_archive_is_reproducible(self):
        first, second = self.output / "first", self.output / "second"
        release.prepare(None, first, release.TARGET, unsigned=True)
        release.prepare(None, second, release.TARGET, unsigned=True)
        self.assertEqual(next(first.glob("*.tar.gz")).read_bytes(), next(second.glob("*.tar.gz")).read_bytes())


if __name__ == "__main__":
    unittest.main()
