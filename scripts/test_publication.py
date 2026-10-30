import os
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

import check_docs
import public_source
import release


class ReleaseRevisionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.git("init", "-q")
        (self.root / "source.go").write_text("package example\n")
        self.git("add", "source.go")
        self.git("-c", "user.name=Publication Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "initial")
        self.git("tag", "v1")

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.root, check=True, capture_output=True, env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"})

    def test_staged_change_is_dirty_and_cannot_be_released(self):
        clean = release.source_revision(self.root, "v1")
        (self.root / "source.go").write_text("package changed\n")
        self.git("add", "source.go")
        self.assertEqual(release.source_revision(self.root), clean + "-dirty")
        with self.assertRaisesRegex(ValueError, "clean"):
            release.source_revision(self.root, "v1")

    def test_untracked_source_is_dirty(self):
        (self.root / "new.go").write_text("package example\n")
        self.assertTrue(release.source_revision(self.root).endswith("-dirty"))
        with self.assertRaisesRegex(ValueError, "clean"):
            release.source_revision(self.root, "v1")

    def test_tag_must_identify_the_built_commit(self):
        (self.root / "source.go").write_text("package changed\n")
        self.git("add", "source.go")
        self.git("-c", "user.name=Publication Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "next")
        with self.assertRaisesRegex(ValueError, "HEAD"):
            release.source_revision(self.root, "v1")


class SourcePolicyTests(unittest.TestCase):
    def test_private_material_and_history_are_not_publishable(self):
        for name in [".git/config", "labs/bsd_emu/dump.bin", "README.me.md", ".env", "subdir/secret.pem", "../escape", ".aws/credentials", "docs/AUDIT_private.md", "zig/apk_editor/src/assets/apked-sign.key", "zig/apk_editor/src/main.zig",
                     "subdir/SECRET.PEM", ".ENV.production", ".env.example_ru.local", ".env.example_ru.bak", ".env.example.secret", ".ssh/id_ed25519", ".dai-v07/get.py", "tools/decision-ai/model.dte", "dist/source.go", "tools/webui-split/split_report.txt", "a/../README.md", "./README.md", "a//b", "C:/source.go", "source.go:stream", r".git\config", "a./b"]:
            with self.subTest(name=name):
                self.assertFalse(public_source.publishable(name))
        for name in ["pkg/decompiler/decompiler.go", "pkg/internal/dataflow/audit_bounds.go", "pkg/internal/crypto/AUDIT_vectors.go", ".github/workflows/core.yml", ".env.example", ".env.example_ru", ".gitleaks.toml", "docs/CODE_REVIEW.md", "docs/REPORT_COMPARISON.md"]:
            with self.subTest(name=name):
                self.assertTrue(public_source.publishable(name))

    def test_internal_reports_and_generated_metadata_stay_out_of_sources(self):
        for name in ["WEB_STATIC_UPGRADE.ru.md", "SOURCE_MANIFEST.json", ".github/dependabot.yml",
                     "docs/RELEASE_VALIDATION.md", "docs/PETYA_DECRYPTOR_REVIEW.ru.md",
                     "docs/review-jar-minecraft/source-checks.json",
                     "docs/review-jar-workspace/checks.json",
                     "docs/ncer/SMALI_DEX_MODULE_AUDIT_TODO.md", "docs/security-audit.ru.md",
                     "pkg/ml/security_report.md", "testkit/REPORT.md",
                     "demo/demo_test_apk/decompiled/.mega-analyzer-decode-cache.json",
                     "examples/native-apk/project/.mega-analyzer-build-cache.json"]:
            with self.subTest(name=name):
                self.assertFalse(public_source.publishable(name))

    def test_export_refuses_to_overwrite_sources(self):
        with self.assertRaisesRegex(ValueError, "dist"):
            public_source.export(public_source.ROOT / "pkg")

    def test_doc_checker_distinguishes_examples_from_real_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text("`[example](absent.md)`\n[broken](missing.md)\n[valid](present.md)\n")
            (root / "present.md").write_text("Present\n")
            failures = check_docs.check(root, ["README.md"])
            self.assertEqual(len(failures), 1)
            self.assertIn("missing.md", failures[0])


class PackagedDocumentationTests(unittest.TestCase):
    def test_missing_examples_and_links_in_other_packaged_docs_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            (stage / "QUICKSTART.md").write_text("[Example](examples/native-apk/README.md)\n")
            with self.assertRaisesRegex(ValueError, "examples/native-apk"):
                release.verify_package_docs(stage)
            example = stage / "examples/native-apk"
            example.mkdir(parents=True)
            (example / "README.md").write_text("[Project](project)\n")
            (example / "project").mkdir()
            (stage / "FlagiFiles.md").write_text("[Usage](docs/USAGE.md)\n")
            with self.assertRaisesRegex(ValueError, "FlagiFiles.md"):
                release.verify_package_docs(stage)
            (stage / "FlagiFiles.md").write_text("[Usage](https://example.invalid/docs/USAGE.md)\n")
            release.verify_package_docs(stage)
            (example / "README.md").write_text("[Missing](absent.md)\n")
            with self.assertRaisesRegex(ValueError, "examples/native-apk/README.md"):
                release.verify_package_docs(stage)

    def test_build_includes_offline_example_and_rewrites_extended_documentation(self):
        def fake_command(args, **kwargs):
            if args[:2] == ["go", "env"]:
                return SimpleNamespace(stdout="windows\namd64\n")
            self.assertEqual(args[:2], ["go", "build"])
            Path(args[args.index("-o") + 1]).write_bytes(b"binary fixture")

        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(release, "command", side_effect=fake_command), \
                mock.patch.object(release, "source_revision", return_value="test-commit"), \
                contextlib.redirect_stdout(io.StringIO()):
            release.build(SimpleNamespace(output=directory, tag=None, goos="windows", goarch="amd64"))
            archive_path, = Path(directory).glob("*.zip")
            with zipfile.ZipFile(archive_path) as archive:
                self.assertIn("examples/native-apk/README.md", archive.namelist())
                self.assertIn("examples/native-apk/project/AndroidManifest.xml", archive.namelist())
                self.assertIn("COPYING", archive.namelist())
                self.assertIn(b"https://github.com/Promastergame/mega-analyzer/blob/main/docs/USAGE.md", archive.read("FlagiFiles.md"))
                archive.extractall(Path(directory) / "unpacked")
            release.verify_package_docs(Path(directory) / "unpacked")


class SourceExportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.names = ["pkg/example.go", "README.md", ".env.example", ".env.example_ru", ".env", ".env.example_ru.local", ".ssh/id_ed25519", "labs/bsd_emu/private.txt"]
        for name in self.names:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture for " + name + "\n", encoding="utf-8")
        self.output = self.root / "dist/public-source"
        with mock.patch.object(public_source, "repository_files", return_value=self.names), contextlib.redirect_stdout(io.StringIO()):
            public_source.export(self.output, root=self.root)

    def test_export_contains_only_reviewable_sources_and_verifies(self):
        digest = public_source.verify_export(self.output)
        manifest = json.loads((self.output / "SOURCE_MANIFEST.json").read_text(encoding="utf-8"))
        self.assertEqual(digest, manifest["tree_sha256"])
        self.assertFalse(manifest["history_included"])
        self.assertEqual({f["path"] for f in manifest["files"]}, {"README.md", "pkg/example.go", ".env.example", ".env.example_ru"})
        with zipfile.ZipFile(self.output.with_suffix(".zip")) as archive:
            self.assertEqual(set(archive.namelist()), {"public-source/README.md", "public-source/pkg/example.go", "public-source/.env.example", "public-source/.env.example_ru", "public-source/SOURCE_MANIFEST.json"})
        self.assertEqual(release.source_revision(self.output), "source-" + digest + "-unversioned")

    def test_changed_export_cannot_claim_original_build_identity(self):
        (self.output / "pkg/example.go").write_text("modified\n")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            release.source_revision(self.output)

    def test_missing_and_added_sources_are_detected(self):
        source = self.output / "pkg/example.go"
        source.rename(source.with_suffix(".new"))
        with self.assertRaises(ValueError):
            public_source.verify_export(self.output)
        source.with_suffix(".new").rename(source)
        (self.output / "extra.go").write_text("new source\n")
        with self.assertRaisesRegex(ValueError, "Unmanifested"):
            public_source.verify_export(self.output)

    def test_tampered_manifest_is_detected(self):
        path = self.output / "SOURCE_MANIFEST.json"
        manifest = json.loads(path.read_text())
        manifest["files"][0]["sha256"] = "0" * 64
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "tree checksum"):
            public_source.verify_export(self.output)

    def test_build_cache_does_not_change_source_identity(self):
        before = public_source.verify_export(self.output)
        cache = self.output / "scripts/__pycache__"
        cache.mkdir(parents=True)
        (cache / "release.pyc").write_bytes(b"cache")
        self.assertEqual(public_source.verify_export(self.output), before)


if __name__ == "__main__":
    unittest.main()
