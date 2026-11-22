import unittest

from release import (
    ReleaseError,
    bump,
    bump_pr,
    check,
    next_version,
    release_section,
    set_workspace_version,
    workspace_version,
)

CARGO_TOML = """[workspace]
members = ["dash"]

[workspace.package]
authors = ["The Developers"]
edition = "2024"
version = "0.46.0"

[workspace.dependencies]
serde = { version = "1.0.0" }
"""

HEADER = "# Changelog\n\nIntro.\n\n"

CHANGELOG = (
    HEADER
    + "## 0.46.0 - 2026-11-13\n\n### Added\n\n- New thing (#2) @a\n\n"
    + "## 0.45.0 - 2026-10-21\n\n### Fixed\n\n- Old thing (#1) @b\n"
)


class VersionTests(unittest.TestCase):
    def test_reads_and_sets_only_the_workspace_version(self):
        self.assertEqual(workspace_version(CARGO_TOML), "0.46.0")
        updated = set_workspace_version(CARGO_TOML, "0.47.0")
        self.assertEqual(updated, CARGO_TOML.replace('version = "0.46.0"', 'version = "0.47.0"'))
        self.assertIn('serde = { version = "1.0.0" }', updated)

    def test_missing_workspace_version_is_an_error(self):
        for cargo_toml in ('[package]\nversion = "1.0.0"\n', '[workspace.package]\nedition = "2024"\n\n[package]\nversion = "1.0.0"\n'):
            with self.subTest(cargo_toml=cargo_toml), self.assertRaises(ReleaseError):
                workspace_version(cargo_toml)

    def test_next_version_bumps_the_minor(self):
        self.assertEqual(next_version("0.46.0"), "0.47.0")
        self.assertEqual(next_version("0.46.3"), "0.47.0")
        self.assertEqual(next_version("1.9.0"), "1.10.0")


class ReleaseSectionTests(unittest.TestCase):
    def test_returns_the_section_with_its_heading(self):
        self.assertEqual(
            release_section(CHANGELOG, "0.46.0"),
            "## 0.46.0 - 2026-11-13\n\n### Added\n\n- New thing (#2) @a\n",
        )
        self.assertEqual(release_section(CHANGELOG, "0.45.0"), "## 0.45.0 - 2026-10-21\n\n### Fixed\n\n- Old thing (#1) @b\n")

    def test_missing_undated_or_misdated_section_is_an_error(self):
        for changelog in (
            CHANGELOG,
            HEADER + "## 0.47.0\n\n- x\n",
            HEADER + "## 0.47.0 - soon\n\n- x\n",
            HEADER + "## 0.47.0 - 2026-13-01\n\n- x\n",
            HEADER + "## 0.47.0-rc - 2026-11-01\n\n- x\n",
        ):
            with self.subTest(changelog=changelog), self.assertRaises(ReleaseError):
                release_section(changelog, "0.47.0")


class CheckTests(unittest.TestCase):
    def test_accepts_a_new_version_above_every_tag(self):
        check("0.46.0", CHANGELOG, ["v0.44.0", "v0.45.0"])
        check("0.46.0", CHANGELOG, [])

    def test_rejects_a_released_or_lower_version(self):
        for tags in (["v0.45.0", "v0.46.0"], ["v0.47.0"], ["v0.46.1"]):
            with self.subTest(tags=tags), self.assertRaises(ReleaseError):
                check("0.46.0", CHANGELOG, tags)

    def test_rejects_a_version_without_a_section(self):
        with self.assertRaises(ReleaseError):
            check("0.47.0", CHANGELOG, ["v0.46.0"])

    def test_rejects_a_pr_an_earlier_release_lists(self):
        carried_over = CHANGELOG.replace("- New thing (#2) @a", "- New thing (#2) @a\n- Old thing (#1) @b")
        with self.assertRaises(ReleaseError):
            check("0.46.0", carried_over, ["v0.45.0"])

    def test_mentions_upstream_links_and_foreign_references_are_not_own_prs(self):
        changelog = CHANGELOG + "\n## 0.1.0 - 2020-01-01\n\n- Upstream [#2](https://github.com/rust-bitcoin/rust-bitcoin/pull/2)\n"
        changelog = changelog.replace("New thing (#2)", "New thing, see rust-bitcoin#1 and https://example.com/x#1 (#2)")
        changelog = changelog.replace(
            "- New thing",
            '- Revert "feat: x (#1)" (#7) @c\n- Follow-up fixes to #1 (#8) @c\n- Wrapped, finishing the old thing (#1)\n  for more cases (#9) @c\n- New thing',
        )
        check("0.46.0", changelog, ["v0.45.0"])


class BumpTests(unittest.TestCase):
    def test_moves_dev_on_the_released_version_to_the_next_minor(self):
        self.assertEqual(bump("0.46.0", "0.46.0"), "0.47.0")

    def test_dev_past_a_patch_release_keeps_its_version(self):
        self.assertIsNone(bump("0.47.0", "0.46.1"))

    def test_dev_behind_the_release_is_an_error(self):
        with self.assertRaises(ReleaseError):
            bump("0.46.0", "0.46.1")

    def test_pr_text_for_a_bump_and_for_a_patch_release(self):
        branch, title, body = bump_pr("0.46.0", "0.47.0", "dashpay/rust-dashcore", "abc123")
        self.assertEqual((branch, title), ("chore/bump-version-to-0.47.0", "chore: bump version to `0.47.0`"))
        self.assertIn("https://github.com/dashpay/rust-dashcore/releases/tag/v0.46.0", body)
        self.assertIn("Bump the workspace version to `0.47.0`", body)
        self.assertIn("tag `v0.46.0` on abc123", body)
        branch, title, body = bump_pr("0.46.1", None, "dashpay/rust-dashcore", "abc123")
        self.assertEqual((branch, title), ("chore/changelog-v0.46.1", "chore: add the `0.46.1` changelog"))
        self.assertIn("its version stays", body)


if __name__ == "__main__":
    unittest.main()
