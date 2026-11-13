import unittest

from release import ReleaseError, bump, check, next_version, release_section, set_workspace_version, workspace_version

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


class BumpTests(unittest.TestCase):
    def test_inserts_the_released_section_and_bumps_the_version(self):
        dev_changelog = HEADER + "## 0.45.0 - 2026-10-21\n\n### Fixed\n\n- Old thing (#1) @b\n"
        cargo_toml, changelog, version = bump(CARGO_TOML, dev_changelog, CHANGELOG, "0.46.0")
        self.assertEqual(version, "0.47.0")
        self.assertEqual(workspace_version(cargo_toml), "0.47.0")
        self.assertEqual(changelog, CHANGELOG)

    def test_first_release_into_a_changelog_without_sections(self):
        _, changelog, _ = bump(CARGO_TOML, "# Changelog\n\n", CHANGELOG, "0.46.0")
        self.assertEqual(changelog, "# Changelog\n\n## 0.46.0 - 2026-11-13\n\n### Added\n\n- New thing (#2) @a\n")

    def test_skips_when_dev_already_moved_on(self):
        moved_on = set_workspace_version(CARGO_TOML, "0.47.0")
        self.assertIsNone(bump(moved_on, CHANGELOG, CHANGELOG, "0.46.0"))

    def test_released_changelog_without_the_section_is_an_error(self):
        with self.assertRaises(ReleaseError):
            bump(CARGO_TOML, HEADER, HEADER, "0.46.0")


if __name__ == "__main__":
    unittest.main()
