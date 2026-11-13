import unittest

from release import (
    ReleaseError,
    bump,
    bump_pr,
    check,
    merged_prs,
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
        self.assertEqual(check("0.46.0", CHANGELOG, ["v0.44.0", "v0.45.0"], {2: "feat: new thing (#2)"}), [])
        self.assertEqual(check("0.46.0", CHANGELOG, [], None), [])

    def test_rejects_a_released_or_lower_version(self):
        for tags in (["v0.45.0", "v0.46.0"], ["v0.47.0"], ["v0.46.1"]):
            with self.subTest(tags=tags), self.assertRaises(ReleaseError):
                check("0.46.0", CHANGELOG, tags, None)

    def test_rejects_a_version_without_a_section(self):
        with self.assertRaises(ReleaseError):
            check("0.47.0", CHANGELOG, ["v0.46.0"], None)

    def test_rejects_a_pr_an_earlier_release_lists(self):
        carried_over = CHANGELOG.replace("- New thing (#2) @a", "- New thing (#2) @a\n- Old thing (#1) @b")
        with self.assertRaises(ReleaseError):
            check("0.46.0", carried_over, ["v0.45.0"], None)

    def test_upstream_links_and_foreign_references_are_not_prs(self):
        changelog = CHANGELOG + "\n## 0.1.0 - 2020-01-01\n\n- Upstream [#2](https://github.com/rust-bitcoin/rust-bitcoin/pull/2)\n"
        changelog = changelog.replace("(#2) @a", "(#2) @a, see rust-bitcoin#1 and https://example.com/x#1")
        self.assertEqual(check("0.46.0", changelog, ["v0.45.0"], {2: "fix: new thing (#2)"}), [])

    def test_warns_about_unmerged_and_left_out_prs(self):
        merged = {
            3: "feat(dash-spv)!: left out (#3)",
            4: "fix: left out too (#4)",
            5: "ci: routinely left out (#5)",
            6: "chore: also routinely left out (#6)",
        }
        warnings = check("0.46.0", CHANGELOG, ["v0.45.0"], merged)
        self.assertEqual(len(warnings), 2)
        self.assertIn("not merged since the latest release: #2", warnings[0])
        self.assertTrue(warnings[1].endswith(": #3, #4"))


class MergedPrsTests(unittest.TestCase):
    def test_reads_squash_and_merge_commit_subjects(self):
        subjects = [
            "feat(key-wallet): expose `holds_coin` (#1400)",
            "Merge pull request #1402 from dashpay/chore/release-v0.46.0",
            "chore: merge `master` into the release branch",
            "fix: mention #12 midway",
        ]
        self.assertEqual(
            merged_prs(subjects),
            {1400: subjects[0], 1402: subjects[1]},
        )


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

    def test_patch_release_adds_its_section_below_newer_ones_and_keeps_the_version(self):
        dev_cargo_toml = set_workspace_version(CARGO_TOML, "0.47.0")
        dev_changelog = HEADER + "## 0.47.0 - 2026-12-01\n\n- Newer (#9) @c\n\n" + CHANGELOG[len(HEADER) :]
        released = CHANGELOG.replace("## 0.46.0 - 2026-11-13", "## 0.46.1 - 2026-11-20\n\n- Patch (#5) @d\n\n## 0.46.0 - 2026-11-13")
        cargo_toml, changelog, version = bump(dev_cargo_toml, dev_changelog, released, "0.46.1")
        self.assertIsNone(version)
        self.assertEqual(cargo_toml, dev_cargo_toml)
        self.assertEqual(
            changelog,
            dev_changelog.replace("## 0.46.0 - 2026-11-13", "## 0.46.1 - 2026-11-20\n\n- Patch (#5) @d\n\n## 0.46.0 - 2026-11-13"),
        )

    def test_skips_when_dev_already_has_the_section(self):
        moved_on = set_workspace_version(CARGO_TOML, "0.47.0")
        self.assertIsNone(bump(moved_on, CHANGELOG, CHANGELOG, "0.46.0"))

    def test_bumps_a_dev_that_already_has_the_section(self):
        cargo_toml, changelog, version = bump(CARGO_TOML, CHANGELOG, CHANGELOG, "0.46.0")
        self.assertEqual((workspace_version(cargo_toml), changelog, version), ("0.47.0", CHANGELOG, "0.47.0"))

    def test_refuses_a_section_that_is_not_a_release_or_dev_behind_the_release(self):
        behind = set_workspace_version(CARGO_TOML, "0.45.0")
        cases = [(behind, HEADER)]
        for heading in ("## Unreleased", "## [Unreleased]", "## unreleased", "## 0.47.0"):
            cases.append((CARGO_TOML, HEADER + heading + "\n\n- Pending (#2) @a\n\n## 0.45.0 - 2026-10-21\n"))
        for cargo_toml, changelog in cases:
            with self.subTest(changelog=changelog), self.assertRaises(ReleaseError):
                bump(cargo_toml, changelog, CHANGELOG, "0.46.0")

    def test_released_changelog_without_the_section_is_an_error(self):
        with self.assertRaises(ReleaseError):
            bump(CARGO_TOML, HEADER, HEADER, "0.46.0")

    def test_pr_text_for_a_bump_and_for_a_patch_release(self):
        branch, title, body = bump_pr("0.46.0", "0.47.0", "dashpay/rust-dashcore", "abc123")
        self.assertEqual((branch, title), ("chore/bump-version-to-0.47.0", "chore: bump version to `0.47.0`"))
        self.assertIn("https://github.com/dashpay/rust-dashcore/releases/tag/v0.46.0", body)
        self.assertIn("tag `v0.46.0` on abc123", body)
        branch, title, body = bump_pr("0.46.1", None, "dashpay/rust-dashcore", "abc123")
        self.assertEqual((branch, title), ("chore/changelog-v0.46.1", "chore: add the `0.46.1` changelog"))
        self.assertIn("its version stays", body)


if __name__ == "__main__":
    unittest.main()
