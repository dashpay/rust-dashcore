import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from draft_ci import BODY, BOT, GATED, MARKER, POLLS, GitHubError, boxes, gate, is_ticked, notice, set_output

SHA = "a" * 40
OTHER_SHA = "b" * 40
GATE = {"name": "Draft Gate / check", "conclusion": "success"}
WORKFLOWS = Path(__file__).resolve().parents[1] / "workflows"
PATHS = {"Continuous integration": ".github/workflows/rust.yml", "Sanitizer": ".github/workflows/sanitizer.yml",
         "Pre-commit Checks": ".github/workflows/pre-commit.yml", "Changelog Guard": ".github/workflows/changelog-guard.yml"}


class FakeGitHub:
    """A repository with one PR. A run goes through its gate the way `draft-gate.yml` decides."""

    def __init__(self, draft=True):
        self.pr = {"number": 1, "draft": draft, "head": {"sha": SHA}}
        self.comments = []
        self.runs = []
        self.reruns = []
        self.fail_reruns = False
        self.fail_run_list = False
        self.fail_comments = False

    def push(self, sha=SHA, workflows=("Continuous integration", "Sanitizer"), running=False, listed=True):
        self.pr["head"]["sha"] = sha
        for name in workflows:
            run = {"id": len(self.runs) + 1, "workflow_id": name, "run_number": len(self.runs) + 1, "name": name,
                   "path": PATHS[name], "head_sha": sha, "status": "completed", "conclusion": "success", "attempt": 1}
            run["gated"] = run["path"] in GATED
            run["ci"] = not run["gated"] or not self.pr["draft"] or gate(self, 1)
            run["listed"] = listed
            run["status"] = "in_progress" if running else "completed"
            self.runs.append(run)
        return self.runs[-len(workflows)]

    def jobs(self, run):
        if run["conclusion"] == "action_required" or not run["listed"]:
            return []
        gate = [GATE] if run["gated"] else []
        if run["status"] != "completed" and not run["ci"]:
            return gate
        conclusion = None if run["status"] != "completed" else ("success" if run["ci"] or not run["gated"] else "skipped")
        return gate + [{"name": "Test", "conclusion": conclusion}]

    def finish_runs(self, _seconds):
        for run in self.runs:
            run.update(status="completed", listed=True)

    def tick(self, *names, untick=()):
        previous = body = self.comments[-1]["body"]
        for name in names:
            body = body.replace(f"- [ ] <!-- draft-ci:{name} -->", f"- [x] <!-- draft-ci:{name} -->")
        for name in untick:
            body = body.replace(f"- [x] <!-- draft-ci:{name} -->", f"- [ ] <!-- draft-ci:{name} -->")
        self.comments[-1]["body"] = body
        boxes(self, 1, self.comments[-1]["id"], previous, sleep=self.finish_runs)

    def open_draft(self):
        run = self.push()
        notice(self, run["id"], SHA)

    @property
    def body(self):
        return self.comments[-1]["body"]

    def get_list(self, path, key=None):
        if match := re.match(r"actions/runs/(\d+)/jobs", path):
            return self.jobs(self.runs[int(match.group(1)) - 1])
        if path.startswith("actions/runs?"):
            if self.fail_run_list:
                raise GitHubError("HTTP 502")
            return [run for run in self.runs if f"head_sha={run['head_sha']}&" in path]
        if path.startswith("pulls?"):
            return [self.pr]
        if path.startswith("issues/1/comments"):
            if self.fail_comments:
                raise GitHubError("HTTP 502")
            return self.comments
        raise AssertionError(path)

    def request(self, method, path, fields=None):
        if match := re.fullmatch(r"issues/comments/(\d+)", path):
            comment = self.comments[int(match.group(1)) - 1]
            if method == "PATCH":
                comment["body"] = fields["body"]
            return comment
        if (method, path) == ("POST", "issues/1/comments"):
            self.comments.append({"id": len(self.comments) + 1, "user": {"login": BOT}, **fields})
        elif (method, path) == ("GET", "pulls/1"):
            return self.pr
        elif match := re.fullmatch(r"actions/runs/(\d+)(/rerun)?", path):
            run = self.runs[int(match.group(1)) - 1]
            if method == "GET":
                return run
            if self.fail_reruns or run["status"] != "completed":
                raise GitHubError("HTTP 403")
            run.update(attempt=run["attempt"] + 1, ci=True, status="in_progress")
            self.reruns.append(run["name"])
        else:
            raise AssertionError(f"{method} {path}")


class NoticeTests(unittest.TestCase):
    def test_posts_one_comment_on_a_skipped_draft(self):
        gh = FakeGitHub()
        gh.open_draft()
        gh.open_draft()
        self.assertEqual([comment["body"] for comment in gh.comments], [BODY])
        self.assertFalse(is_ticked(gh.body, "once") or is_ticked(gh.body, "auto"))

    def test_posts_nothing_when_ci_ran(self):
        gh = FakeGitHub(draft=False)
        run = gh.push()
        notice(gh, run["id"], SHA)
        self.assertEqual(gh.comments, [])

    def test_posts_nothing_once_the_pr_moved_on_or_is_ready(self):
        gh = FakeGitHub()
        run = gh.push()
        gh.pr["head"]["sha"] = OTHER_SHA
        notice(gh, run["id"], SHA)
        gh.pr.update(draft=False, head={"sha": SHA})
        notice(gh, run["id"], SHA)
        self.assertEqual(gh.comments, [])

    def test_a_copy_of_the_marker_by_someone_else_is_not_the_comment(self):
        gh = FakeGitHub()
        gh.comments = [{"id": 1, "user": {"login": "someone"}, "body": MARKER}]
        gh.open_draft()
        self.assertEqual(len(gh.comments), 2)


class GateTests(unittest.TestCase):
    def test_reads_the_every_push_box_of_the_bot_comment(self):
        gh = FakeGitHub()
        self.assertFalse(gate(gh, 1))
        gh.open_draft()
        self.assertFalse(gate(gh, 1))
        ticked = BODY.replace("- [ ] <!-- draft-ci:auto", "- [x] <!-- draft-ci:auto")
        for body, user, expected in ((ticked, BOT, True), (ticked.replace("\n", "\r\n"), BOT, True),
                                     (ticked.replace(MARKER, ""), BOT, False), (ticked, "someone", False),
                                     (BODY.replace("- [ ] <!-- draft-ci:once", "- [x] <!-- draft-ci:once"), BOT, False)):
            with self.subTest(body=body, user=user):
                gh.comments = [{"id": 1, "user": {"login": user}, "body": body}]
                self.assertEqual(gate(gh, 1), expected)

    def test_a_read_error_runs_ci(self):
        gh = FakeGitHub()
        gh.fail_comments = True
        self.assertTrue(gate(gh, 1))


class BoxTests(unittest.TestCase):
    def setUp(self):
        self.gh = FakeGitHub()
        self.gh.open_draft()

    def test_once_runs_the_commit_but_not_the_next_push(self):
        self.gh.tick("once")
        self.assertEqual(self.gh.reruns, ["Continuous integration", "Sanitizer"])
        self.assertFalse(is_ticked(self.gh.body, "once"))
        self.assertIn("CI started for aaaaaaaa", self.gh.body)
        self.assertFalse(self.gh.push(OTHER_SHA)["ci"])

    def test_auto_runs_the_commit_and_every_push_until_unticked(self):
        self.gh.tick("auto")
        self.assertEqual(self.gh.reruns, ["Continuous integration", "Sanitizer"])
        self.assertTrue(is_ticked(self.gh.body, "auto"))
        self.assertTrue(self.gh.push(OTHER_SHA)["ci"])
        body = self.gh.body
        self.gh.tick()
        self.assertEqual((self.gh.body, len(self.gh.reruns)), (body, 2))
        self.gh.tick(untick=["auto"])
        self.assertIn("no longer runs", self.gh.body)
        self.assertFalse(self.gh.push("c" * 40)["ci"])
        self.assertEqual(len(self.gh.reruns), 2)

    def test_both_boxes_start_each_run_once(self):
        self.gh.tick("once", "auto")
        self.assertEqual(self.gh.reruns, ["Continuous integration", "Sanitizer"])
        self.assertFalse(is_ticked(self.gh.body, "once"))
        self.assertTrue(is_ticked(self.gh.body, "auto"))

    def test_an_edit_without_a_tick_changes_nothing(self):
        self.gh.tick()
        self.assertEqual(self.gh.body, BODY)
        self.assertEqual(self.gh.reruns, [])

    def test_windows_line_endings(self):
        self.gh.comments[-1]["body"] = self.gh.body.replace("\n", "\r\n")
        self.gh.tick("once")
        self.assertEqual(len(self.gh.reruns), 2)
        self.assertFalse(is_ticked(self.gh.body, "once"))

    def test_a_second_request_leaves_running_ci_alone_and_repeats_finished_ci(self):
        self.gh.tick("once")
        self.gh.tick("once")
        self.assertEqual(len(self.gh.reruns), 2)
        self.assertIn("already ran or is running", self.gh.body)
        self.gh.finish_runs(0)
        self.gh.tick("auto")
        self.assertEqual(len(self.gh.reruns), 2)
        self.gh.tick("once")
        self.assertEqual(len(self.gh.reruns), 4)

    def test_waits_for_a_running_gate(self):
        self.gh.push(OTHER_SHA, running=True)
        self.gh.tick("once")
        self.assertEqual(len(self.gh.reruns), 2)

    def test_restarts_only_the_newest_gated_runs_of_the_current_commit(self):
        self.gh.push(OTHER_SHA, workflows=("Changelog Guard",))
        self.gh.tick("once")
        self.assertIn("no CI run to start", self.gh.body)
        first = self.gh.push(OTHER_SHA, workflows=("Continuous integration",))
        second = self.gh.push(OTHER_SHA, workflows=("Continuous integration",))
        self.gh.tick("once")
        self.assertEqual(self.gh.reruns, ["Continuous integration"])
        self.assertEqual((first["attempt"], second["attempt"]), (1, 2))

    def test_waits_for_a_run_that_lists_no_jobs_yet(self):
        self.gh.push(OTHER_SHA, running=True, listed=False)
        self.gh.tick("once")
        self.assertEqual(self.gh.reruns, ["Continuous integration", "Sanitizer"])

    def test_all_runs_share_one_wait(self):
        sleeps = []
        self.gh.push(OTHER_SHA, workflows=("Continuous integration", "Pre-commit Checks", "Sanitizer"), running=True)
        self.gh.comments[-1]["body"] = self.gh.body.replace("- [ ] <!-- draft-ci:once", "- [x] <!-- draft-ci:once")
        boxes(self.gh, 1, 1, BODY, sleep=sleeps.append)
        self.assertEqual((len(sleeps), self.gh.reruns), (POLLS, []))
        self.assertEqual(self.gh.body.count("gate has not finished yet"), 3)

    def test_gated_lists_every_workflow_that_calls_the_gate(self):
        callers = {f".github/workflows/{path.name}" for path in WORKFLOWS.glob("*.yml") if "/draft-gate.yml" in path.read_text()}
        self.assertEqual(callers, GATED)

    def test_no_run_on_the_commit(self):
        self.gh.pr["head"]["sha"] = OTHER_SHA
        self.gh.tick("once")
        self.assertIn("no CI run to start", self.gh.body)

    def test_a_run_waiting_for_approval_is_reported(self):
        self.gh.push(OTHER_SHA, workflows=("Continuous integration", "Changelog Guard"))
        for run in self.gh.runs:
            run["conclusion"] = "action_required"
        self.gh.tick("once")
        self.assertEqual(self.gh.reruns, [])
        self.assertIn("Continuous integration: waits for a maintainer to approve the run.", self.gh.body)
        self.assertNotIn("Changelog Guard", self.gh.body)

    def test_failures_are_reported(self):
        self.gh.fail_reruns = True
        self.gh.tick("once")
        self.assertIn("could not be restarted", self.gh.body)
        self.gh.fail_run_list = True
        self.gh.tick("once")
        self.assertIn("could not be started", self.gh.body)
        self.assertEqual(self.gh.body.count("draft-ci:note"), 1)

    def test_a_ready_pr_starts_nothing(self):
        self.gh.pr["draft"] = False
        self.gh.tick("once")
        self.assertEqual(self.gh.reruns, [])
        self.assertIn("not a draft", self.gh.body)

    def test_a_box_ticked_while_runs_start_is_kept(self):
        tick = self.gh.finish_runs

        def sleep(seconds):
            tick(seconds)
            self.gh.comments[-1]["body"] = self.gh.body.replace("- [ ] <!-- draft-ci:auto", "- [x] <!-- draft-ci:auto")

        self.gh.push(OTHER_SHA, running=True)
        self.gh.comments[-1]["body"] = self.gh.body.replace("- [ ] <!-- draft-ci:once", "- [x] <!-- draft-ci:once")
        boxes(self.gh, 1, 1, BODY, sleep=sleep)
        self.assertTrue(is_ticked(self.gh.body, "auto"))


class OutputTests(unittest.TestCase):
    def test_set_output_writes_only_inside_actions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "output")
            with mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(path)}):
                set_output("run", "true")
            self.assertEqual(path.read_text(), "run=true\n")
        with mock.patch.dict(os.environ, clear=True):
            set_output("run", "true")


if __name__ == "__main__":
    unittest.main()
