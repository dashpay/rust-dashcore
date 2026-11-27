#!/usr/bin/env python3
"""CI control of draft PRs for the `Draft CI` workflow.

Subcommands:
    gate      Decide whether a draft push runs CI, for `Draft Gate`
    notice    Post the comment with the CI boxes on the draft PR of a skipped run
    boxes     Apply the boxes of the comment
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time

MARKER = "<!-- draft-ci -->"
BOT = "github-actions[bot]"
GATE = "Draft Gate"
ONCE = "once"
AUTO = "auto"
# The workflows whose jobs wait for `Draft Gate`.
GATED = {".github/workflows/rust.yml", ".github/workflows/pre-commit.yml", ".github/workflows/sanitizer.yml"}
POLL_SECONDS = 10
# Shared by all runs of one request and counted in real time, so a request ends within the job's
# 15 minute timeout and still reports what happened.
WAIT_SECONDS = 600
CALL_SECONDS = 30
NOTE = re.compile(r"\n*<!-- draft-ci:note -->.*", re.DOTALL)

BODY = f"""{MARKER}
CI does not run on this PR while it is a draft. Someone with write access can start it here:

- [ ] <!-- draft-ci:{ONCE} --> **Run CI once** on the current commit
- [ ] <!-- draft-ci:{AUTO} --> **Run CI on every push**, starting now

Marking the PR ready for review also starts CI."""


class GitHubError(Exception):
    pass


class GitHub:
    """The `gh api` calls on one repository."""

    def __init__(self, repo: str):
        self.repo = repo

    def request(self, method: str, path: str, fields: dict | None = None, paginate: bool = False):
        command = ["gh", "api", "--method", method, f"repos/{self.repo}/{path}"]
        if paginate:
            command += ["--paginate", "--slurp"]
        if fields is not None:
            command += ["--input", "-"]
        try:
            result = subprocess.run(command, input=json.dumps(fields) if fields is not None else None, capture_output=True,
                                    text=True, timeout=CALL_SECONDS)
        except subprocess.TimeoutExpired:
            raise GitHubError(f"{method} {path}: no answer within {CALL_SECONDS} seconds") from None
        if result.returncode != 0:
            raise GitHubError(f"{method} {path}: {result.stderr.strip()}")
        return json.loads(result.stdout) if result.stdout.strip() else None

    def get_list(self, path: str, key: str | None = None) -> list:
        pages = self.request("GET", path, paginate=True)
        return [item for page in pages for item in (page[key] if key else page)]


def is_ticked(body: str, box: str) -> bool:
    return re.search(rf"^- \[[xX]\] <!-- draft-ci:{box} -->", body, re.MULTILINE) is not None


def set_note(body: str, note: str) -> str:
    return f"{NOTE.sub('', body).rstrip()}\n\n<!-- draft-ci:note -->\n{note}"


def untick(body: str, box: str) -> str:
    return re.sub(rf"^- \[[xX]\] (<!-- draft-ci:{box} -->)", r"- [ ] \1", body, flags=re.MULTILINE)


def ci_comments(gh, number: int) -> list:
    """Returns the bot's CI comments. Only the bot's count, since editing them takes write access."""
    comments = gh.get_list(f"issues/{number}/comments?per_page=100")
    return [comment for comment in comments if comment["user"]["login"] == BOT and MARKER in comment["body"]]


def gate(gh, number: int) -> bool:
    """Whether a draft push runs CI, which it does when the "Run CI on every push" box is ticked."""
    try:
        return any(is_ticked(comment["body"], AUTO) for comment in ci_comments(gh, number))
    except GitHubError as error:
        # A read error must not hide CI.
        print(f"::warning::Could not read the CI comment, so CI runs. {error}")
        return True


def jobs_of(gh, run_id: int) -> list:
    return gh.get_list(f"actions/runs/{run_id}/jobs?per_page=100", "jobs")


def ran_ci(jobs: list) -> bool:
    """Whether any job besides the gate started. Jobs behind a gate that is still running are not listed."""
    return any(not job["name"].startswith(GATE) and job["conclusion"] != "skipped" for job in jobs)


def newest_runs(gh, sha: str) -> list:
    """Returns the newest pull request run of each gated workflow on the commit."""
    newest = {}
    for run in gh.get_list(f"actions/runs?head_sha={sha}&event=pull_request&per_page=100", "workflow_runs"):
        if run["path"] not in GATED:
            continue
        known = newest.get(run["workflow_id"])
        if known is None or run["run_number"] > known["run_number"]:
            newest[run["workflow_id"]] = run
    return sorted(newest.values(), key=lambda run: run["name"])


def moved_on(gh, number: int, sha: str) -> str | None:
    """Returns why a request for `sha` no longer applies, or `None` while the PR is still a draft at `sha`."""
    pr = gh.request("GET", f"pulls/{number}")
    if not pr["draft"]:
        return "The PR was marked ready for review, so CI runs on every push."
    if pr["head"]["sha"] != sha:
        return f"The PR moved on to {pr['head']['sha'][:8]}, so CI for {sha[:8]} was not started."
    return None


def start_runs(gh, number: int, sha: str, again: bool, sleep=time.sleep, clock=time.monotonic) -> str:
    """Restarts the commit's gated runs and returns what happened.

    Leaves a run whose CI is in progress alone, and with `again` unset also one whose CI finished.
    """
    runs = newest_runs(gh, sha)
    started, failed, deadline = [], [], clock() + WAIT_SECONDS
    for run in runs:
        if run["conclusion"] == "action_required":
            failed.append(f"{run['name']}: waits for a maintainer to approve the run")
            continue
        jobs = jobs_of(gh, run["id"])
        # GitHub refuses to restart a run before it completes.
        while run["status"] != "completed" and not ran_ci(jobs) and clock() < deadline:
            sleep(POLL_SECONDS)
            run = gh.request("GET", f"actions/runs/{run['id']}")
            jobs = jobs_of(gh, run["id"])
        if ran_ci(jobs) and (run["status"] != "completed" or not again):
            continue
        if run["status"] != "completed":
            failed.append(f"{run['name']}: its gate has not finished yet, tick a box again later")
            continue
        # A restart joins the concurrency group of the PR's newer runs and would cancel them.
        if reason := moved_on(gh, number, sha):
            return f"CI started for {sha[:8]}: {', '.join(started)}. {reason}" if started else reason
        try:
            gh.request("POST", f"actions/runs/{run['id']}/rerun")
            started.append(run["name"])
        except GitHubError as error:
            print(f"::error::{error}")
            failed.append(f"{run['name']}: could not be restarted")
    if failed:
        return f"CI did not start fully for {sha[:8]}. {'. '.join(failed)}."
    if started:
        return f"CI started for {sha[:8]}: {', '.join(started)}."
    if runs:
        return f"CI already ran or is running for {sha[:8]}."
    return f"There is no CI run to start for {sha[:8]}. Resolve any merge conflict and push again."


def notice(gh, run_id: int, sha: str) -> None:
    if ran_ci(jobs_of(gh, run_id)):
        return
    # The run lists no PR when it comes from a fork, and the commit endpoint knows no fork heads.
    for pr in gh.get_list("pulls?state=open&per_page=100"):
        if pr["head"]["sha"] != sha or not pr["draft"]:
            continue
        if not ci_comments(gh, pr["number"]):
            gh.request("POST", f"issues/{pr['number']}/comments", {"body": BODY})


def boxes(gh, number: int, comment_id: int, previous: str, sleep=time.sleep, clock=time.monotonic) -> None:
    """Applies the live boxes, so ticks that arrive while this runs are not lost.

    `previous` is the body before the edit. `draft-gate.yml` reads the "Run CI on every push" box
    on each push, so a change of it only starts the current commit or reports itself.
    """
    path = f"issues/comments/{comment_id}"
    body = gh.request("GET", path)["body"]
    pr = gh.request("GET", f"pulls/{number}")
    once, auto = is_ticked(body, ONCE), is_ticked(body, AUTO)
    if once:
        gh.request("PATCH", path, {"body": untick(body, ONCE)})
    enabled = auto and not is_ticked(previous, AUTO)
    disabled = not auto and is_ticked(previous, AUTO)

    if not (once or enabled or disabled):
        return
    if not pr["draft"]:
        note = "This PR is not a draft, so CI runs on every push."
    elif once or enabled:
        try:
            note = start_runs(gh, number, pr["head"]["sha"], again=once, sleep=sleep, clock=clock)
        except GitHubError as error:
            # The box is already unticked, so without a note the tick would seem to do nothing.
            print(f"::error::{error}")
            note = "CI could not be started. Tick a box again to retry."
    else:
        note = "CI no longer runs on every push."
    body = gh.request("GET", path)["body"]
    gh.request("PATCH", path, {"body": set_note(body, note)})


def set_output(name: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a") as output:
            output.write(f"{name}={value}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    gate_parser = commands.add_parser("gate")
    gate_parser.add_argument("pr", type=int)
    notice_parser = commands.add_parser("notice")
    notice_parser.add_argument("run_id", type=int)
    notice_parser.add_argument("sha")
    boxes_parser = commands.add_parser("boxes")
    boxes_parser.add_argument("pr", type=int)
    boxes_parser.add_argument("comment_id", type=int)
    args = parser.parse_args()

    gh = GitHub(os.environ["GITHUB_REPOSITORY"])
    try:
        if args.command == "gate":
            run = gate(gh, args.pr)
            set_output("run", str(run).lower())
            if not run:
                print("::notice::CI is off for draft PRs. Tick a box in the CI comment on the PR to start it.")
        elif args.command == "notice":
            notice(gh, args.run_id, args.sha)
        else:
            boxes(gh, args.pr, args.comment_id, os.environ.get("PREVIOUS_BODY", ""))
    except GitHubError as error:
        print(f"::error::{error}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
