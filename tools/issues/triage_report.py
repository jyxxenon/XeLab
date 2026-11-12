#!/usr/bin/env python3
"""Read-only open-issue triage: status, assignees, claim and duplicate candidates. Never writes."""
import argparse
from collections import Counter
import json
import os
import re
import sys
import unicodedata
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPRedirectHandler

SCHEMA = 1
CREDENTIAL = re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|MERGE_TOKEN|AGENT_TOKEN", re.IGNORECASE)
CLAIM_MARKERS = ("认领申请", "切片认领", "/claim")
BRANCH_CLAIM = re.compile(r"将在独立分支[ \t]+`[^`\r\n]{1,200}`[ \t]+推进本[ \t]+Issue\b", re.IGNORECASE)
STOPWORDS = {
    "a", "an", "and", "for", "of", "the", "to", "with", "in", "on", "is", "bug", "feature", "redacted",
    "实现", "实现微插件", "实现普通", "微插件", "插件",
}
NOTE = ("Read-only report. Duplicate and claim matches are candidates for manual review, "
        "never definitive rulings; no issue state was changed.")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Do not forward an authorization header to a redirect target.
        raise ValueError("GitHub redirect refused; verify the current repository name")


class GitHub:
    def __init__(self, repo, token):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) or any(part in {".", ".."} for part in repo.split("/")):
            raise ValueError("repository must be owner/name")
        self.repo = repo
        self.base = "https://api.github.com/repos/" + repo
        self.token = token
        self.opener = build_opener(NoRedirect())

    def request(self, path):
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        with self.opener.open(Request(self.base + path, headers=headers, method="GET"), timeout=30) as response:
            return json.load(response)


def pages(api, path):
    page = 1
    while True:
        batch = api.request(f"{path}{'&' if '?' in path else '?'}per_page=100&page={page}")
        yield from batch
        if len(batch) < 100:
            return
        page += 1


def redact(text):
    return CREDENTIAL.sub("<redacted>", text)


def safe_text(value):
    """Replace terminal/format control characters from untrusted issue titles."""
    return "".join(" " if unicodedata.category(char) in {"Cc", "Cf", "Cs"} else char
                   for char in value)


def normalize_title(title):
    title = re.sub(r"^(?:\[[^\]]*\]\s*)+", "", title)
    return " ".join(re.sub(r"[^\w]+", " ", title.casefold()).split())


def keywords(title):
    cleaned = re.sub(r"^(?:\[[^\]]*\]\s*)+", "", title.casefold()).replace("<redacted>", " ")
    return {word for word in re.findall(r"\w+(?:[.-]\w+)*", cleaned) if word not in STOPWORDS and len(word) > 1}


def claim_candidates(api, number):
    claims = []
    seen = set()
    for comment in pages(api, f"/issues/{number}/comments"):
        body = comment.get("body") or ""
        url = comment["html_url"]
        matched = any(marker in body for marker in CLAIM_MARKERS) or BRANCH_CLAIM.search(body)
        if matched and url not in seen:
            seen.add(url)
            claims.append({"user": comment["user"]["login"], "created_at": comment["created_at"], "url": url})
    claims.sort(key=lambda c: (c["created_at"], c["user"], c["url"]))
    return claims


def duplicate_candidates(issues):
    candidates = []
    by_title = {}
    for issue in issues:
        by_title.setdefault(normalize_title(issue["title"]), []).append(issue["number"])
    for numbers in by_title.values():
        if len(numbers) > 1:
            candidates.append({"kind": "same-normalized-title", "issues": sorted(numbers)})
    for index, left in enumerate(issues):
        for right in issues[index + 1:]:
            shared = keywords(left["title"]) & keywords(right["title"])
            union = keywords(left["title"]) | keywords(right["title"])
            if len(shared) >= 2 and union and len(shared) / len(union) >= 0.5:
                pair = sorted((left["number"], right["number"]))
                if not any(c["kind"] == "same-normalized-title" and c["issues"] == pair for c in candidates):
                    candidates.append({"kind": "shared-keywords", "issues": pair, "shared": sorted(shared)})
    candidates.sort(key=lambda c: (c["kind"], c["issues"]))
    return candidates


def build_report(api):
    # Page boundaries can overlap; retain one, last-seen record per repository issue number.
    items = {item["number"]: item for item in pages(api, "/issues?state=open")}.values()
    prs = [item for item in items if "pull_request" in item]
    issues = []
    for item in sorted((i for i in items if "pull_request" not in i), key=lambda i: i["number"]):
        labels = sorted(label["name"] for label in item.get("labels", []))
        status = next((label for label in labels if label.startswith("status:")), "no-status")
        claims = [] if item.get("comments") == 0 else claim_candidates(api, item["number"])
        claim_counts = Counter(claim["user"].casefold() for claim in claims)
        issues.append({
            "number": item["number"],
            "title": safe_text(redact(item["title"]))[:120],
            "url": item["html_url"],
            "labels": labels,
            "status": status,
            "assignees": sorted(a["login"] for a in item.get("assignees", [])),
            "claim_candidates": claims,
            "multiple_claimants": len(claim_counts) > 1,
            "repeated_claim_candidates": any(count > 1 for count in claim_counts.values()),
        })
    return {
        "schema": SCHEMA,
        "kind": "issue-triage-report",
        "repository": api.repo,
        "open_issues": len(issues),
        "excluded_prs": len(prs),
        "issues": issues,
        "needs_triage": [i["number"] for i in issues if i["status"] in {"no-status", "status:needs-triage"}],
        "unassigned": [i["number"] for i in issues if not i["assignees"]],
        "multiple_claimants": [i["number"] for i in issues if i["multiple_claimants"]],
        "repeated_claim_candidates": [i["number"] for i in issues if i["repeated_claim_candidates"]],
        "duplicate_candidates": duplicate_candidates(issues),
        "duplicates_are_definitive": False,
        "note": NOTE,
    }


def render_text(report):
    lines = [
        f"{report['repository']}: {report['open_issues']} open issues ({report['excluded_prs']} PRs excluded)",
        f"needs triage (no-status or needs-triage): {report['needs_triage'] or 'none'}",
        f"unassigned: {report['unassigned'] or 'none'}",
        f"multiple claim candidates (manual review): {report['multiple_claimants'] or 'none'}",
        f"repeated same-account claim candidates (manual review): {report.get('repeated_claim_candidates', []) or 'none'}",
    ]
    for issue in report["issues"]:
        lines.append(f"  #{issue['number']} {issue['status']} assignees={issue['assignees'] or 'none'} claims={len(issue['claim_candidates'])} {issue['title']}")
    if report["duplicate_candidates"]:
        lines.append("duplicate candidates (NOT definitive; manual review required):")
        for candidate in report["duplicate_candidates"]:
            lines.append(f"  {candidate['kind']}: {candidate['issues']}")
    else:
        lines.append("duplicate candidates: none")
    lines.append(report["note"])
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--json", action="store_true", help="emit stable machine-readable JSON instead of text")
    args = parser.parse_args(argv)
    try:
        api = GitHub(args.repo, os.environ.get("GITHUB_TOKEN", ""))
        report = build_report(api)
        print(json.dumps(report, sort_keys=True, indent=2, ensure_ascii=False) if args.json else render_text(report))
    except HTTPError as error:
        print(f"GitHub API returned HTTP {error.code}; stopped. Review permissions/rate limits and retry.", file=sys.stderr)
        return 1
    except (ValueError, OSError, URLError) as error:
        print(f"Triage report stopped: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())