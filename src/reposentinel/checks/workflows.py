"""Unsafe GitHub Actions workflow patterns (rules RS-GHA-001 to RS-GHA-004).

Only workflow files directly inside ``.github/workflows/`` are analysed,
because those are the only files GitHub runs as workflows. Composite actions
(``action.yml``) are out of scope for this release.

Workflows are parsed with PyYAML's *safe* loader into a node tree. Working
with nodes rather than loaded Python objects has two benefits: every value
carries its line number, and the key ``on`` stays the string "on" (YAML 1.1
would otherwise turn it into the boolean ``True``).

Nothing in a workflow is executed or evaluated: ``${{ }}`` expressions are
treated as plain text.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

import yaml

from reposentinel.checks.base import Check, CheckOutput
from reposentinel.context import ScanContext
from reposentinel.models import Confidence, CoverageReason, Finding, Rule, Severity
from reposentinel.walker import FileEntry

SCRIPT_INJECTION = Rule(
    id="RS-GHA-001",
    title="Untrusted input expanded inside a script",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    description=(
        "A run: step, or an actions/github-script script, contains a ${{ }} expression that "
        "attacker-controlled data can reach, such as an issue title, pull request body, comment "
        "or branch name. GitHub pastes the value into the script before it runs, so crafted "
        "input can execute arbitrary commands on the runner."
    ),
    severity_rationale=(
        "High: successful injection runs attacker code with the job's GITHUB_TOKEN and any "
        "secrets available to it. Confidence is medium because exploitability depends on the "
        "trigger (who can open issues or pull requests) and on the job's permissions, which this "
        "rule does not evaluate."
    ),
    remediation=(
        "Pass the value through an environment variable and use it as a quoted shell variable, "
        'e.g. env: TITLE: ${{ github.event.issue.title }} and then run: echo "$TITLE". Never '
        "place expressions containing user-controlled data directly inside a script."
    ),
    limitations=(
        "Recognises a fixed list of well-known attacker-controllable contexts. Values that become "
        "untrusted indirectly (step outputs, env values, toJSON(github.event), bracket syntax "
        "such as github.event['issue']) are not detected. Composite actions are not analysed. "
        "Expressions that can only produce true or false (a single contains, startsWith or "
        "endsWith call, a comparison, or a negation, without && or ||) are not reported. The "
        "rule does not check whether the trigger actually provides the context, so a context "
        "that is always empty for that trigger is still reported."
    ),
    references=("https://securitylab.github.com/resources/github-actions-untrusted-input/",),
    recheck_limits=(
        "Moving the value into env: is the right fix, but then using it unsafely in the "
        'script (for example eval "$TITLE") is not detected, and contexts that become '
        "untrusted indirectly are not followed."
    ),
)

PWN_REQUEST = Rule(
    id="RS-GHA-002",
    title="pull_request_target workflow checks out pull request code",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    description=(
        "The workflow runs on pull_request_target, which executes with the base repository's "
        "secrets and a write-capable token, and it explicitly checks out the pull request's "
        "code. If a later step builds, installs or runs that code, a pull request from a fork "
        "can steal secrets or push to the repository (a 'pwn request')."
    ),
    severity_rationale=(
        "High: this pattern has led to real repository compromises. Confidence is medium because "
        "a workflow that only reads the checked-out files, without executing them, may be safe."
    ),
    remediation=(
        "Use the pull_request trigger to build and test untrusted code. If pull_request_target "
        "is needed (for example to label or comment), do not check out the pull request head, or "
        "split the work into an unprivileged pull_request workflow and a privileged workflow "
        "that only consumes its artifacts. Set persist-credentials: false and minimal "
        "permissions."
    ),
    limitations=(
        "Detects actions/checkout steps whose ref or repository refers to the pull request's code "
        "(github.event.pull_request.head.*, github.event.pull_request.merge_commit_sha, "
        "github.head_ref, refs/pull/...). Other ways to fetch "
        "pull request code (git commands in run steps, other actions, workflow_run triggers) "
        "are not detected."
    ),
    references=(
        "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
    ),
    recheck_limits=(
        "Fetching the pull request with git commands in a run: step, or with another action, "
        "is not detected."
    ),
)

UNPINNED_ACTION = Rule(
    id="RS-GHA-003",
    title="Third-party action not pinned to a commit SHA",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    description=(
        "A step or reusable workflow uses a third-party action by tag or branch (e.g. "
        "owner/action@v3) instead of a full 40-character commit SHA. Tags and branches can be "
        "moved by the maintainer, or by anyone who compromises their account, to point at "
        "malicious code."
    ),
    severity_rationale=(
        "Medium: exploitation requires compromising the upstream action, but when that happens "
        "every workflow using a movable reference runs the attacker's code with its own secrets, "
        "as happened in the 2025 tj-actions/changed-files incident."
    ),
    remediation=(
        "Pin to the full commit SHA of a reviewed release and record the version in a comment, "
        "e.g. uses: owner/action@<40-character-sha> # v3.1.0. Dependabot can keep SHA pins up "
        "to date."
    ),
    limitations=(
        "Actions owned by the 'actions' and 'github' organisations are not reported, to reduce "
        "noise; pinning them is still good practice. Docker references (docker://) and local "
        "actions (./path) are not evaluated. A SHA pin does not make the pinned code trustworthy."
    ),
    recheck_limits=(
        "A SHA pin is not checked for trustworthiness: pinning to a malicious or compromised "
        "commit satisfies the rule."
    ),
)

WRITE_ALL_PERMISSIONS = Rule(
    id="RS-GHA-004",
    title="Workflow grants write-all permissions",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    description=(
        "permissions: write-all gives the GITHUB_TOKEN write access to every scope (contents, "
        "packages, pull requests and more)."
    ),
    severity_rationale=(
        "Medium: not exploitable on its own, but it turns any other weakness in the workflow "
        "(such as RS-GHA-001) into full write access to the repository."
    ),
    remediation=(
        "Replace write-all with the minimum scopes needed, e.g. permissions: contents: read, and "
        "grant write scopes only to the specific jobs that need them."
    ),
    limitations=(
        "Only the literal value write-all is reported. Broad explicit grants and missing "
        "permissions blocks (which fall back to the repository's default token permissions) are "
        "not evaluated."
    ),
    recheck_limits=(
        "Only the literal value write-all is reported. Broad explicit write scopes are not, "
        "so replacing write-all with many write scopes is not detected."
    ),
)

RULES: tuple[Rule, ...] = (SCRIPT_INJECTION, PWN_REQUEST, UNPINNED_ACTION, WRITE_ALL_PERMISSIONS)

WORKFLOW_DIR = ".github/workflows/"

# A ${{ ... }} expression.
_EXPRESSION_RE = re.compile(r"\$\{\{(?P<body>.*?)\}\}", re.DOTALL)

# Contexts that people outside the project can control, based on GitHub
# Security Lab's guidance on untrusted input. ".*" and "[n]" cover arrays.
_ANY_INDEX = r"(?:\.\*|\[[^\]]*\])"
_UNTRUSTED_CONTEXT_RE = re.compile(
    r"github\.head_ref\b"
    r"|github\.event\.(?:issue|pull_request|discussion)\.(?:title|body)\b"
    r"|github\.event\.(?:comment|review|review_comment)\.body\b"
    rf"|github\.event\.pages{_ANY_INDEX}\.page_name\b"
    rf"|github\.event\.commits{_ANY_INDEX}\.(?:message|author\.(?:email|name))\b"
    r"|github\.event\.head_commit\.(?:message|author\.(?:email|name))\b"
    r"|github\.event\.pull_request\.head\.(?:ref|label|repo\.default_branch)\b"
    r"|github\.event\.workflow_run\.(?:head_branch|display_title"
    r"|head_commit\.(?:message|author\.(?:email|name)))\b"
    rf"|github\.event\.workflow_run\.pull_requests{_ANY_INDEX}\.head\.ref\b"
)

# Expressions that can only evaluate to true or false cannot inject text into a
# script, even when they read untrusted data, e.g. startsWith(github.head_ref,
# 'release/'). Recognised conservatively, after removing string literals:
# no && or || (they return one of their operands, which may be text), and
# either one top-level contains/startsWith/endsWith call, a top-level
# comparison, or a leading "!".
_STRING_LITERAL_RE = re.compile(r"'(?:[^']|'')*'")
_BOOLEAN_FUNCTION_RE = re.compile(r"\s*(?:contains|startsWith|endsWith)\s*", re.IGNORECASE)
_COMPARISON_OPERATORS = ("==", "!=", "<=", ">=", "<", ">")

# A checkout ref or repository that points at the pull request's own code.
# merge_commit_sha is the test merge of the pull request, so it contains that code too.
_PR_HEAD_RE = re.compile(
    r"github\.event\.pull_request\.(?:head\.|merge_commit_sha\b)|github\.head_ref\b|refs/pull/",
    re.IGNORECASE,
)

_USES_RE = re.compile(
    r"^(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)(?P<subpath>/[^@\s]*)?@(?P<ref>\S+)$"
)
_FULL_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_FIRST_PARTY_OWNERS = frozenset({"actions", "github"})


def _top_level_text(code: str) -> str | None:
    """``code`` with everything inside parentheses removed; None if unbalanced."""
    depth = 0
    kept: list[str] = []
    for char in code:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                return None
        elif depth == 0:
            kept.append(char)
    return "".join(kept) if depth == 0 else None


def is_boolean_expression(body: str) -> bool:
    """True if the ``${{ }}`` expression ``body`` can only produce true or false."""
    code = _STRING_LITERAL_RE.sub("''", body).strip()
    if "&&" in code or "||" in code:
        return False
    top = _top_level_text(code)
    if top is None:
        return False
    if code.startswith("!") or any(op in top for op in _COMPARISON_OPERATORS):
        return True
    # A single call such as startsWith(...): with the parenthesised arguments
    # removed, only the function name is left.
    return _BOOLEAN_FUNCTION_RE.fullmatch(top) is not None


def is_workflow_file(entry: FileEntry) -> bool:
    if not entry.path.startswith(WORKFLOW_DIR):
        return False
    rest = entry.path[len(WORKFLOW_DIR) :]
    return "/" not in rest and rest.lower().endswith((".yml", ".yaml"))


# --- small helpers for walking the YAML node tree ---------------------------


def _items(node: yaml.Node | None) -> list[tuple[str, yaml.Node]]:
    if not isinstance(node, yaml.MappingNode):
        return []
    return [(key.value, value) for key, value in node.value if isinstance(key, yaml.ScalarNode)]


def _get(node: yaml.Node | None, key: str) -> yaml.Node | None:
    for name, value in _items(node):
        if name == key:
            return value
    return None


def _scalar(node: yaml.Node | None) -> str | None:
    return node.value if isinstance(node, yaml.ScalarNode) else None


def _sequence(node: yaml.Node | None) -> list[yaml.Node]:
    return list(node.value) if isinstance(node, yaml.SequenceNode) else []


def _line_of(node: yaml.Node) -> int:
    return int(node.start_mark.line) + 1


def _line_containing(lines: list[str], node: yaml.Node, needle: str) -> int:
    """First line within ``node``'s source range containing ``needle``."""
    last = min(int(node.end_mark.line), len(lines) - 1)
    for index in range(int(node.start_mark.line), last + 1):
        if needle in lines[index]:
            return index + 1
    return _line_of(node)


def _triggers(root: yaml.Node) -> set[str]:
    on = _get(root, "on")
    if (single := _scalar(on)) is not None:
        return {single}
    if isinstance(on, yaml.SequenceNode):
        return {value for item in _sequence(on) if (value := _scalar(item)) is not None}
    return {name for name, _ in _items(on)}


_ANY_INDEX_RE = re.compile(_ANY_INDEX)


def normalise_context(matched: str) -> str:
    """The matched untrusted context with any array index replaced by ``[*]``.

    The index text (``commits[0]``, ``commits[x]``) comes from the repository,
    so it is removed; what remains is fixed by ``_UNTRUSTED_CONTEXT_RE``, which
    makes the result RepoSentinel vocabulary that is safe to use for identity.
    """
    return _ANY_INDEX_RE.sub("[*]", matched)


def mask_literals(expression: str) -> str:
    """Replace the content of quoted string literals in an expression with ``***``.

    Literals are free text written in the workflow and may contain a password
    in a format the credential patterns do not recognise, so evidence shows
    only that a literal is there.
    """
    return _STRING_LITERAL_RE.sub(lambda m: "''" if m.group() == "''" else "'***'", expression)


def _shorten(text: str, limit: int = 120) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def parse_workflow(text: str) -> yaml.Node | None:
    """Parse YAML into a node tree with the safe loader. Raises yaml.YAMLError."""
    node: yaml.Node | None = yaml.compose(text, Loader=yaml.SafeLoader)
    return node


# An alias (*name) reuses an anchored node without copying it, but the analysis
# visits that node again wherever an alias refers to it. Nested aliases multiply:
# a 30 KB file whose jobs alias one job whose steps alias one step took almost
# a minute and hundreds of MiB, and a 1 MiB file would never finish. So a
# workflow whose alias-expanded size is far larger than the file itself is not
# analysed. Ordinary reuse (GitHub Actions supports anchors) stays well within
# the allowance.
MAX_ALIAS_EXPANSION = 4  # times the size without repetition
ALIAS_EXPANSION_ALLOWANCE = 100_000  # always allowed, so small files may reuse freely


def _node_weight(node: yaml.Node) -> int:
    return 1 + len(node.value) if isinstance(node, yaml.ScalarNode) else 1


def _children(node: yaml.Node) -> list[yaml.Node]:
    if isinstance(node, yaml.MappingNode):
        return [part for pair in node.value for part in pair]
    if isinstance(node, yaml.SequenceNode):
        return list(node.value)
    return []


def alias_expansion_too_large(root: yaml.Node) -> bool:
    """True if expanding the aliases in ``root`` would make it far larger than it is.

    Size counts nodes plus the characters of scalar values. Both sizes are
    computed in time linear in the number of distinct nodes; a cycle (an alias
    inside the node it refers to) counts as too large.
    """
    distinct: dict[int, yaml.Node] = {}
    pending = [root]
    while pending:
        node = pending.pop()
        if id(node) not in distinct:
            distinct[id(node)] = node
            pending.extend(_children(node))
    limit = max(
        MAX_ALIAS_EXPANSION * sum(map(_node_weight, distinct.values())),
        ALIAS_EXPANSION_ALLOWANCE,
    )
    # Expanded size of every node, children first; sums stop growing past the
    # limit, so the numbers stay small however deep the aliases go.
    expanded: dict[int, int] = {}
    in_progress: set[int] = set()
    stack: list[tuple[yaml.Node, bool]] = [(root, False)]
    while stack:
        node, children_done = stack.pop()
        key = id(node)
        if children_done:
            in_progress.discard(key)
            total = _node_weight(node) + sum(expanded[id(c)] for c in _children(node))
            expanded[key] = min(total, limit + 1)
            continue
        if key in expanded:
            continue
        if key in in_progress:
            return True  # a cycle: infinite when expanded
        in_progress.add(key)
        stack.append((node, True))
        stack.extend((child, False) for child in _children(node) if id(child) not in expanded)
    return expanded[id(root)] > limit


_QUOTED_RE = re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"")


def describe_yaml_error(exc: Exception) -> str:
    """Line number and problem only; PyYAML's full message quotes file content.

    PyYAML's problem text can also quote content (an alias, tag or character,
    written with repr quotes), so quoted parts are replaced with '...'.
    """
    if isinstance(exc, RecursionError):
        return "YAML nesting is too deep to analyse"
    if isinstance(exc, yaml.MarkedYAMLError) and exc.problem_mark is not None:
        problem = _QUOTED_RE.sub("'...'", exc.problem or "")[:100]
        return f"invalid YAML at line {exc.problem_mark.line + 1}: {problem}"
    return "invalid YAML"


# --- what findings may say -----------------------------------------------------
#
# Finding summaries and evidence are built only from RepoSentinel's own
# vocabulary, positions and line numbers. Repository text (step names, job IDs,
# expressions, YAML values, action refs) is never copied into them: redaction
# patterns cannot recognise every credential, so text that is not needed is
# not shown at all. The file path and line number locate the finding.

_COMMON_BRANCHES = frozenset({"main", "master", "latest", "stable", "dev", "develop", "trunk"})
_VERSION_TAG_RE = re.compile(r"v?\d{1,6}(?:\.\d{1,6}){0,3}")
_PR_HEAD_LABELS = {
    "github.event.pull_request.head.": "github.event.pull_request.head.*",
    "github.event.pull_request.merge_commit_sha": "github.event.pull_request.merge_commit_sha",
    "github.head_ref": "github.head_ref",
    "refs/pull/": "refs/pull/*",
}


def _job_label(position: int) -> str:
    return f"Job {position}"


def _step_label(job_position: int, step_position: int) -> str:
    return f"Job {job_position}, step {step_position}"


def _expression_evidence(body: str, matched: str) -> str:
    """``${{ context }}``, or ``${{ ... context ... }}`` when the expression has more.

    ``matched`` is the untrusted context as found; only its normalised form
    (RepoSentinel vocabulary) is shown.
    """
    context = normalise_context(matched)
    if body.strip() == matched:
        return f"${{{{ {context} }}}}"
    return f"${{{{ ... {context} ... }}}}"


def _ref_label(ref: str) -> str:
    """A version tag or common branch name is shown; any other ref is not."""
    if _VERSION_TAG_RE.fullmatch(ref) or ref in _COMMON_BRANCHES:
        return ref
    return "<tag or branch not shown>"


class WorkflowCheck(Check):
    id = "github-actions"
    name = "GitHub Actions workflows"
    description = "Looks for selected unsafe patterns in .github/workflows/*.yml files."
    rules = RULES

    def run(self, context: ScanContext) -> CheckOutput:
        workflows = context.files_matching(is_workflow_file)
        if not workflows:
            return CheckOutput(
                message="no workflow files found in .github/workflows/", examined_paths=()
            )
        findings: list[Finding] = []
        examined: list[str] = []
        for entry in workflows:
            text = context.read_text(entry)
            if text is None:
                continue
            try:
                root = parse_workflow(text)
            except (yaml.YAMLError, RecursionError) as exc:
                context.record_issue(
                    entry.path, CoverageReason.UNPARSEABLE, describe_yaml_error(exc)
                )
                continue
            if root is None:
                examined.append(entry.path)  # empty file: examined, nothing to analyse
                continue
            if not isinstance(root, yaml.MappingNode):
                # Not analysed, so not counted as examined (it is a coverage issue).
                context.record_issue(
                    entry.path, CoverageReason.UNPARSEABLE, "top level is not a YAML mapping"
                )
                continue
            if alias_expansion_too_large(root):
                context.record_issue(
                    entry.path,
                    CoverageReason.UNPARSEABLE,
                    "YAML aliases repeat parts of this workflow so often that analysing it "
                    "would take too long; not analysed",
                )
                continue
            examined.append(entry.path)
            findings.extend(self._analyse(entry.path, text.split("\n"), root))
        return CheckOutput(
            findings=findings, examined=len(examined), examined_paths=tuple(examined)
        )

    def _analyse(self, path: str, lines: list[str], root: yaml.Node) -> Iterator[Finding]:
        triggers = _triggers(root)
        yield from self._check_permissions(path, root, "Workflow", scope="scope=workflow")

        for job_position, (job_id, job) in enumerate(_items(_get(root, "jobs")), start=1):
            # The job ID is a structural identifier; identity.py redacts it before
            # hashing. It is never shown: summaries use the job's position.
            job_identity = f"job={job_id}"
            job_label = _job_label(job_position)
            yield from self._check_permissions(path, job, job_label, scope=job_identity)
            uses = _get(job, "uses")  # a reusable workflow called by this job
            if uses is not None:
                yield from self._check_uses(path, uses, job_label)

            for index, step in enumerate(_sequence(_get(job, "steps")), start=1):
                where = _step_label(job_position, index)  # never the step's name
                step_uses_node = _get(step, "uses")
                step_uses = (_scalar(step_uses_node) or "").strip()
                action = step_uses.split("@", 1)[0].lower()

                if step_uses_node is not None:
                    yield from self._check_uses(path, step_uses_node, where)

                run = _get(step, "run")
                if run is not None:
                    yield from self._check_script(
                        path, lines, run, where, "shell script", (job_identity, "sink=run")
                    )
                if action == "actions/github-script":
                    script = _get(_get(step, "with"), "script")
                    if script is not None:
                        yield from self._check_script(
                            path,
                            lines,
                            script,
                            where,
                            "JavaScript",
                            (job_identity, "sink=github-script"),
                        )
                if action == "actions/checkout" and "pull_request_target" in triggers:
                    yield from self._check_pr_checkout(path, step, where, job_identity)

    def _check_script(
        self,
        path: str,
        lines: list[str],
        node: yaml.Node,
        where: str,
        language: str,
        identity: tuple[str, str],
    ) -> Iterator[Finding]:
        script = _scalar(node)
        if script is None:
            return
        job, sink = identity
        seen: set[str] = set()
        for match in _EXPRESSION_RE.finditer(script):
            untrusted = _UNTRUSTED_CONTEXT_RE.search(match.group("body"))
            if untrusted is None or match.group() in seen:
                continue
            if is_boolean_expression(match.group("body")):
                continue  # can only expand to "true" or "false"
            seen.add(match.group())
            # The matched context with any index replaced is RepoSentinel
            # vocabulary; the rest of the expression is repository text.
            context = normalise_context(untrusted.group())
            yield self.finding(
                SCRIPT_INJECTION,
                summary=f"{where}: {context} is expanded directly into a {language}.",
                evidence=_expression_evidence(match.group("body"), untrusted.group()),
                path=path,
                line=_line_containing(lines, node, match.group()),
                # Never the expression text: only the job, the normalised context
                # (RepoSentinel vocabulary) and the kind of script.
                identity=(job, "context=" + normalise_context(untrusted.group()), sink),
            )

    def _check_pr_checkout(
        self, path: str, step: yaml.Node, where: str, job_identity: str
    ) -> Iterator[Finding]:
        with_node = _get(step, "with")
        for key in ("ref", "repository"):
            node = _get(with_node, key)
            value = _scalar(node)
            head = _PR_HEAD_RE.search(value) if value else None
            if node is not None and head is not None:
                label = _PR_HEAD_LABELS.get(head.group().lower(), "the pull request head")
                yield self.finding(
                    PWN_REQUEST,
                    summary=f"{where}: workflow is triggered by pull_request_target and checks "
                    "out pull request code.",
                    evidence=f"{key}: refers to {label}",
                    path=path,
                    line=_line_of(node),
                    identity=(job_identity,),
                )
                return

    def _check_uses(self, path: str, node: yaml.Node, where: str) -> Iterator[Finding]:
        value = (_scalar(node) or "").strip()
        if value.startswith(("./", "docker://")):
            return
        match = _USES_RE.match(value)
        if match is None or match.group("owner").lower() in _FIRST_PARTY_OWNERS:
            return
        if _FULL_SHA_RE.match(match.group("ref")):
            return
        # owner/repo names the third-party code being run, so it is shown (it
        # can only contain letters, digits, '.', '_' and '-'); the ref only if
        # it is a version tag or a common branch name. Sub-paths are dropped.
        action_name = f"{match.group('owner')}/{match.group('repo')}"
        ref = _ref_label(match.group("ref"))
        yield self.finding(
            UNPINNED_ACTION,
            summary=f"{where}: {action_name} is referenced by a tag or branch, which can be "
            "moved, instead of a full commit SHA.",
            evidence=_shorten(f"uses: {action_name}@{ref}"),
            path=path,
            line=_line_of(node),
            # owner/repo is a structural identifier (GitHub treats it case-
            # insensitively); the ref is deliberately left out.
            identity=(f"action={match.group('owner')}/{match.group('repo')}".lower(),),
        )

    def _check_permissions(
        self, path: str, node: yaml.Node, where: str, *, scope: str
    ) -> Iterator[Finding]:
        permissions = _get(node, "permissions")
        if permissions is not None and _scalar(permissions) == "write-all":
            yield self.finding(
                WRITE_ALL_PERMISSIONS,
                summary=f"{where} grants the GITHUB_TOKEN write access to every scope.",
                evidence="permissions: write-all",
                path=path,
                line=_line_of(permissions),
                identity=(scope,),
            )
