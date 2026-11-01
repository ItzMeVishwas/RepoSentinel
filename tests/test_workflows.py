"""GitHub Actions rules RS-GHA-001 to RS-GHA-004 and workflow parsing."""

from __future__ import annotations

import textwrap
import time

import pytest

from reposentinel.models import CheckStatus, CoverageReason, Finding, Outcome
from tests import synthetic
from tests.conftest import RepoFactory
from tests.helpers import scan

SHA = "0123456789abcdef0123456789abcdef01234567"


def workflow_findings(make_repo: RepoFactory, workflow: str, name: str = "ci.yml") -> list[Finding]:
    report = scan(make_repo({f".github/workflows/{name}": textwrap.dedent(workflow)}))
    return [f for f in report.findings if f.check_id == "github-actions"]


def ids(findings: list[Finding]) -> list[str]:
    return [f.rule_id for f in findings]


# --- RS-GHA-001 script injection ----------------------------------------------


def test_untrusted_input_in_block_run_script(make_repo: RepoFactory) -> None:
    findings = workflow_findings(
        make_repo,
        """\
        on: issues
        jobs:
          greet:
            runs-on: ubuntu-latest
            steps:
              - name: Greet
                run: |
                  echo "hello"
                  echo "${{ github.event.issue.title }}"
        """,
    )
    (finding,) = findings
    assert finding.rule_id == "RS-GHA-001"
    assert finding.line == 9  # the exact line inside the block scalar
    assert finding.evidence == "${{ github.event.issue.title }}"
    # Positions, never the job ID or step name (repository text).
    assert finding.summary.startswith("Job 1, step 1: ")
    assert "greet" not in finding.summary.lower()


def test_untrusted_input_in_single_line_run(make_repo: RepoFactory) -> None:
    findings = workflow_findings(
        make_repo,
        """\
        on: pull_request
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: echo ${{ github.head_ref }}
        """,
    )
    assert [(f.rule_id, f.line) for f in findings] == [("RS-GHA-001", 6)]


@pytest.mark.parametrize(
    "expression",
    [
        "github.event.pull_request.title",
        "github.event.pull_request.body",
        "github.event.comment.body",
        "github.event.review.body",
        "github.event.discussion.title",
        "github.event.head_commit.message",
        "github.event.head_commit.author.email",
        "github.event.commits[0].message",
        "github.event.commits.*.author.name",
        "github.event.pages[0].page_name",
        "github.event.pull_request.head.ref",
        "github.event.pull_request.head.label",
        "github.event.workflow_run.head_branch",
        "format('x {0}', github.event.issue.body)",
    ],
)
def test_untrusted_contexts(make_repo: RepoFactory, expression: str) -> None:
    workflow = f"""\
    on: issue_comment
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - run: echo "${{{{ {expression} }}}}"
    """
    assert ids(workflow_findings(make_repo, workflow)) == ["RS-GHA-001"]


@pytest.mark.parametrize(
    "expression",
    [
        "github.sha",
        "github.event.issue.number",
        "github.event.pull_request.head.sha",
        "secrets.DEPLOY_KEY",
        "github.event.issue.title_prefix_is_not_a_real_field",
    ],
)
def test_trusted_contexts_are_not_reported(make_repo: RepoFactory, expression: str) -> None:
    workflow = f"""\
    on: push
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - run: echo "${{{{ {expression} }}}}"
    """
    assert workflow_findings(make_repo, workflow) == []


def test_environment_variable_indirection_is_safe(make_repo: RepoFactory) -> None:
    findings = workflow_findings(
        make_repo,
        """\
        on: issues
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - env:
                  TITLE: ${{ github.event.issue.title }}
                run: echo "$TITLE"
              - if: contains(github.event.issue.title, 'bug')
                run: echo bug
        """,
    )
    assert findings == []


def test_untrusted_input_in_github_script(make_repo: RepoFactory) -> None:
    findings = workflow_findings(
        make_repo,
        f"""\
        on: issues
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/github-script@{SHA}
                with:
                  script: |
                    console.log("${{{{ github.event.issue.body }}}}")
        """,
    )
    (finding,) = findings
    assert finding.rule_id == "RS-GHA-001"
    assert "JavaScript" in finding.summary
    assert finding.line == 9


def test_same_expression_twice_in_one_step_is_reported_once(make_repo: RepoFactory) -> None:
    findings = workflow_findings(
        make_repo,
        """\
        on: issues
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  echo "${{ github.event.issue.title }}"
                  echo "${{ github.event.issue.title }}"
        """,
    )
    assert len(findings) == 1


# --- RS-GHA-002 pull_request_target ---------------------------------------------

PR_TARGET_CHECKOUT = """\
on: {trigger}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: {ref}
      - run: npm install && npm test
"""


@pytest.mark.parametrize(
    "trigger", ["pull_request_target", "[push, pull_request_target]", "{pull_request_target: {}}"]
)
@pytest.mark.parametrize(
    "ref",
    [
        "${{ github.event.pull_request.head.sha }}",
        "${{ github.event.pull_request.head.ref }}",
        "${{ github.head_ref }}",
        "refs/pull/${{ github.event.number }}/merge",
    ],
)
def test_pull_request_target_with_head_checkout(
    make_repo: RepoFactory, trigger: str, ref: str
) -> None:
    findings = workflow_findings(make_repo, PR_TARGET_CHECKOUT.format(trigger=trigger, ref=ref))
    (finding,) = [f for f in findings if f.rule_id == "RS-GHA-002"]
    assert finding.line == 8


def test_pull_request_target_checkout_of_fork_repository(make_repo: RepoFactory) -> None:
    findings = workflow_findings(
        make_repo,
        """\
        on: pull_request_target
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  repository: ${{ github.event.pull_request.head.repo.full_name }}
        """,
    )
    assert ids(findings) == ["RS-GHA-002"]


def test_pull_request_trigger_with_head_checkout_is_not_reported(make_repo: RepoFactory) -> None:
    workflow = PR_TARGET_CHECKOUT.format(
        trigger="pull_request", ref="${{ github.event.pull_request.head.sha }}"
    )
    assert workflow_findings(make_repo, workflow) == []


def test_pull_request_target_with_default_checkout_is_not_reported(
    make_repo: RepoFactory,
) -> None:
    findings = workflow_findings(
        make_repo,
        """\
        on: pull_request_target
        jobs:
          label:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
        """,
    )
    assert findings == []


# --- RS-GHA-003 unpinned actions --------------------------------------------------


def test_third_party_action_by_tag(make_repo: RepoFactory) -> None:
    findings = workflow_findings(
        make_repo,
        """\
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - uses: some-org/deploy-action@v2
              - uses: some-org/monorepo/sub/path@main
        """,
    )
    assert [(f.rule_id, f.line, f.evidence) for f in findings] == [
        ("RS-GHA-003", 7, "uses: some-org/deploy-action@v2"),
        ("RS-GHA-003", 8, "uses: some-org/monorepo@main"),  # sub-path not shown
    ]


@pytest.mark.parametrize(
    "uses",
    [
        f"some-org/deploy-action@{SHA}",
        f"some-org/deploy-action@{SHA.upper()}",
        "actions/setup-python@v5",
        "github/codeql-action/init@v3",
        "./.github/actions/local",
        "docker://alpine:3.20",
    ],
)
def test_pinned_first_party_local_and_docker_actions_are_not_reported(
    make_repo: RepoFactory, uses: str
) -> None:
    workflow = f"""\
    on: push
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - uses: {uses}
    """
    assert workflow_findings(make_repo, workflow) == []


def test_reusable_workflow_by_tag(make_repo: RepoFactory) -> None:
    findings = workflow_findings(
        make_repo,
        """\
        on: push
        jobs:
          call:
            uses: some-org/shared/.github/workflows/build.yml@v1
          local:
            uses: ./.github/workflows/local.yml
        """,
    )
    assert [(f.rule_id, f.line) for f in findings] == [("RS-GHA-003", 4)]
    assert findings[0].summary.startswith("Job 1: ")


# --- RS-GHA-004 permissions ------------------------------------------------------


def test_write_all_at_workflow_and_job_level(make_repo: RepoFactory) -> None:
    findings = workflow_findings(
        make_repo,
        """\
        on: push
        permissions: write-all
        jobs:
          a:
            runs-on: ubuntu-latest
            permissions: write-all
            steps:
              - run: echo hi
          b:
            runs-on: ubuntu-latest
            permissions:
              contents: read
            steps:
              - run: echo hi
        """,
    )
    assert [(f.rule_id, f.line) for f in findings] == [("RS-GHA-004", 2), ("RS-GHA-004", 6)]


@pytest.mark.parametrize("value", ["read-all", "{}", "{contents: write}"])
def test_other_permission_values_are_not_reported(make_repo: RepoFactory, value: str) -> None:
    workflow = f"on: push\npermissions: {value}\njobs: {{}}\n"
    assert workflow_findings(make_repo, workflow) == []


# --- parsing, scope and robustness ------------------------------------------------


def test_no_workflows_completes_with_a_note(make_repo: RepoFactory) -> None:
    report = scan(make_repo({"README.md": "# x"}))
    (result,) = [c for c in report.checks if c.check_id == "github-actions"]
    assert result.status is CheckStatus.COMPLETED
    assert result.examined == 0
    assert "no workflow files" in result.message


def test_only_top_level_workflow_files_are_analysed(make_repo: RepoFactory) -> None:
    bad = "on: push\npermissions: write-all\njobs: {}\n"
    report = scan(
        make_repo(
            {
                ".github/workflows/real.yaml": bad,
                ".github/workflows/nested/ignored.yml": bad,
                ".github/workflows/notes.txt": bad,
                "ci/workflow.yml": bad,
            }
        )
    )
    assert [(f.rule_id, f.path) for f in report.findings] == [
        ("RS-GHA-004", ".github/workflows/real.yaml")
    ]


def test_malformed_yaml_is_recorded_without_quoting_content(make_repo: RepoFactory) -> None:
    # The broken line contains a fake token; the error message must not repeat it.
    broken = f"on: push\njobs:\n  a: [unclosed, {synthetic.GITHUB_TOKEN}\n"
    report = scan(make_repo({".github/workflows/broken.yml": broken}))
    (issue,) = [i for i in report.coverage if i.reason is CoverageReason.UNPARSEABLE]
    assert issue.path == ".github/workflows/broken.yml"
    assert issue.detail.startswith("invalid YAML at line")
    assert synthetic.GITHUB_TOKEN not in issue.detail
    assert report.outcome is Outcome.INCOMPLETE  # an unanalysed workflow is not a pass


def test_non_mapping_workflow_is_unparseable(make_repo: RepoFactory) -> None:
    report = scan(make_repo({".github/workflows/list.yml": "- just\n- a list\n"}))
    assert [i.detail for i in report.coverage] == ["top level is not a YAML mapping"]


def test_empty_workflow_file_is_not_an_error(make_repo: RepoFactory) -> None:
    report = scan(make_repo({".github/workflows/empty.yml": ""}))
    assert report.coverage == ()
    assert report.outcome is Outcome.CLEAN


def test_multiple_documents_are_unparseable(make_repo: RepoFactory) -> None:
    report = scan(make_repo({".github/workflows/multi.yml": "on: push\n---\non: pull_request\n"}))
    assert [i.reason for i in report.coverage] == [CoverageReason.UNPARSEABLE]


def test_deeply_nested_yaml_does_not_crash(make_repo: RepoFactory) -> None:
    depth = 5000
    report = scan(make_repo({".github/workflows/deep.yml": "x: " + "[" * depth + "]" * depth}))
    (result,) = [c for c in report.checks if c.check_id == "github-actions"]
    assert result.status is CheckStatus.COMPLETED
    assert [i.reason for i in report.coverage] == [CoverageReason.UNPARSEABLE]


def test_yaml_aliases_do_not_cause_repeated_work(make_repo: RepoFactory) -> None:
    # Many jobs sharing one anchored step list: findings are de-duplicated and
    # parsing stays fast because aliases are shared nodes, not copies.
    jobs = "\n".join(f"  job{i}: *job" for i in range(200))
    workflow = (
        "on: issues\n"
        "x-template: &job\n"
        "  runs-on: ubuntu-latest\n"
        "  steps:\n"
        '    - run: echo "${{ github.event.issue.title }}"\n'
        f"jobs:\n{jobs}\n"
    )
    started = time.perf_counter()
    report = scan(make_repo({".github/workflows/anchors.yml": workflow}))
    assert time.perf_counter() - started < 10
    assert [f.rule_id for f in report.findings] == ["RS-GHA-001"]


def test_on_key_is_not_confused_with_boolean(make_repo: RepoFactory) -> None:
    # YAML 1.1 reads a bare `on` key as True; the node-based parser keeps "on".
    workflow = PR_TARGET_CHECKOUT.format(
        trigger="pull_request_target", ref="${{ github.head_ref }}"
    ).replace("on:", '"on":', 1)
    assert "RS-GHA-002" in ids(workflow_findings(make_repo, workflow))


# --- regressions found in the October 2026 security audit --------------------


@pytest.mark.parametrize(
    "expression",
    [
        "startsWith(github.head_ref, 'release/')",
        "contains(github.event.pull_request.title, '[skip ci]')",
        "github.event.issue.title == 'bug'",
        "!github.event.issue.body",
        "endsWith(github.head_ref, '-rc') == false",
    ],
)
def test_boolean_only_expressions_are_not_injection(
    make_repo: RepoFactory, expression: str
) -> None:
    workflow = f"""\
    on: pull_request
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - run: echo "${{{{ {expression} }}}}"
    """
    assert workflow_findings(make_repo, workflow) == []


@pytest.mark.parametrize(
    "expression",
    [
        "github.event.issue.title == 'x' && github.event.issue.title",  # && returns an operand
        "github.event.issue.title || 'default'",
        "format('{0} == {1}', github.event.issue.title, 'x')",  # '==' only inside a string
        "format('{0}', github.event.issue.title == 'x', github.event.issue.body)",
        "toJSON(github.event.issue.title)",
    ],
)
def test_text_producing_expressions_are_still_reported(
    make_repo: RepoFactory, expression: str
) -> None:
    workflow = f"""\
    on: issues
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - run: echo "${{{{ {expression} }}}}"
    """
    assert ids(workflow_findings(make_repo, workflow)) == ["RS-GHA-001"]


@pytest.mark.parametrize(
    "expression",
    [
        "github.event.workflow_run.display_title",
        "github.event.workflow_run.pull_requests[0].head.ref",
    ],
)
def test_workflow_run_untrusted_contexts(make_repo: RepoFactory, expression: str) -> None:
    workflow = f"""\
    on: workflow_run
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - run: echo "${{{{ {expression} }}}}"
    """
    assert ids(workflow_findings(make_repo, workflow)) == ["RS-GHA-001"]


def test_pull_request_target_checkout_of_merge_commit(make_repo: RepoFactory) -> None:
    workflow = PR_TARGET_CHECKOUT.format(
        trigger="pull_request_target", ref="${{ github.event.pull_request.merge_commit_sha }}"
    )
    assert "RS-GHA-002" in ids(workflow_findings(make_repo, workflow))


def test_pull_request_target_checkout_of_base_sha_is_not_reported(make_repo: RepoFactory) -> None:
    workflow = PR_TARGET_CHECKOUT.format(
        trigger="pull_request_target", ref="${{ github.event.pull_request.base.sha }}"
    )
    assert workflow_findings(make_repo, workflow) == []
