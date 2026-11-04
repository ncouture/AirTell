# Project Workflow

## Guiding Principles

1.  **The Plan is the Source of Truth:** All work must be tracked in `plan.md`
2.  **The Tech Stack is Deliberate:** Changes to the tech stack must be
    documented in `tech-stack.md` *before* implementation
3.  **Test-Driven Development:** Write unit tests before implementing
    functionality
4.  **High Code Coverage:** Aim for >80% code coverage for all modules
5.  **User Experience First:** Every decision should prioritize user experience
6.  **Non-Interactive & CI-Aware:** Prefer non-interactive commands. Use
    `CI=true` for watch-mode tools (tests, linters) to ensure single execution.

## Task Workflow

All tasks follow a strict lifecycle:

### Standard Task Workflow

1.  **Select Task:** Choose the next available task from `plan.md` in sequential
    order

2.  **Mark In Progress:** Before beginning work, edit `plan.md` and change the
    task from `[ ]` to `[~]`

3.  **Write Failing Tests (Red Phase):**

    -   Create a new test file for the feature or bug fix.
    -   Write one or more unit tests that clearly define the expected behavior
        and acceptance criteria for the task.
    -   **CRITICAL:** Run the tests and confirm that they fail as expected. This
        is the "Red" phase of TDD. Do not proceed until you have failing tests.

4.  **Implement to Pass Tests (Green Phase):**

    -   Write the minimum amount of application code necessary to make the
        failing tests pass.
    -   Run the test suite again and confirm that all tests now pass. This is
        the "Green" phase.

5.  **Refactor (Optional but Recommended):**

    -   With the safety of passing tests, refactor the implementation code and
        the test code to improve clarity, remove duplication, and enhance
        performance without changing the external behavior.
    -   Rerun tests to ensure they still pass after refactoring.

6.  **Verify Coverage:** Run coverage reports using the project's chosen tools.
    For example, in a Python project, this might look like: `bash pytest
    --cov=app --cov-report=html` Target: >80% coverage for new code. The
    specific tools and commands will vary by language and framework.

7.  **Document Deviations:** If implementation differs from tech stack:

    -   **STOP** implementation
    -   Update `tech-stack.md` with new design
    -   Add dated note explaining the change
    -   Resume implementation

8.  **Commit Code Changes:**

    -   Stage all code changes related to the task.
    -   Propose a clear, concise commit message following Conventional Commits, e.g.,
        `feat(telemetry): Add sliding-window heuristic evaluation for anti-stalking tracker`.
    -   Perform the commit.

9.  **Get and Record Task Commit SHA:**

    -   **Step 9.1: Update Plan:** Read `plan.md`, find the line for the
        completed task, update its status from `[~]` to `[x]`, and append the
        first 7 characters of the *just-completed commit's* commit hash.
    -   **Step 9.2: Write Plan:** Write the updated content back to `plan.md`.

10. **Commit Plan Update:**

    -   **Action:** Stage the modified `plan.md` file.
    -   **Action:** Commit this change with a descriptive message (e.g.,
        `conductor(plan): Mark task 'Create user model' as complete`).

### Task Correction & Plan Amendment Workflows

When an implemented task or phase requires corrections, amendments, or additions, follow these standard workflows to maintain plan integrity and avoid untracked code drift:

1.  **In-Flight Refinements:** If minor gaps are found while a task is actively
    in-progress (`[~]`), make the adjustments directly in the active
    implementation stream and ensure passing tests before committing.
2.  **Code Review Corrections (`conductor-review`):** If issues are identified
    during or after a code review, instruct the agent to review your changes
    (e.g., *"run a review"* or triggering the action manually in compatible
    clients). The review agent will automatically append a `Review Fixes` phase
    to `plan.md` so that correction tasks are formally tracked and
    checkpointed.
3.  **Logical State Reversions (`conductor-revert`):** If a task implementation
    is fundamentally flawed or needs to be redone, instruct the agent to revert
    the changes (e.g., *"revert the last task"* or triggering the action
    manually in compatible clients). This safely rolls back associated git
    commits and resets the task state in `plan.md` back to pending `[ ]` to
    allow a clean restart.

### Phase Completion Verification and Checkpointing Protocol

**Trigger:** This protocol is executed immediately after a task is completed
that also concludes a phase in `plan.md`.

1.  **Announce Protocol Start:** Inform the user that the phase is complete and
    the verification and checkpointing protocol has begun.

2.  **Ensure Test Coverage for Phase Changes:**

    -   **Step 2.1: Determine Phase Scope:** To identify the files changed in
        this phase, you must first find the starting point. Read `plan.md` to
        find the Git commit SHA of the *previous* phase's checkpoint. If no
        previous checkpoint exists, the scope is all changes since the first
        commit.
    -   **Step 2.2: List Changed Files:** Execute `git diff --name-only
        <previous_checkpoint_sha> HEAD` to get a precise list of all files
        modified during this phase.
    -   **Step 2.3: Verify and Create Tests:** For each file in the list:
        -   **CRITICAL:** First, check its extension. Exclude non-code files
            (e.g., `.json`, `.md`, `.yaml`).
        -   For each remaining code file, verify a corresponding test file
            exists.
        -   If a test file is missing, you **must** create one. Before writing
            the test, **first, analyze other test files in the repository to
            determine the correct naming convention and testing style.** The new
            tests **must** validate the functionality described in this phase's
            tasks (`plan.md`).

3.  **Execute Automated Tests with Proactive Debugging:**

    -   Before execution, you **must** announce the exact shell command you will
        use to run the tests.
    -   **Example Announcement:** "I will now run the automated test suite to
        verify the phase. **Command:** `uv run pytest`"
    -   Execute the announced command.
    -   If tests fail, you **must** inform the user and begin debugging. You may
        attempt to propose a fix a **maximum of two times**. If the tests still
        fail after your second proposed fix, you **must stop**, report the
        persistent failure, and ask the user for guidance.

4.  **Propose a Detailed, Actionable Manual Verification Plan:**

    -   **CRITICAL:** To generate the plan, first analyze `product.md`,
        `product-guidelines.md`, and `plan.md` to determine the user-facing
        goals of the completed phase.
    -   You **must** generate a step-by-step plan that walks the user through
        the verification process, including any necessary commands and specific,
        expected outcomes.
    -   The plan you present to the user **must** follow this format:

        **For a Frontend / Dashboard Change:** ``` The automated tests have passed. For
        manual verification, please follow these steps:

        **Manual Verification Steps:** 1. **Start the Streamlit dashboard with
        the command:** `streamlit run app/streamlit_app.py` 2. **Open your browser to:**
        `http://localhost:8501` 3. **Confirm that you see:** The tactical BLE
        telemetry views and controls updating cleanly. ```

        **For a Backend / CLI Change:** ``` The automated tests have passed. For
        manual verification, please follow these steps:

        **Manual Verification Steps:** 1. **Ensure your environment is active.** 2.
        **Execute the following command in your terminal:** `python3 -m airtell.cli --help`
        or `python3 -m airtell.cli topology-a --mock` 3. **Confirm that you receive:**
        A clean exit code 0 and expected telemetry output. ```

5.  **Await Explicit User Feedback:**

    -   After presenting the detailed plan, ask the user for confirmation:
        "**Does this meet your expectations? Please confirm with yes or provide
        feedback on what needs to be changed.**"
    -   **PAUSE** and await the user's response. Do not proceed without an
        explicit yes or confirmation.

6.  **Identify Target Commit for Report:**

    -   Do NOT create a new empty commit for checkpointing.
    -   Identify the hash of the last functional commit made during this phase. This will be the target for the verification report.

7.  **Record Phase Verification Report:**

    -   **Step 7.1: Draft Report Content:** Create a detailed verification report
        including the automated test command, the manual verification steps, and
        the user's confirmation.
    -   **Step 7.2: Record Report:** Document the verification report in the phase summary.

8.  **Get and Record Phase Checkpoint SHA:**

    -   **Step 8.1: Get Commit Hash:** Obtain the hash of the *just-created
        checkpoint commit* (`git log -1 --format="%H"`).
    -   **Step 8.2: Update Plan:** Read `plan.md`, find the heading for the
        completed phase, and append the first 7 characters of the commit hash in
        the format `[checkpoint: <sha>]`.
    -   **Step 8.3: Write Plan:** Write the updated content back to `plan.md`.

9.  **Commit Plan Update:**

    -   **Action:** Stage the modified `plan.md` file.
    -   **Action:** Commit this change with a descriptive message following the
        format `conductor(plan): Mark phase '<PHASE NAME>' as complete`.

10. **Announce Completion:** Inform the user that the phase is complete and the
    checkpoint has been created.

### Quality Gates

Before marking any task complete, verify:

-   [ ] All tests pass
-   [ ] Code coverage meets requirements (>80%)
-   [ ] Code follows project's code style guidelines (as defined in
    `code_styleguides/`)
-   [ ] All public functions/methods are documented (e.g., docstrings)
-   [ ] Type safety is enforced (e.g., Python type hints)
-   [ ] No linting or static analysis errors (using ruff check)
-   [ ] Hardware / radio simulation tests pass (e.g., VirtualRadioBus, packet decoders)
-   [ ] Documentation updated if needed
-   [ ] No security vulnerabilities introduced

## Development Commands

### Setup

```bash
# Virtual environment setup
python3 -m venv .venv && source .venv/bin/activate
pip install -e .[test]

# Or with uv:
uv sync
```

### Daily Development

```bash
# Run pytest test suite
uv run pytest -v tests/

# Run linter
uv run ruff check .

# Run tactical Streamlit dashboard
streamlit run app/streamlit_app.py

# Run AirTell CLI
python3 -m airtell.cli --help
```

### Before Committing

```bash
# Full regression test run
uv run pytest tests/ --ignore=tests/benchmarks

# Lint validation across codebase
uv run ruff check .
```

## Testing Requirements

### Unit Testing

-   Every module must have corresponding tests.
-   Use appropriate test setup/teardown mechanisms (e.g., fixtures,
    beforeEach/afterEach).
-   Mock external dependencies.
-   Test both success and failure cases.

### Integration Testing

-   Test complete user flows
-   Verify database transactions
-   Test authentication and authorization
-   Check form submissions

### Hardware & Simulation Testing

-   Test against `VirtualRadioBus` mock interfaces for zero-device verification
-   Validate dual CC2652P serial dongles (`/dev/ttyUSB0` & `/dev/ttyUSB1`) when hardware is present
-   Verify multi-channel capture, hopping sequence, and PCAP output integrity
-   Verify Streamlit tactical telemetry rendering and WebSocket/queue bridges

## Code Review Process

### Self-Review Checklist

Before requesting review:

1.  **Functionality**

    -   Feature works as specified
    -   Edge cases handled
    -   Error messages are user-friendly

2.  **Code Quality**

    -   Follows style guide
    -   DRY principle applied
    -   Clear variable/function names
    -   Appropriate comments

3.  **Testing**

    -   Unit tests comprehensive
    -   Integration tests pass
    -   Coverage adequate (>80%)

4.  **Security**

    -   No hardcoded secrets
    -   Input validation present
    -   SQL injection prevented
    -   XSS protection in place

5.  **Performance**

    -   Database queries optimized
    -   Images optimized
    -   Caching implemented where needed

6.  **Telemetry & Hardware Experience**

    -   Streamlit tactical UI renders cleanly without layout overflow
    -   RSSI charts, radar tomographic heatmaps, and threat lists refresh smoothly
    -   Serial communication handles disconnects and re-enumerations gracefully

## Commit Guidelines

### Message Format

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

-   `feat`: New feature
-   `fix`: Bug fix
-   `docs`: Documentation only
-   `style`: Formatting, missing semicolons, etc.
-   `refactor`: Code change that neither fixes a bug nor adds a feature
-   `test`: Adding missing tests
-   `chore`: Maintenance tasks

### Examples

```bash
git commit -m "feat(telemetry): Add sliding-window heuristic evaluation for anti-stalking tracker"
git commit -m "fix(extcap): Prevent subprocess deadlock on unconsumed stderr in tshark runner"
git commit -m "test(dissector): Add unit tests for Apple Find My payload unpacking"
git commit -m "refactor(storage): Implement DatabaseBackend abstraction protocol for DuckDB"
```

## Definition of Done

A task is complete when:

1.  All code implemented to specification
2.  Unit tests written and passing
3.  Code coverage meets project requirements
4.  Documentation complete (if applicable)
5.  Code passes all configured linting and static analysis checks
6.  Hardware & simulation verification passes (if applicable)
7.  Implementation notes added to `plan.md`
8.  Changes committed with proper message

## Emergency Procedures

### Critical Bug in Production

1.  Create hotfix branch from main
2.  Write failing test for bug
3.  Implement minimal fix
4.  Test thoroughly with automated test suite and simulation
5.  Deploy immediately
6.  Document in plan.md

### Data Loss

1.  Stop all write operations
2.  Restore from latest backup
3.  Verify data integrity
4.  Document incident
5.  Update backup procedures

### Security Breach

1.  Rotate all secrets immediately
2.  Review access logs
3.  Patch vulnerability
4.  Notify affected users (if any)
5.  Document and update security procedures

## Deployment Workflow

### Pre-Deployment Checklist

-   [ ] All tests passing
-   [ ] Coverage >80%
-   [ ] No linting errors
-   [ ] Hardware / simulation test validation complete
-   [ ] Environment variables configured
-   [ ] Database migrations ready
-   [ ] Backup created

### Deployment Steps

1.  Merge feature branch to main
2.  Tag release with version
3.  Push to deployment service
4.  Run database migrations
5.  Verify deployment
6.  Test critical paths
7.  Monitor for errors

### Post-Deployment

1.  Monitor analytics
2.  Check error logs
3.  Gather user feedback
4.  Plan next iteration

## Continuous Improvement

-   Review workflow weekly
-   Update based on pain points
-   Document lessons learned
-   Optimize for user happiness
-   Keep things simple and maintainable
