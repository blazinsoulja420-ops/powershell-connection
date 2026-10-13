# Project Intake Engine — explicit commands + intelligent idea suggestions

**Candidate stage:** Proposal classification only. There is NO project or chat creation capability.
The existing 64-project limit stays unchanged.

## Intent and trust

The future central watcher manager accepts requests only from an authenticated
user-submission channel. It does not read all ChatGPT chats, screen-scrape
them, intercept other processes, or treat content from repo files, research,
web pages, comments, logs, or other AI outputs as owner commands.

Pipeline:

1. Submit: owner enters a single request into the local intake CLI or
   (later) a trusted authenticated dashboard/agent.
2. Classify: explicit new-project command, potential new-project idea,
   or no request. Conservative deterministic patterns reduce false positives.
3. Check: compare candidate project ID with current registered names and
   repository identities; flag possible duplicates. Enforce 64 max projects.
4. Propose: JSON status (PROPOSED_EXPLICIT, SUGGESTED_IDEA,
   REVIEW_EXISTING, CAPACITY_BLOCKED or NO_PROJECT_REQUEST). Proposed specialist
   chat workstreams are inert string labels, not created chats.
5. Owner review: owner confirms name, folder parent, project purpose,
   whether a Git repository is needed, and chat/workstream choices.
6. Trusted approval: a separate owner-authenticated, scope-bound local
   authorization step must validate current registry version, expiry, exact
   proposed paths, expected target absence, and replay protection.
7. Creation: only then may a separate protected Project Builder create
   allowed resources with auditable receipts and rollback planning.
8. Chat registration: prepare prompts and links. Use supported ChatGPT
   interfaces only where available; never equate API conversations with
   ordinary ChatGPT Project chats or assume access.

**Stages 5-8 are design requirements, NOT implementation.** A proposal ID is
a deterministic correlation identifier, not an approval token or signature.
There is no "approve", "create", or "execute" command in the current module.

## Example preview commands

From the UPAB repository checkout (Windows PowerShell, Python >= 3.11):

    $env:PYTHONPATH = ".\src"
    python -m upab.project_intake --registry .\config\multi-projects.example.json --text "Create a project called Motorcycle Diagnostic AI"

This emits a JSON proposal and changes no files. Example status:
PROPOSED_EXPLICIT, with creation_authorized=false.

    python -m upab.project_intake --registry .\config\multi-projects.example.json --text "I want to build an AI app that diagnoses motorcycles"

Returns SUGGESTED_IDEA, still without creation authorization.

    python -m upab.project_intake --registry .\config\multi-projects.example.json --text "Create a project called Poindexter"

Returns REVIEW_EXISTING and identifies the matching registered project.
Detection supports useful common phrasing but is not yet an LLM semantic
classifier. Unknown/unrecognized requests require manual intake; never guess
authority.

## Project name and security boundaries

- Untrusted input is capped at 500 characters and one line; it is never used
  as shell source. Proposed slugs are normalized and limited to 63 characters.
- No new project folders, no GitHub repository writes, no ChatGPT chat creation,
  no background monitoring or automation.
- No cross-project permissions, file writes, clipboard reads, elevated
  privileges, network requests or paid API calls.
- Existing five projects keep their private independent governance and paths.
- No silent dedupe guarantee against unknown disk folders or GitHub repositories:
  the candidate checks registered profiles only. Creation stage must
  separately inspect real disk/GitHub state before authorizing or modifying.
- Suggested chat workstreams are descriptive templates, NOT automatically
  created conversations.
- A proposal must never self-approve, including when text says "authorized".

## Acceptance gates for next stage

- Authenticated owner source and explicit approval separate from free text.
- Stale-approval rejection, nonce/replay, path/ACL and symlink/reparse checks.
- Reservation/locking for concurrent project creations; atomic registry update.
- Five-project and 64-project capacity regression tests.
- Duplicate detection beyond exact profile IDs, without deleting existing work.
- Read-only preview of all planned filesystem/repository/chat changes.
- Windows dry-run, failure injection and recovery before any live creation.

This component is independent from the v2 transactional relay-ledger draft
PR #2. No merging or activation based solely on proposal-classification tests.
