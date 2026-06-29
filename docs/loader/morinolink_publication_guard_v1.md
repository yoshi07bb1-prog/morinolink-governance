# MorinoLink Publication Guard v1

This guard defines dry-run publication preparation only.

## Allowed in PR #44

- Generate draft text for Slack.
- Generate draft text for Teams.
- Read LATEST, BuildMemo, and Owner Cockpit inputs.
- Produce Executive Brief dry-run output to stdout or an explicit temporary output path.

## Not Allowed

- Send Slack messages.
- Post Teams messages.
- Create M365 / OneDrive files.
- Change runtime files.
- Run Gate3 or workflow dispatch.
- Change finance, IntegratedReport, or FullsetCache records.
- Claim AI final decision.

## Required Fields

- case_id
- owner_review_required
- owner_review_packet
- ai_final_decision=false
- full_autonomous_completion=false
- final_decision_owner=島田善信オーナー


## Validator Decisions

`validate_publication_guard.py` checks draft packets before Slack, Teams, or M365 publication steps. It does not send, post, create files, or change runtime state.

Decisions:

- `ALLOW_DRAFT`: draft-only packet is safe for Owner Review.
- `HOLD_SECRET`: credential-like material is detected.
- `HOLD_GUARD`: required owner/AI guard fields are missing or unsafe.
- `HOLD_CONFIDENTIAL`: prohibited confidential content marker is detected.

Slack and Teams remain draft-only. `teams_publish_allowed` must be false unless a later owner-approved publication step explicitly handles it outside this dry-run guard.


## Slack Owner Review Draft Board

`generate_slack_owner_review_draft.py` prepares Slack draft text for `HOLD`, `OWNER_REVIEW`, and `IMPORTANT_DONE` items only. It must pass Publication Guard validation and never sends messages.


## Teams and M365 Publication Drafts

`generate_teams_publication_draft.py` creates Teams draft text only. `generate_m365_publication_packet.py` creates a local/explicit-output publication packet only. Neither script posts to Teams or creates M365/OneDrive production files.
