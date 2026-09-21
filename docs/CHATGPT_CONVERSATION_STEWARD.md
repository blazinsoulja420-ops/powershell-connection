# ChatGPT Conversation Steward

This package extends UPAB with a recommendation-only conversation stewardship layer.

## Goals

1. Observe or import ChatGPT conversation/message data through an authorized supported source.
2. Analyze the newest message and propose the strongest next-best reply.
3. Classify chats against known project identities.
4. Detect duplicate or overlapping chat knowledge and produce merge candidates.
5. Recommend correct project folder placement and canonical chat/folder names.
6. Preserve unique requirements, decisions, evidence, unresolved conflicts, and provenance during consolidation.

## Safety boundary

The initial implementation is **recommendation-only** for replies and **plan-only** for rename/move/merge/archive operations.

It does not:
- scrape ChatGPT credentials or private browser state;
- bypass ChatGPT access controls;
- auto-send replies;
- rename, move, merge, archive, or delete ChatGPT conversations;
- infer that access to a UI or message source grants mutation authority.

A supported ChatGPT conversation source/connector must provide the data. Any future mutation feature requires explicit capability discovery, authorization, target resolution, preflight validation, and postcondition verification.

## Cleanup workflow

DISCOVER → CLASSIFY → IDENTIFY DUPLICATES → EXTRACT UNIQUE KNOWLEDGE → PROPOSE MERGE → RESOLVE PROJECT → PROPOSE TITLE/FOLDER → REVIEW → APPLY (only when explicitly authorized and technically supported) → VERIFY

Do not merge by title similarity alone. Semantic overlap must be checked and unique content preserved.
