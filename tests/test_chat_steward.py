from upab.chat_steward import ChatMessage, build_cleanup_plan, classify_chat, suggest_next_reply


def test_next_reply_is_recommendation_only_continuation():
    msg = ChatMessage(
        chat_id="c1",
        message_id="m1",
        role="assistant",
        content="Latest work completed. Next step is assurance.",
    )
    result = suggest_next_reply(msg)
    assert result.chat_id == "c1"
    assert "latest verified checkpoint" in result.reply
    assert result.confidence == "INFERRED"


def test_chat_classification_prefers_matching_project_aliases():
    known = {
        "UP-RES-001": ["Autonomous Research System", "UARS", "research"],
        "RAID-AI": ["RAID AI", "RAID: Shadow Legends"],
    }
    result = classify_chat(
        chat_id="c2",
        title="UARS research orchestration",
        content="continue autonomous research system",
        known_projects=known,
    )
    assert result.project_id == "UP-RES-001"
    assert result.suggested_folder == "UP-RES-001"


def test_cleanup_plan_never_authorizes_destructive_actions():
    item = classify_chat(
        chat_id="c3",
        title="RAID AI",
        content="RAID AI popup handling",
        known_projects={"RAID-AI": ["RAID AI"]},
    )
    plan = build_cleanup_plan([item], duplicate_groups={"g1": ["c3", "c4"]})
    assert plan.destructive_actions_authorized is False
    assert plan.classifications[0].merge_with_chat_ids == ("c4",)
    assert any("Plan only" in warning for warning in plan.warnings)
