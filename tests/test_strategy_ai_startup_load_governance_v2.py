import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_json(path: str):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def test_strategy_personality_requires_startup_system_state_load():
    data = load_json("strategy_agent/keieisenryaku_personality.json")
    protocol = data["startup_system_state_load_protocol"]

    assert data["persona_meta"]["persona_version"] == "2026-06-29-strategy-v2.0.0-startup-system-state-aware"
    assert "strategy_ai_startup_load_contract_v2" in data["persona_meta"]["expected_load_order"]
    assert "morinolink_current_system_state" in data["persona_meta"]["expected_load_order"]
    assert "スタート" in protocol["trigger_phrases"]
    assert protocol["fixed_boundaries"]["ai_final_decision"] is False
    assert protocol["fixed_boundaries"]["full_autonomous_completion"] is False
    assert protocol["fixed_boundaries"]["final_decision_owner"] == "島田善信オーナー"
    assert "strategy_ai_startup_load_contract_v2.md" in protocol["runtime_contract"]["contract_url"]
    assert "yoshi07bb1-prog/morinolink-governance/main/docs/loader" in protocol["runtime_contract"]["contract_url"]


def test_gpts_load_contract_strategy_agent_startup_rule():
    data = load_json("master_core/GPTs_load_contract.json")
    levels = [item["name"] for item in data["global_priority_order"]]
    rule = data["agent_specific_rules"]["strategy_agent"]["startup_load_required"]

    assert "MorinoLink Current System State Startup Contract" in levels
    assert rule["enabled"] is True
    assert "スタート" in rule["trigger_phrases"]
    assert rule["required_output_boundaries"]["ai_final_decision"] is False
    assert rule["required_output_boundaries"]["full_autonomous_completion"] is False
    assert rule["required_output_boundaries"]["final_decision_owner"] == "島田善信オーナー"


def test_action_schema_exposes_runtime_startup_contract_v2():
    text = (ROOT / "gpts_action_schemas/strategy_loader_4personality_openapi.yaml").read_text(encoding="utf-8")

    assert "7.0-STARTUP-SYSTEM-STATE-LOAD-V2" in text
    assert "loadStrategyStartupSystemStateContractV2" in text
    assert "loadStrategyStartupSystemStateSchemaV2" in text
    assert "loadStrategyStartupResponseTemplateV2" in text
    assert "/yoshi07bb1-prog/morinolink-governance/main/docs/loader/strategy_ai_startup_load_contract_v2.md" in text
    assert "/yoshi07bb1-prog/morinolink-governance/main/docs/loader/morinolink_common_safety_gate_schema.json" in text
    assert "/refs/heads/" not in text
    assert "raw.githubusercontent.com" in text


def test_docs_loader_mirrors_updated_json_files():
    assert load_json("docs/loader/strategy_personality.json") == load_json("strategy_agent/keieisenryaku_personality.json")
    assert load_json("docs/loader/GPTs_load_contract.json") == load_json("master_core/GPTs_load_contract.json")
    assert (ROOT / "docs/loader/strategy_ai_startup_load_contract_v2.md").exists()
    assert (ROOT / "docs/loader/strategy_ai_startup_load_contract_v2_schema.json").exists()
    assert (ROOT / "docs/loader/strategy_ai_startup_response_template.json").exists()
    assert (ROOT / "docs/loader/morinolink_common_safety_gate_schema.json").exists()
    assert (ROOT / "docs/loader/morinolink_publication_guard_v1.md").exists()
