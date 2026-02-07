"""Tests for parsing.py changes - direct import to avoid circular imports."""
import sys
import json

# Import directly from the module files to avoid circular dependency
from state import LLMDecision, OutputAnalysis, ExtractedTargetInfo
from orchestrator_helpers.json_utils import extract_json
from orchestrator_helpers.parsing import _normalize_extracted_info, try_parse_llm_decision, parse_llm_decision

def test_normalize_services_dicts():
    extracted = {
        "services": [
            {"port": 22, "protocol": "tcp", "service_name": "ssh", "product_version": None},
            {"port": 8080, "protocol": "tcp", "service_name": "http-proxy", "product_version": None}
        ]
    }
    _normalize_extracted_info(extracted)
    expected = ["ssh/22/tcp", "http-proxy/8080/tcp"]
    assert extracted["services"] == expected, f"Got: {extracted[services]}"
    print("PASS: test_normalize_services_dicts")

def test_normalize_services_strings():
    extracted = {"services": ["ssh", "http"]}
    _normalize_extracted_info(extracted)
    assert extracted["services"] == ["ssh", "http"]
    print("PASS: test_normalize_services_strings")

def test_normalize_services_mixed():
    extracted = {"services": ["ftp", {"service_name": "ssh", "port": 22}]}
    _normalize_extracted_info(extracted)
    expected = ["ftp", "ssh/22"]
    assert extracted["services"] == expected, f"Got: {extracted[services]}"
    print("PASS: test_normalize_services_mixed")

def test_normalize_sessions_strings():
    extracted = {"sessions": ["Session 1 opened", "3", 5]}
    _normalize_extracted_info(extracted)
    assert extracted["sessions"] == [1, 3, 5], f"Got: {extracted[sessions]}"
    print("PASS: test_normalize_sessions_strings")

def test_try_parse_valid_json():
    valid_json = json.dumps({"thought": "t", "reasoning": "r", "action": "use_tool", "tool_name": "naabu", "tool_args": {"target": "1.2.3.4"}, "updated_todo_list": []})
    decision, error = try_parse_llm_decision(valid_json)
    assert decision is not None, f"Expected decision, got error: {error}"
    assert error is None
    assert decision.action == "use_tool"
    assert decision.tool_name == "naabu"
    print("PASS: test_try_parse_valid_json")

def test_try_parse_malformed_json():
    decision, error = try_parse_llm_decision("{invalid json")
    assert decision is None
    assert "Invalid JSON" in error
    print("PASS: test_try_parse_malformed_json")

def test_try_parse_no_json():
    decision, error = try_parse_llm_decision("Just text no JSON")
    assert decision is None
    assert "No JSON" in error
    print("PASS: test_try_parse_no_json")

def test_try_parse_pydantic_validation_error():
    bad = json.dumps({"thought": "t", "reasoning": "r", "action": "invalid_action", "updated_todo_list": []})
    decision, error = try_parse_llm_decision(bad)
    assert decision is None
    assert "Validation error" in error
    print("PASS: test_try_parse_pydantic_validation_error")

def test_bug_scenario_services_as_dicts():
    response = json.dumps({
        "output_analysis": {
            "interpretation": "Found services",
            "extracted_info": {
                "primary_target": "15.160.68.117",
                "ports": [22, 8080],
                "services": [
                    {"port": 22, "protocol": "tcp", "service_name": "ssh", "product_version": None},
                    {"port": 8080, "protocol": "tcp", "service_name": "http-proxy", "product_version": None}
                ]
            },
            "actionable_findings": ["SSH open"],
            "recommended_next_steps": ["Brute force"],
            "exploit_succeeded": False,
            "exploit_details": None
        },
        "thought": "found services",
        "reasoning": "graph shows SSH",
        "action": "transition_phase",
        "phase_transition": {"to_phase": "exploitation", "reason": "run brute force", "planned_actions": ["ssh_login"], "risks": ["lockout"]},
        "updated_todo_list": [{"id": "1", "description": "Run SSH bf", "status": "pending", "priority": "high"}]
    })
    decision, error = try_parse_llm_decision(response)
    assert decision is not None, f"BUG STILL PRESENT - got error: {error}"
    assert error is None
    assert decision.action == "transition_phase"
    services = decision.output_analysis.extracted_info.services
    expected = ["ssh/22/tcp", "http-proxy/8080/tcp"]
    assert services == expected, f"Got: {services}"
    print("PASS: test_bug_scenario_services_as_dicts (THE ORIGINAL BUG)")

def test_backward_compat():
    decision = parse_llm_decision("no json")
    assert decision.action == "complete"
    print("PASS: test_backward_compat")

def test_empty_nested_objects():
    response = json.dumps({"thought": "t", "reasoning": "r", "action": "use_tool", "tool_name": "naabu", "tool_args": {}, "phase_transition": {}, "user_question": {}, "output_analysis": {}, "updated_todo_list": []})
    decision, error = try_parse_llm_decision(response)
    assert decision is not None, f"Got error: {error}"
    assert decision.phase_transition is None
    assert decision.user_question is None
    assert decision.output_analysis is None
    print("PASS: test_empty_nested_objects")

if __name__ == "__main__":
    test_normalize_services_dicts()
    test_normalize_services_strings()
    test_normalize_services_mixed()
    test_normalize_sessions_strings()
    test_try_parse_valid_json()
    test_try_parse_malformed_json()
    test_try_parse_no_json()
    test_try_parse_pydantic_validation_error()
    test_bug_scenario_services_as_dicts()
    test_backward_compat()
    test_empty_nested_objects()
    print("\nAll 11 tests passed!")
