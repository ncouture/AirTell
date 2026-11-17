"""Comprehensive test suite for the ARIEL neurosymbolic logical entailment privacy engine.

Covers Contextual Integrity 5-tuple request models, strict Pydantic v2 ontology validation,
Definition 4.1 partial order (<=_O), Definition 4.2 entailment rules, Algorithm 1 single-parameter
neighborhood (d <= 1) soundness, contradictory prior abstention, dynamic social role ("housemate")
memory anchoring, SPA and Education domain benchmarks, and memory-size ablations.
"""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError

import pytest
from pydantic import ValidationError

from airtell.ariel import (
    CI_PARAMETERS,
    AdaptiveMemoryAnchoredMapper,
    ARIELSolver,
    DecisionLabel,
    EntailmentProof,
    EntailmentResult,
    GeneralCINormsBaseline,
    InformationFlowRequest,
    LightweightEdgeOntologyMapper,
    OntologySchema,
    OntologySet,
    ParameterMappingSchema,
    ParameterOntology,
    PriorDecisionRecord,
    SimulatedICLBaseline,
    StructuredOntologyMapper,
    UserDecisionMemory,
    build_education_benchmark,
    build_education_ontology,
    build_ontology_prompt,
    build_spa_benchmark,
    build_spa_ontology,
    check_entailment_rule_1,
    check_entailment_rule_2,
    compute_evaluation_metrics,
    is_less_or_equal,
    level_to_rank,
    parse_validated_ontology_json,
    parse_validated_parameter_mapping_json,
    rank_to_level,
    run_memory_ablation,
)

# ---------------------------------------------------------------------------
# 1. Models & CI 5-Tuple Tests
# ---------------------------------------------------------------------------


class TestARIELModels:
    """Tests for DecisionLabel, InformationFlowRequest, PriorDecisionRecord, and UserDecisionMemory."""

    def test_decision_labels_and_ci_parameters(self) -> None:
        """Verify exact enum values and Contextual Integrity 5-tuple parameter names."""
        assert DecisionLabel.APPROPRIATE.value == "appropriate"
        assert DecisionLabel.INAPPROPRIATE.value == "inappropriate"
        assert DecisionLabel.UNDETERMINED.value == "undetermined"
        assert CI_PARAMETERS == (
            "data_type",
            "data_subject",
            "data_sender",
            "data_recipient",
            "transmission_principle",
        )

    def test_information_flow_request_immutability_and_distances(self) -> None:
        """Verify frozen 5-tuple request, dictionary serialization, and Hamming distance."""
        req_a = InformationFlowRequest(
            data_type="partial SSN",
            data_subject="user",
            data_sender="assistant provider",
            data_recipient="bank",
            transmission_principle="with requirement of confidentiality",
        )
        req_b = req_a.with_parameter("data_recipient", "hospital")
        req_c = InformationFlowRequest(
            data_type="full SSN",
            data_subject="user",
            data_sender="assistant provider",
            data_recipient="hospital",
            transmission_principle="with requirement of confidentiality",
        )

        with pytest.raises(FrozenInstanceError):
            req_a.data_type = "mutated"  # type: ignore[misc]

        as_dict = req_a.as_dict()
        assert tuple(as_dict.keys()) == CI_PARAMETERS
        assert as_dict["data_recipient"] == "bank"
        assert req_a.as_tuple() == (
            "partial SSN",
            "user",
            "assistant provider",
            "bank",
            "with requirement of confidentiality",
        )
        assert req_a.get_parameter("data_sender") == "assistant provider"

        assert req_a.hamming_distance(req_a) == 0
        assert req_a.differing_parameters(req_a) == []

        assert req_a.hamming_distance(req_b) == 1
        assert req_a.differing_parameters(req_b) == [("data_recipient", "bank", "hospital")]

        assert req_a.hamming_distance(req_c) == 2
        assert req_a.differing_parameters(req_c) == [
            ("data_type", "partial SSN", "full SSN"),
            ("data_recipient", "bank", "hospital"),
        ]

    def test_information_flow_request_validation_errors(self) -> None:
        """Reject empty strings, unknown parameter names, and non-request comparisons."""
        with pytest.raises(ValueError, match="data_type"):
            InformationFlowRequest(
                data_type="   ",
                data_subject="user",
                data_sender="assistant provider",
                data_recipient="bank",
                transmission_principle="with subject's consent",
            )

        valid = InformationFlowRequest(
            data_type="calendar availability",
            data_subject="user",
            data_sender="assistant provider",
            data_recipient="bank",
            transmission_principle="with subject's consent",
        )
        with pytest.raises(ValueError, match="Unknown CI parameter"):
            valid.get_parameter("invalid_param")
        with pytest.raises(ValueError, match="Unknown CI parameter"):
            valid.with_parameter("invalid_param", "val")
        with pytest.raises(TypeError):
            valid.hamming_distance("not_a_request")  # type: ignore[arg-type]

    def test_prior_decision_record_and_memory_operations(self) -> None:
        """Verify PriorDecisionRecord rejects UNDETERMINED and UserDecisionMemory slices/filters."""
        req_base = InformationFlowRequest(
            data_type="course grades",
            data_subject="student",
            data_sender="professor",
            data_recipient="department chair",
            transmission_principle="with requirement of confidentiality",
        )
        rec_ok = PriorDecisionRecord(request=req_base, label=DecisionLabel.APPROPRIATE)
        assert rec_ok.label is DecisionLabel.APPROPRIATE

        with pytest.raises(ValueError, match="UNDETERMINED|APPROPRIATE or INAPPROPRIATE"):
            PriorDecisionRecord(request=req_base, label=DecisionLabel.UNDETERMINED)

        with pytest.raises(TypeError):
            PriorDecisionRecord(request="bad", label=DecisionLabel.APPROPRIATE)  # type: ignore[arg-type]

        memory = UserDecisionMemory(user_id="student-01")
        memory.add_record(rec_ok)
        req_d1 = req_base.with_parameter("data_recipient", "parents")
        req_d2 = req_d1.with_parameter("data_sender", "TA")
        memory.add_record(req_d1, DecisionLabel.INAPPROPRIATE)
        memory.add_record(req_d2, DecisionLabel.INAPPROPRIATE)

        assert len(memory) == 3
        neighbors_d1 = memory.neighbors(req_base, max_distance=1)
        assert len(neighbors_d1) == 2
        assert all(r.request.hamming_distance(req_base) <= 1 for r in neighbors_d1)

        sliced = memory.slice_memory(2)
        assert len(sliced) == 2
        assert len(memory) == 3  # original memory untouched

        with pytest.raises(ValueError):
            memory.neighbors(req_base, max_distance=-1)
        with pytest.raises(ValueError):
            memory.slice_memory(-1)
        with pytest.raises(ValueError):
            UserDecisionMemory(user_id="")


# ---------------------------------------------------------------------------
# 2. Ontology Validation & Partial Order (Definition 4.1) Tests
# ---------------------------------------------------------------------------


class TestOntologyAndPartialOrder:
    """Tests for strict Pydantic JSON schema validation and Definition 4.1 partial order."""

    def test_level_rank_conversions(self) -> None:
        """Verify L1..Lk conversions and rejection of malformed ranks."""
        assert level_to_rank("L1") == 1
        assert level_to_rank("L12") == 12
        assert level_to_rank(3) == 3
        assert rank_to_level(1) == "L1"
        assert rank_to_level(5) == "L5"

        for bad in ("L0", "L-1", "level1", "", True, 0, -2):
            with pytest.raises((ValueError, TypeError)):
                level_to_rank(bad)  # type: ignore[arg-type]
        with pytest.raises((ValueError, TypeError)):
            rank_to_level(0)
        with pytest.raises((ValueError, TypeError)):
            rank_to_level(True)  # type: ignore[arg-type]

    def test_strict_json_validation_and_anti_hallucination(self) -> None:
        """Verify OntologySchema rejects extra keys, bad levels, duplicates, and hallucinations."""
        valid_payload = {
            "domain": "SPA_Mini",
            "parameters": {
                "data_type": {
                    "L1": ["public weather forecast"],
                    "L2": ["partial SSN"],
                    "L3": ["full SSN"],
                },
                "data_recipient": {
                    "L1": ["bank"],
                    "L2": ["hospital"],
                    "L3": ["advertising agency"],
                },
            },
        }
        raw_json = json.dumps(valid_payload)
        ontology_set = parse_validated_ontology_json(
            raw_json,
            allowed_entities={
                "data_type": ["public weather forecast", "partial SSN", "full SSN"],
                "data_recipient": ["bank", "hospital", "advertising agency"],
            },
            require_all_allowed=True,
        )
        assert ontology_set.domain == "SPA_Mini"
        assert ontology_set.get_rank("data_type", "partial SSN") == 2
        assert ontology_set.get_rank("data_recipient", "advertising agency") == 3

        # 1. Extra unexpected field rejected
        bad_extra = dict(valid_payload, unexpected_key="hallucinated")
        with pytest.raises(ValidationError):
            OntologySchema.model_validate_json(json.dumps(bad_extra))

        # 2. Unknown CI parameter rejected
        bad_param = {"domain": "SPA", "parameters": {"unknown_ci_slot": {"L1": ["foo"]}}}
        with pytest.raises(ValidationError):
            parse_validated_ontology_json(json.dumps(bad_param))

        # 3. Invalid level label ("L0" or "High") rejected
        bad_level = {"domain": "SPA", "parameters": {"data_type": {"L0": ["public weather forecast"]}}}
        with pytest.raises(ValidationError):
            parse_validated_ontology_json(json.dumps(bad_level))

        # 4. Duplicate entity assigned to two levels rejected
        bad_dup = {
            "domain": "SPA",
            "parameters": {
                "data_type": {
                    "L1": ["partial SSN"],
                    "L2": ["partial SSN"],
                }
            },
        }
        with pytest.raises(ValidationError):
            parse_validated_ontology_json(json.dumps(bad_dup))

        # 5. Hallucinated entity outside allowed_entities rejected
        with pytest.raises(ValidationError):
            parse_validated_ontology_json(
                raw_json,
                allowed_entities={
                    "data_type": ["public weather forecast", "partial SSN"],  # "full SSN" disallowed
                    "data_recipient": ["bank", "hospital", "advertising agency"],
                },
            )

        # 6. Missing required entity when require_all_allowed=True rejected
        with pytest.raises(ValidationError):
            parse_validated_ontology_json(
                raw_json,
                allowed_entities={
                    "data_type": ["public weather forecast", "partial SSN", "full SSN", "biometrics"],
                    "data_recipient": ["bank", "hospital", "advertising agency"],
                },
                require_all_allowed=True,
            )

    def test_parameter_mapping_schema_and_prompt_builder(self) -> None:
        """Verify strict validation of single-parameter edge level mappings and prompt builder."""
        prompt = build_ontology_prompt(
            domain="Education",
            candidate_entities={
                "data_recipient": ["department chair", "parents", "advertising agencies"],
            },
            prior_feedback=["Keep institutional leadership at L1."],
        )
        assert "Education" in prompt
        assert "department chair" in prompt
        assert "Keep institutional leadership at L1." in prompt

        valid_map_json = json.dumps(
            {
                "parameter": "data_recipient",
                "value": "parents",
                "level": "L3",
            }
        )
        parsed = parse_validated_parameter_mapping_json(valid_map_json)
        assert isinstance(parsed, ParameterMappingSchema)
        assert parsed.rank == 3

        with pytest.raises(ValidationError):
            parse_validated_parameter_mapping_json(
                json.dumps({"parameter": "data_recipient", "value": "parents", "level": "LEVEL_3"})
            )

    def test_definition_4_1_partial_order_properties(self) -> None:
        """Verify reflexivity, transitivity, anti-symmetry on ranks, and False on unmapped/incomparable."""
        ontology = build_spa_ontology()
        mapper = StructuredOntologyMapper()

        r1 = InformationFlowRequest(
            data_type="public weather forecast",
            data_subject="user",
            data_sender="assistant provider",
            data_recipient="device owner",
            transmission_principle="with subject's consent",
        )
        r2 = r1.with_parameter("data_type", "partial SSN")
        r3 = r2.with_parameter("data_recipient", "advertising agency")

        # Reflexivity (even with an unmapped custom subject if equal on both sides)
        r_custom_subj = r1.with_parameter("data_subject", "custom_guest_profile")
        assert is_less_or_equal(r_custom_subj, r_custom_subj, ontology, mapper) is True

        # Monotonic chain r1 <=_O r2 <=_O r3 => r1 <=_O r3
        assert is_less_or_equal(r1, r2, ontology, mapper) is True
        assert is_less_or_equal(r2, r1, ontology, mapper) is False
        assert is_less_or_equal(r2, r3, ontology, mapper) is True
        assert is_less_or_equal(r1, r3, ontology, mapper) is True
        assert is_less_or_equal(r3, r1, ontology, mapper) is False

        # Incomparable trade-off: higher data_type sensitivity, lower recipient risk
        r_high_data_low_recip = r1.with_parameter("data_type", "full SSN")
        r_low_data_high_recip = r1.with_parameter("data_recipient", "advertising agency")
        assert is_less_or_equal(r_high_data_low_recip, r_low_data_high_recip, ontology, mapper) is False
        assert is_less_or_equal(r_low_data_high_recip, r_high_data_low_recip, ontology, mapper) is False

        # Unmapped entity when p_left != p_right must return False in both directions
        r_unmapped = r1.with_parameter("data_recipient", "unknown_drone_relay")
        assert is_less_or_equal(r1, r_unmapped, ontology, mapper) is False
        assert is_less_or_equal(r_unmapped, r1, ontology, mapper) is False


# ---------------------------------------------------------------------------
# 3. Entailment Rules (Def 4.2), Algorithm 1 & Soundness Counterexample Tests
# ---------------------------------------------------------------------------


class TestARIELSolverAndSoundness:
    """Tests for Definition 4.2 entailment rules, Algorithm 1, d <= 1 soundness, and abstentions."""

    def test_definition_4_2_rule_1_and_rule_2_directions(self) -> None:
        """Verify Rule 1 (inappropriate upward) and Rule 2 (appropriate downward) without false converse."""
        ontology = build_education_ontology()
        mapper = StructuredOntologyMapper()
        solver = ARIELSolver(ontology_set=ontology, mapper=mapper)

        base_grades_parents = InformationFlowRequest(
            data_type="course grades",
            data_subject="student",
            data_sender="professor",
            data_recipient="parents",
            transmission_principle="with requirement of confidentiality",
        )
        prior_inapp = PriorDecisionRecord(base_grades_parents, DecisionLabel.INAPPROPRIATE)

        # Higher risk recipient (advertising agencies, L5 >= L3): Rule 1 entails INAPPROPRIATE
        to_ads = base_grades_parents.with_parameter("data_recipient", "advertising agencies")
        assert check_entailment_rule_1(prior_inapp, to_ads, ontology, mapper) is True
        assert check_entailment_rule_2(prior_inapp, to_ads, ontology, mapper) is False

        # Lower risk recipient (department chair, L1 <= L3): Rule 1 MUST NOT fire (non-entailed boundary!)
        to_chair = base_grades_parents.with_parameter("data_recipient", "department chair")
        assert check_entailment_rule_1(prior_inapp, to_chair, ontology, mapper) is False

        mem_inapp = UserDecisionMemory(user_id="stu-1", records=[prior_inapp])
        res_ads = solver.evaluate(to_ads, mem_inapp)
        assert res_ads.label is DecisionLabel.INAPPROPRIATE
        assert res_ads.proof.c_minus == 1
        assert res_ads.proof.c_plus == 0
        assert res_ads.proof.abstention_reason is None
        assert res_ads.proof.escalate_to_user is False

        res_chair = solver.evaluate(to_chair, mem_inapp)
        assert res_chair.label is DecisionLabel.UNDETERMINED
        assert res_chair.proof.abstention_reason == "non_entailed_boundary"
        assert res_chair.proof.escalate_to_user is True

        # Rule 2: prior APPROPRIATE for parents (L3) entails APPROPRIATE for department chair (L1 <= L3),
        # but abstains for advertising agencies (L5 > L3)
        prior_app = PriorDecisionRecord(base_grades_parents, DecisionLabel.APPROPRIATE)
        mem_app = UserDecisionMemory(user_id="stu-2", records=[prior_app])

        assert check_entailment_rule_2(prior_app, to_chair, ontology, mapper) is True
        assert check_entailment_rule_2(prior_app, to_ads, ontology, mapper) is False

        res_chair_app = solver.evaluate(to_chair, mem_app)
        assert res_chair_app.label is DecisionLabel.APPROPRIATE
        assert res_chair_app.proof.c_plus == 1
        assert res_chair_app.proof.c_minus == 0
        assert res_chair_app.proof.escalate_to_user is False

        res_ads_app = solver.evaluate(to_ads, mem_app)
        assert res_ads_app.label is DecisionLabel.UNDETERMINED
        assert res_ads_app.proof.abstention_reason == "non_entailed_boundary"
        assert res_ads_app.proof.escalate_to_user is True

    def test_single_parameter_soundness_counterexample_ssn_bank_vs_hospital(self) -> None:
        """Verify d <= 1 rejects multi-parameter jump ('partial SSN'+'bank' vs 'full SSN'+'hospital')."""
        ontology = build_spa_ontology()
        mapper = StructuredOntologyMapper()
        solver = ARIELSolver(ontology_set=ontology, mapper=mapper)

        r_partial_bank = InformationFlowRequest(
            data_type="partial SSN",
            data_subject="user",
            data_sender="assistant provider",
            data_recipient="bank",
            transmission_principle="with requirement of confidentiality",
        )
        r_full_hospital = InformationFlowRequest(
            data_type="full SSN",
            data_subject="user",
            data_sender="assistant provider",
            data_recipient="hospital",
            transmission_principle="with requirement of confidentiality",
        )

        # Componentwise partial order holds (partial SSN <= full SSN and bank <= hospital),
        # yet two CI parameters shift simultaneously (Hamming distance d == 2).
        assert r_partial_bank.hamming_distance(r_full_hospital) == 2
        assert is_less_or_equal(r_partial_bank, r_full_hospital, ontology, mapper) is True

        # Direction A: Prior says (partial SSN, bank) is INAPPROPRIATE, but user may legitimately
        # allow (full SSN, hospital) for medical admission billing; d <= 1 blocks unsound Rule 1 leap.
        mem_bank_denied = UserDecisionMemory(
            user_id="u-ssn-1",
            records=[PriorDecisionRecord(r_partial_bank, DecisionLabel.INAPPROPRIATE)],
        )
        res_hospital = solver.evaluate(r_full_hospital, mem_bank_denied)
        assert res_hospital.label is DecisionLabel.UNDETERMINED
        assert res_hospital.proof.neighbors_checked == 0
        assert res_hospital.proof.abstention_reason == "empty_neighborhood"
        assert res_hospital.proof.escalate_to_user is True

        # Direction B: Prior says (full SSN, hospital) is APPROPRIATE; d <= 1 blocks unsound Rule 2 leap
        # that would otherwise authorize sharing partial SSN with a bank.
        mem_hospital_allowed = UserDecisionMemory(
            user_id="u-ssn-2",
            records=[PriorDecisionRecord(r_full_hospital, DecisionLabel.APPROPRIATE)],
        )
        res_bank = solver.evaluate(r_partial_bank, mem_hospital_allowed)
        assert res_bank.label is DecisionLabel.UNDETERMINED
        assert res_bank.proof.neighbors_checked == 0
        assert res_bank.proof.abstention_reason == "empty_neighborhood"
        assert res_bank.proof.escalate_to_user is True

        # Single-parameter transition (d == 1) within the SAME recipient context remains active & sound:
        r_partial_hospital = r_full_hospital.with_parameter("data_type", "partial SSN")
        assert r_partial_hospital.hamming_distance(r_full_hospital) == 1
        res_partial_hospital = solver.evaluate(r_partial_hospital, mem_hospital_allowed)
        assert res_partial_hospital.label is DecisionLabel.APPROPRIATE
        assert res_partial_hospital.proof.c_plus == 1

    def test_contradictory_priors_abstention_and_escalation(self) -> None:
        """Verify c+ > 0 and c- > 0 halts automation with 'contradictory_priors' and escalate_to_user=True."""
        ontology = build_education_ontology()
        solver = ARIELSolver(ontology_set=ontology)

        # Incoming flow at L3 recipient ("parents")
        incoming = InformationFlowRequest(
            data_type="course grades",
            data_subject="student",
            data_sender="professor",
            data_recipient="parents",
            transmission_principle="with requirement of confidentiality",
        )
        # Prior 1: L4 ("classmates") marked APPROPRIATE => entails L3 ("parents") APPROPRIATE (c+ = 1)
        prior_permissive = PriorDecisionRecord(
            incoming.with_parameter("data_recipient", "classmates"),
            DecisionLabel.APPROPRIATE,
        )
        # Prior 2: L2 ("graduate schools") marked INAPPROPRIATE => entails L3 ("parents") INAPPROPRIATE (c- = 1)
        prior_restrictive = PriorDecisionRecord(
            incoming.with_parameter("data_recipient", "graduate schools"),
            DecisionLabel.INAPPROPRIATE,
        )

        memory = UserDecisionMemory(user_id="stu-conflict", records=[prior_permissive, prior_restrictive])
        result: EntailmentResult = solver.evaluate(incoming, memory)
        proof: EntailmentProof = result.proof

        assert result.label is DecisionLabel.UNDETERMINED
        assert proof.c_plus == 1
        assert proof.c_minus == 1
        assert proof.neighbors_checked == 2
        assert len(proof.entailed_steps) == 2
        assert proof.abstention_reason == "contradictory_priors"
        assert proof.escalate_to_user is True


# ---------------------------------------------------------------------------
# 4. Dynamic Role ("housemate") Anchoring & Ontology Alignment Tests
# ---------------------------------------------------------------------------


class TestDynamicRoleHousemateAnchoring:
    """Tests for AdaptiveMemoryAnchoredMapper mitigating Ontology Hierarchy Misalignment."""

    def test_misaligned_static_housemate_anchored_to_user_memory(self) -> None:
        """Verify 'housemate' misaligned at L2 is blocked when unanchored and re-ranked from D_u."""
        # Construct a misaligned ontology that places "housemate" alongside "family member" at L2,
        # below "close friend" (L3) and "work colleague" (L4).
        base_spa = build_spa_ontology()
        misaligned_ontology = base_spa.with_updated_rank("data_recipient", "housemate", 2)

        req_friend_gps = InformationFlowRequest(
            data_type="exact GPS location",
            data_subject="user",
            data_sender="assistant provider",
            data_recipient="close friend",
            transmission_principle="with requirement of confidentiality",
        )
        req_housemate_gps = req_friend_gps.with_parameter("data_recipient", "housemate")

        # Without anchoring, StructuredOntologyMapper trusts static L2 <= L3 and falsely entails APPROPRIATE!
        cold_memory = UserDecisionMemory(
            user_id="u-apt",
            records=[PriorDecisionRecord(req_friend_gps, DecisionLabel.APPROPRIATE)],
        )
        naive_solver = ARIELSolver(misaligned_ontology, StructuredOntologyMapper())
        assert naive_solver.evaluate(req_housemate_gps, cold_memory).label is DecisionLabel.APPROPRIATE

        # Step 1: With zero "housemate" evidence in D_u, AdaptiveMemoryAnchoredMapper treats dynamic role
        # "housemate" as unanchored -> abstains safely instead of leaking GPS to housemate!
        anchored_cold_mapper = AdaptiveMemoryAnchoredMapper(memory=cold_memory)
        anchored_solver_cold = ARIELSolver(misaligned_ontology, anchored_cold_mapper)
        cold_verdict = anchored_solver_cold.evaluate(req_housemate_gps, cold_memory)
        assert cold_verdict.label is DecisionLabel.UNDETERMINED
        assert cold_verdict.proof.abstention_reason == "non_entailed_boundary"

        # Step 2: Historical D_u shows user approved calendar availability for "close friend" (L3),
        # DENIED calendar availability for "housemate", and DENIED smart home status? Wait:
        # user APPROVED smart home device status for "housemate" while DENYING it for "advertising agency" (L5).
        # This bounds rank("housemate") in [4, 4] => L4!
        cal_friend = InformationFlowRequest(
            data_type="calendar availability",
            data_subject="user",
            data_sender="assistant provider",
            data_recipient="close friend",
            transmission_principle="with requirement of confidentiality",
        )
        cal_housemate = cal_friend.with_parameter("data_recipient", "housemate")
        home_housemate = cal_housemate.with_parameter("data_type", "smart home device status")
        home_ads = home_housemate.with_parameter("data_recipient", "advertising agency")

        rich_memory = UserDecisionMemory(
            user_id="u-apt",
            records=[
                PriorDecisionRecord(req_friend_gps, DecisionLabel.APPROPRIATE),
                PriorDecisionRecord(cal_friend, DecisionLabel.APPROPRIATE),
                PriorDecisionRecord(cal_housemate, DecisionLabel.INAPPROPRIATE),
                PriorDecisionRecord(home_housemate, DecisionLabel.APPROPRIATE),
                PriorDecisionRecord(home_ads, DecisionLabel.INAPPROPRIATE),
            ],
        )
        anchored_mapper = AdaptiveMemoryAnchoredMapper(memory=rich_memory)
        assert anchored_mapper.map_parameter(misaligned_ontology, "data_recipient", "housemate") == 4

        # Now on incoming GPS request for "housemate":
        # - Close friend GPS (L3, APPROPRIATE) no longer entails housemate (L4 > L3)!
        # - Calendar housemate (L2 data_type, INAPPROPRIATE) entails GPS housemate (L3 data_type, d == 1) INAPPROPRIATE!
        anchored_solver = ARIELSolver(misaligned_ontology, anchored_mapper)
        warm_verdict = anchored_solver.evaluate(req_housemate_gps, rich_memory)
        assert warm_verdict.label is DecisionLabel.INAPPROPRIATE
        assert warm_verdict.proof.c_minus >= 1
        assert warm_verdict.proof.c_plus == 0

        # Also works when "housemate" was completely absent from the static SPA ontology!
        assert base_spa.get_rank("data_recipient", "housemate") is None
        assert anchored_mapper.map_parameter(base_spa, "data_recipient", "housemate") == 4

        # Iterative ontology tuning exports an updated OntologySet with anchored ranks
        tuned_ontology = anchored_mapper.build_tuned_ontology(
            base_spa,
            candidate_values={"data_recipient": ["housemate"]},
        )
        assert tuned_ontology.get_rank("data_recipient", "housemate") == 4

    def test_inconsistent_dynamic_role_bounds_abstain_safely(self) -> None:
        """If user memory implies contradictory bounds (lower_bound > upper_bound), return None."""
        ontology = build_spa_ontology()
        cal_base = InformationFlowRequest(
            data_type="calendar availability",
            data_subject="user",
            data_sender="assistant provider",
            data_recipient="family member",  # L2
            transmission_principle="with subject's consent",
        )
        # "housemate" APPROPRIATE where L4 ("work colleague") INAPPROPRIATE => rank <= 3
        # AND "housemate" INAPPROPRIATE where L4 ("work colleague") APPROPRIATE on lower sensitivity => rank >= 5
        home_base = cal_base.with_parameter("data_type", "smart home device status")
        contradictory_mem = UserDecisionMemory(
            user_id="u-inconsistent",
            records=[
                PriorDecisionRecord(
                    cal_base.with_parameter("data_recipient", "work colleague"),
                    DecisionLabel.INAPPROPRIATE,
                ),
                PriorDecisionRecord(
                    cal_base.with_parameter("data_recipient", "housemate"),
                    DecisionLabel.APPROPRIATE,
                ),
                PriorDecisionRecord(
                    home_base.with_parameter("data_recipient", "work colleague"),
                    DecisionLabel.APPROPRIATE,
                ),
                PriorDecisionRecord(
                    home_base.with_parameter("data_recipient", "housemate"),
                    DecisionLabel.INAPPROPRIATE,
                ),
            ],
        )
        mapper = AdaptiveMemoryAnchoredMapper(memory=contradictory_mem)
        assert mapper.map_parameter(ontology, "data_recipient", "housemate") is None

        # Explicit manual tuning override
        mapper.tune_rank("data_recipient", "custom_caretaker", 2)
        assert mapper.map_parameter(ontology, "data_recipient", "custom_caretaker") == 2


# ---------------------------------------------------------------------------
# 5. Domains (SPA & Education) and Memory-Size Ablation Evaluation Tests
# ---------------------------------------------------------------------------


class TestDomainsAndMemoryAblation:
    """Tests for SPA and Education ontologies, metrics, baselines, and |D_u| = 10..60 ablations."""

    def test_spa_and_education_domain_ontologies_exact_entities(self) -> None:
        """Verify exact required CI entities in SPA and Education ontologies."""
        spa = build_spa_ontology()
        assert spa.domain == "SPA"
        assert spa.get_rank("data_subject", "user") == 1
        assert spa.get_rank("data_sender", "assistant provider") == 1
        partial_rank = spa.get_rank("data_type", "partial SSN")
        full_rank = spa.get_rank("data_type", "full SSN")
        assert partial_rank is not None and full_rank is not None
        assert partial_rank < full_rank

        edu = build_education_ontology()
        assert edu.domain == "Education"
        assert edu.get_rank("data_subject", "student") == 1

        for sender in ("professor", "registrar", "advisor", "TA", "librarian"):
            assert edu.get_rank("data_sender", sender) is not None

        for recipient in ("department chair", "graduate schools", "parents", "classmates", "advertising agencies"):
            assert edu.get_rank("data_recipient", recipient) is not None

        for tp in (
            "with subject's consent",
            "with requirement of confidentiality",
            "if subject is performing poorly",
        ):
            assert edu.get_rank("transmission_principle", tp) is not None

        # Round-trip JSON schema serialization & validation
        re_parsed = parse_validated_ontology_json(edu.to_json())
        assert re_parsed.domain == "Education"
        assert re_parsed.get_rank("data_recipient", "advertising agencies") == edu.get_rank(
            "data_recipient", "advertising agencies"
        )

    def test_evaluation_metrics_computation(self) -> None:
        """Verify F1_A, F1_I, abstention accuracy, and contradiction escalation rate math."""
        predictions = [
            DecisionLabel.APPROPRIATE,
            DecisionLabel.INAPPROPRIATE,
            DecisionLabel.UNDETERMINED,
            DecisionLabel.UNDETERMINED,
        ]
        ground_truth = [
            DecisionLabel.APPROPRIATE,
            DecisionLabel.INAPPROPRIATE,
            DecisionLabel.UNDETERMINED,
            DecisionLabel.UNDETERMINED,
        ]
        escalations = [False, False, True, True]
        contradiction_flags = [False, False, False, True]

        metrics = compute_evaluation_metrics(
            predictions=predictions,
            ground_truth=ground_truth,
            escalations=escalations,
            contradiction_flags=contradiction_flags,
        )
        assert metrics.f1_appropriate == pytest.approx(1.0)
        assert metrics.f1_inappropriate == pytest.approx(1.0)
        assert metrics.abstention_accuracy == pytest.approx(1.0)
        assert metrics.contradiction_escalation_rate == pytest.approx(1.0)

    @pytest.mark.parametrize("builder_fn", [build_spa_benchmark, build_education_benchmark])
    def test_memory_size_ablation_stability_and_edge_mapper_parity(self, builder_fn) -> None:
        """Verify |D_u| in [10, 20, 40, 60] stability down to 20 priors, baseline gains, and edge parity."""
        benchmark = builder_fn(seed=42)
        report = run_memory_ablation(benchmark, memory_sizes=(10, 20, 40, 60))

        assert tuple(report.memory_sizes) == (10, 20, 40, 60)

        ariel_20 = report.results["ariel"][20]
        ariel_40 = report.results["ariel"][40]
        ariel_60 = report.results["ariel"][60]
        edge_20 = report.results["ariel_edge_lightweight"][20]
        edge_60 = report.results["ariel_edge_lightweight"][60]
        norms_20 = report.results["general_ci_norms"][20]
        icl_20 = report.results["simulated_icl"][20]

        # 1. Stability down to 20 prior requests (high F1_A and F1_I and tight stability from 20 -> 60)
        assert ariel_20.f1_appropriate >= 0.85
        assert ariel_20.f1_inappropriate >= 0.85
        assert abs(ariel_60.f1_appropriate - ariel_20.f1_appropriate) <= 0.10
        assert abs(ariel_60.f1_inappropriate - ariel_20.f1_inappropriate) <= 0.10
        assert ariel_40.f1_appropriate >= ariel_20.f1_appropriate - 1e-9

        # 2. Contradiction escalation rate is 100% for ARIEL across memory sizes
        assert ariel_20.contradiction_escalation_rate == pytest.approx(1.0)
        assert ariel_60.contradiction_escalation_rate == pytest.approx(1.0)
        assert ariel_20.abstention_accuracy > norms_20.abstention_accuracy
        assert ariel_20.abstention_accuracy > icl_20.abstention_accuracy

        # 3. ARIEL outperforms GeneralCINormsBaseline and SimulatedICLBaseline at |D_u| = 20
        assert ariel_20.f1_appropriate > norms_20.f1_appropriate
        assert ariel_20.f1_inappropriate > norms_20.f1_inappropriate
        assert ariel_20.f1_appropriate > icl_20.f1_appropriate
        assert ariel_20.f1_inappropriate > icl_20.f1_inappropriate

        # 4. LightweightEdgeOntologyMapper achieves exact parity with StructuredOntologyMapper
        assert report.edge_mapper_parity[20] == pytest.approx(1.0)
        assert report.edge_mapper_parity[60] == pytest.approx(1.0)
        assert edge_20.f1_appropriate == pytest.approx(ariel_20.f1_appropriate)
        assert edge_60.f1_inappropriate == pytest.approx(ariel_60.f1_inappropriate)

        # Direct standalone smoke test of baselines and edge mapper
        edge_mapper = LightweightEdgeOntologyMapper()
        sample_user = benchmark.users[0]
        sample_req = sample_user.eval_cases[0].request
        assert edge_mapper.map_parameter(benchmark.ontology, "data_type", sample_req.data_type) is not None
        assert isinstance(GeneralCINormsBaseline(benchmark.ontology).predict(sample_req), DecisionLabel)
        assert isinstance(
            SimulatedICLBaseline(benchmark.ontology).predict(sample_req, sample_user.memory.slice_memory(20)),
            DecisionLabel,
        )


# ---------------------------------------------------------------------------
# 6. Additional Boundary & Validation Coverage Tests
# ---------------------------------------------------------------------------


class TestEdgeCasesAndValidationCoverage:
    """Comprehensive boundary, error-handling, and convenience-property tests."""

    def test_model_coercions_and_error_branches(self) -> None:
        """Verify string coercion and TypeError/ValueError branches in models.py."""
        req = InformationFlowRequest(
            data_type="course grades",
            data_subject="student",
            data_sender="professor",
            data_recipient="parents",
            transmission_principle="with subject's consent",
        )
        rec = PriorDecisionRecord(request=req, label="appropriate")  # type: ignore[arg-type]
        assert rec.label is DecisionLabel.APPROPRIATE

        with pytest.raises(TypeError):
            PriorDecisionRecord(request=req, label=123)  # type: ignore[arg-type]

        with pytest.raises(TypeError):
            UserDecisionMemory(user_id="u1", records=["bad"])  # type: ignore[list-item]

        mem = UserDecisionMemory(user_id="u1")
        with pytest.raises(ValueError):
            mem.add_record(rec, label=DecisionLabel.INAPPROPRIATE)
        with pytest.raises(ValueError):
            mem.add_record(req, label=None)
        with pytest.raises(TypeError):
            mem.add_record(42)  # type: ignore[arg-type]

    def test_ontology_and_mapper_boundary_branches(self) -> None:
        """Verify ParameterOntology, OntologySet, aliases, edge mapper, and anchoring branches."""
        with pytest.raises(ValueError):
            ParameterOntology(parameter_name="bad", entity_ranks={"a": 1})
        with pytest.raises(ValueError):
            ParameterOntology(parameter_name="data_type", entity_ranks={})
        with pytest.raises(ValueError):
            ParameterOntology.from_levels("data_type", {})
        with pytest.raises(ValueError):
            ParameterOntology.from_levels("data_type", {"L1": []})

        partial_ont = OntologySet(
            domain="Partial",
            ontologies={"data_type": ParameterOntology("data_type", {"weather": 1, "SSN": 2})},
        )
        assert partial_ont.get_rank("data_recipient", "bank") is None
        expanded = partial_ont.with_updated_rank("data_recipient", "bank", 1)
        assert expanded.get_rank("data_recipient", "bank") == 1
        assert OntologySet.from_schema(expanded.to_schema()).domain == "Partial"

        with pytest.raises(ValueError):
            partial_ont.get_parameter_ontology("not_a_ci_param")

        alias_mapper = StructuredOntologyMapper(aliases={("data_type", "forecast"): "weather"})
        assert alias_mapper.map_parameter(partial_ont, "data_type", "Forecast") == 1
        assert alias_mapper.map_parameter(partial_ont, "data_type", "unknown") is None

        edge_mapper = LightweightEdgeOntologyMapper()
        assert edge_mapper.map_parameter(partial_ont, "data_recipient", "bank") is None
        assert edge_mapper.map_parameter(partial_ont, "data_type", "unknown") is None

        mismatched_edge = LightweightEdgeOntologyMapper(
            edge_json_extractor=lambda _o, _p, v: json.dumps({"parameter": "data_sender", "value": v, "level": "L1"})
        )
        assert mismatched_edge.map_parameter(partial_ont, "data_type", "weather") is None

        with pytest.raises(ValidationError):
            parse_validated_parameter_mapping_json(
                json.dumps({"parameter": "data_type", "value": "SSN", "level": "L5"}),
                allowed_max_rank=2,
            )

        for bad_args in (
            ("", {"data_type": ["a"]}),
            ("SPA", {}),
            ("SPA", {"bad": ["a"]}),
            ("SPA", {"data_type": ["   "]}),
        ):
            with pytest.raises(ValueError):
                build_ontology_prompt(*bad_args)

    def test_one_sided_memory_anchoring_and_solver_conveniences(self) -> None:
        """Verify one-sided lower/upper bounds, auto-bound mapper, exact d=0 step, and aliases."""
        spa = build_spa_ontology()
        base = InformationFlowRequest(
            data_type="calendar availability",
            data_subject="user",
            data_sender="assistant provider",
            data_recipient="device owner",
            transmission_principle="with subject's consent",
        )
        # Upper bound == 1 pins dynamic role to L1
        mem_ub1 = UserDecisionMemory(
            user_id="u-ub1",
            records=[
                PriorDecisionRecord(
                    base.with_parameter("data_recipient", "hospital"),  # L2
                    DecisionLabel.INAPPROPRIATE,
                ),
                PriorDecisionRecord(
                    base.with_parameter("data_recipient", "housemate"),
                    DecisionLabel.APPROPRIATE,
                ),
            ],
        )
        unbound_mapper = AdaptiveMemoryAnchoredMapper(tuned_ranks={("data_sender", "bot"): 1})
        with pytest.raises(ValueError):
            unbound_mapper.tune_rank("bad_param", "x", 1)
        with pytest.raises(ValueError):
            unbound_mapper.tune_rank("data_sender", "  ", 1)
        with pytest.raises(ValueError):
            unbound_mapper.map_parameter(spa, "bad_param", "x")
        assert unbound_mapper.map_parameter(spa, "data_recipient", "   ") is None

        with pytest.raises(ValueError):
            ARIELSolver(spa, max_neighbor_distance=-1)

        solver = ARIELSolver(spa, mapper=unbound_mapper)
        # Auto-binds mem_ub1 so "housemate" resolves to L1; exact d=0 match also checked
        exact_res = solver.solve(base.with_parameter("data_recipient", "housemate"), mem_ub1)
        assert exact_res.decision is DecisionLabel.APPROPRIATE
        assert exact_res.c_plus == 1
        assert exact_res.c_minus == 0
        assert exact_res.abstention_reason is None
        assert solver.predict(base, mem_ub1) is DecisionLabel.APPROPRIATE

        # Lower bound == max_rank (L5) pins dynamic role to L5
        mem_lb5 = UserDecisionMemory(
            user_id="u-lb5",
            records=[
                PriorDecisionRecord(
                    base.with_parameter("data_recipient", "work colleague"),  # L4
                    DecisionLabel.APPROPRIATE,
                ),
                PriorDecisionRecord(
                    base.with_parameter("data_recipient", "housemate"),
                    DecisionLabel.INAPPROPRIATE,
                ),
            ],
        )
        assert AdaptiveMemoryAnchoredMapper(memory=mem_lb5).map_parameter(spa, "data_recipient", "housemate") == 5

        # Peer-agreement fallback when unmapped dynamic role matches a single static peer rank
        mem_agree = UserDecisionMemory(
            user_id="u-agree",
            records=[
                PriorDecisionRecord(base.with_parameter("data_recipient", "close friend"), DecisionLabel.APPROPRIATE),
                PriorDecisionRecord(base.with_parameter("data_recipient", "housemate"), DecisionLabel.APPROPRIATE),
            ],
        )
        assert AdaptiveMemoryAnchoredMapper(memory=mem_agree).map_parameter(spa, "data_recipient", "housemate") == 3

    def test_evaluation_and_benchmark_error_guards(self) -> None:
        """Verify validation guards in evaluation.py and domains.py."""
        metrics = compute_evaluation_metrics(
            predictions=[DecisionLabel.UNDETERMINED],
            ground_truth=[DecisionLabel.UNDETERMINED],
        )
        assert metrics.f1_a == 0.0
        assert metrics.f1_i == 0.0
        assert metrics.contradiction_escalation_rate == 1.0

        with pytest.raises(ValueError):
            compute_evaluation_metrics([], [])
        with pytest.raises(ValueError):
            compute_evaluation_metrics([DecisionLabel.APPROPRIATE], [])
        with pytest.raises(ValueError):
            compute_evaluation_metrics(
                [DecisionLabel.APPROPRIATE],
                [DecisionLabel.APPROPRIATE],
                escalations=[],
            )
        with pytest.raises(ValueError):
            compute_evaluation_metrics(
                [DecisionLabel.APPROPRIATE],
                [DecisionLabel.APPROPRIATE],
                contradiction_flags=[],
            )
        with pytest.raises(ValueError):
            build_spa_benchmark(num_users=0)
        with pytest.raises(ValueError):
            build_education_benchmark(num_users=0)

        mini = build_spa_benchmark(num_users=1, seed=7)
        with pytest.raises(ValueError):
            run_memory_ablation(mini, memory_sizes=())
        with pytest.raises(ValueError):
            run_memory_ablation(mini, memory_sizes=(0,))

    def test_duck_typed_gateway_interoperability(self) -> None:
        """Verify OntologySet/ParameterOntology introspection properties and 5-tuple coercion."""
        spa = build_spa_ontology()
        dt_ont = spa.get_parameter_ontology("data_type")
        assert dt_ont is not None
        assert dt_ont.ranks["partial SSN"] == 2
        assert "partial SSN" in dt_ont.levels["L2"]
        assert spa.rank_of("data_type", "partial SSN") == 2

        class _DuckFlow:
            data_type = "public weather forecast"
            data_subject = "user"
            data_sender = "assistant provider"
            data_recipient = "bank"
            transmission_principle = "with subject's consent"

        duck = _DuckFlow()
        prior_req = InformationFlowRequest(
            data_type="partial SSN",
            data_subject="user",
            data_sender="assistant provider",
            data_recipient="bank",
            transmission_principle="with subject's consent",
        )
        assert prior_req.hamming_distance(duck) == 1  # type: ignore[arg-type]
        mem = UserDecisionMemory(
            user_id="u-duck",
            records=[PriorDecisionRecord(prior_req, DecisionLabel.APPROPRIATE)],
        )
        res = ARIELSolver(spa).evaluate(duck, mem)  # type: ignore[arg-type]
        assert res.label is DecisionLabel.APPROPRIATE
