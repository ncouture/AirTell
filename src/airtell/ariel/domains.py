"""Domain ontologies and deterministic synthetic benchmark builders for SPA and Education.

Defines graded Contextual Integrity ontologies for the Smart Device Assistant ('SPA') and
Educational Environment ('Education') domains, along with deterministic personalized user
benchmark generators for evaluating logical entailment accuracy, abstention, and memory
scaling ablations.
"""

from __future__ import annotations

import random
from collections.abc import Sequence
from dataclasses import dataclass

from airtell.ariel.models import (
    DecisionLabel,
    InformationFlowRequest,
    PriorDecisionRecord,
    UserDecisionMemory,
)
from airtell.ariel.ontology import OntologySet, ParameterOntology


@dataclass(frozen=True)
class BenchmarkEvalCase:
    """Single ground-truth evaluation query for privacy engine benchmarking.

    Attributes:
        request: Incoming Contextual Integrity 5-tuple request to classify.
        ground_truth: Expected ideal label (APPROPRIATE, INAPPROPRIATE, or UNDETERMINED).
        is_contradictory: True if historical priors in D_u intentionally conflict on this flow.
    """

    request: InformationFlowRequest
    ground_truth: DecisionLabel
    is_contradictory: bool = False


@dataclass(frozen=True)
class UserBenchmarkScenario:
    """Personalized user privacy benchmark profile with 60 prior records and evaluation queries.

    Attributes:
        user_id: Unique synthetic user identifier.
        memory: Full UserDecisionMemory D_u of 60 historical resolved records.
        eval_cases: Tuple of ground-truth BenchmarkEvalCase queries.
    """

    user_id: str
    memory: UserDecisionMemory
    eval_cases: tuple[BenchmarkEvalCase, ...]


@dataclass(frozen=True)
class DomainBenchmarkDataset:
    """Complete deterministic benchmark dataset for a Contextual Integrity domain.

    Attributes:
        domain: Domain name ('SPA' or 'Education').
        ontology: Domain OntologySet O.
        users: Tuple of personalized UserBenchmarkScenario instances.
    """

    domain: str
    ontology: OntologySet
    users: tuple[UserBenchmarkScenario, ...]


def build_spa_ontology() -> OntologySet:
    """Build the graded ontology O for the Smart Device Assistant (SPA) domain.

    Sets data_subject='user' and data_sender='assistant provider' with monotonically
    graded data_type, data_recipient, and transmission_principle sensitivity/risk levels.

    Returns:
        Validated OntologySet for domain 'SPA'.
    """
    ontologies = {
        "data_type": ParameterOntology.from_levels(
            "data_type",
            {
                "L1": ["public weather forecast", "smart home device status"],
                "L2": ["calendar availability", "partial SSN"],
                "L3": ["exact GPS location", "voice command transcript"],
                "L4": ["full SSN", "biometric health records"],
            },
        ),
        "data_subject": ParameterOntology.from_levels(
            "data_subject",
            {
                "L1": ["user"],
            },
        ),
        "data_sender": ParameterOntology.from_levels(
            "data_sender",
            {
                "L1": ["assistant provider"],
            },
        ),
        "data_recipient": ParameterOntology.from_levels(
            "data_recipient",
            {
                "L1": ["device owner", "bank"],
                "L2": ["hospital", "family member"],
                "L3": ["close friend"],
                "L4": ["work colleague", "neighbor"],
                "L5": ["third-party app developer", "advertising agency"],
            },
        ),
        "transmission_principle": ParameterOntology.from_levels(
            "transmission_principle",
            {
                "L1": ["with subject's consent"],
                "L2": ["with requirement of confidentiality", "for requested transaction only"],
                "L3": ["for automated background sync"],
                "L4": ["for targeted advertising"],
            },
        ),
    }
    return OntologySet(
        domain="SPA",
        ontologies=ontologies,
        description="Smart Personal Assistant (SPA) Contextual Integrity ontology.",
    )


def build_education_ontology() -> OntologySet:
    """Build the graded ontology O for the Educational Environment (Education) domain.

    Sets data_subject='student' with organizational data_sender roles, institutional to
    external data_recipient tiers, and consent/confidentiality/conditional transmission
    principles.

    Returns:
        Validated OntologySet for domain 'Education'.
    """
    ontologies = {
        "data_type": ParameterOntology.from_levels(
            "data_type",
            {
                "L1": ["course enrollment directory", "club membership"],
                "L2": ["class attendance", "assignment submission timestamp"],
                "L3": ["course grades", "academic transcript"],
                "L4": ["disciplinary record", "disability accommodation record"],
            },
        ),
        "data_subject": ParameterOntology.from_levels(
            "data_subject",
            {
                "L1": ["student"],
            },
        ),
        "data_sender": ParameterOntology.from_levels(
            "data_sender",
            {
                "L1": ["registrar"],
                "L2": ["professor"],
                "L3": ["advisor"],
                "L4": ["TA"],
                "L5": ["librarian"],
            },
        ),
        "data_recipient": ParameterOntology.from_levels(
            "data_recipient",
            {
                "L1": ["department chair"],
                "L2": ["graduate schools"],
                "L3": ["parents"],
                "L4": ["classmates"],
                "L5": ["advertising agencies"],
            },
        ),
        "transmission_principle": ParameterOntology.from_levels(
            "transmission_principle",
            {
                "L1": ["with subject's consent"],
                "L2": ["with requirement of confidentiality"],
                "L3": ["if subject is performing poorly"],
            },
        ),
    }
    return OntologySet(
        domain="Education",
        ontologies=ontologies,
        description="Educational Environment Contextual Integrity ontology.",
    )


def _monotone_risk_score(
    request: InformationFlowRequest,
    ontology: OntologySet,
    weights: tuple[float, float, float, float],
) -> float:
    w_dt, w_ds, w_dr, w_tp = weights
    r_dt = ontology.get_rank("data_type", request.data_type) or 1
    r_ds = ontology.get_rank("data_sender", request.data_sender) or 1
    r_dr = ontology.get_rank("data_recipient", request.data_recipient) or 1
    r_tp = ontology.get_rank("transmission_principle", request.transmission_principle) or 1
    return (w_dt * r_dt) + (w_ds * r_ds) + (w_dr * r_dr) + (w_tp * r_tp)


def _assemble_user_scenario(
    user_id: str,
    ontology: OntologySet,
    monotone_pool: list[InformationFlowRequest],
    contradiction_priors: list[PriorDecisionRecord],
    contradiction_eval: BenchmarkEvalCase,
    boundary_priors: list[PriorDecisionRecord],
    boundary_evals: Sequence[BenchmarkEvalCase],
    threshold: float,
    weights: tuple[float, float, float, float],
    rng: random.Random,
) -> UserBenchmarkScenario:
    """Construct a 60-record user memory and balanced evaluation suite for one synthetic user."""
    labeled_pool: dict[InformationFlowRequest, DecisionLabel] = {}
    for req in monotone_pool:
        score = _monotone_risk_score(req, ontology, weights)
        labeled_pool[req] = DecisionLabel.APPROPRIATE if score <= threshold else DecisionLabel.INAPPROPRIATE

    app_pairs: list[tuple[InformationFlowRequest, list[PriorDecisionRecord]]] = []
    inapp_pairs: list[tuple[InformationFlowRequest, list[PriorDecisionRecord]]] = []

    shuffled_reqs = list(monotone_pool)
    rng.shuffle(shuffled_reqs)

    for candidate in shuffled_reqs:
        cand_label = labeled_pool[candidate]
        entailing_priors: list[PriorDecisionRecord] = []
        for peer in shuffled_reqs:
            if peer == candidate or peer.hamming_distance(candidate) != 1:
                continue
            peer_label = labeled_pool[peer]
            if peer_label != cand_label:
                continue
            diffs = peer.differing_parameters(candidate)
            param_name, peer_val, cand_val = diffs[0]
            peer_rank = ontology.get_rank(param_name, peer_val)
            cand_rank = ontology.get_rank(param_name, cand_val)
            if peer_rank is None or cand_rank is None:
                continue
            if cand_label is DecisionLabel.APPROPRIATE and cand_rank <= peer_rank:
                entailing_priors.append(PriorDecisionRecord(peer, DecisionLabel.APPROPRIATE))
            elif cand_label is DecisionLabel.INAPPROPRIATE and peer_rank <= cand_rank:
                entailing_priors.append(PriorDecisionRecord(peer, DecisionLabel.INAPPROPRIATE))

        if entailing_priors:
            if cand_label is DecisionLabel.APPROPRIATE:
                app_pairs.append((candidate, entailing_priors))
            else:
                inapp_pairs.append((candidate, entailing_priors))

    # Select disjoint evaluation queries and non-overlapping d == 1 boundary anchors
    selected_eval: list[BenchmarkEvalCase] = []
    early_anchors: list[PriorDecisionRecord] = []
    mid_anchors: list[PriorDecisionRecord] = []
    late_anchors: list[PriorDecisionRecord] = []
    reserved_eval_requests: set[InformationFlowRequest] = set()
    reserved_anchor_requests: set[InformationFlowRequest] = set()

    for pairs_group, target_count in ((app_pairs, 7), (inapp_pairs, 7)):
        chosen = 0
        for eval_req, candidate_anchors in pairs_group:
            if chosen >= target_count:
                break
            if eval_req in reserved_eval_requests or eval_req in reserved_anchor_requests:
                continue
            valid_anchor = next(
                (a for a in candidate_anchors if a.request not in reserved_eval_requests),
                None,
            )
            if valid_anchor is None:
                continue
            reserved_eval_requests.add(eval_req)
            reserved_anchor_requests.add(valid_anchor.request)
            selected_eval.append(
                BenchmarkEvalCase(
                    request=eval_req,
                    ground_truth=labeled_pool[eval_req],
                    is_contradictory=False,
                )
            )
            if chosen < 2:
                early_anchors.append(valid_anchor)
            elif chosen < 6:
                mid_anchors.append(valid_anchor)
            else:
                late_anchors.append(valid_anchor)
            chosen += 1

    # Build ordered 60-record memory D_u:
    # - Slots 0..9: contradiction priors + boundary priors + early_anchors (cold start |D_u|=10)
    # - Slots 10..19: mid_anchors + boundary-adjacent contrast records (|D_u|=20 reaches stability)
    # - Slots 20..39: late_anchors + additional user decisions (|D_u|=40)
    # - Slots 40..59: additional user decisions up to 60 records (|D_u|=60)
    seen_requests: set[InformationFlowRequest] = set(reserved_eval_requests)
    ordered_records: list[PriorDecisionRecord] = []

    def _try_append(rec: PriorDecisionRecord) -> None:
        if rec.request not in seen_requests and len(ordered_records) < 60:
            seen_requests.add(rec.request)
            ordered_records.append(rec)

    for rec in contradiction_priors:
        _try_append(rec)
    for rec in boundary_priors:
        _try_append(rec)
    for rec in early_anchors:
        _try_append(rec)

    remaining_candidates = [
        PriorDecisionRecord(req, labeled_pool[req])
        for req in shuffled_reqs
        if req not in seen_requests and req not in reserved_anchor_requests
    ]
    remaining_candidates.sort(key=lambda rec: abs(_monotone_risk_score(rec.request, ontology, weights) - threshold))

    rem_idx = 0
    while len(ordered_records) < 10 and rem_idx < len(remaining_candidates):
        _try_append(remaining_candidates[rem_idx])
        rem_idx += 1

    for rec in mid_anchors:
        _try_append(rec)

    while len(ordered_records) < 20 and rem_idx < len(remaining_candidates):
        _try_append(remaining_candidates[rem_idx])
        rem_idx += 1

    for rec in late_anchors:
        _try_append(rec)

    while len(ordered_records) < 60 and rem_idx < len(remaining_candidates):
        _try_append(remaining_candidates[rem_idx])
        rem_idx += 1

    eval_suite = tuple([*selected_eval, *boundary_evals, contradiction_eval])
    return UserBenchmarkScenario(
        user_id=user_id,
        memory=UserDecisionMemory(user_id=user_id, records=ordered_records),
        eval_cases=eval_suite,
    )


def build_spa_benchmark(
    num_users: int = 8,
    seed: int = 42,
) -> DomainBenchmarkDataset:
    """Generate deterministic personalized benchmark scenarios for the SPA domain.

    Args:
        num_users: Number of synthetic users with heterogeneous privacy thresholds.
        seed: Deterministic PRNG seed.

    Returns:
        DomainBenchmarkDataset for 'SPA' with 60 prior records per user.
    """
    if num_users < 1:
        raise ValueError(f"num_users must be >= 1, got {num_users}.")
    rng = random.Random(seed)
    ontology = build_spa_ontology()

    monotone_data_types = [
        "public weather forecast",
        "smart home device status",
        "calendar availability",
        "partial SSN",
        "exact GPS location",
        "full SSN",
        "biometric health records",
    ]
    monotone_recipients = [
        "device owner",
        "bank",
        "hospital",
        "family member",
        "close friend",
        "work colleague",
        "third-party app developer",
        "advertising agency",
    ]
    monotone_principles = [
        "with subject's consent",
        "with requirement of confidentiality",
        "for requested transaction only",
    ]

    monotone_pool = [
        InformationFlowRequest(
            data_type=dt,
            data_subject="user",
            data_sender="assistant provider",
            data_recipient=dr,
            transmission_principle=tp,
        )
        for dt in monotone_data_types
        for dr in monotone_recipients
        for tp in monotone_principles
    ]

    # Isolated contradiction stem (d >= 2 from monotone_pool and boundary stem)
    contra_base = InformationFlowRequest(
        data_type="voice command transcript",
        data_subject="user",
        data_sender="assistant provider",
        data_recipient="close friend",
        transmission_principle="for targeted advertising",
    )
    contradiction_priors = [
        PriorDecisionRecord(
            contra_base.with_parameter("data_recipient", "work colleague"),
            DecisionLabel.APPROPRIATE,
        ),
        PriorDecisionRecord(
            contra_base.with_parameter("data_recipient", "family member"),
            DecisionLabel.INAPPROPRIATE,
        ),
    ]
    contradiction_eval = BenchmarkEvalCase(
        request=contra_base,
        ground_truth=DecisionLabel.UNDETERMINED,
        is_contradictory=True,
    )

    # Isolated non-entailed boundary stem (d >= 2 from monotone_pool and contradiction stem)
    boundary_base = InformationFlowRequest(
        data_type="calendar availability",
        data_subject="user",
        data_sender="assistant provider",
        data_recipient="neighbor",
        transmission_principle="for automated background sync",
    )
    boundary_priors = [
        PriorDecisionRecord(
            boundary_base.with_parameter("data_type", "public weather forecast"),
            DecisionLabel.APPROPRIATE,
        ),
        PriorDecisionRecord(
            boundary_base.with_parameter("data_type", "full SSN"),
            DecisionLabel.INAPPROPRIATE,
        ),
    ]
    boundary_evals = [
        BenchmarkEvalCase(
            request=boundary_base,
            ground_truth=DecisionLabel.UNDETERMINED,
            is_contradictory=False,
        ),
        BenchmarkEvalCase(
            request=boundary_base.with_parameter("data_type", "partial SSN"),
            ground_truth=DecisionLabel.UNDETERMINED,
            is_contradictory=False,
        ),
        BenchmarkEvalCase(
            request=boundary_base.with_parameter("data_type", "exact GPS location"),
            ground_truth=DecisionLabel.UNDETERMINED,
            is_contradictory=False,
        ),
    ]

    # Alternate strict privacy-focused users and permissive utility-focused users
    threshold_profiles = [4.6, 8.8, 5.0, 8.4, 4.8, 8.6, 5.2, 8.2]
    weight_profiles = [
        (1.3, 0.2, 1.1, 1.0),
        (1.0, 0.2, 1.3, 0.9),
        (1.4, 0.2, 1.0, 1.1),
        (1.1, 0.2, 1.2, 1.0),
    ]

    users: list[UserBenchmarkScenario] = []
    for idx in range(num_users):
        threshold = threshold_profiles[idx % len(threshold_profiles)]
        weights = weight_profiles[idx % len(weight_profiles)]
        users.append(
            _assemble_user_scenario(
                user_id=f"spa-user-{idx + 1:02d}",
                ontology=ontology,
                monotone_pool=monotone_pool,
                contradiction_priors=contradiction_priors,
                contradiction_eval=contradiction_eval,
                boundary_priors=boundary_priors,
                boundary_evals=boundary_evals,
                threshold=threshold,
                weights=weights,
                rng=rng,
            )
        )
    return DomainBenchmarkDataset(domain="SPA", ontology=ontology, users=tuple(users))


def build_education_benchmark(
    num_users: int = 8,
    seed: int = 42,
) -> DomainBenchmarkDataset:
    """Generate deterministic personalized benchmark scenarios for the Education domain.

    Args:
        num_users: Number of synthetic student profiles with heterogeneous privacy norms.
        seed: Deterministic PRNG seed.

    Returns:
        DomainBenchmarkDataset for 'Education' with 60 prior records per student.
    """
    if num_users < 1:
        raise ValueError(f"num_users must be >= 1, got {num_users}.")
    rng = random.Random(seed)
    ontology = build_education_ontology()

    monotone_data_types = [
        "course enrollment directory",
        "class attendance",
        "course grades",
        "academic transcript",
        "disciplinary record",
        "disability accommodation record",
    ]
    monotone_senders = ["registrar", "professor", "advisor", "TA"]
    monotone_recipients = [
        "department chair",
        "graduate schools",
        "parents",
        "classmates",
        "advertising agencies",
    ]
    monotone_principles = [
        "with subject's consent",
        "with requirement of confidentiality",
        "if subject is performing poorly",
    ]

    monotone_pool = [
        InformationFlowRequest(
            data_type=dt,
            data_subject="student",
            data_sender=ds,
            data_recipient=dr,
            transmission_principle=tp,
        )
        for dt in monotone_data_types
        for ds in monotone_senders
        for dr in monotone_recipients
        for tp in monotone_principles
    ]

    # Isolated contradiction stem (d >= 2 from monotone_pool and boundary stem)
    contra_base = InformationFlowRequest(
        data_type="club membership",
        data_subject="student",
        data_sender="librarian",
        data_recipient="parents",
        transmission_principle="if subject is performing poorly",
    )
    contradiction_priors = [
        PriorDecisionRecord(
            contra_base.with_parameter("data_recipient", "classmates"),
            DecisionLabel.APPROPRIATE,
        ),
        PriorDecisionRecord(
            contra_base.with_parameter("data_recipient", "graduate schools"),
            DecisionLabel.INAPPROPRIATE,
        ),
    ]
    contradiction_eval = BenchmarkEvalCase(
        request=contra_base,
        ground_truth=DecisionLabel.UNDETERMINED,
        is_contradictory=True,
    )

    # Isolated non-entailed boundary stem (d >= 2 from monotone_pool and contradiction stem)
    boundary_base = InformationFlowRequest(
        data_type="assignment submission timestamp",
        data_subject="student",
        data_sender="librarian",
        data_recipient="parents",
        transmission_principle="with subject's consent",
    )
    boundary_priors = [
        PriorDecisionRecord(
            boundary_base.with_parameter("data_recipient", "department chair"),
            DecisionLabel.APPROPRIATE,
        ),
        PriorDecisionRecord(
            boundary_base.with_parameter("data_recipient", "advertising agencies"),
            DecisionLabel.INAPPROPRIATE,
        ),
    ]
    boundary_evals = [
        BenchmarkEvalCase(
            request=boundary_base,
            ground_truth=DecisionLabel.UNDETERMINED,
            is_contradictory=False,
        ),
        BenchmarkEvalCase(
            request=boundary_base.with_parameter("data_recipient", "graduate schools"),
            ground_truth=DecisionLabel.UNDETERMINED,
            is_contradictory=False,
        ),
        BenchmarkEvalCase(
            request=boundary_base.with_parameter("data_recipient", "classmates"),
            ground_truth=DecisionLabel.UNDETERMINED,
            is_contradictory=False,
        ),
    ]

    threshold_profiles = [6.2, 10.6, 6.5, 10.2, 6.4, 10.4, 6.8, 10.0]
    weight_profiles = [
        (1.2, 0.8, 1.2, 0.9),
        (1.0, 0.9, 1.3, 1.0),
        (1.3, 0.7, 1.1, 1.0),
        (1.1, 0.8, 1.2, 1.1),
    ]

    users: list[UserBenchmarkScenario] = []
    for idx in range(num_users):
        threshold = threshold_profiles[idx % len(threshold_profiles)]
        weights = weight_profiles[idx % len(weight_profiles)]
        users.append(
            _assemble_user_scenario(
                user_id=f"edu-student-{idx + 1:02d}",
                ontology=ontology,
                monotone_pool=monotone_pool,
                contradiction_priors=contradiction_priors,
                contradiction_eval=contradiction_eval,
                boundary_priors=boundary_priors,
                boundary_evals=boundary_evals,
                threshold=threshold,
                weights=weights,
                rng=rng,
            )
        )
    return DomainBenchmarkDataset(domain="Education", ontology=ontology, users=tuple(users))
