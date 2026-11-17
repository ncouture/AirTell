"""Evaluation metrics, baselines, and memory-size ablation runner for ARIEL.

Computes utility (F1_A), privacy (F1_I), abstention accuracy, and contradiction escalation
rate across |D_u| in [10, 20, 40, 60], comparing ARIELSolver (host structured mapper and
edge lightweight JSON mapper) against GeneralCINormsBaseline and SimulatedICLBaseline.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from airtell.ariel.domains import DomainBenchmarkDataset
from airtell.ariel.models import (
    CI_PARAMETERS,
    DecisionLabel,
    InformationFlowRequest,
    UserDecisionMemory,
)
from airtell.ariel.ontology import (
    LightweightEdgeOntologyMapper,
    OntologySet,
    StructuredOntologyMapper,
)
from airtell.ariel.solver import ARIELSolver


@dataclass(frozen=True)
class EvaluationMetrics:
    """Quantitative privacy and utility metrics for an evaluated decision engine.

    Attributes:
        f1_appropriate: Binary F1 score on APPROPRIATE flows (F1_A utility metric).
        f1_inappropriate: Binary F1 score on INAPPROPRIATE flows (F1_I privacy metric).
        abstention_accuracy: Accuracy on deciding when to abstain (UNDETERMINED vs decided).
        contradiction_escalation_rate: Fraction of contradictory-prior queries halted with
            UNDETERMINED and escalate_to_user=True.
    """

    f1_appropriate: float
    f1_inappropriate: float
    abstention_accuracy: float
    contradiction_escalation_rate: float

    @property
    def f1_a(self) -> float:
        """Shorthand alias for f1_appropriate (utility)."""
        return self.f1_appropriate

    @property
    def f1_i(self) -> float:
        """Shorthand alias for f1_inappropriate (privacy)."""
        return self.f1_inappropriate


def _binary_f1_for_label(
    predictions: Sequence[DecisionLabel],
    ground_truth: Sequence[DecisionLabel],
    target_label: DecisionLabel,
) -> float:
    tp = 0
    fp = 0
    fn = 0
    for pred, truth in zip(predictions, ground_truth, strict=True):
        if pred == target_label and truth == target_label:
            tp += 1
        elif pred == target_label and truth != target_label:
            fp += 1
        elif pred != target_label and truth == target_label:
            fn += 1
    denom = (2 * tp) + fp + fn
    if denom == 0:
        return 0.0
    return (2.0 * tp) / denom


def compute_evaluation_metrics(
    predictions: Sequence[DecisionLabel],
    ground_truth: Sequence[DecisionLabel],
    escalations: Sequence[bool] | None = None,
    contradiction_flags: Sequence[bool] | None = None,
) -> EvaluationMetrics:
    """Compute F1_A, F1_I, abstention accuracy, and contradiction escalation rate.

    Args:
        predictions: Predicted DecisionLabel sequence.
        ground_truth: Ground-truth DecisionLabel sequence of equal length.
        escalations: Optional boolean flags indicating whether user escalation was triggered.
            Defaults to [pred is DecisionLabel.UNDETERMINED for pred in predictions].
        contradiction_flags: Optional boolean flags marking contradictory-prior queries.

    Returns:
        Populated EvaluationMetrics summary.

    Raises:
        ValueError: If sequences are empty or lengths do not match.
    """
    n_items = len(predictions)
    if n_items == 0:
        raise ValueError("predictions cannot be empty.")
    if len(ground_truth) != n_items:
        raise ValueError("predictions and ground_truth must have identical length.")

    resolved_escalations = (
        list(escalations) if escalations is not None else [pred is DecisionLabel.UNDETERMINED for pred in predictions]
    )
    if len(resolved_escalations) != n_items:
        raise ValueError("escalations must match length of predictions.")

    resolved_contra = list(contradiction_flags) if contradiction_flags is not None else [False] * n_items
    if len(resolved_contra) != n_items:
        raise ValueError("contradiction_flags must match length of predictions.")

    f1_a = _binary_f1_for_label(predictions, ground_truth, DecisionLabel.APPROPRIATE)
    f1_i = _binary_f1_for_label(predictions, ground_truth, DecisionLabel.INAPPROPRIATE)

    abstention_matches = sum(
        1
        for pred, truth in zip(predictions, ground_truth, strict=True)
        if (pred is DecisionLabel.UNDETERMINED) == (truth is DecisionLabel.UNDETERMINED)
    )
    abstention_acc = abstention_matches / n_items

    contra_indices = [idx for idx, flag in enumerate(resolved_contra) if flag]
    if not contra_indices:
        contra_rate = 1.0
    else:
        escalated_contra = sum(
            1 for idx in contra_indices if predictions[idx] is DecisionLabel.UNDETERMINED and resolved_escalations[idx]
        )
        contra_rate = escalated_contra / len(contra_indices)

    return EvaluationMetrics(
        f1_appropriate=f1_a,
        f1_inappropriate=f1_i,
        abstention_accuracy=abstention_acc,
        contradiction_escalation_rate=contra_rate,
    )


class GeneralCINormsBaseline:
    """Population-average Contextual Integrity baseline ignoring personalized memory D_u.

    Computes a normalized domain risk score across the ontology and applies a fixed
    population threshold, defaulting to INAPPROPRIATE when above the norm cutoff rather
    than abstaining on user-specific boundaries.
    """

    def __init__(self, ontology_set: OntologySet, cutoff: float = 0.52) -> None:
        """Initialize GeneralCINormsBaseline.

        Args:
            ontology_set: Domain OntologySet O.
            cutoff: Normalized population risk cutoff in [0.0, 1.0].
        """
        self.ontology_set = ontology_set
        self.cutoff = cutoff

    def evaluate(
        self,
        incoming: InformationFlowRequest,
        memory: UserDecisionMemory | None = None,
    ) -> tuple[DecisionLabel, bool]:
        """Classify incoming flow using population-average risk norms without D_u."""
        del memory
        normalized_risks: list[float] = []
        for param_name in CI_PARAMETERS:
            param_ont = self.ontology_set.get_parameter_ontology(param_name)
            if param_ont is None or param_ont.max_rank <= 1:
                continue
            rank = param_ont.get_rank(incoming.get_parameter(param_name))
            if rank is None:
                return DecisionLabel.INAPPROPRIATE, False
            normalized_risks.append((rank - 1) / (param_ont.max_rank - 1))

        avg_risk = sum(normalized_risks) / len(normalized_risks) if normalized_risks else 1.0
        if avg_risk <= self.cutoff:
            return DecisionLabel.APPROPRIATE, False
        return DecisionLabel.INAPPROPRIATE, False

    def predict(
        self,
        incoming: InformationFlowRequest,
        memory: UserDecisionMemory | None = None,
    ) -> DecisionLabel:
        """Return population-norm DecisionLabel prediction."""
        label, _ = self.evaluate(incoming, memory)
        return label


class SimulatedICLBaseline:
    """Simulated In-Context Learning (ICL) baseline using heuristic similarity voting over D_u.

    Aggregates inverse-Hamming-distance votes across neighbors up to d <= 3 without enforcing
    Definition 4.1 partial-order directionality (<=_O), single-parameter soundness (d <= 1),
    or formal contradiction halting.
    """

    def __init__(
        self,
        ontology_set: OntologySet,
        max_context_distance: int = 3,
    ) -> None:
        """Initialize SimulatedICLBaseline.

        Args:
            ontology_set: Domain OntologySet O used for fallback norm tie-breaking.
            max_context_distance: Maximum Hamming distance included in similarity voting.
        """
        self.ontology_set = ontology_set
        self.max_context_distance = max_context_distance
        self._fallback = GeneralCINormsBaseline(ontology_set)

    def evaluate(
        self,
        incoming: InformationFlowRequest,
        memory: UserDecisionMemory,
    ) -> tuple[DecisionLabel, bool]:
        """Classify incoming request via heuristic nearest-neighbor voting over D_u."""
        pos_weight = 0.0
        neg_weight = 0.0
        for rec in memory.records:
            dist = rec.request.hamming_distance(incoming)
            if dist > self.max_context_distance:
                continue
            weight = 4.0 if dist == 0 else (1.0 / (dist * dist))
            if rec.label is DecisionLabel.APPROPRIATE:
                pos_weight += weight
            else:
                neg_weight += weight

        if pos_weight == 0.0 and neg_weight == 0.0:
            return self._fallback.evaluate(incoming, memory)
        if pos_weight > neg_weight:
            return DecisionLabel.APPROPRIATE, False
        if neg_weight > pos_weight:
            return DecisionLabel.INAPPROPRIATE, False
        return self._fallback.evaluate(incoming, memory)

    def predict(
        self,
        incoming: InformationFlowRequest,
        memory: UserDecisionMemory,
    ) -> DecisionLabel:
        """Return heuristic ICL DecisionLabel prediction."""
        label, _ = self.evaluate(incoming, memory)
        return label


@dataclass(frozen=True)
class MemoryAblationReport:
    """Aggregated memory-scaling ablation results across |D_u| sizes and baselines.

    Attributes:
        domain: Evaluated domain identifier ('SPA' or 'Education').
        memory_sizes: Ordered tuple of evaluated prior memory sizes |D_u|.
        results: Nested dict mapping model name -> memory_size -> EvaluationMetrics.
        edge_mapper_parity: Mapping from memory_size -> exact label agreement rate in [0, 1]
            between StructuredOntologyMapper and LightweightEdgeOntologyMapper.
    """

    domain: str
    memory_sizes: tuple[int, ...]
    results: dict[str, dict[int, EvaluationMetrics]]
    edge_mapper_parity: dict[int, float]


def run_memory_ablation(
    dataset: DomainBenchmarkDataset,
    memory_sizes: Sequence[int] = (10, 20, 40, 60),
) -> MemoryAblationReport:
    """Run memory-size ablation comparing ARIELSolver, edge mapper, CI norms, and ICL.

    Args:
        dataset: Deterministic DomainBenchmarkDataset to evaluate.
        memory_sizes: Sequence of |D_u| slice sizes (defaults to (10, 20, 40, 60)).

    Returns:
        MemoryAblationReport containing per-size metrics and edge mapper parity rates.

    Raises:
        ValueError: If memory_sizes is empty or contains non-positive sizes.
    """
    if not memory_sizes:
        raise ValueError("memory_sizes cannot be empty.")
    sizes_tuple = tuple(int(s) for s in memory_sizes)
    if any(size < 1 for size in sizes_tuple):
        raise ValueError(f"All memory_sizes must be >= 1, got {sizes_tuple}.")

    ariel_host = ARIELSolver(dataset.ontology, StructuredOntologyMapper())
    ariel_edge = ARIELSolver(dataset.ontology, LightweightEdgeOntologyMapper())
    norms_baseline = GeneralCINormsBaseline(dataset.ontology)
    icl_baseline = SimulatedICLBaseline(dataset.ontology)

    results: dict[str, dict[int, EvaluationMetrics]] = {
        "ariel": {},
        "ariel_edge_lightweight": {},
        "general_ci_norms": {},
        "simulated_icl": {},
    }
    parity_by_size: dict[int, float] = {}

    for size in sizes_tuple:
        truth_all: list[DecisionLabel] = []
        contra_all: list[bool] = []

        preds_host: list[DecisionLabel] = []
        esc_host: list[bool] = []

        preds_edge: list[DecisionLabel] = []
        esc_edge: list[bool] = []

        preds_norms: list[DecisionLabel] = []
        esc_norms: list[bool] = []

        preds_icl: list[DecisionLabel] = []
        esc_icl: list[bool] = []

        for user in dataset.users:
            sliced_memory = user.memory.slice_memory(size)
            for case in user.eval_cases:
                truth_all.append(case.ground_truth)
                contra_all.append(case.is_contradictory)

                res_host = ariel_host.evaluate(case.request, sliced_memory)
                preds_host.append(res_host.label)
                esc_host.append(res_host.escalate_to_user)

                res_edge = ariel_edge.evaluate(case.request, sliced_memory)
                preds_edge.append(res_edge.label)
                esc_edge.append(res_edge.escalate_to_user)

                lbl_norms, esc_n = norms_baseline.evaluate(case.request, sliced_memory)
                preds_norms.append(lbl_norms)
                esc_norms.append(esc_n)

                lbl_icl, esc_i = icl_baseline.evaluate(case.request, sliced_memory)
                preds_icl.append(lbl_icl)
                esc_icl.append(esc_i)

        results["ariel"][size] = compute_evaluation_metrics(preds_host, truth_all, esc_host, contra_all)
        results["ariel_edge_lightweight"][size] = compute_evaluation_metrics(
            preds_edge, truth_all, esc_edge, contra_all
        )
        results["general_ci_norms"][size] = compute_evaluation_metrics(preds_norms, truth_all, esc_norms, contra_all)
        results["simulated_icl"][size] = compute_evaluation_metrics(preds_icl, truth_all, esc_icl, contra_all)

        exact_matches = sum(1 for lbl_h, lbl_e in zip(preds_host, preds_edge, strict=True) if lbl_h == lbl_e)
        parity_by_size[size] = exact_matches / len(preds_host)

    return MemoryAblationReport(
        domain=dataset.domain,
        memory_sizes=sizes_tuple,
        results=results,
        edge_mapper_parity=parity_by_size,
    )
