"""Neurosymbolic logical entailment solver (Definition 4.2 and Online Phase Algorithm 1).

Evaluates incoming Contextual Integrity information flow requests against single-parameter
user decision neighborhoods (d <= 1), accumulates formal entailment evidence (c_plus, c_minus),
and enforces explicit abstention and user escalation on contradictory priors, empty
neighborhoods, or non-entailed privacy boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass

from airtell.ariel.models import (
    DecisionLabel,
    InformationFlowRequest,
    PriorDecisionRecord,
    UserDecisionMemory,
)
from airtell.ariel.ontology import (
    AdaptiveMemoryAnchoredMapper,
    OntologyMapper,
    OntologySet,
    StructuredOntologyMapper,
    is_less_or_equal,
)

RULE_1_NAME = "RULE_1_INAPPROPRIATE"
RULE_2_NAME = "RULE_2_APPROPRIATE"

ABSTENTION_CONTRADICTORY_PRIORS = "contradictory_priors"
ABSTENTION_EMPTY_NEIGHBORHOOD = "empty_neighborhood"
ABSTENTION_NON_ENTAILED_BOUNDARY = "non_entailed_boundary"


def check_entailment_rule_1(
    prior: PriorDecisionRecord,
    incoming: InformationFlowRequest,
    ontology_set: OntologySet,
    mapper: OntologyMapper | None = None,
) -> bool:
    """Evaluate Definition 4.2 Rule 1: l' == INAPPROPRIATE and R' <=_O R => (R, INAPPROPRIATE).

    Args:
        prior: Historical user decision record (R', l').
        incoming: Target incoming request R.
        ontology_set: Domain OntologySet O.
        mapper: Optional OntologyMapper (defaults to StructuredOntologyMapper()).

    Returns:
        True if prior formally entails that incoming is INAPPROPRIATE, else False.
    """
    if prior.label is not DecisionLabel.INAPPROPRIATE:
        return False
    return is_less_or_equal(prior.request, incoming, ontology_set, mapper)


def check_entailment_rule_2(
    prior: PriorDecisionRecord,
    incoming: InformationFlowRequest,
    ontology_set: OntologySet,
    mapper: OntologyMapper | None = None,
) -> bool:
    """Evaluate Definition 4.2 Rule 2: l' == APPROPRIATE and R <=_O R' => (R, APPROPRIATE).

    Args:
        prior: Historical user decision record (R', l').
        incoming: Target incoming request R.
        ontology_set: Domain OntologySet O.
        mapper: Optional OntologyMapper (defaults to StructuredOntologyMapper()).

    Returns:
        True if prior formally entails that incoming is APPROPRIATE, else False.
    """
    if prior.label is not DecisionLabel.APPROPRIATE:
        return False
    return is_less_or_equal(incoming, prior.request, ontology_set, mapper)


@dataclass(frozen=True)
class EntailmentStep:
    """Single formal deduction step within an ARIEL entailment proof trace.

    Attributes:
        prior: Historical PriorDecisionRecord triggering the entailment rule.
        rule: Identifier of the rule fired ('RULE_1_INAPPROPRIATE' or 'RULE_2_APPROPRIATE').
        entailed_label: Entailed DecisionLabel (INAPPROPRIATE or APPROPRIATE).
        hamming_distance: Parameter Hamming distance between prior.request and incoming (0 or 1).
        varied_parameter: Name of the single differing CI parameter when d == 1, else None.
        prior_rank: Mapped integer rank of prior's varied parameter (if d == 1), else None.
        incoming_rank: Mapped integer rank of incoming's varied parameter (if d == 1), else None.
    """

    prior: PriorDecisionRecord
    rule: str
    entailed_label: DecisionLabel
    hamming_distance: int
    varied_parameter: str | None = None
    prior_rank: int | None = None
    incoming_rank: int | None = None


@dataclass(frozen=True)
class EntailmentProof:
    """Transparent audit proof produced by Online Phase Algorithm 1.

    Attributes:
        neighbors_checked: Count of prior records in single-parameter neighborhood E.
        entailed_steps: Ordered list of EntailmentStep deductions fired over E.
        c_plus: Total count of APPROPRIATE entailments (Rule 2 matches).
        c_minus: Total count of INAPPROPRIATE entailments (Rule 1 matches).
        abstention_reason: Explicit reason when decision is UNDETERMINED
            ('contradictory_priors', 'empty_neighborhood', or 'non_entailed_boundary'),
            or None when uniquely entailed.
        escalate_to_user: True whenever automated execution must halt and escalate to the user.
        neighbor_records: Tuple of PriorDecisionRecord entries belonging to E.
    """

    neighbors_checked: int
    entailed_steps: list[EntailmentStep]
    c_plus: int
    c_minus: int
    abstention_reason: str | None
    escalate_to_user: bool
    neighbor_records: tuple[PriorDecisionRecord, ...] = ()


@dataclass(frozen=True)
class EntailmentResult:
    """Final ARIEL solver outcome pairing the inferred DecisionLabel with its EntailmentProof.

    Attributes:
        label: Resolved DecisionLabel (APPROPRIATE, INAPPROPRIATE, or UNDETERMINED).
        proof: Transparent EntailmentProof trace explaining the verdict.
    """

    label: DecisionLabel
    proof: EntailmentProof

    @property
    def decision(self) -> DecisionLabel:
        """Alias for label."""
        return self.label

    @property
    def c_plus(self) -> int:
        """Count of Rule 2 (APPROPRIATE) entailments."""
        return self.proof.c_plus

    @property
    def c_minus(self) -> int:
        """Count of Rule 1 (INAPPROPRIATE) entailments."""
        return self.proof.c_minus

    @property
    def abstention_reason(self) -> str | None:
        """Reason for UNDETERMINED abstention, or None when decided."""
        return self.proof.abstention_reason

    @property
    def escalate_to_user(self) -> bool:
        """Whether execution must escalate to explicit user confirmation."""
        return self.proof.escalate_to_user


class ARIELSolver:
    """Online Phase Algorithm 1 neurosymbolic privacy entailment engine."""

    def __init__(
        self,
        ontology_set: OntologySet,
        mapper: OntologyMapper | None = None,
        max_neighbor_distance: int = 1,
    ) -> None:
        """Initialize ARIELSolver.

        Args:
            ontology_set: Domain OntologySet O defining partial-order hierarchies.
            mapper: Parameter rank mapper (defaults to StructuredOntologyMapper()).
            max_neighbor_distance: Maximum parameter Hamming distance allowed in neighborhood E
                (defaults to 1 for single-parameter monotonicity soundness).

        Raises:
            ValueError: If max_neighbor_distance < 0.
        """
        if max_neighbor_distance < 0:
            raise ValueError(f"max_neighbor_distance must be >= 0, got {max_neighbor_distance}.")
        self.ontology_set = ontology_set
        self.mapper: OntologyMapper = StructuredOntologyMapper() if mapper is None else mapper
        self.max_neighbor_distance = max_neighbor_distance

    def _resolve_active_mapper(self, memory: UserDecisionMemory) -> OntologyMapper:
        if isinstance(self.mapper, AdaptiveMemoryAnchoredMapper) and self.mapper.memory is None:
            return AdaptiveMemoryAnchoredMapper(
                memory=memory,
                dynamic_roles=self.mapper.dynamic_roles,
                tuned_ranks=self.mapper._tuned_ranks,
            )
        return self.mapper

    def _build_step(
        self,
        prior: PriorDecisionRecord,
        incoming: InformationFlowRequest,
        rule_name: str,
        entailed_label: DecisionLabel,
        active_mapper: OntologyMapper,
    ) -> EntailmentStep:
        diffs = prior.request.differing_parameters(incoming)
        distance = len(diffs)
        varied_param: str | None = None
        prior_rank: int | None = None
        incoming_rank: int | None = None
        if distance == 1:
            varied_param, prior_val, incoming_val = diffs[0]
            prior_rank = active_mapper.map_parameter(self.ontology_set, varied_param, prior_val)
            incoming_rank = active_mapper.map_parameter(self.ontology_set, varied_param, incoming_val)
        return EntailmentStep(
            prior=prior,
            rule=rule_name,
            entailed_label=entailed_label,
            hamming_distance=distance,
            varied_parameter=varied_param,
            prior_rank=prior_rank,
            incoming_rank=incoming_rank,
        )

    def evaluate(
        self,
        incoming: InformationFlowRequest,
        memory: UserDecisionMemory,
    ) -> EntailmentResult:
        """Execute Online Phase Algorithm 1 to classify incoming request R_u against memory D_u.

        Args:
            incoming: Target InformationFlowRequest R_u.
            memory: Historical UserDecisionMemory D_u.

        Returns:
            EntailmentResult containing DecisionLabel and full EntailmentProof.
        """
        target_incoming = InformationFlowRequest.coerce(incoming)
        active_mapper = self._resolve_active_mapper(memory)
        coerced_records = [
            rec
            if isinstance(rec, PriorDecisionRecord)
            else PriorDecisionRecord(InformationFlowRequest.coerce(rec.request), rec.label)
            for rec in memory.records
        ]
        coerced_memory = UserDecisionMemory(user_id=memory.user_id, records=coerced_records)
        neighborhood = coerced_memory.neighbors(target_incoming, max_distance=self.max_neighbor_distance)

        c_plus = 0
        c_minus = 0
        entailed_steps: list[EntailmentStep] = []

        for prior in neighborhood:
            if check_entailment_rule_1(prior, target_incoming, self.ontology_set, active_mapper):
                c_minus += 1
                entailed_steps.append(
                    self._build_step(
                        prior=prior,
                        incoming=target_incoming,
                        rule_name=RULE_1_NAME,
                        entailed_label=DecisionLabel.INAPPROPRIATE,
                        active_mapper=active_mapper,
                    )
                )
            elif check_entailment_rule_2(prior, target_incoming, self.ontology_set, active_mapper):
                c_plus += 1
                entailed_steps.append(
                    self._build_step(
                        prior=prior,
                        incoming=target_incoming,
                        rule_name=RULE_2_NAME,
                        entailed_label=DecisionLabel.APPROPRIATE,
                        active_mapper=active_mapper,
                    )
                )

        if c_plus > 0 and c_minus == 0:
            label = DecisionLabel.APPROPRIATE
            abstention_reason: str | None = None
            escalate_to_user = False
        elif c_minus > 0 and c_plus == 0:
            label = DecisionLabel.INAPPROPRIATE
            abstention_reason = None
            escalate_to_user = False
        else:
            label = DecisionLabel.UNDETERMINED
            escalate_to_user = True
            if c_plus > 0 and c_minus > 0:
                abstention_reason = ABSTENTION_CONTRADICTORY_PRIORS
            elif not neighborhood:
                abstention_reason = ABSTENTION_EMPTY_NEIGHBORHOOD
            else:
                abstention_reason = ABSTENTION_NON_ENTAILED_BOUNDARY

        proof = EntailmentProof(
            neighbors_checked=len(neighborhood),
            entailed_steps=entailed_steps,
            c_plus=c_plus,
            c_minus=c_minus,
            abstention_reason=abstention_reason,
            escalate_to_user=escalate_to_user,
            neighbor_records=tuple(neighborhood),
        )
        return EntailmentResult(label=label, proof=proof)

    def solve(
        self,
        incoming: InformationFlowRequest,
        memory: UserDecisionMemory,
    ) -> EntailmentResult:
        """Alias for evaluate(incoming, memory)."""
        return self.evaluate(incoming, memory)

    def predict(
        self,
        incoming: InformationFlowRequest,
        memory: UserDecisionMemory,
    ) -> DecisionLabel:
        """Return only the resolved DecisionLabel for incoming against memory."""
        return self.evaluate(incoming, memory).label
