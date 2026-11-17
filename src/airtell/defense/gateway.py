"""Systemic failure mode taxonomy, edge logical offloading, and unified defense gateway.

Unifies software Contextual Integrity (CI) neurosymbolic entailment, all four systemic
privacy failure-mode mitigations (`DEFAULT_TO_INAPPROPRIATE`, `CONTRADICTORY_PRIORS`,
`ONTOLOGY_HIERARCHY_MISALIGNMENT`, `IMPLICIT_CONSENT_TRAP`), lightweight edge ontology
extraction (`p_O <- theta(O, p)`), cryptographic HMAC-SHA256 local opt-out enforcement,
and `IDBLEEDSideChannelMonitor` physical link-layer hardening.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, ValidationError, model_validator

from airtell.defense.monitor import (
    IDBLEEDSideChannelMonitor,
    MonitoredFrameDecision,
    SideChannelExposureReport,
)

CI_PARAMETERS: tuple[str, str, str, str, str] = (
    "data_type",
    "data_subject",
    "data_sender",
    "data_recipient",
    "transmission_principle",
)

DEFAULT_DYNAMIC_ROLES: frozenset[str] = frozenset(
    {"housemate", "roommate", "partner", "teammate", "neighbor", "acquaintance"}
)

AMBIENT_TRANSMISSION_INDICATORS: frozenset[str] = frozenset(
    {
        "passive_ambient_sensing",
        "ambient_background_collection",
        "implicit_beacon_harvesting",
        "pervasive_telemetry",
    }
)

_LEVEL_PATTERN = re.compile(r"^L([1-9][0-9]*)$")


class DefenseDecisionLabel(str, Enum):
    """Canonical 3-valued Contextual Integrity privacy decision label."""

    APPROPRIATE = "appropriate"
    INAPPROPRIATE = "inappropriate"
    UNDETERMINED = "undetermined"


class FailureMode(str, Enum):
    """Taxonomy of systemic failure modes in neurosymbolic & ambient privacy systems."""

    DEFAULT_TO_INAPPROPRIATE = "default_to_inappropriate"
    CONTRADICTORY_PRIORS = "contradictory_priors"
    ONTOLOGY_HIERARCHY_MISALIGNMENT = "ontology_hierarchy_misalignment"
    IMPLICIT_CONSENT_TRAP = "implicit_consent_trap"


@runtime_checkable
class InformationFlowProtocol(Protocol):
    """Structural 5-tuple Contextual Integrity request protocol (`R = {d_u, u, s, r, t}`)."""

    data_type: str
    data_subject: str
    data_sender: str
    data_recipient: str
    transmission_principle: str


@runtime_checkable
class UserMemoryProtocol(Protocol):
    """Structural user decision memory protocol (`D_u`) compatible with `airtell.ariel`."""

    user_id: str
    records: Sequence[Any]


@dataclass(frozen=True)
class FlowRequest:
    """Standalone Contextual Integrity 5-tuple compatible with `InformationFlowRequest`."""

    data_type: str
    data_subject: str
    data_sender: str
    data_recipient: str
    transmission_principle: str

    def as_dict(self) -> dict[str, str]:
        """Return parameter dictionary representation."""
        return {param: str(getattr(self, param)) for param in CI_PARAMETERS}

    def hamming_distance(self, other: InformationFlowProtocol | Any) -> int:
        """Compute parameter-level Hamming distance against another 5-tuple request."""
        return sum(1 for param in CI_PARAMETERS if str(getattr(self, param)) != str(getattr(other, param)))

    def differing_parameters(self, other: InformationFlowProtocol | Any) -> list[tuple[str, str, str]]:
        """Return `(parameter, self_val, other_val)` for each differing CI parameter."""
        diffs: list[tuple[str, str, str]] = []
        for param in CI_PARAMETERS:
            left_val = str(getattr(self, param))
            right_val = str(getattr(other, param))
            if left_val != right_val:
                diffs.append((param, left_val, right_val))
        return diffs


@dataclass(frozen=True)
class PriorRecord:
    """Historical user decision record `(R', l')` in `D_u`."""

    request: FlowRequest | Any
    label: DefenseDecisionLabel | str

    def __post_init__(self) -> None:
        normalized = _normalize_decision_label(self.label)
        if normalized not in (
            DefenseDecisionLabel.APPROPRIATE.value,
            DefenseDecisionLabel.INAPPROPRIATE.value,
        ):
            raise ValueError(f"PriorRecord label must be 'appropriate' or 'inappropriate', got {self.label!r}")


@dataclass
class UserMemory:
    """User historical decision memory `D_u` compatible with `UserDecisionMemory`."""

    user_id: str
    records: list[PriorRecord] = field(default_factory=list)

    def neighbors(
        self,
        incoming: InformationFlowProtocol | Any,
        max_distance: int = 1,
    ) -> list[PriorRecord]:
        """Return records within Hamming distance `<= max_distance` of `incoming`."""
        return [rec for rec in self.records if _hamming_distance(rec.request, incoming) <= max_distance]

    def slice_memory(self, max_records: int) -> UserMemory:
        """Return a sliced memory view containing at most `max_records` prior records."""
        return UserMemory(user_id=self.user_id, records=list(self.records[:max_records]))

    def add_record(self, request: FlowRequest | Any, label: DefenseDecisionLabel | str) -> None:
        """Append a validated prior decision record."""
        self.records.append(PriorRecord(request=request, label=label))


@dataclass(frozen=True)
class DefenseParameterOntology:
    """Ranked hierarchy for a single CI parameter (`L1` < `L2` < `L3` ...)."""

    parameter: str
    levels: Mapping[str, Sequence[str]]

    def rank_map(self) -> dict[str, int]:
        """Build `entity -> integer rank` dictionary."""
        mapping: dict[str, int] = {}
        for level_key, items in self.levels.items():
            rank = _parse_level_rank(level_key)
            if rank is not None:
                for item in items:
                    mapping[str(item)] = rank
        return mapping

    def valid_ranks(self) -> set[int]:
        """Return set of defined integer level ranks."""
        ranks: set[int] = set()
        for level_key in self.levels:
            rank = _parse_level_rank(level_key)
            if rank is not None:
                ranks.add(rank)
        return ranks

    def rank_of(self, value: str) -> int | None:
        """Look up integer rank of `value` (`None` if unmapped)."""
        return self.rank_map().get(value)


@dataclass(frozen=True)
class DefenseOntologySet:
    """Domain ontology collection `O` across the 5 Contextual Integrity parameters."""

    domain: str
    parameters: Mapping[str, DefenseParameterOntology]

    def get_parameter_ontology(self, param_name: str) -> DefenseParameterOntology | None:
        """Retrieve parameter ontology by CI parameter name."""
        return self.parameters.get(param_name)


def _parse_level_rank(level_key: str | int) -> int | None:
    if isinstance(level_key, int):
        return level_key if level_key >= 1 else None
    match = _LEVEL_PATTERN.match(str(level_key).strip())
    if match is None:
        return None
    return int(match.group(1))


def _normalize_decision_label(label: Any) -> str:
    if isinstance(label, Enum):
        return str(label.value).lower()
    return str(label).strip().lower()


def _hamming_distance(left: InformationFlowProtocol | Any, right: InformationFlowProtocol | Any) -> int:
    return sum(1 for param in CI_PARAMETERS if str(getattr(left, param)) != str(getattr(right, param)))


def _extract_value_ranks(ontology_set: Any, param_name: str) -> tuple[dict[str, int], set[int]]:
    """Introspect either `DefenseOntologySet` or duck-typed `airtell.ariel.OntologySet`."""
    if ontology_set is None:
        return {}, set()

    param_ont: Any = None
    if hasattr(ontology_set, "get_parameter_ontology"):
        param_ont = ontology_set.get_parameter_ontology(param_name)
    elif hasattr(ontology_set, "parameters") and isinstance(ontology_set.parameters, Mapping):
        param_ont = ontology_set.parameters.get(param_name)
    elif hasattr(ontology_set, "ontologies") and isinstance(ontology_set.ontologies, Mapping):
        param_ont = ontology_set.ontologies.get(param_name)
    elif hasattr(ontology_set, param_name):
        param_ont = getattr(ontology_set, param_name)
    elif isinstance(ontology_set, Mapping):
        param_ont = ontology_set.get(param_name)

    if param_ont is None:
        return {}, set()

    if isinstance(param_ont, DefenseParameterOntology):
        return param_ont.rank_map(), param_ont.valid_ranks()

    ranks: dict[str, int] = {}
    valid_levels: set[int] = set()

    for dict_attr in ("value_to_rank", "ranks", "entity_to_rank"):
        candidate = getattr(param_ont, dict_attr, None)
        if isinstance(candidate, Mapping):
            for entity, rank_val in candidate.items():
                if isinstance(rank_val, int) and rank_val >= 1:
                    ranks[str(entity)] = rank_val
                    valid_levels.add(rank_val)
            if ranks:
                return ranks, valid_levels

    levels_attr = getattr(param_ont, "levels", None)
    if isinstance(levels_attr, Mapping):
        for level_key, entities in levels_attr.items():
            rank = _parse_level_rank(level_key)
            if rank is not None:
                valid_levels.add(rank)
                if isinstance(entities, Sequence) and not isinstance(entities, (str, bytes)):
                    for ent in entities:
                        ranks[str(ent)] = rank
        return ranks, valid_levels

    return {}, set()


# ---------------------------------------------------------------------------
# Cryptographic Local Opt-Out Switch (`IMPLICIT_CONSENT_TRAP` mitigation)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SignedOptOutDirective:
    """HMAC-SHA256 authenticated local opt-out state record for `(user_id, domain)`."""

    user_id: str
    domain: str
    opted_out: bool
    issued_at: float
    nonce: str
    signature_hex: str


class CryptographicLocalOptOutSwitch:
    """Tamper-evident local opt-out registry backed by HMAC-SHA256 authentication.

    Mitigates `FailureMode.IMPLICIT_CONSENT_TRAP` by ensuring user opt-out state
    cannot be silently cleared or forged by untrusted ambient applications. If a
    stored opt-out record fails HMAC-SHA256 verification, the switch fails closed.
    """

    def __init__(self, secret_key: bytes) -> None:
        """Initialize the switch with an HMAC secret key (`>= 16` bytes).

        Args:
            secret_key: Secret key bytes for HMAC-SHA256 signing and verification.

        Raises:
            ValueError: If `secret_key` is shorter than 16 bytes.
        """
        if len(secret_key) < 16:
            raise ValueError("HMAC secret_key must be at least 16 bytes")
        self._secret_key: bytes = bytes(secret_key)
        self._directives: dict[tuple[str, str], SignedOptOutDirective] = {}

    def _compute_hmac(
        self,
        user_id: str,
        domain: str,
        opted_out: bool,
        issued_at: float,
        nonce: str,
    ) -> str:
        canonical = f"{user_id}|{domain}|{1 if opted_out else 0}|{issued_at:.6f}|{nonce}"
        return hmac.new(
            self._secret_key,
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def set_opt_out(
        self,
        user_id: str,
        domain: str = "*",
        opted_out: bool = True,
        *,
        timestamp: float | None = None,
        nonce: str | None = None,
    ) -> SignedOptOutDirective:
        """Sign and persist a local opt-out state transition for `(user_id, domain)`."""
        if not user_id.strip():
            raise ValueError("user_id must be a non-empty string")
        if not domain.strip():
            raise ValueError("domain must be a non-empty string")

        issued_at = time.time() if timestamp is None else float(timestamp)
        resolved_nonce = secrets.token_hex(8) if nonce is None else str(nonce)
        sig = self._compute_hmac(user_id, domain, opted_out, issued_at, resolved_nonce)
        directive = SignedOptOutDirective(
            user_id=user_id,
            domain=domain,
            opted_out=opted_out,
            issued_at=issued_at,
            nonce=resolved_nonce,
            signature_hex=sig,
        )
        self._directives[(user_id, domain)] = directive
        return directive

    def verify_directive(self, directive: SignedOptOutDirective) -> bool:
        """Verify HMAC-SHA256 integrity of a `SignedOptOutDirective` in constant time."""
        expected = self._compute_hmac(
            directive.user_id,
            directive.domain,
            directive.opted_out,
            directive.issued_at,
            directive.nonce,
        )
        return hmac.compare_digest(expected, directive.signature_hex)

    def inject_directive_for_audit(self, directive: SignedOptOutDirective) -> None:
        """Insert a raw directive directly into storage to audit tamper fail-closed behavior."""
        self._directives[(directive.user_id, directive.domain)] = directive

    def check_opt_out_status(self, user_id: str, domain: str) -> tuple[bool, bool, str]:
        """Evaluate `(opted_out, signature_valid, reason)` for `(user_id, domain)`.

        Checks both the exact `(user_id, domain)` entry and wildcard `(user_id, "*")`.
        Any signature failure triggers immediate fail-closed blocking (`opted_out=True`).
        """
        candidates: list[SignedOptOutDirective] = []
        exact = self._directives.get((user_id, domain))
        if exact is not None:
            candidates.append(exact)
        wildcard = self._directives.get((user_id, "*"))
        if wildcard is not None and domain != "*":
            candidates.append(wildcard)

        if not candidates:
            return False, True, "No local opt-out directive active"

        for directive in candidates:
            if not self.verify_directive(directive):
                return (
                    True,
                    False,
                    "Tampered local opt-out HMAC signature detected; failing closed",
                )

        for directive in candidates:
            if directive.opted_out:
                return (
                    True,
                    True,
                    f"Verified cryptographic opt-out active for domain '{directive.domain}'",
                )

        return False, True, "Verified cryptographic opt-in state"

    def is_opted_out(self, user_id: str, domain: str = "*") -> bool:
        """Return `True` if opted out or if local opt-out storage failed HMAC verification."""
        opted_out, _valid, _reason = self.check_opt_out_status(user_id, domain)
        return opted_out


# ---------------------------------------------------------------------------
# Lightweight Edge Logical Offloading (`p_O <- theta(O, p)` + host `<=_O`)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EdgeModelProfile:
    """Hardware/runtime deployment profile for lightweight edge ontology extraction."""

    model_id: str = "gemma-3-4b-it"
    parameter_count_billions: float = 4.0
    quantization: str = "int4"
    max_output_tokens: int = 256
    temperature: float = 0.0


class EdgeParameterMappingSchema(BaseModel):
    """Strict Pydantic v2 schema validating `p_O <- theta(O, p)` JSON outputs."""

    model_config = ConfigDict(extra="forbid", strict=True)

    parameter: str
    value: str
    level: str
    rank: int

    @model_validator(mode="after")
    def _validate_consistency(self) -> EdgeParameterMappingSchema:
        if self.parameter not in CI_PARAMETERS:
            raise ValueError(f"Unknown CI parameter: {self.parameter!r}")
        if not self.value.strip():
            raise ValueError("Mapped value must not be empty")
        parsed_rank = _parse_level_rank(self.level)
        if parsed_rank is None:
            raise ValueError(f"Level must match 'L<positive_int>', got {self.level!r}")
        if parsed_rank != self.rank:
            raise ValueError(f"Inconsistent level {self.level!r} and integer rank {self.rank}")
        return self


class LightweightEdgeOntologyOffloader:
    """Edge deployment runtime separating neural ontology mapping from symbolic `<=_O`.

    Models an on-device lightweight model (default `gemma-3-4b-it`) that extracts
    structured parameter levels `p_O <- theta(O, p)` validated against a strict
    Pydantic v2 JSON schema, while executing the partial-order check `R' <=_O R`
    deterministically on the host solver runtime.
    """

    def __init__(
        self,
        profile: EdgeModelProfile | None = None,
        *,
        edge_inference_fn: Callable[[str, str, Any], str | None] | None = None,
    ) -> None:
        """Initialize the edge offloader.

        Args:
            profile: Edge LLM hardware/quantization profile (`gemma-3-4b-it` default).
            edge_inference_fn: Optional callable `(param_name, value, ontology_set) -> raw_json`
                modeling on-device model generation. Defaults to deterministic JSON extraction
                over `ontology_set`.
        """
        self.profile: EdgeModelProfile = profile or EdgeModelProfile()
        self._edge_inference_fn = edge_inference_fn
        self._cache: dict[tuple[int, str, str], int] = {}
        self.extractions_attempted: int = 0
        self.extractions_succeeded: int = 0
        self.validation_rejections: int = 0

    def _default_edge_json_emitter(
        self,
        param_name: str,
        value: str,
        ontology_set: Any,
    ) -> str | None:
        ranks, _valid = _extract_value_ranks(ontology_set, param_name)
        rank = ranks.get(value)
        if rank is None:
            if hasattr(ontology_set, "rank_of"):
                maybe_rank = ontology_set.rank_of(param_name, value)
                if isinstance(maybe_rank, int):
                    rank = maybe_rank
        if rank is None:
            return None
        return json.dumps(
            {
                "parameter": param_name,
                "value": value,
                "level": f"L{rank}",
                "rank": rank,
            }
        )

    def map_parameter(
        self,
        ontology_set: Any,
        param_name: str,
        value: str,
    ) -> int | None:
        """Extract and validate integer ontology rank `p_O <- theta(O, p)`.

        Satisfies the `OntologyMapper` protocol (`map_parameter(ontology_set, param_name, value)`).
        """
        cache_key = (id(ontology_set), param_name, value)
        if self._edge_inference_fn is None and cache_key in self._cache:
            return self._cache[cache_key]

        self.extractions_attempted += 1
        emitter = self._edge_inference_fn or self._default_edge_json_emitter
        raw_json = emitter(param_name, value, ontology_set)
        if raw_json is None:
            return None

        try:
            validated = EdgeParameterMappingSchema.model_validate_json(raw_json)
        except (ValidationError, ValueError, TypeError):
            self.validation_rejections += 1
            return None

        if validated.parameter != param_name or validated.value != value:
            self.validation_rejections += 1
            return None

        _ranks, valid_ranks = _extract_value_ranks(ontology_set, param_name)
        if valid_ranks and validated.rank not in valid_ranks:
            self.validation_rejections += 1
            return None

        self.extractions_succeeded += 1
        if self._edge_inference_fn is None:
            self._cache[cache_key] = validated.rank
        return validated.rank

    def compare_partial_order(
        self,
        r_left: InformationFlowProtocol | Any,
        r_right: InformationFlowProtocol | Any,
        ontology_set: Any,
        *,
        role_overrides: Mapping[tuple[str, str], int | None] | None = None,
    ) -> bool:
        """Execute deterministic host partial-order check `R_left <=_O R_right` (Def. 4.1).

        Holds iff for all 5 CI parameters `p`, either `p_left == p_right` or both
        map to validated integer levels with `rank(p_left) <= rank(p_right)`.
        """
        overrides = role_overrides or {}
        for param in CI_PARAMETERS:
            left_val = str(getattr(r_left, param))
            right_val = str(getattr(r_right, param))
            if left_val == right_val:
                continue

            if (param, left_val) in overrides:
                left_rank = overrides[(param, left_val)]
            else:
                left_rank = self.map_parameter(ontology_set, param, left_val)

            if (param, right_val) in overrides:
                right_rank = overrides[(param, right_val)]
            else:
                right_rank = self.map_parameter(ontology_set, param, right_val)

            if left_rank is None or right_rank is None or left_rank > right_rank:
                return False

        return True


# ---------------------------------------------------------------------------
# Iterative Dynamic Role Memory Anchoring & Host Entailment Solver
# ---------------------------------------------------------------------------


def anchor_dynamic_roles_to_memory(
    request: InformationFlowProtocol | Any,
    user_memory: UserMemoryProtocol | Any,
    ontology_set: Any,
    offloader: LightweightEdgeOntologyOffloader,
    dynamic_roles: frozenset[str] = DEFAULT_DYNAMIC_ROLES,
) -> tuple[dict[tuple[str, str], int | None], bool]:
    """Tune and anchor dynamic social roles (e.g. `'housemate'`) to explicit user memory `D_u`.

    Mitigates `FailureMode.ONTOLOGY_HIERARCHY_MISALIGNMENT`:
    1. If a request involves a dynamic role `r_dyn` that has NO explicit prior record in
       `D_u`, unpins `r_dyn` (`None`) from generic static cross-role comparisons so
       another role (such as `'family'`) cannot falsely entail `appropriate` for `r_dyn`.
    2. If `D_u` contains explicit rejections for `r_dyn` while approving static peer roles
       of equal or higher rank, tunes `r_dyn`'s effective rank strictly above those
       approved peer roles (`max_approved_rank + 1`) so cross-role false approvals are
       eliminated while preserving single-role monotonicity on `r_dyn`.
    """
    overrides: dict[tuple[str, str], int | None] = {}
    mitigated = False
    records = list(getattr(user_memory, "records", ()))

    for role_param in ("data_recipient", "data_sender"):
        req_role = str(getattr(request, role_param))
        candidate_roles: set[str] = set()
        if req_role in dynamic_roles:
            candidate_roles.add(req_role)
        for rec in records:
            rec_role = str(getattr(rec.request, role_param))
            if rec_role in dynamic_roles and _hamming_distance(rec.request, request) <= 1:
                candidate_roles.add(rec_role)

        for dyn_role in candidate_roles:
            static_rank = offloader.map_parameter(ontology_set, role_param, dyn_role)
            dyn_records = [rec for rec in records if str(getattr(rec.request, role_param)) == dyn_role]
            if not dyn_records:
                if static_rank is not None:
                    overrides[(role_param, dyn_role)] = None
                    mitigated = True
                continue

            has_rejection = any(
                _normalize_decision_label(rec.label) == DefenseDecisionLabel.INAPPROPRIATE.value for rec in dyn_records
            )
            has_approval = any(
                _normalize_decision_label(rec.label) == DefenseDecisionLabel.APPROPRIATE.value for rec in dyn_records
            )

            approved_peer_ranks: list[int] = []
            rejected_peer_ranks: list[int] = []
            for rec in records:
                peer_role = str(getattr(rec.request, role_param))
                if peer_role == dyn_role:
                    continue
                peer_rank = offloader.map_parameter(ontology_set, role_param, peer_role)
                if peer_rank is None:
                    continue
                norm_label = _normalize_decision_label(rec.label)
                if norm_label == DefenseDecisionLabel.APPROPRIATE.value:
                    approved_peer_ranks.append(peer_rank)
                elif norm_label == DefenseDecisionLabel.INAPPROPRIATE.value:
                    rejected_peer_ranks.append(peer_rank)

            if has_rejection and not has_approval and approved_peer_ranks:
                max_approved = max(approved_peer_ranks)
                if static_rank is None or static_rank <= max_approved:
                    overrides[(role_param, dyn_role)] = max_approved + 1
                    mitigated = True
            elif has_approval and not has_rejection and rejected_peer_ranks:
                min_rejected = min(rejected_peer_ranks)
                if static_rank is None or static_rank >= min_rejected:
                    overrides[(role_param, dyn_role)] = min_rejected - 1 if min_rejected > 1 else None
                    mitigated = True

    return overrides, mitigated


@dataclass(frozen=True)
class ReferenceEntailmentResult:
    """Transparent entailment result produced by the built-in Algorithm 1 solver."""

    decision: DefenseDecisionLabel
    neighbors_checked: int
    entailed_steps: tuple[str, ...]
    c_plus: int
    c_minus: int
    abstention_reason: str | None
    escalate_to_user: bool


class ReferenceEntailmentSolver:
    """Deterministic host solver implementing Definitions 4.1, 4.2, and Algorithm 1."""

    def __init__(
        self,
        ontology_set: Any,
        offloader: LightweightEdgeOntologyOffloader,
    ) -> None:
        self.ontology_set = ontology_set
        self.offloader = offloader

    def evaluate(
        self,
        request: InformationFlowProtocol | Any,
        user_memory: UserMemoryProtocol | Any,
        *,
        ontology_set: Any | None = None,
        role_overrides: Mapping[tuple[str, str], int | None] | None = None,
    ) -> ReferenceEntailmentResult:
        """Run single-parameter (`d <= 1`) monotonic entailment over `user_memory`."""
        active_ont = ontology_set if ontology_set is not None else self.ontology_set
        records = list(getattr(user_memory, "records", ()))
        neighbors = [rec for rec in records if _hamming_distance(rec.request, request) <= 1]

        if not neighbors:
            return ReferenceEntailmentResult(
                decision=DefenseDecisionLabel.UNDETERMINED,
                neighbors_checked=0,
                entailed_steps=(),
                c_plus=0,
                c_minus=0,
                abstention_reason="empty_neighborhood",
                escalate_to_user=True,
            )

        c_plus = 0
        c_minus = 0
        steps: list[str] = []

        for rec in neighbors:
            norm_label = _normalize_decision_label(rec.label)
            if norm_label == DefenseDecisionLabel.INAPPROPRIATE.value:
                # Rule 1: l' == INAPPROPRIATE and R' <=_O R => (R, INAPPROPRIATE)
                if self.offloader.compare_partial_order(
                    rec.request,
                    request,
                    active_ont,
                    role_overrides=role_overrides,
                ):
                    c_minus += 1
                    steps.append("Rule 1 (inappropriate upward sensitivity/risk entailment)")
            elif norm_label == DefenseDecisionLabel.APPROPRIATE.value:
                # Rule 2: l' == APPROPRIATE and R <=_O R' => (R, APPROPRIATE)
                if self.offloader.compare_partial_order(
                    request,
                    rec.request,
                    active_ont,
                    role_overrides=role_overrides,
                ):
                    c_plus += 1
                    steps.append("Rule 2 (appropriate downward sensitivity/risk entailment)")

        if c_plus > 0 and c_minus == 0:
            return ReferenceEntailmentResult(
                decision=DefenseDecisionLabel.APPROPRIATE,
                neighbors_checked=len(neighbors),
                entailed_steps=tuple(steps),
                c_plus=c_plus,
                c_minus=0,
                abstention_reason=None,
                escalate_to_user=False,
            )
        if c_minus > 0 and c_plus == 0:
            return ReferenceEntailmentResult(
                decision=DefenseDecisionLabel.INAPPROPRIATE,
                neighbors_checked=len(neighbors),
                entailed_steps=tuple(steps),
                c_plus=0,
                c_minus=c_minus,
                abstention_reason=None,
                escalate_to_user=False,
            )
        if c_plus > 0 and c_minus > 0:
            return ReferenceEntailmentResult(
                decision=DefenseDecisionLabel.UNDETERMINED,
                neighbors_checked=len(neighbors),
                entailed_steps=tuple(steps),
                c_plus=c_plus,
                c_minus=c_minus,
                abstention_reason="contradictory_priors",
                escalate_to_user=True,
            )

        return ReferenceEntailmentResult(
            decision=DefenseDecisionLabel.UNDETERMINED,
            neighbors_checked=len(neighbors),
            entailed_steps=(),
            c_plus=0,
            c_minus=0,
            abstention_reason="non_entailed_boundary",
            escalate_to_user=True,
        )


def _invoke_duck_typed_solver(
    solver: Any,
    request: InformationFlowProtocol | Any,
    user_memory: UserMemoryProtocol | Any,
) -> tuple[str, int, int, str | None, bool]:
    """Invoke an injected `ARIELSolver` or custom solver via structural duck-typing."""
    raw_out: Any = None
    for method_name in ("evaluate", "solve", "infer", "decide"):
        fn = getattr(solver, method_name, None)
        if callable(fn):
            raw_out = fn(request, user_memory)
            break
    else:
        if callable(solver):
            raw_out = solver(request, user_memory)
        else:
            raise TypeError(
                f"Unsupported solver object of type {type(solver).__name__}; expected "
                ".evaluate(request, memory) or .solve(request, memory)"
            )

    if isinstance(raw_out, tuple) and len(raw_out) == 2:
        raw_label, proof = raw_out
        decision = _normalize_decision_label(raw_label)
        c_plus = int(getattr(proof, "c_plus", 0))
        c_minus = int(getattr(proof, "c_minus", 0))
        abstention_reason = getattr(proof, "abstention_reason", None)
        escalate = bool(getattr(proof, "escalate_to_user", decision == "undetermined"))
        return decision, c_plus, c_minus, abstention_reason, escalate

    label_attr = getattr(raw_out, "decision", getattr(raw_out, "label", raw_out))
    proof_obj = getattr(raw_out, "proof", raw_out)
    decision = _normalize_decision_label(label_attr)
    c_plus = int(getattr(proof_obj, "c_plus", 0))
    c_minus = int(getattr(proof_obj, "c_minus", 0))
    abstention_reason = getattr(proof_obj, "abstention_reason", None)
    escalate = bool(getattr(proof_obj, "escalate_to_user", decision == "undetermined"))
    return decision, c_plus, c_minus, abstention_reason, escalate


# ---------------------------------------------------------------------------
# Unified Operational Defense Gateway
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GatewayDefenseVerdict:
    """Unified software + physical-layer verdict emitted by `IntegratedDefenseGateway`."""

    decision: str
    flow_allowed: bool
    escalate_to_user: bool
    automated_execution_halted: bool
    abstention_reason: str | None
    c_plus: int
    c_minus: int
    mitigated_failure_modes: tuple[FailureMode, ...]
    opt_out_verified: bool
    opted_out: bool
    frame_decisions: tuple[MonitoredFrameDecision, ...]
    exposure_report: SideChannelExposureReport
    edge_offloaded: bool
    reason: str


class IntegratedDefenseGateway:
    """Unified operational defense gateway bridging CI logical entailment and BLE hardening."""

    def __init__(
        self,
        *,
        ontology_set: Any | None = None,
        solver: Any | None = None,
        edge_offloader: LightweightEdgeOntologyOffloader | None = None,
        side_channel_monitor: IDBLEEDSideChannelMonitor | None = None,
        opt_out_switch: CryptographicLocalOptOutSwitch | None = None,
        dynamic_roles: set[str] | frozenset[str] | None = None,
        domain: str = "default",
    ) -> None:
        """Initialize the unified defense gateway.

        Args:
            ontology_set: Domain ontology `O` (`DefenseOntologySet` or `airtell.ariel.OntologySet`).
            solver: Optional external entailment solver (`ARIELSolver` or duck-typed equivalent).
            edge_offloader: Optional `LightweightEdgeOntologyOffloader` for `p_O <- theta(O, p)`.
            side_channel_monitor: Optional `IDBLEEDSideChannelMonitor` instance.
            opt_out_switch: Optional `CryptographicLocalOptOutSwitch` instance.
            dynamic_roles: Dynamic social roles requiring explicit `D_u` anchoring.
            domain: Default domain name for local opt-out verification.
        """
        self.ontology_set = ontology_set
        self.solver = solver
        self.edge_offloader = edge_offloader or LightweightEdgeOntologyOffloader()
        self.side_channel_monitor = side_channel_monitor or IDBLEEDSideChannelMonitor()
        self.opt_out_switch = opt_out_switch or CryptographicLocalOptOutSwitch(secrets.token_bytes(32))
        self.dynamic_roles: frozenset[str] = (
            frozenset(dynamic_roles) if dynamic_roles is not None else DEFAULT_DYNAMIC_ROLES
        )
        self.domain = domain

    def evaluate_and_enforce(
        self,
        request: InformationFlowProtocol | Any,
        user_memory: UserMemoryProtocol | Any,
        *,
        ble_frames: Sequence[Any] | None = None,
        domain: str | None = None,
        is_ambient_flow: bool = False,
        active_agent_authorized: bool = True,
        ontology_set: Any | None = None,
        elapsed_ms_per_frame: Sequence[float] | float | None = None,
    ) -> GatewayDefenseVerdict:
        """Evaluate software CI entailment, enforce all 4 failure guards, and harden BLE frames."""
        active_domain = domain or self.domain
        active_ont = ontology_set if ontology_set is not None else self.ontology_set
        user_id = str(getattr(user_memory, "user_id", getattr(request, "data_subject", "user")))

        mitigated: list[FailureMode] = []
        opted_out, opt_out_verified, opt_out_msg = self.opt_out_switch.check_opt_out_status(user_id, active_domain)

        # 1. Guard 4a: Cryptographic local opt-out / tamper fail-closed check
        if opted_out or not opt_out_verified:
            mitigated.append(FailureMode.IMPLICIT_CONSENT_TRAP)
            decision = DefenseDecisionLabel.INAPPROPRIATE.value
            flow_allowed = False
            escalate = not opt_out_verified
            halted = True
            c_plus = 0
            c_minus = 0
            abstention_reason = "opt_out_integrity_failure" if not opt_out_verified else None
            edge_used = False
            verdict_reason = opt_out_msg
        else:
            # 2. Guard 3: Dynamic social role anchoring against explicit user memory D_u
            role_overrides, misalignment_fixed = anchor_dynamic_roles_to_memory(
                request=request,
                user_memory=user_memory,
                ontology_set=active_ont,
                offloader=self.edge_offloader,
                dynamic_roles=self.dynamic_roles,
            )
            if misalignment_fixed:
                mitigated.append(FailureMode.ONTOLOGY_HIERARCHY_MISALIGNMENT)

            # 3. Entailment evaluation (external solver or edge-offloaded host solver)
            if self.solver is not None and not misalignment_fixed:
                decision, c_plus, c_minus, abstention_reason, escalate = _invoke_duck_typed_solver(
                    self.solver, request, user_memory
                )
                edge_used = False
            else:
                ref_solver = ReferenceEntailmentSolver(active_ont, self.edge_offloader)
                ref_res = ref_solver.evaluate(
                    request,
                    user_memory,
                    ontology_set=active_ont,
                    role_overrides=role_overrides,
                )
                decision = ref_res.decision.value
                c_plus = ref_res.c_plus
                c_minus = ref_res.c_minus
                abstention_reason = ref_res.abstention_reason
                escalate = ref_res.escalate_to_user
                edge_used = True

            halted = False

            # 4. Guard 2: Contradictory priors (c_plus > 0 and c_minus > 0)
            if c_plus > 0 and c_minus > 0:
                if FailureMode.CONTRADICTORY_PRIORS not in mitigated:
                    mitigated.append(FailureMode.CONTRADICTORY_PRIORS)
                decision = DefenseDecisionLabel.UNDETERMINED.value
                abstention_reason = "contradictory_priors"
                escalate = True
                halted = True

            # 5. Guard 1: Prevent silent default-to-inappropriate when <=_O is unsatisfied
            elif c_plus == 0 and c_minus == 0:
                if FailureMode.DEFAULT_TO_INAPPROPRIATE not in mitigated:
                    mitigated.append(FailureMode.DEFAULT_TO_INAPPROPRIATE)
                decision = DefenseDecisionLabel.UNDETERMINED.value
                if abstention_reason is None:
                    abstention_reason = "non_entailed_boundary"
                escalate = True

            # 6. Guard 4b: Pervasive / ambient sensing flows require active agent authorization
            tp_val = str(getattr(request, "transmission_principle", "")).strip().lower()
            ambient_detected = is_ambient_flow or tp_val in AMBIENT_TRANSMISSION_INDICATORS
            if ambient_detected and not active_agent_authorized:
                if FailureMode.IMPLICIT_CONSENT_TRAP not in mitigated:
                    mitigated.append(FailureMode.IMPLICIT_CONSENT_TRAP)
                halted = True
                escalate = True
                if decision == DefenseDecisionLabel.APPROPRIATE.value:
                    decision = DefenseDecisionLabel.UNDETERMINED.value
                    abstention_reason = "ambient_flow_requires_active_authorization"

            flow_allowed = decision == DefenseDecisionLabel.APPROPRIATE.value and not halted
            verdict_reason = f"Entailment decision='{decision}' (c_plus={c_plus}, c_minus={c_minus})"

        # 7. Physical Link-Layer Side-Channel Hardening
        frame_decisions: list[MonitoredFrameDecision] = []
        frames_seq = list(ble_frames) if ble_frames is not None else []
        for idx, frame in enumerate(frames_seq):
            if isinstance(elapsed_ms_per_frame, (int, float)):
                frame_elapsed: float | None = float(elapsed_ms_per_frame)
            elif isinstance(elapsed_ms_per_frame, Sequence):
                frame_elapsed = float(elapsed_ms_per_frame[idx]) if idx < len(elapsed_ms_per_frame) else None
            else:
                frame_elapsed = None

            f_dec = self.side_channel_monitor.inspect_frame(
                frame,
                elapsed_ms=frame_elapsed,
                suppress_unauthenticated_handshakes=not flow_allowed,
            )
            frame_decisions.append(f_dec)

        exposure_report = self.side_channel_monitor.compute_exposure_report()

        return GatewayDefenseVerdict(
            decision=decision,
            flow_allowed=flow_allowed,
            escalate_to_user=escalate,
            automated_execution_halted=halted,
            abstention_reason=abstention_reason,
            c_plus=c_plus,
            c_minus=c_minus,
            mitigated_failure_modes=tuple(mitigated),
            opt_out_verified=opt_out_verified,
            opted_out=opted_out,
            frame_decisions=tuple(frame_decisions),
            exposure_report=exposure_report,
            edge_offloaded=edge_used,
            reason=verdict_reason,
        )
