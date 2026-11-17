"""Hierarchical domain ontologies, strict Pydantic v2 JSON validation, and <=_O partial order.

Implements ranked ontology levels (L1, L2, ... -> integer ranks 1, 2, ... where lower integer
rank represents lower data sensitivity, lower recipient exposure risk, or lower transmission
risk), strict anti-hallucination schema parsing, structured and memory-anchored mappers, and
Definition 4.1 formal partial order comparisons.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, ValidationInfo, field_validator, model_validator

from airtell.ariel.models import (
    CI_PARAMETERS,
    DecisionLabel,
    InformationFlowRequest,
    UserDecisionMemory,
)

LEVEL_PATTERN = re.compile(r"^L([1-9][0-9]*)$")

DEFAULT_DYNAMIC_ROLES: frozenset[str] = frozenset(
    {
        "housemate",
        "roommate",
        "partner",
        "acquaintance",
    }
)


def level_to_rank(level: str | int) -> int:
    """Convert an ontology level label ('L1', 'L2', ...) or positive integer into an int rank.

    Args:
        level: Ranked level label matching '^L[1-9][0-9]*$' or a positive integer >= 1.

    Returns:
        Positive integer rank (1, 2, 3, ...).

    Raises:
        TypeError: If level is a boolean or neither str nor int.
        ValueError: If level is < 1 or does not match 'L<positive_int>'.
    """
    if isinstance(level, bool):
        raise TypeError("Ontology level rank cannot be a boolean.")
    if isinstance(level, int):
        if level < 1:
            raise ValueError(f"Ontology integer rank must be >= 1, got {level}.")
        return level
    if isinstance(level, str):
        match = LEVEL_PATTERN.match(level.strip())
        if match is None:
            raise ValueError(f"Invalid ontology level label {level!r}; expected 'L1', 'L2', ...")
        return int(match.group(1))
    raise TypeError(f"Expected str or int level, got {type(level).__name__}.")


def rank_to_level(rank: int) -> str:
    """Convert a positive integer rank (1, 2, ...) into canonical level string ('L1', 'L2', ...).

    Args:
        rank: Positive integer rank >= 1.

    Returns:
        Canonical level string such as 'L1'.

    Raises:
        TypeError: If rank is a boolean or not an int.
        ValueError: If rank < 1.
    """
    if isinstance(rank, bool) or not isinstance(rank, int):
        raise TypeError(f"Ontology rank must be an int, got {type(rank).__name__}.")
    if rank < 1:
        raise ValueError(f"Ontology rank must be >= 1, got {rank}.")
    return f"L{rank}"


@dataclass(frozen=True)
class ParameterOntology:
    """Ranked ontology hierarchy for a single Contextual Integrity parameter.

    Attributes:
        parameter_name: One of the five CI_PARAMETERS.
        entity_ranks: Mapping from canonical domain entity string to integer rank >= 1.
    """

    parameter_name: str
    entity_ranks: dict[str, int]
    _normalized_lookup: dict[str, int] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate parameter name, entity strings, and positive integer ranks."""
        if self.parameter_name not in CI_PARAMETERS:
            raise ValueError(f"Invalid CI parameter {self.parameter_name!r}; expected one of {CI_PARAMETERS}.")
        if not self.entity_ranks:
            raise ValueError(f"ParameterOntology for {self.parameter_name!r} cannot be empty.")

        cleaned: dict[str, int] = {}
        normalized: dict[str, int] = {}
        for entity, rank in self.entity_ranks.items():
            if not isinstance(entity, str) or not entity.strip():
                raise ValueError(f"Ontology entity must be a non-empty string, got {entity!r}.")
            int_rank = level_to_rank(rank)
            cleaned[entity] = int_rank
            norm_key = entity.strip().lower()
            if norm_key in normalized and normalized[norm_key] != int_rank:
                raise ValueError(
                    f"Ambiguous case-insensitive entity collision for {entity!r} in {self.parameter_name!r}."
                )
            normalized[norm_key] = int_rank

        object.__setattr__(self, "entity_ranks", cleaned)
        object.__setattr__(self, "_normalized_lookup", normalized)

    @classmethod
    def from_levels(
        cls,
        parameter_name: str,
        levels: Mapping[str | int, Sequence[str]],
    ) -> ParameterOntology:
        """Build a ParameterOntology from ranked level buckets ('L1' -> [...], 'L2' -> [...]).

        Args:
            parameter_name: Target CI parameter name.
            levels: Mapping from level key ('L1' or 1) to sequence of domain entities.

        Returns:
            Validated ParameterOntology instance.

        Raises:
            ValueError: If levels are empty, invalid, or assign an entity to multiple levels.
        """
        if not levels:
            raise ValueError(f"Levels mapping for {parameter_name!r} cannot be empty.")
        ranks: dict[str, int] = {}
        for level_key, entities in levels.items():
            rank = level_to_rank(level_key)
            if not entities:
                raise ValueError(f"Level {rank_to_level(rank)} in {parameter_name!r} cannot be empty.")
            for entity in entities:
                if not isinstance(entity, str) or not entity.strip():
                    raise ValueError(f"Invalid entity {entity!r} in {parameter_name!r}.")
                if entity in ranks:
                    raise ValueError(f"Duplicate entity {entity!r} assigned to multiple levels in {parameter_name!r}.")
                ranks[entity] = rank
        return cls(parameter_name=parameter_name, entity_ranks=ranks)

    @property
    def max_rank(self) -> int:
        """Highest integer rank present in this parameter ontology."""
        return max(self.entity_ranks.values())

    @property
    def ranks(self) -> dict[str, int]:
        """Dictionary view of entity-to-rank mappings for gateway protocol introspection."""
        return dict(self.entity_ranks)

    @property
    def levels(self) -> dict[str, list[str]]:
        """Ordered 'L1'..'Lk' level buckets view for gateway protocol introspection."""
        return self.to_levels_dict()

    def get_rank(self, value: str) -> int | None:
        """Look up the integer rank for an entity value, or None if unmapped.

        Args:
            value: Parameter entity string to resolve.

        Returns:
            Positive integer rank >= 1 if found, else None.
        """
        if not isinstance(value, str) or not value.strip():
            return None
        direct = self.entity_ranks.get(value)
        if direct is not None:
            return direct
        return self._normalized_lookup.get(value.strip().lower())

    def get_level(self, value: str) -> str | None:
        """Look up the canonical 'Lk' level label for value, or None if unmapped."""
        rank = self.get_rank(value)
        return rank_to_level(rank) if rank is not None else None

    def to_levels_dict(self) -> dict[str, list[str]]:
        """Serialize entity ranks into ordered 'L1', 'L2', ... buckets."""
        grouped: dict[int, list[str]] = {}
        for entity, rank in self.entity_ranks.items():
            grouped.setdefault(rank, []).append(entity)
        return {rank_to_level(rank): grouped[rank] for rank in sorted(grouped)}

    def with_entity_rank(self, value: str, rank: int) -> ParameterOntology:
        """Return a new ParameterOntology with value assigned to rank."""
        int_rank = level_to_rank(rank)
        updated = dict(self.entity_ranks)
        # Remove any existing case-equivalent key if updating with different casing
        norm_target = value.strip().lower()
        for existing_key in list(updated):
            if existing_key.strip().lower() == norm_target and existing_key != value:
                del updated[existing_key]
        updated[value] = int_rank
        return ParameterOntology(parameter_name=self.parameter_name, entity_ranks=updated)


@dataclass(frozen=True)
class OntologySet:
    """Domain ontology collection O across Contextual Integrity parameters.

    Attributes:
        domain: Domain identifier (e.g., 'SPA' or 'Education').
        ontologies: Mapping from CI parameter name to ParameterOntology.
        description: Optional human-readable description of domain conventions.
    """

    domain: str
    ontologies: dict[str, ParameterOntology]
    description: str = ""

    def __post_init__(self) -> None:
        """Validate domain name and ensure keys match ParameterOntology parameter_name."""
        if not isinstance(self.domain, str) or not self.domain.strip():
            raise ValueError("OntologySet domain must be a non-empty string.")
        if not self.ontologies:
            raise ValueError("OntologySet must define at least one ParameterOntology.")
        cleaned: dict[str, ParameterOntology] = {}
        for key, param_ont in self.ontologies.items():
            if key not in CI_PARAMETERS:
                raise ValueError(f"Unknown CI parameter {key!r} in OntologySet.")
            if not isinstance(param_ont, ParameterOntology):
                raise TypeError(f"Expected ParameterOntology for {key!r}, got {type(param_ont).__name__}.")
            if param_ont.parameter_name != key:
                raise ValueError(
                    f"Key {key!r} mismatches ParameterOntology.parameter_name {param_ont.parameter_name!r}."
                )
            cleaned[key] = param_ont
        object.__setattr__(self, "ontologies", cleaned)

    def get_parameter_ontology(self, param_name: str) -> ParameterOntology | None:
        """Return the ParameterOntology for param_name if present."""
        if param_name not in CI_PARAMETERS:
            raise ValueError(f"Unknown CI parameter {param_name!r}; expected one of {CI_PARAMETERS}.")
        return self.ontologies.get(param_name)

    def get_rank(self, param_name: str, value: str) -> int | None:
        """Return the integer rank of value under param_name in O, or None if unmapped."""
        param_ont = self.get_parameter_ontology(param_name)
        if param_ont is None:
            return None
        return param_ont.get_rank(value)

    def rank_of(self, param_name: str, value: str) -> int | None:
        """Alias for get_rank(param_name, value) supporting gateway protocol introspection."""
        return self.get_rank(param_name, value)

    def with_updated_rank(self, param_name: str, value: str, rank: int) -> OntologySet:
        """Return a new OntologySet with (param_name, value) updated or added at rank."""
        int_rank = level_to_rank(rank)
        updated_map = dict(self.ontologies)
        existing = updated_map.get(param_name)
        if existing is None:
            updated_map[param_name] = ParameterOntology(
                parameter_name=param_name,
                entity_ranks={value: int_rank},
            )
        else:
            updated_map[param_name] = existing.with_entity_rank(value, int_rank)
        return OntologySet(
            domain=self.domain,
            ontologies=updated_map,
            description=self.description,
        )

    def to_schema(self) -> OntologySchema:
        """Convert this OntologySet into a strictly validated OntologySchema."""
        params_payload = {
            param_name: self.ontologies[param_name].to_levels_dict()
            for param_name in CI_PARAMETERS
            if param_name in self.ontologies
        }
        return OntologySchema(
            domain=self.domain,
            parameters=params_payload,
            description=self.description if self.description else None,
        )

    def to_json(self, indent: int = 2) -> str:
        """Serialize this OntologySet as formatted strict JSON."""
        return self.to_schema().model_dump_json(indent=indent, exclude_none=True)

    @classmethod
    def from_schema(cls, schema: OntologySchema) -> OntologySet:
        """Construct an OntologySet from a validated OntologySchema."""
        return schema.to_ontology_set()


class OntologySchema(BaseModel):
    """Strict Pydantic v2 JSON schema for domain ontology hierarchies.

    Prevents generative hallucination by enforcing strict types, forbidding extra keys,
    validating CI parameter slots and 'L1'..'Lk' labels, rejecting duplicate entities,
    and optionally checking exact membership against allowed_entities context.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    domain: str
    parameters: dict[str, dict[str, list[str]]]
    description: str | None = None

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("domain must be a non-empty string.")
        return value

    @field_validator("parameters")
    @classmethod
    def _validate_parameters(
        cls,
        value: dict[str, dict[str, list[str]]],
    ) -> dict[str, dict[str, list[str]]]:
        if not value:
            raise ValueError("parameters dictionary cannot be empty.")

        for param_name, level_map in value.items():
            if param_name not in CI_PARAMETERS:
                raise ValueError(f"Unknown CI parameter {param_name!r}; expected subset of {CI_PARAMETERS}.")
            if not level_map:
                raise ValueError(f"Level map for {param_name!r} cannot be empty.")

            seen_entities: set[str] = set()
            for level_key, entities in level_map.items():
                level_to_rank(level_key)  # raises ValueError if not 'L1', 'L2', ...
                if not entities:
                    raise ValueError(f"Entity list for {param_name!r} level {level_key!r} cannot be empty.")
                for entity in entities:
                    if not entity.strip():
                        raise ValueError(f"Empty entity string in {param_name!r} level {level_key!r}.")
                    norm = entity.strip().lower()
                    if norm in seen_entities:
                        raise ValueError(f"Duplicate entity {entity!r} across levels in parameter {param_name!r}.")
                    seen_entities.add(norm)
        return value

    @model_validator(mode="after")
    def _validate_allowed_entities_context(self, info: ValidationInfo) -> OntologySchema:
        context = info.context if isinstance(info.context, Mapping) else {}
        allowed_entities = context.get("allowed_entities")
        require_all_allowed = bool(context.get("require_all_allowed", False))

        if allowed_entities is not None:
            for param_name, level_map in self.parameters.items():
                if param_name not in allowed_entities:
                    raise ValueError(f"Parameter {param_name!r} is not permitted in allowed_entities.")
                allowed_set = {str(item) for item in allowed_entities[param_name]}
                emitted_set = {entity for entities in level_map.values() for entity in entities}
                hallucinated = emitted_set - allowed_set
                if hallucinated:
                    raise ValueError(
                        f"Hallucinated entities in {param_name!r} outside candidate vocabulary: {sorted(hallucinated)}."
                    )
                if require_all_allowed:
                    missing = allowed_set - emitted_set
                    if missing:
                        raise ValueError(f"Missing required candidate entities in {param_name!r}: {sorted(missing)}.")

            if require_all_allowed:
                missing_params = set(allowed_entities.keys()) - set(self.parameters.keys())
                if missing_params:
                    raise ValueError(f"Missing required CI parameters from ontology output: {sorted(missing_params)}.")
        return self

    def to_ontology_set(self) -> OntologySet:
        """Convert validated schema into an immutable OntologySet."""
        ontologies = {
            param_name: ParameterOntology.from_levels(param_name, level_map)
            for param_name, level_map in self.parameters.items()
        }
        return OntologySet(
            domain=self.domain,
            ontologies=ontologies,
            description=self.description or "",
        )


class ParameterMappingSchema(BaseModel):
    """Strict Pydantic v2 schema for single-parameter level extraction p_O <- theta(O, p)."""

    model_config = ConfigDict(strict=True, extra="forbid")

    parameter: str
    value: str
    level: str
    rationale: str | None = None

    @field_validator("parameter")
    @classmethod
    def _validate_parameter(cls, val: str) -> str:
        if val not in CI_PARAMETERS:
            raise ValueError(f"Invalid CI parameter {val!r}; expected one of {CI_PARAMETERS}.")
        return val

    @field_validator("value")
    @classmethod
    def _validate_value(cls, val: str) -> str:
        if not val.strip():
            raise ValueError("Mapped parameter value must be a non-empty string.")
        return val

    @field_validator("level")
    @classmethod
    def _validate_level(cls, val: str) -> str:
        level_to_rank(val)
        return val.strip()

    @model_validator(mode="after")
    def _validate_rank_bound(self, info: ValidationInfo) -> ParameterMappingSchema:
        context = info.context if isinstance(info.context, Mapping) else {}
        max_rank = context.get("allowed_max_rank")
        if max_rank is not None and self.rank > int(max_rank):
            raise ValueError(f"Extracted level {self.level!r} exceeds ontology max rank L{max_rank}.")
        return self

    @property
    def rank(self) -> int:
        """Integer rank corresponding to validated level label."""
        return level_to_rank(self.level)


def parse_validated_ontology_json(
    raw_json: str | bytes,
    allowed_entities: Mapping[str, Collection[str]] | None = None,
    require_all_allowed: bool = False,
) -> OntologySet:
    """Parse and strictly validate a JSON ontology specification into an OntologySet.

    Args:
        raw_json: Raw UTF-8 JSON string or bytes conforming to OntologySchema.
        allowed_entities: Optional per-parameter vocabulary guard rejecting hallucinated entities.
        require_all_allowed: If True, require every entity in allowed_entities to be ranked.

    Returns:
        Validated OntologySet instance.

    Raises:
        pydantic.ValidationError: On malformed JSON, invalid types/levels, duplicates, or
            hallucinated entities.
    """
    schema = OntologySchema.model_validate_json(
        raw_json,
        context={
            "allowed_entities": allowed_entities,
            "require_all_allowed": require_all_allowed,
        },
    )
    return schema.to_ontology_set()


def parse_validated_parameter_mapping_json(
    raw_json: str | bytes,
    allowed_max_rank: int | None = None,
) -> ParameterMappingSchema:
    """Parse and strictly validate a lightweight edge parameter-to-level JSON mapping.

    Args:
        raw_json: Raw JSON string or bytes conforming to ParameterMappingSchema.
        allowed_max_rank: Optional upper bound on permissible ontology level rank.

    Returns:
        Validated ParameterMappingSchema.

    Raises:
        pydantic.ValidationError: If JSON, parameter name, or level label is invalid.
    """
    return ParameterMappingSchema.model_validate_json(
        raw_json,
        context={"allowed_max_rank": allowed_max_rank},
    )


def build_ontology_prompt(
    domain: str,
    candidate_entities: Mapping[str, Sequence[str]],
    prior_feedback: Sequence[str] | None = None,
) -> str:
    """Build a deterministic structured prompt for strict JSON ontology synthesis/tuning.

    Args:
        domain: Target domain name (e.g., 'SPA' or 'Education').
        candidate_entities: Allowed domain vocabulary per CI parameter.
        prior_feedback: Optional alignment constraints from iterative ontology tuning.

    Returns:
        Formatted prompt string embedding exact candidate entities and JSON schema rules.

    Raises:
        ValueError: If domain or candidate_entities is empty or uses unknown CI parameters.
    """
    if not domain.strip():
        raise ValueError("domain must be a non-empty string.")
    if not candidate_entities:
        raise ValueError("candidate_entities cannot be empty.")

    normalized_candidates: dict[str, list[str]] = {}
    for param_name, entities in candidate_entities.items():
        if param_name not in CI_PARAMETERS:
            raise ValueError(f"Unknown CI parameter {param_name!r} in candidate_entities.")
        entity_list = [str(item) for item in entities if str(item).strip()]
        if not entity_list:
            raise ValueError(f"Candidate entities for {param_name!r} cannot be empty.")
        normalized_candidates[param_name] = entity_list

    lines = [
        f"Construct a ranked Contextual Integrity privacy ontology for domain '{domain}'.",
        "Ordering invariant:",
        "- L1 = lowest data sensitivity, lowest recipient exposure risk, or lowest transmission risk.",
        "- L2, L3, ... = monotonically higher privacy sensitivity or exposure risk.",
        "Anti-hallucination rules:",
        "- Output ONLY valid JSON matching OntologySchema (keys: 'domain', 'parameters').",
        "- Classify ONLY the exact candidate strings provided below; never invent or omit entities.",
        "- Assign each entity to at most one level within its parameter.",
        f"Candidate vocabulary:\n{json.dumps(normalized_candidates, indent=2, sort_keys=True)}",
    ]
    if prior_feedback:
        feedback_items = "\n".join(f"- {note}" for note in prior_feedback if note.strip())
        if feedback_items:
            lines.append(f"Iterative tuning feedback:\n{feedback_items}")
    return "\n\n".join(lines)


@runtime_checkable
class OntologyMapper(Protocol):
    """Protocol for mapping a Contextual Integrity parameter entity to an integer rank in O."""

    def map_parameter(
        self,
        ontology_set: OntologySet,
        param_name: str,
        value: str,
    ) -> int | None:
        """Return positive integer rank for (param_name, value) in ontology_set, or None."""


class StructuredOntologyMapper:
    """Deterministic table-backed mapper resolving CI parameter values against OntologySet."""

    def __init__(
        self,
        aliases: Mapping[tuple[str, str], str] | None = None,
    ) -> None:
        """Initialize StructuredOntologyMapper with optional canonical synonym aliases.

        Args:
            aliases: Optional mapping from (param_name, raw_value) to canonical ontology entity.
        """
        self._aliases: dict[tuple[str, str], str] = (
            {(param, raw.strip().lower()): canon for (param, raw), canon in aliases.items()} if aliases else {}
        )

    def map_parameter(
        self,
        ontology_set: OntologySet,
        param_name: str,
        value: str,
    ) -> int | None:
        """Resolve value to its integer rank in ontology_set, or None if unmapped."""
        rank = ontology_set.get_rank(param_name, value)
        if rank is not None:
            return rank
        canonical = self._aliases.get((param_name, value.strip().lower()))
        if canonical is not None:
            return ontology_set.get_rank(param_name, canonical)
        return None


class LightweightEdgeOntologyMapper:
    """Edge lightweight parameter-level mapper (p_O <- theta(O, p)) with strict JSON validation.

    Models edge offloading (e.g., Gemma 3 4B IT profile) where the lightweight extractor only
    outputs JSON level assignments validated via ParameterMappingSchema, leaving deterministic
    partial-order comparison R' <=_O R on the host solver runtime.
    """

    def __init__(
        self,
        edge_json_extractor: Callable[[OntologySet, str, str], str | None] | None = None,
    ) -> None:
        """Initialize LightweightEdgeOntologyMapper.

        Args:
            edge_json_extractor: Optional callable returning raw JSON matching
                ParameterMappingSchema for (ontology_set, param_name, value). Defaults to
                deterministic structured JSON emission over ontology_set.
        """
        self._extractor = edge_json_extractor or self._default_structured_edge_extractor

    @staticmethod
    def _default_structured_edge_extractor(
        ontology_set: OntologySet,
        param_name: str,
        value: str,
    ) -> str | None:
        param_ont = ontology_set.get_parameter_ontology(param_name)
        if param_ont is None:
            return None
        level = param_ont.get_level(value)
        if level is None:
            return None
        return json.dumps(
            {
                "parameter": param_name,
                "value": value,
                "level": level,
            }
        )

    def map_parameter(
        self,
        ontology_set: OntologySet,
        param_name: str,
        value: str,
    ) -> int | None:
        """Extract and strictly validate parameter level JSON into an integer rank."""
        param_ont = ontology_set.get_parameter_ontology(param_name)
        max_rank = param_ont.max_rank if param_ont is not None else None
        raw_json = self._extractor(ontology_set, param_name, value)
        if raw_json is None:
            return None
        validated = parse_validated_parameter_mapping_json(
            raw_json,
            allowed_max_rank=max_rank,
        )
        if validated.parameter != param_name:
            return None
        return validated.rank


class AdaptiveMemoryAnchoredMapper:
    """Mapper mitigating Ontology Hierarchy Misalignment via user memory D_u anchoring.

    Supports both explicit iterative ontology tuning and automatic contrapositive bound
    anchoring for dynamic social roles (such as 'housemate') directly against explicit
    historical user judgments in D_u.
    """

    def __init__(
        self,
        memory: UserDecisionMemory | None = None,
        dynamic_roles: Collection[str] | None = None,
        tuned_ranks: Mapping[tuple[str, str], int] | None = None,
    ) -> None:
        """Initialize AdaptiveMemoryAnchoredMapper.

        Args:
            memory: Optional UserDecisionMemory D_u used to anchor dynamic/misaligned entities.
            dynamic_roles: Collection of role names treated as user-dependent dynamic roles
                requiring empirical memory anchoring (defaults to DEFAULT_DYNAMIC_ROLES).
            tuned_ranks: Optional initial dictionary of iterative rank overrides.
        """
        self.memory = memory
        roles = DEFAULT_DYNAMIC_ROLES if dynamic_roles is None else dynamic_roles
        self.dynamic_roles: frozenset[str] = frozenset(r.strip().lower() for r in roles)
        self._tuned_ranks: dict[tuple[str, str], int] = {}
        if tuned_ranks:
            for (param_name, entity), rank in tuned_ranks.items():
                self.tune_rank(param_name, entity, rank)

    def tune_rank(self, param_name: str, value: str, rank: int) -> None:
        """Register an explicit iterative ontology tuning rank override.

        Args:
            param_name: Target CI parameter name in CI_PARAMETERS.
            value: Parameter entity string to override.
            rank: Positive integer rank >= 1.
        """
        if param_name not in CI_PARAMETERS:
            raise ValueError(f"Unknown CI parameter {param_name!r}; expected one of {CI_PARAMETERS}.")
        if not value.strip():
            raise ValueError("Entity value must be a non-empty string.")
        self._tuned_ranks[(param_name, value.strip().lower())] = level_to_rank(rank)

    def _base_peer_rank(
        self,
        ontology_set: OntologySet,
        param_name: str,
        value: str,
    ) -> int | None:
        norm = value.strip().lower()
        tuned = self._tuned_ranks.get((param_name, norm))
        if tuned is not None:
            return tuned
        if norm in self.dynamic_roles:
            return None
        return ontology_set.get_rank(param_name, value)

    def _other_params_leq(
        self,
        r_left: InformationFlowRequest,
        r_right: InformationFlowRequest,
        excluded_param: str,
        ontology_set: OntologySet,
    ) -> bool:
        for param_name in CI_PARAMETERS:
            if param_name == excluded_param:
                continue
            p_left = r_left.get_parameter(param_name)
            p_right = r_right.get_parameter(param_name)
            if p_left == p_right:
                continue
            rank_left = self._base_peer_rank(ontology_set, param_name, p_left)
            rank_right = self._base_peer_rank(ontology_set, param_name, p_right)
            if rank_left is None or rank_right is None or rank_left > rank_right:
                return False
        return True

    def _other_params_equal(
        self,
        r_left: InformationFlowRequest,
        r_right: InformationFlowRequest,
        excluded_param: str,
    ) -> bool:
        for param_name in CI_PARAMETERS:
            if param_name == excluded_param:
                continue
            if r_left.get_parameter(param_name) != r_right.get_parameter(param_name):
                return False
        return True

    def compute_memory_rank_bounds(
        self,
        ontology_set: OntologySet,
        param_name: str,
        value: str,
    ) -> tuple[int | None, int | None, list[int]]:
        """Derive contrapositive (lower_bound, upper_bound, agreed_peer_ranks) from D_u.

        Args:
            ontology_set: Reference domain OntologySet O.
            param_name: Target CI parameter slot.
            value: Entity string (e.g., 'housemate') to anchor against D_u.

        Returns:
            Tuple (lower_bound, upper_bound, agreed_ranks) deduced from user memory.
        """
        if self.memory is None or not self.memory.records:
            return None, None, []

        norm_val = value.strip().lower()
        target_records = [
            rec for rec in self.memory.records if rec.request.get_parameter(param_name).strip().lower() == norm_val
        ]
        if not target_records:
            return None, None, []

        peer_records = [
            rec for rec in self.memory.records if rec.request.get_parameter(param_name).strip().lower() != norm_val
        ]

        lower_bound: int | None = None
        upper_bound: int | None = None
        agreed_ranks: list[int] = []

        for t_rec in target_records:
            for p_rec in peer_records:
                peer_val = p_rec.request.get_parameter(param_name)
                peer_rank = self._base_peer_rank(ontology_set, param_name, peer_val)
                if peer_rank is None:
                    continue

                if (
                    t_rec.label is DecisionLabel.INAPPROPRIATE
                    and p_rec.label is DecisionLabel.APPROPRIATE
                    and self._other_params_leq(t_rec.request, p_rec.request, param_name, ontology_set)
                ):
                    candidate_lb = peer_rank + 1
                    lower_bound = candidate_lb if lower_bound is None else max(lower_bound, candidate_lb)

                elif (
                    t_rec.label is DecisionLabel.APPROPRIATE
                    and p_rec.label is DecisionLabel.INAPPROPRIATE
                    and self._other_params_leq(p_rec.request, t_rec.request, param_name, ontology_set)
                ):
                    candidate_ub = peer_rank - 1
                    upper_bound = candidate_ub if upper_bound is None else min(upper_bound, candidate_ub)

                elif t_rec.label == p_rec.label and self._other_params_equal(t_rec.request, p_rec.request, param_name):
                    agreed_ranks.append(peer_rank)

        return lower_bound, upper_bound, sorted(agreed_ranks)

    def map_parameter(
        self,
        ontology_set: OntologySet,
        param_name: str,
        value: str,
    ) -> int | None:
        """Resolve (param_name, value) using tuned overrides and empirical D_u anchoring."""
        if param_name not in CI_PARAMETERS:
            raise ValueError(f"Unknown CI parameter {param_name!r}; expected one of {CI_PARAMETERS}.")
        if not isinstance(value, str) or not value.strip():
            return None

        norm_val = value.strip().lower()
        tuned = self._tuned_ranks.get((param_name, norm_val))
        if tuned is not None:
            return tuned

        r_static = ontology_set.get_rank(param_name, value)
        is_dynamic = norm_val in self.dynamic_roles

        lower_bound, upper_bound, agreed_ranks = self.compute_memory_rank_bounds(ontology_set, param_name, value)

        # Contradictory or impossible empirical bounds -> abstain safely
        if upper_bound is not None and upper_bound < 1:
            return None
        if lower_bound is not None and upper_bound is not None and lower_bound > upper_bound:
            return None

        # Non-dynamic static entities retain r_static whenever consistent with D_u bounds
        if r_static is not None and not is_dynamic:
            if (lower_bound is None or lower_bound <= r_static) and (upper_bound is None or r_static <= upper_bound):
                return r_static

        # Bounded from both sides by D_u
        if lower_bound is not None and upper_bound is not None:
            in_band = [r for r in agreed_ranks if lower_bound <= r <= upper_bound]
            if in_band:
                return in_band[len(in_band) // 2]
            return (lower_bound + upper_bound) // 2

        # One-sided lower bound from D_u
        if lower_bound is not None:
            in_band = [r for r in agreed_ranks if r >= lower_bound]
            if in_band and min(in_band) == max(in_band):
                return in_band[0]
            param_ont = ontology_set.get_parameter_ontology(param_name)
            if param_ont is not None and lower_bound == param_ont.max_rank:
                return lower_bound
            if r_static is not None and not is_dynamic:
                return max(r_static, lower_bound)
            if r_static is not None and is_dynamic and r_static < lower_bound and param_ont is not None:
                if lower_bound >= param_ont.max_rank:
                    return lower_bound
            return None

        # One-sided upper bound from D_u
        if upper_bound is not None:
            if upper_bound == 1:
                return 1
            in_band = [r for r in agreed_ranks if r <= upper_bound]
            if in_band and min(in_band) == max(in_band):
                return in_band[0]
            if r_static is not None and not is_dynamic:
                return min(r_static, upper_bound)
            return None

        # No strict inequality bounds triggered
        if agreed_ranks and min(agreed_ranks) == max(agreed_ranks):
            return agreed_ranks[0]

        if is_dynamic:
            return None
        return r_static

    def build_tuned_ontology(
        self,
        ontology_set: OntologySet,
        candidate_values: Mapping[str, Sequence[str]] | None = None,
    ) -> OntologySet:
        """Export a new OntologySet incorporating tuned overrides and memory-anchored entities.

        Args:
            ontology_set: Base OntologySet O to refine.
            candidate_values: Optional mapping of additional dynamic entities to resolve and embed.

        Returns:
            Refined OntologySet with consistent user-aligned ranks.
        """
        updated = ontology_set
        for (param_name, norm_entity), rank in sorted(self._tuned_ranks.items()):
            updated = updated.with_updated_rank(param_name, norm_entity, rank)

        to_check: dict[str, set[str]] = {}
        if self.memory is not None:
            for rec in self.memory.records:
                for param_name in CI_PARAMETERS:
                    to_check.setdefault(param_name, set()).add(rec.request.get_parameter(param_name))
        if candidate_values:
            for param_name, values in candidate_values.items():
                for val in values:
                    to_check.setdefault(param_name, set()).add(val)

        for param_name, values in sorted(to_check.items()):
            if param_name not in updated.ontologies and param_name not in (candidate_values or {}):
                continue
            for val in sorted(values):
                resolved = self.map_parameter(ontology_set, param_name, val)
                if resolved is not None:
                    updated = updated.with_updated_rank(param_name, val, resolved)
        return updated


def is_less_or_equal(
    r_left: InformationFlowRequest,
    r_right: InformationFlowRequest,
    ontology_set: OntologySet,
    mapper: OntologyMapper | None = None,
) -> bool:
    """Evaluate Definition 4.1 formal partial order r_left <=_O r_right.

    Holds iff for all 5 Contextual Integrity parameters p_left and p_right, either
    p_left == p_right or both map to comparable integer ranks in ontology_set O with
    rank(p_left) <= rank(p_right). Unmapped or incomparable values return False.

    Args:
        r_left: Left-hand InformationFlowRequest.
        r_right: Right-hand InformationFlowRequest.
        ontology_set: Domain OntologySet O.
        mapper: Optional OntologyMapper (defaults to StructuredOntologyMapper()).

    Returns:
        True if r_left <=_O r_right across all 5 CI parameters, else False.
    """
    active_mapper: OntologyMapper = StructuredOntologyMapper() if mapper is None else mapper
    left_req = InformationFlowRequest.coerce(r_left)
    right_req = InformationFlowRequest.coerce(r_right)
    for param_name in CI_PARAMETERS:
        p_left = left_req.get_parameter(param_name)
        p_right = right_req.get_parameter(param_name)
        if p_left == p_right:
            continue
        rank_left = active_mapper.map_parameter(ontology_set, param_name, p_left)
        rank_right = active_mapper.map_parameter(ontology_set, param_name, p_right)
        if rank_left is None or rank_right is None:
            return False
        if rank_left > rank_right:
            return False
    return True
