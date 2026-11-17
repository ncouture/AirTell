"""Core Contextual Integrity (CI) data structures and user memory models for ARIEL.

Defines the 5-tuple information flow request R = {d_u, u, s, r, t}, decision labels,
prior decision records, and user decision memory with single-parameter neighborhood
filtering and memory-scaling slice operations.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum

CI_PARAMETERS: tuple[str, ...] = (
    "data_type",
    "data_subject",
    "data_sender",
    "data_recipient",
    "transmission_principle",
)


class DecisionLabel(str, Enum):
    """Privacy appropriateness classification labels for information flows."""

    APPROPRIATE = "appropriate"
    INAPPROPRIATE = "inappropriate"
    UNDETERMINED = "undetermined"


@dataclass(frozen=True)
class InformationFlowRequest:
    """Contextual Integrity 5-tuple information flow request R = {d_u, u, s, r, t}.

    Attributes:
        data_type: Type or category of personal information (d_u).
        data_subject: Individual to whom the data pertains (u).
        data_sender: Entity initiating or transmitting the flow (s).
        data_recipient: Entity receiving the transmitted information (r).
        transmission_principle: Normative condition or constraint governing transmission (t).
    """

    data_type: str
    data_subject: str
    data_sender: str
    data_recipient: str
    transmission_principle: str

    def __post_init__(self) -> None:
        """Validate that all five CI parameters are non-empty strings."""
        for param_name in CI_PARAMETERS:
            val = getattr(self, param_name)
            if not isinstance(val, str) or not val.strip():
                raise ValueError(f"CI parameter '{param_name}' must be a non-empty string, got {val!r}.")

    def as_dict(self) -> dict[str, str]:
        """Return a dictionary mapping each CI parameter name to its value."""
        return {param_name: getattr(self, param_name) for param_name in CI_PARAMETERS}

    def as_tuple(self) -> tuple[str, str, str, str, str]:
        """Return the ordered 5-tuple (d_u, u, s, r, t)."""
        return (
            self.data_type,
            self.data_subject,
            self.data_sender,
            self.data_recipient,
            self.transmission_principle,
        )

    def get_parameter(self, param_name: str) -> str:
        """Retrieve a single CI parameter value by name.

        Args:
            param_name: Name of the CI parameter in CI_PARAMETERS.

        Returns:
            The string value assigned to param_name.

        Raises:
            ValueError: If param_name is not one of the five CI parameters.
        """
        if param_name not in CI_PARAMETERS:
            raise ValueError(f"Unknown CI parameter {param_name!r}; expected one of {CI_PARAMETERS}.")
        return str(getattr(self, param_name))

    def with_parameter(self, param_name: str, value: str) -> InformationFlowRequest:
        """Return a new InformationFlowRequest with one CI parameter replaced.

        Args:
            param_name: Name of the CI parameter in CI_PARAMETERS.
            value: Replacement parameter value.

        Returns:
            A new immutable InformationFlowRequest instance.

        Raises:
            ValueError: If param_name is unknown or value is empty.
        """
        if param_name not in CI_PARAMETERS:
            raise ValueError(f"Unknown CI parameter {param_name!r}; expected one of {CI_PARAMETERS}.")
        return replace(self, **{param_name: value})

    @classmethod
    def coerce(cls, obj: object) -> InformationFlowRequest:
        """Coerce a duck-typed 5-tuple CI request object into InformationFlowRequest."""
        if isinstance(obj, cls):
            return obj
        if isinstance(obj, (str, bytes)) or not all(hasattr(obj, p) for p in CI_PARAMETERS):
            raise TypeError(f"Expected InformationFlowRequest, got {type(obj).__name__}.")
        return cls(
            data_type=str(getattr(obj, "data_type")),
            data_subject=str(getattr(obj, "data_subject")),
            data_sender=str(getattr(obj, "data_sender")),
            data_recipient=str(getattr(obj, "data_recipient")),
            transmission_principle=str(getattr(obj, "transmission_principle")),
        )

    def differing_parameters(self, other: InformationFlowRequest) -> list[tuple[str, str, str]]:
        """Identify all CI parameters whose values differ between self and other.

        Args:
            other: Another InformationFlowRequest (or compatible 5-tuple protocol) to compare.

        Returns:
            Ordered list of (param_name, self_val, other_val) for each differing slot.

        Raises:
            TypeError: If other is not an InformationFlowRequest or 5-tuple CI flow object.
        """
        coerced_other = self.coerce(other)
        diffs: list[tuple[str, str, str]] = []
        for param_name in CI_PARAMETERS:
            self_val = getattr(self, param_name)
            other_val = getattr(coerced_other, param_name)
            if self_val != other_val:
                diffs.append((param_name, self_val, other_val))
        return diffs

    def hamming_distance(self, other: InformationFlowRequest) -> int:
        """Compute the parameter-level Hamming distance in {0, 1, 2, 3, 4, 5}.

        Args:
            other: Another InformationFlowRequest to compare against.

        Returns:
            Count of CI parameters that differ between self and other.
        """
        return len(self.differing_parameters(other))


@dataclass(frozen=True)
class PriorDecisionRecord:
    """A historical resolved user privacy decision (R_i^u, l_i^u) in D_u.

    Attributes:
        request: Resolved Contextual Integrity 5-tuple request R_i^u.
        label: Definite binary user judgment (APPROPRIATE or INAPPROPRIATE).
    """

    request: InformationFlowRequest
    label: DecisionLabel

    def __post_init__(self) -> None:
        """Validate request type and ensure label is strictly APPROPRIATE or INAPPROPRIATE."""
        if not isinstance(self.request, InformationFlowRequest):
            raise TypeError(f"request must be an InformationFlowRequest, got {type(self.request).__name__}.")
        coerced_label = self.label
        if isinstance(coerced_label, str) and not isinstance(coerced_label, DecisionLabel):
            coerced_label = DecisionLabel(coerced_label)
            object.__setattr__(self, "label", coerced_label)
        if not isinstance(coerced_label, DecisionLabel):
            raise TypeError(f"label must be a DecisionLabel, got {type(coerced_label).__name__}.")
        if coerced_label not in (DecisionLabel.APPROPRIATE, DecisionLabel.INAPPROPRIATE):
            raise ValueError(
                f"PriorDecisionRecord label must be APPROPRIATE or INAPPROPRIATE, got {coerced_label.value!r}."
            )


@dataclass
class UserDecisionMemory:
    """Historical user decision repository D_u supporting neighborhood lookup and ablations.

    Attributes:
        user_id: Unique identifier of the user u.
        records: Ordered historical sequence of resolved PriorDecisionRecord entries.
    """

    user_id: str
    records: list[PriorDecisionRecord] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate user_id and record types."""
        if not isinstance(self.user_id, str) or not self.user_id.strip():
            raise ValueError("user_id must be a non-empty string.")
        validated: list[PriorDecisionRecord] = []
        for rec in self.records:
            if not isinstance(rec, PriorDecisionRecord):
                raise TypeError(f"All memory entries must be PriorDecisionRecord, got {type(rec).__name__}.")
            validated.append(rec)
        self.records = validated

    def __len__(self) -> int:
        """Return the number of historical prior records |D_u|."""
        return len(self.records)

    def add_record(
        self,
        request: InformationFlowRequest | PriorDecisionRecord,
        label: DecisionLabel | str | None = None,
    ) -> PriorDecisionRecord:
        """Append a resolved decision record to user memory D_u.

        Accepts either an existing PriorDecisionRecord or an (InformationFlowRequest, label) pair.

        Args:
            request: Either a PriorDecisionRecord or an InformationFlowRequest.
            label: DecisionLabel when request is an InformationFlowRequest; must be None or
                matching when request is already a PriorDecisionRecord.

        Returns:
            The appended PriorDecisionRecord.

        Raises:
            TypeError: If request is neither PriorDecisionRecord nor InformationFlowRequest.
            ValueError: If label is missing, mismatched, or UNDETERMINED.
        """
        if isinstance(request, PriorDecisionRecord):
            if label is not None and DecisionLabel(label) != request.label:
                raise ValueError("Conflicting label argument provided alongside PriorDecisionRecord.")
            self.records.append(request)
            return request
        if isinstance(request, InformationFlowRequest):
            if label is None:
                raise ValueError("label must be provided when adding an InformationFlowRequest.")
            record = PriorDecisionRecord(request=request, label=DecisionLabel(label))
            self.records.append(record)
            return record
        raise TypeError(f"Expected PriorDecisionRecord or InformationFlowRequest, got {type(request).__name__}.")

    def neighbors(
        self,
        incoming: InformationFlowRequest,
        max_distance: int = 1,
    ) -> list[PriorDecisionRecord]:
        """Return neighborhood E = {(R_i^u, l_i^u) in D_u : Distance(R_i^u, incoming) <= max_distance}.

        Args:
            incoming: Target InformationFlowRequest R_u to evaluate.
            max_distance: Maximum parameter Hamming distance allowed (default 1 per Algorithm 1).

        Returns:
            Ordered list of neighboring PriorDecisionRecord entries.

        Raises:
            ValueError: If max_distance < 0.
        """
        if max_distance < 0:
            raise ValueError(f"max_distance must be >= 0, got {max_distance}.")
        return [record for record in self.records if record.request.hamming_distance(incoming) <= max_distance]

    def slice_memory(self, max_records: int) -> UserDecisionMemory:
        """Return a truncated copy of user memory with at most max_records entries.

        Used in memory-scaling ablation experiments (e.g., |D_u| in [10, 20, 40, 60]).

        Args:
            max_records: Maximum number of leading prior records to retain.

        Returns:
            New UserDecisionMemory containing records[:max_records].

        Raises:
            ValueError: If max_records < 0.
        """
        if max_records < 0:
            raise ValueError(f"max_records must be >= 0, got {max_records}.")
        return UserDecisionMemory(user_id=self.user_id, records=list(self.records[:max_records]))
