"""ARIEL Neurosymbolic Logical Entailment Privacy Engine for AirTell.

Provides Contextual Integrity (CI) 5-tuple request models, strict Pydantic v2 ontology
hierarchies, formal partial-order comparisons (<=_O), Online Phase Algorithm 1 logical
entailment with transparent proofs and contradiction abstention, dynamic social role
memory anchoring, and SPA/Education domain benchmarks.
"""

from __future__ import annotations

from airtell.ariel.domains import (
    BenchmarkEvalCase,
    DomainBenchmarkDataset,
    UserBenchmarkScenario,
    build_education_benchmark,
    build_education_ontology,
    build_spa_benchmark,
    build_spa_ontology,
)
from airtell.ariel.evaluation import (
    EvaluationMetrics,
    GeneralCINormsBaseline,
    MemoryAblationReport,
    SimulatedICLBaseline,
    compute_evaluation_metrics,
    run_memory_ablation,
)
from airtell.ariel.models import (
    CI_PARAMETERS,
    DecisionLabel,
    InformationFlowRequest,
    PriorDecisionRecord,
    UserDecisionMemory,
)
from airtell.ariel.ontology import (
    DEFAULT_DYNAMIC_ROLES,
    AdaptiveMemoryAnchoredMapper,
    LightweightEdgeOntologyMapper,
    OntologyMapper,
    OntologySchema,
    OntologySet,
    ParameterMappingSchema,
    ParameterOntology,
    StructuredOntologyMapper,
    build_ontology_prompt,
    is_less_or_equal,
    level_to_rank,
    parse_validated_ontology_json,
    parse_validated_parameter_mapping_json,
    rank_to_level,
)
from airtell.ariel.solver import (
    ABSTENTION_CONTRADICTORY_PRIORS,
    ABSTENTION_EMPTY_NEIGHBORHOOD,
    ABSTENTION_NON_ENTAILED_BOUNDARY,
    RULE_1_NAME,
    RULE_2_NAME,
    ARIELSolver,
    EntailmentProof,
    EntailmentResult,
    EntailmentStep,
    check_entailment_rule_1,
    check_entailment_rule_2,
)

__all__ = [
    "ABSTENTION_CONTRADICTORY_PRIORS",
    "ABSTENTION_EMPTY_NEIGHBORHOOD",
    "ABSTENTION_NON_ENTAILED_BOUNDARY",
    "ARIELSolver",
    "AdaptiveMemoryAnchoredMapper",
    "BenchmarkEvalCase",
    "CI_PARAMETERS",
    "DEFAULT_DYNAMIC_ROLES",
    "DecisionLabel",
    "DomainBenchmarkDataset",
    "EntailmentProof",
    "EntailmentResult",
    "EntailmentStep",
    "EvaluationMetrics",
    "GeneralCINormsBaseline",
    "InformationFlowRequest",
    "LightweightEdgeOntologyMapper",
    "MemoryAblationReport",
    "OntologyMapper",
    "OntologySchema",
    "OntologySet",
    "ParameterMappingSchema",
    "ParameterOntology",
    "PriorDecisionRecord",
    "RULE_1_NAME",
    "RULE_2_NAME",
    "SimulatedICLBaseline",
    "StructuredOntologyMapper",
    "UserBenchmarkScenario",
    "UserDecisionMemory",
    "build_education_benchmark",
    "build_education_ontology",
    "build_ontology_prompt",
    "build_spa_benchmark",
    "build_spa_ontology",
    "check_entailment_rule_1",
    "check_entailment_rule_2",
    "compute_evaluation_metrics",
    "is_less_or_equal",
    "level_to_rank",
    "parse_validated_ontology_json",
    "parse_validated_parameter_mapping_json",
    "rank_to_level",
    "run_memory_ablation",
]
