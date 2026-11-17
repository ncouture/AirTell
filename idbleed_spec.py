#!/usr/bin/env python3
"""Repository-root entry point and public API re-export for the IDBLEED verification spec.

Re-exports all verification data structures, side-channel protocol evaluators, AirTell
packet record adapters, and canonical unit tests from airtell.sidechannel.idbleed_spec.
"""

from __future__ import annotations

import unittest

from airtell.sidechannel.idbleed_spec import (
    ActiveRelayProbeOrchestrator,
    AppAuthOracleEvaluator,
    ATTOpcode,
    ATTSignedWritePayload,
    BLEFrame,
    CSRKSigningOracleEvaluator,
    IdbleedVerificationAnalyzer,
    IdentityRecord,
    LLEncryptionOracleEvaluator,
    LLEncryptionReqPayload,
    LLOpcode,
    OracleResult,
    TestIDBLEEDSpecification,
    ble_packet_record_to_frame,
    compute_csrk_cmac,
)

__all__ = [
    "OracleResult",
    "LLOpcode",
    "ATTOpcode",
    "BLEFrame",
    "LLEncryptionReqPayload",
    "ATTSignedWritePayload",
    "compute_csrk_cmac",
    "LLEncryptionOracleEvaluator",
    "CSRKSigningOracleEvaluator",
    "AppAuthOracleEvaluator",
    "IdentityRecord",
    "ActiveRelayProbeOrchestrator",
    "ble_packet_record_to_frame",
    "IdbleedVerificationAnalyzer",
    "TestIDBLEEDSpecification",
]


def main() -> None:
    """Execute the canonical IDBLEED specification verification suite."""
    unittest.main()


if __name__ == "__main__":
    main()
