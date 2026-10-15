"""Empirical Adversarial Stress Test Suite for Milestone 2 Analyzers.

Challenger: Challenger M2 SC 2 (teamwork_preview_challenger)
Target Analyzers:
- CsrkCounterAnalyzer (src/airtell/sidechannel/csrk_counter.py)
- BatAllowlistAnalyzer (src/airtell/sidechannel/bat_allowlist.py)

Stress Vectors Tested:
1. Multi-sender RPA rotation clusters (concurrent devices, counter collisions, FIFO eviction)
2. Interleaving legitimate and spoofed/replayed packets (replay classification, counter poisoning, invalid MAC handling)
3. 32-bit SignCounter boundary rollovers and wrap-around behavior
4. Subtle timing jitter, out-of-order delivery, and scanner collision in BAT allowlist scans
"""

from __future__ import annotations

from airtell.sidechannel import (
    BatAllowlistAnalyzer,
    BlePacketRecord,
    CsrkCounterAnalyzer,
    Verdict,
    build_adv_direct_ind,
    build_adv_ind,
    build_att_signed_write,
    build_connect_ind,
    build_scan_req,
    build_scan_rsp,
)
from airtell.sniff.pcap import BLE_ADV_AA


# =============================================================================
# Helper Functions
# =============================================================================
def _make_signed_write_record(
    csrk: bytes,
    counter: int,
    ts_usec: int,
    conn_aa: int = 0x8E89BED6,
    corrupt_mac: bool = False,
    handle: int = 0x0001,
    value: bytes = b"test",
    direction: int = 0,
) -> BlePacketRecord:
    """Helper to synthesize a signed write packet record."""
    body = build_att_signed_write(
        csrk=csrk,
        handle=handle,
        value=value,
        counter=counter,
        corrupt_mac=corrupt_mac,
    )
    return BlePacketRecord(
        body=body,
        channel=1,
        rssi=-60,
        timestamp_usec=ts_usec,
        access_address=conn_aa,
        direction=direction,
    )


def _make_connect_ind_record(
    init_a: str,
    adv_a: str,
    conn_aa: int,
    ts_usec: int,
) -> BlePacketRecord:
    """Helper to synthesize a CONNECT_IND packet record."""
    body = build_connect_ind(
        init_a=init_a,
        adv_a=adv_a,
        conn_aa=conn_aa,
    )
    return BlePacketRecord(
        body=body,
        channel=37,
        rssi=-50,
        timestamp_usec=ts_usec,
        access_address=BLE_ADV_AA,
        direction=0,
    )


# =============================================================================
# 1. Multi-Sender RPA Rotation Clusters & Cross-RPA Linking
# =============================================================================
class TestMultiSenderRpaRotationClusters:
    """Adversarial challenge for cross-RPA linking and cluster separation."""

    def test_concurrent_multi_sender_rpa_rotation_clean_separation(self) -> None:
        """Test 3 independent devices concurrently rotating RPAs at distinct counter ranges.

        Asserts that each device's rotating RPAs are linked only within their own cluster.
        Device 1: RPA1_A -> RPA1_B -> RPA1_C (SC: 1..6)
        Device 2: RPA2_A -> RPA2_B (SC: 101..104)
        Device 3: RPA3_A -> RPA3_B (SC: 501..504)
        """
        csrk1 = b"\x11" * 16
        csrk2 = b"\x22" * 16
        csrk3 = b"\x33" * 16
        analyzer = CsrkCounterAnalyzer()

        rpa1_a = "C0:01:00:00:00:01"
        rpa1_b = "C0:01:00:00:00:02"
        rpa1_c = "C0:01:00:00:00:03"

        rpa2_a = "C0:02:00:00:00:01"
        rpa2_b = "C0:02:00:00:00:02"

        rpa3_a = "C0:03:00:00:00:01"
        rpa3_b = "C0:03:00:00:00:02"

        periph1 = "D0:01:00:00:00:01"
        periph2 = "D0:02:00:00:00:01"
        periph3 = "D0:03:00:00:00:01"

        # Connections for each device
        analyzer.process_packet(_make_connect_ind_record(rpa1_a, periph1, 0x11111111, 1_000))
        analyzer.process_packet(_make_connect_ind_record(rpa2_a, periph2, 0x22222222, 2_000))
        analyzer.process_packet(_make_connect_ind_record(rpa3_a, periph3, 0x33333333, 3_000))

        # Interleaved initial packets
        analyzer.process_packet(_make_signed_write_record(csrk1, 1, 10_000, 0x11111111))
        analyzer.process_packet(_make_signed_write_record(csrk2, 101, 11_000, 0x22222222))
        analyzer.process_packet(_make_signed_write_record(csrk3, 501, 12_000, 0x33333333))
        analyzer.process_packet(_make_signed_write_record(csrk1, 2, 20_000, 0x11111111))
        analyzer.process_packet(_make_signed_write_record(csrk2, 102, 21_000, 0x22222222))
        analyzer.process_packet(_make_signed_write_record(csrk3, 502, 22_000, 0x33333333))

        # Rotation 1: Device 1 rotates to RPA1_B, Device 2 rotates to RPA2_B, Device 3 rotates to RPA3_B
        analyzer.process_packet(_make_connect_ind_record(rpa1_b, periph1, 0x11111112, 30_000))
        analyzer.process_packet(_make_signed_write_record(csrk1, 3, 31_000, 0x11111112))
        analyzer.process_packet(_make_signed_write_record(csrk1, 4, 32_000, 0x11111112))

        analyzer.process_packet(_make_connect_ind_record(rpa2_b, periph2, 0x22222223, 40_000))
        analyzer.process_packet(_make_signed_write_record(csrk2, 103, 41_000, 0x22222223))
        analyzer.process_packet(_make_signed_write_record(csrk2, 104, 42_000, 0x22222223))

        analyzer.process_packet(_make_connect_ind_record(rpa3_b, periph3, 0x33333334, 50_000))
        analyzer.process_packet(_make_signed_write_record(csrk3, 503, 51_000, 0x33333334))
        analyzer.process_packet(_make_signed_write_record(csrk3, 504, 52_000, 0x33333334))

        # Rotation 2: Device 1 rotates to RPA1_C
        analyzer.process_packet(_make_connect_ind_record(rpa1_c, periph1, 0x11111113, 60_000))
        analyzer.process_packet(_make_signed_write_record(csrk1, 5, 61_000, 0x11111113))
        analyzer.process_packet(_make_signed_write_record(csrk1, 6, 62_000, 0x11111113))

        report = analyzer.finalize()
        assert report.verdict == Verdict.CROSS_RPA_LINKED.value
        groups = report.metrics["linked_rpa_groups"]

        # Assert no cross-contamination between Device 1, Device 2, Device 3
        d1_group = next((g for g in groups if rpa1_a in g), [])
        d2_group = next((g for g in groups if rpa2_a in g), [])
        d3_group = next((g for g in groups if rpa3_a in g), [])

        assert set(d1_group) == {rpa1_a, rpa1_b, rpa1_c}
        assert set(d2_group) == {rpa2_a, rpa2_b}
        assert set(d3_group) == {rpa3_a, rpa3_b}

    def test_cross_rpa_linking_counter_collision_false_positive_risk(self) -> None:
        """Adversarial test: Two UNRELATED devices have counters within delta <= 5.

        Device A is at SC=10 (to Peripheral A).
        Device B is at SC=12 (to Peripheral B).
        Device A rotates to RPA_A2 and sends SC=11 (which continues A's sequence from 10).
        """
        csrkA = b"\xAA" * 16
        csrkB = b"\xBB" * 16
        analyzer = CsrkCounterAnalyzer()

        rpa_a1 = "C0:0A:00:00:00:01"
        rpa_a2 = "C0:0A:00:00:00:02"
        rpa_b1 = "C0:0B:00:00:00:01"

        analyzer.process_packet(_make_connect_ind_record(rpa_a1, "D0:0A:00:00:00:01", 0xAAAAAAAA, 1_000))
        analyzer.process_packet(_make_connect_ind_record(rpa_b1, "D0:0B:00:00:00:01", 0xBBBBBBBB, 2_000))

        analyzer.process_packet(_make_signed_write_record(csrkA, 10, 10_000, 0xAAAAAAAA))
        # Device B sends SC=12
        analyzer.process_packet(_make_signed_write_record(csrkB, 12, 11_000, 0xBBBBBBBB))

        # Device A rotates to RPA_A2 and sends SC=11 (which continues A's sequence from 10)
        analyzer.process_packet(_make_connect_ind_record(rpa_a2, "D0:0A:00:00:00:01", 0xAAAAAAAB, 20_000))
        analyzer.process_packet(_make_signed_write_record(csrkA, 11, 21_000, 0xAAAAAAAB))

        report = analyzer.finalize()
        groups = report.metrics["linked_rpa_groups"]

        # Remediated: Unrelated Device B (rpa_b1) is NOT falsely linked to Device A (rpa_a1)
        # because linking is properly scoped by target peripheral address (D0:0A vs D0:0B)
        falsely_linked = any(rpa_a1 in g and rpa_b1 in g for g in groups)
        assert not falsely_linked
        # Device A's own rotation is properly linked
        assert any(rpa_a1 in g and rpa_a2 in g for g in groups)

    def test_cross_rpa_linking_accidental_collision_when_interleaved(self) -> None:
        """Adversarial stress: Device B sends SC=10, Device A rotates to RPA_A2 and sends SC=11.

        Scoped linking prevents RPA_A2 from being falsely linked to Device B.
        """
        analyzer = CsrkCounterAnalyzer()

        rpa_a1 = "C0:0A:00:00:00:01"
        rpa_a2 = "C0:0A:00:00:00:02"
        rpa_b1 = "C0:0B:00:00:00:01"

        analyzer.process_packet(_make_connect_ind_record(rpa_a1, "D0:0A:00:00:00:01", 0xAAAAAAAA, 1_000))
        analyzer.process_packet(_make_connect_ind_record(rpa_b1, "D0:0B:00:00:00:01", 0xBBBBBBBB, 2_000))

        # Device A was at SC=5
        analyzer.process_packet(_make_signed_write_record(b"\x11" * 16, 5, 10_000, 0xAAAAAAAA))
        # Device B was at SC=10
        analyzer.process_packet(_make_signed_write_record(b"\x22" * 16, 10, 11_000, 0xBBBBBBBB))

        # Device A rotates to RPA_A2 and sends SC=11 (Device A experienced a jump 5->11)
        analyzer.process_packet(_make_connect_ind_record(rpa_a2, "D0:0A:00:00:00:01", 0xAAAAAAAB, 20_000))
        analyzer.process_packet(_make_signed_write_record(b"\x11" * 16, 11, 21_000, 0xAAAAAAAB))

        report = analyzer.finalize()
        groups = report.metrics["linked_rpa_groups"]
        # Remediated: RPA_A2 is NOT falsely linked to RPA_B1 due to target peripheral scoping
        falsely_linked = any(rpa_a2 in g and rpa_b1 in g for g in groups)
        assert not falsely_linked

    def test_cross_rpa_linking_eviction_under_traffic_flood(self) -> None:
        """Adversarial test: History preservation under noise traffic flood."""
        analyzer = CsrkCounterAnalyzer()
        rpa_target_1 = "C0:00:00:00:00:01"
        rpa_target_2 = "C0:00:00:00:00:02"
        noise_dev = "C0:00:00:00:00:99"

        analyzer.process_packet(_make_connect_ind_record(rpa_target_1, "D0:00:00:00:00:01", 0x11111111, 1_000))
        analyzer.process_packet(_make_signed_write_record(b"\x11" * 16, 1, 2_000, 0x11111111))

        # Flood 55 packets from a background noise device
        analyzer.process_packet(_make_connect_ind_record(noise_dev, "D0:00:00:00:00:02", 0x99999999, 3_000))
        for sc in range(100, 155):
            analyzer.process_packet(_make_signed_write_record(b"\x99" * 16, sc, 4_000 + sc, 0x99999999))

        # Now TARGET device rotates to RPA_TARGET_2 and sends SC=2
        analyzer.process_packet(_make_connect_ind_record(rpa_target_2, "D0:00:00:00:00:01", 0x11111112, 100_000))
        analyzer.process_packet(_make_signed_write_record(b"\x11" * 16, 2, 101_000, 0x11111112))

        report = analyzer.finalize()
        # Remediated: Target device's history is preserved and cross-RPA linking succeeds
        groups = report.metrics["linked_rpa_groups"]
        is_linked = any(rpa_target_1 in g and rpa_target_2 in g for g in groups)
        assert is_linked


# =============================================================================
# 2. Interleaving Legitimate & Spoofed / Replayed Packets
# =============================================================================
class TestInterleavedLegitimateAndSpoofedPackets:
    """Adversarial stress testing for replay attacks, counter rollbacks, and MAC spoofing."""

    def test_replay_attack_interleaved_causes_rollback_and_subsequent_jump(self) -> None:
        """Remediated test: Replay of seen counter flags ANOMALY_REPLAY and preserves high-water mark.

        Sequence:
        1. Legitimate: SC=10
        2. Legitimate: SC=11
        3. Legitimate: SC=12
        4. Attacker Replays: SC=10 (already seen -> ANOMALY_REPLAY)
        5. Legitimate: SC=13 (evaluates against high-water mark 12 -> SEQUENTIAL_MONOTONIC)
        """
        csrk = b"\x44" * 16
        analyzer = CsrkCounterAnalyzer(csrk=csrk)
        dev_a = "C0:04:00:00:00:01"
        periph_a = "D0:04:00:00:00:01"
        analyzer.process_packet(_make_connect_ind_record(dev_a, periph_a, 0x44444444, 1_000))

        analyzer.process_packet(_make_signed_write_record(csrk, 10, 10_000, 0x44444444))
        analyzer.process_packet(_make_signed_write_record(csrk, 11, 20_000, 0x44444444))
        analyzer.process_packet(_make_signed_write_record(csrk, 12, 30_000, 0x44444444))

        # Injected replayed packet SC=10 (already seen -> ANOMALY_REPLAY)
        f_replay = analyzer.process_packet(_make_signed_write_record(csrk, 10, 40_000, 0x44444444))
        assert len(f_replay) == 1
        assert f_replay[0].verdict == Verdict.ANOMALY_REPLAY.value
        assert f_replay[0].details["delta"] == -2

        # Subsequent legitimate packet SC=13 evaluates against high-water mark 12 -> delta=1
        f_legit = analyzer.process_packet(_make_signed_write_record(csrk, 13, 50_000, 0x44444444))
        assert len(f_legit) == 1
        assert f_legit[0].verdict == Verdict.SEQUENTIAL_MONOTONIC.value
        assert f_legit[0].details["delta"] == 1

        report = analyzer.finalize()
        assert report.metrics["replay_anomalies"] == 1
        assert report.metrics["rollback_anomalies"] == 0
        assert report.metrics["jump_anomalies"] == 0

    def test_consecutive_immediate_replay_flags_anomaly_replay(self) -> None:
        """Test immediate retransmission of the identical counter (delta = 0)."""
        csrk = b"\x55" * 16
        analyzer = CsrkCounterAnalyzer(csrk=csrk)
        dev_b = "C0:05:00:00:00:01"
        periph_b = "D0:05:00:00:00:01"
        analyzer.process_packet(_make_connect_ind_record(dev_b, periph_b, 0x55555555, 1_000))

        analyzer.process_packet(_make_signed_write_record(csrk, 20, 10_000, 0x55555555))
        # Immediate replay of SC=20
        f_replay = analyzer.process_packet(_make_signed_write_record(csrk, 20, 11_000, 0x55555555))
        assert len(f_replay) == 1
        assert f_replay[0].verdict == Verdict.ANOMALY_REPLAY.value
        assert f_replay[0].details["delta"] == 0

    def test_spoofed_packet_corrupt_mac_dual_findings_and_state_pollution(self) -> None:
        """Remediated: Unauthenticated packet with corrupted MAC aborts immediately.

        1. Emits ONLY VERIFICATION_FAILED.
        2. Does NOT evaluate monotonicity (no spurious SEQUENTIAL_MONOTONIC).
        3. Does NOT pollute last_counter state.
        """
        csrk = b"\x66" * 16
        analyzer = CsrkCounterAnalyzer(csrk=csrk)
        dev_c = "C0:06:00:00:00:01"
        periph_c = "D0:06:00:00:00:01"
        analyzer.process_packet(_make_connect_ind_record(dev_c, periph_c, 0x66666666, 1_000))

        analyzer.process_packet(_make_signed_write_record(csrk, 1, 10_000, 0x66666666))

        # Attacker transmits packet with corrupted MAC and counter=2
        findings = analyzer.process_packet(
            _make_signed_write_record(csrk, 2, 20_000, 0x66666666, corrupt_mac=True)
        )

        # Emits ONLY VERIFICATION_FAILED
        verdicts = [f.verdict for f in findings]
        assert verdicts == [Verdict.VERIFICATION_FAILED.value]
        assert Verdict.SEQUENTIAL_MONOTONIC.value not in verdicts

        # Counter state was NOT polluted
        assert analyzer._senders[dev_c].last_counter == 1

        # Finalize report precedence
        report = analyzer.finalize()
        assert report.verdict == Verdict.VERIFICATION_FAILED.value
        assert report.metrics["mac_verification_failures"] == 1

    def test_attacker_poisoning_via_fake_huge_counter(self) -> None:
        """Remediated: High-water mark prevents counter regression downwards on unkeyed connections."""
        csrk = b"\x77" * 16
        analyzer = CsrkCounterAnalyzer()  # No CSRK known to receiver
        dev_d = "C0:07:00:00:00:01"
        periph_d = "D0:07:00:00:00:01"
        analyzer.process_packet(_make_connect_ind_record(dev_d, periph_d, 0x77777777, 1_000))

        analyzer.process_packet(_make_signed_write_record(csrk, 1, 10_000, 0x77777777))

        # Attacker injects fake SC = 1,000,000
        analyzer.process_packet(_make_signed_write_record(csrk, 1_000_000, 20_000, 0x77777777))

        # Real device transmits legitimate SC = 2 (rollback relative to 1,000,000)
        f2 = analyzer.process_packet(_make_signed_write_record(csrk, 2, 30_000, 0x77777777))
        assert f2[0].verdict == Verdict.ANOMALY_ROLLBACK.value
        assert f2[0].details["delta"] < 0

        # Real device transmits legitimate SC = 3 (high-water mark 1,000,000 retained)
        f3 = analyzer.process_packet(_make_signed_write_record(csrk, 3, 40_000, 0x77777777))
        assert f3[0].verdict == Verdict.ANOMALY_ROLLBACK.value


# =============================================================================
# 3. Boundary Counter Wraps & uint32 Rollovers
# =============================================================================
class TestBoundaryCounterRollover:
    """Boundary testing on 32-bit unsigned integers."""

    def test_uint32_rollover_from_max_to_zero(self) -> None:
        """Bluetooth Core Spec Part H mandates SignCounter cannot wrap around.

        When SC=0xFFFFFFFF increments to SC=0x00000000:
        Analyzer calculates delta = 0 - 0xFFFFFFFF = -4294967295 < 0,
        flagging ANOMALY_ROLLBACK.
        """
        csrk = b"\x88" * 16
        analyzer = CsrkCounterAnalyzer(csrk=csrk)
        dev_e = "C0:08:00:00:00:01"
        periph_e = "D0:08:00:00:00:01"
        analyzer.process_packet(_make_connect_ind_record(dev_e, periph_e, 0x88888888, 1_000))

        analyzer.process_packet(_make_signed_write_record(csrk, 0xFFFFFFFF, 10_000, 0x88888888))
        f_wrap = analyzer.process_packet(_make_signed_write_record(csrk, 0x00000000, 20_000, 0x88888888))

        assert len(f_wrap) == 1
        assert f_wrap[0].verdict == Verdict.ANOMALY_ROLLBACK.value
        assert f_wrap[0].details["delta"] == -4294967295

        report = analyzer.finalize()
        assert report.verdict == Verdict.ANOMALY_ROLLBACK.value
        assert report.metrics["rollback_anomalies"] == 1

    def test_uint32_successive_high_boundaries(self) -> None:
        """Verify sequential increments across high uint32 values."""
        csrk = b"\x99" * 16
        analyzer = CsrkCounterAnalyzer(csrk=csrk)
        dev_f = "C0:09:00:00:00:01"
        periph_f = "D0:09:00:00:00:01"
        analyzer.process_packet(_make_connect_ind_record(dev_f, periph_f, 0x99999999, 1_000))

        for sc in [0xFFFFFFFC, 0xFFFFFFFD, 0xFFFFFFFE, 0xFFFFFFFF]:
            findings = analyzer.process_packet(
                _make_signed_write_record(csrk, sc, 10_000 + (sc & 0xFF), 0x99999999)
            )
            assert findings[0].verdict == Verdict.SEQUENTIAL_MONOTONIC.value

        report = analyzer.finalize()
        assert report.verdict == Verdict.SEQUENTIAL_MONOTONIC.value
        assert report.metrics["total_signed_writes"] == 4
        assert report.metrics["total_anomalies"] == 0


# =============================================================================
# 4. Subtle Timing Jitter & Collision in BAT Allowlist Scans
# =============================================================================
class TestBatAllowlistTimingJitterAndAdversarialScans:
    """Stress tests for BAT timing oracle, jitter tolerance, and probe collisions."""

    def test_scan_rsp_timing_jitter_within_and_exceeding_window(self) -> None:
        """Remediated: Verify behavior of SCAN_RSP latency within window (<=5000us) vs exceeding (>5000us).

        1. Allowed scanner probes at t=2000us, response at t=2999us (delay=999us <= 5000us) -> MATCHED.
        2. Probing at t=10,000us with response at t=12,050us (delay=2050us <= 5000us) -> MATCHED within tolerance.
        3. Probing at t=20,000us with response at t=26,050us (delay=6050us > 5000us) -> NOT MATCHED, flushed as SILENCED.
        """
        analyzer = BatAllowlistAnalyzer()
        pdu_adv = build_adv_ind("11:22:33:44:55:66")
        pdu_req1 = build_scan_req("AA:BB:CC:DD:EE:01", "11:22:33:44:55:66")
        pdu_rsp1 = build_scan_rsp("11:22:33:44:55:66")

        analyzer.process_packet(BlePacketRecord(body=pdu_adv, channel=37, rssi=-60, timestamp_usec=1_000))
        # Probe 1 with 999us delay (within 5000us window)
        analyzer.process_packet(BlePacketRecord(body=pdu_req1, channel=37, rssi=-60, timestamp_usec=2_000))
        f1 = analyzer.process_packet(BlePacketRecord(body=pdu_rsp1, channel=37, rssi=-60, timestamp_usec=2_999))
        assert any(f.verdict == Verdict.OPEN_ADVERTISER.value for f in f1)

        # Probe 2 with 2050us delay (jitter within 5000us window) -> MATCHED
        pdu_req2 = build_scan_req("AA:BB:CC:DD:EE:02", "11:22:33:44:55:66")
        pdu_rsp2 = build_scan_rsp("11:22:33:44:55:66")
        analyzer.process_packet(BlePacketRecord(body=pdu_req2, channel=37, rssi=-60, timestamp_usec=10_000))
        f2 = analyzer.process_packet(BlePacketRecord(body=pdu_rsp2, channel=37, rssi=-60, timestamp_usec=12_050))
        assert any(f.verdict == Verdict.OPEN_ADVERTISER.value for f in f2)

        # Probe 3 with 6050us delay (exceeds 5000us window) -> NOT MATCHED, flushed as SILENCED
        pdu_req3 = build_scan_req("AA:BB:CC:DD:EE:03", "11:22:33:44:55:66")
        analyzer.process_packet(BlePacketRecord(body=pdu_req3, channel=37, rssi=-60, timestamp_usec=20_000))
        analyzer.process_packet(BlePacketRecord(body=pdu_rsp2, channel=37, rssi=-60, timestamp_usec=26_050))

        report = analyzer.finalize()
        # Because Probe 3 exceeded 5000us, it was silenced while Probe 1 & 2 responded -> ALLOWLIST_CONFIRMED
        assert report.verdict == Verdict.ALLOWLIST_CONFIRMED.value
        assert report.metrics["allowlist_confirmed_peripherals"] == 1

    def test_concurrent_scanners_fifo_probe_misattribution(self) -> None:
        """Remediated: Nearest-T_IFS matching associates SCAN_RSP to probe with minimal |delay - 150us|.

        Scanner A probes at t=1000us (delay to 1250us is 250us).
        Scanner B probes at t=1100us (delay to 1250us is 150us -> exact T_IFS).
        Peripheral emits SCAN_RSP at t=1250us.
        Nearest-T_IFS correctly attributes response to Scanner B (allowed), silencing Scanner A (foreign).
        """
        analyzer = BatAllowlistAnalyzer()
        foreign_scanner = "F0:00:00:00:00:01"
        allowed_scanner = "A0:00:00:00:00:01"
        periph_addr = "11:22:33:44:55:66"

        pdu_adv = build_adv_ind(periph_addr)
        pdu_req_foreign = build_scan_req(foreign_scanner, periph_addr)
        pdu_req_allowed = build_scan_req(allowed_scanner, periph_addr)
        pdu_rsp = build_scan_rsp(periph_addr)

        analyzer.process_packet(BlePacketRecord(body=pdu_adv, channel=37, rssi=-60, timestamp_usec=500))
        analyzer.process_packet(BlePacketRecord(body=pdu_req_foreign, channel=37, rssi=-60, timestamp_usec=1_000))
        analyzer.process_packet(BlePacketRecord(body=pdu_req_allowed, channel=37, rssi=-60, timestamp_usec=1_100))
        # Response at 1250us (delay from foreign=250us, from allowed=150us)
        analyzer.process_packet(BlePacketRecord(body=pdu_rsp, channel=37, rssi=-60, timestamp_usec=1_250))

        report = analyzer.finalize()
        assert report.verdict == Verdict.ALLOWLIST_CONFIRMED.value
        periph_state = analyzer._peripherals[periph_addr]
        # Remediated: Response correctly attributed to allowed_scanner with nearest T_IFS delay
        assert allowed_scanner in periph_state.probes_responded
        # Foreign scanner was silenced
        assert foreign_scanner in periph_state.probes_silenced

    def test_out_of_order_negative_delay_jitter(self) -> None:
        """Clock skew between dual sniffers causing SCAN_RSP timestamp before SCAN_REQ."""
        analyzer = BatAllowlistAnalyzer()
        scanner = "E0:00:00:00:00:01"
        periph_addr = "11:22:33:44:55:66"

        pdu_adv = build_adv_ind(periph_addr)
        pdu_req = build_scan_req(scanner, periph_addr)
        pdu_rsp = build_scan_rsp(periph_addr)

        analyzer.process_packet(BlePacketRecord(body=pdu_adv, channel=37, rssi=-60, timestamp_usec=1_000))
        # SCAN_RSP appears 10us BEFORE SCAN_REQ due to sniffer merge clock skew
        analyzer.process_packet(BlePacketRecord(body=pdu_rsp, channel=37, rssi=-60, timestamp_usec=1_990))
        analyzer.process_packet(BlePacketRecord(body=pdu_req, channel=37, rssi=-60, timestamp_usec=2_000))

        report = analyzer.finalize()
        assert report.verdict == Verdict.INCONCLUSIVE.value
        # Because SCAN_RSP came before SCAN_REQ, probe was never matched
        periph_state = analyzer._peripherals[periph_addr]
        assert scanner in periph_state.probes_silenced
        assert scanner not in periph_state.probes_responded

    def test_fast_and_slow_advertising_interval_transitions(self) -> None:
        """Test interval tracking across multi-channel advertising events.

        Simulates primary advertising across channels 37, 38, 39:
        - Fast mode: event interval 20ms
        - Transition to slow mode: event interval 1200ms
        """
        analyzer = BatAllowlistAnalyzer()
        pdu_adv = build_adv_ind("22:33:44:55:66:77")
        t = 1_000_000  # 1 sec

        # Fast advertising bursts (5 events at 20ms intervals)
        for _ in range(5):
            for ch in (37, 38, 39):
                analyzer.process_packet(BlePacketRecord(body=pdu_adv, channel=ch, rssi=-50, timestamp_usec=t))
                t += 1_000  # 1ms between channels
            t += 20_000  # 20ms inter-event

        # Transition to slow background advertising (3 events at 1200ms intervals)
        for _ in range(3):
            for ch in (37, 38, 39):
                analyzer.process_packet(BlePacketRecord(body=pdu_adv, channel=ch, rssi=-50, timestamp_usec=t))
                t += 1_000
            t += 1_200_000  # 1200ms inter-event

        report = analyzer.finalize()
        periph = analyzer._peripherals["22:33:44:55:66:77"]
        assert periph.fast_adv_observed is True
        assert periph.slow_adv_observed is True
        assert report.metrics["fast_slow_transition_peripherals"] == 1

    def test_directed_advertising_burst_detection(self) -> None:
        """Verify high-duty ADV_DIRECT_IND bursts targeting a companion device."""
        analyzer = BatAllowlistAnalyzer()
        pdu_dir = build_adv_direct_ind("AA:11:22:33:44:55", "BB:66:77:88:99:00")

        for idx in range(10):
            analyzer.process_packet(
                BlePacketRecord(body=pdu_dir, channel=37, rssi=-45, timestamp_usec=10_000 + idx * 1_250)
            )

        report = analyzer.finalize()
        assert report.verdict == Verdict.DIRECTED_EXCLUSIVE.value
        assert report.metrics["directed_advertising_events"] == 1
