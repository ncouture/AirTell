"""Empirical Adversarial Challenge Suite: Multi-Device RF Tracking, Timing Jitter, and Connection Isolation.

Challenger: Challenger M4 SC 2 (teamwork_preview_challenger)
Target Scope: Milestone 4 E2E Integration & Stress Testing
- tests/e2e/test_sidechannel_e2e.py
- Multi-device RF tracking with dozens of rotating RPAs
- Timing oracle tolerances & jitter under packet reordering
- CSRK 32-bit rollover and parallel connection state isolation
"""

from __future__ import annotations

import random

from airtell.sidechannel import (
    BatAllowlistAnalyzer,
    BlePacketRecord,
    CsrkCounterAnalyzer,
    DifferentialEncryptionAnalyzer,
    Verdict,
    analyze_pcap,
    build_adv_ind,
    build_att_signed_write,
    build_connect_ind,
    build_ll_enc_req,
    build_ll_enc_rsp,
    build_ll_reject_ind,
    build_ll_start_enc_req,
    build_ll_start_enc_rsp,
    build_scan_req,
    build_scan_rsp,
    generate_synthetic_pcap,
)
from airtell.sidechannel.synthetic import (
    ERROR_PIN_OR_KEY_MISSING,
    SyntheticEvent,
)
from airtell.sniff.pcap import BLE_ADV_AA

CSRK_KEY_ALPHA: bytes = b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
CSRK_KEY_BETA: bytes = b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
CSRK_KEY_GAMMA: bytes = b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"


# =============================================================================
# Helper Functions
# =============================================================================
def _make_signed_write(
    csrk: bytes,
    counter: int,
    ts_usec: int,
    conn_aa: int,
    handle: int = 0x0012,
    corrupt_mac: bool = False,
    direction: int = 0,
) -> BlePacketRecord:
    body = build_att_signed_write(
        csrk=csrk,
        handle=handle,
        value=b"\x01",
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


def _make_connect(
    init_a: str,
    adv_a: str,
    conn_aa: int,
    ts_usec: int,
) -> BlePacketRecord:
    body = build_connect_ind(init_a=init_a, adv_a=adv_a, conn_aa=conn_aa)
    return BlePacketRecord(
        body=body,
        channel=37,
        rssi=-50,
        timestamp_usec=ts_usec,
        access_address=BLE_ADV_AA,
        direction=0,
    )


# =============================================================================
# 1. Challenge Multi-Device RF Tracking with Dozens of Rotating RPAs
# =============================================================================
class TestAdversarialMultiDeviceTracking:
    """Stress tests multi-device RPA tracking across concurrent peripherals and large rotation counts."""

    def test_interleaved_sixty_rotating_rpas_across_six_peripherals(self) -> None:
        """Adversarial stress: 6 concurrent devices, each rotating RPA 10 times (60 RPAs total).

        Validates:
        - 6 distinct peripherals (D0..D5).
        - 6 distinct centrals, each rotating through 10 RPAs.
        - All packets interleaved across time in a shared RF capture.
        - Analyzer cleanly links all 10 RPAs for each central with zero cross-contamination.
        """
        analyzer = CsrkCounterAnalyzer()
        events: list[tuple[int, BlePacketRecord]] = []
        expected_groups: dict[int, list[str]] = {d: [] for d in range(6)}

        for dev_idx in range(6):
            periph = f"D0:00:00:00:00:{dev_idx:02X}"
            csrk = bytes([dev_idx + 1] * 16)
            sc = dev_idx * 1000 + 1

            for rot_idx in range(10):
                rpa = f"C0:{dev_idx:02X}:00:00:00:{rot_idx:02X}"
                expected_groups[dev_idx].append(rpa)
                conn_aa = 0x20000000 + (dev_idx << 12) + rot_idx
                t_conn = (dev_idx * 10 + rot_idx) * 5_000_000 + 1_000

                # Connection event
                events.append((t_conn, _make_connect(rpa, periph, conn_aa, t_conn)))

                # 3 signed writes per rotation
                for pkt_idx in range(3):
                    t_pkt = t_conn + 50_000 + (pkt_idx * 20_000)
                    events.append((t_pkt, _make_signed_write(csrk, sc, t_pkt, conn_aa)))
                    sc += 1

        # Sort all 240 packets deterministically by timestamp
        events.sort(key=lambda x: x[0])

        for _, rec in events:
            analyzer.process_packet(rec)

        rep = analyzer.finalize()
        assert rep.verdict == Verdict.CROSS_RPA_LINKED.value
        assert rep.metrics["total_signed_writes"] == 180
        assert rep.metrics["total_anomalies"] == 0
        assert len(rep.metrics["linked_rpa_groups"]) == 6

        # Verify exact group partitioning: no cross-contamination between devices
        for dev_idx in range(6):
            expected_set = set(expected_groups[dev_idx])
            matched = False
            for group in rep.metrics["linked_rpa_groups"]:
                if expected_groups[dev_idx][0] in group:
                    assert set(group) == expected_set, (
                        f"Device {dev_idx} group contaminated! Got {group} vs {expected_set}"
                    )
                    matched = True
                    break
            assert matched, f"Device {dev_idx} group not found in linked_rpa_groups"

    def test_rapid_subsecond_rpa_rotations_dense_traffic(self) -> None:
        """Adversarial stress: Central rotates RPA every 20ms across 8 rapid rotations."""
        analyzer = CsrkCounterAnalyzer()
        periph = "D0:00:00:00:AA:01"
        csrk = CSRK_KEY_ALPHA
        rpas = [f"C0:00:00:00:00:{i:02X}" for i in range(8)]
        sc = 1

        for idx, rpa in enumerate(rpas):
            conn_aa = 0x30000000 + idx
            t_base = 1_000_000 + (idx * 20_000)  # Every 20ms
            analyzer.process_packet(_make_connect(rpa, periph, conn_aa, t_base))
            analyzer.process_packet(_make_signed_write(csrk, sc, t_base + 5_000, conn_aa))
            sc += 1

        rep = analyzer.finalize()
        assert rep.verdict == Verdict.CROSS_RPA_LINKED.value
        assert len(rep.metrics["linked_rpa_groups"]) == 1
        linked = rep.metrics["linked_rpa_groups"][0]
        assert set(linked) == set(rpas)

    def test_history_preservation_under_noise_flood(self) -> None:
        """Adversarial stress: Target device history survives 400 interleaved noise packets."""
        analyzer = CsrkCounterAnalyzer()
        target_periph = "D0:00:00:00:00:01"
        noise_periph = "D0:00:00:00:00:99"
        target_rpa1 = "C0:00:00:00:00:01"
        target_rpa2 = "C0:00:00:00:00:02"

        # Target packet 1: SC=10
        analyzer.process_packet(_make_connect(target_rpa1, target_periph, 0x11111111, 1_000))
        analyzer.process_packet(_make_signed_write(CSRK_KEY_ALPHA, 10, 2_000, 0x11111111))

        # Flood 400 noise packets from background devices on different peripherals
        for i in range(400):
            noise_rpa = f"C9:00:00:00:{(i // 40):02X}:{(i % 40):02X}"
            conn_aa = 0x90000000 + (i % 10)
            t = 10_000 + (i * 1_000)
            if i % 10 == 0:
                analyzer.process_packet(_make_connect(noise_rpa, noise_periph, conn_aa, t))
            analyzer.process_packet(_make_signed_write(CSRK_KEY_BETA, 100 + i, t + 100, conn_aa))

        # Target rotates to target_rpa2: SC=11 (dt = 500ms < 300s)
        analyzer.process_packet(_make_connect(target_rpa2, target_periph, 0x11111112, 500_000))
        analyzer.process_packet(_make_signed_write(CSRK_KEY_ALPHA, 11, 501_000, 0x11111112))

        rep = analyzer.finalize()
        assert any(target_rpa1 in g and target_rpa2 in g for g in rep.metrics["linked_rpa_groups"])

    def test_unrelated_devices_same_counter_distinct_peripherals_not_linked(self) -> None:
        """Adversarial negative control: Two unrelated devices with identical counters to different peripherals."""
        analyzer = CsrkCounterAnalyzer()
        dev_a = "C0:00:00:00:00:0A"
        dev_b = "C0:00:00:00:00:0B"
        periph_a = "D0:00:00:00:00:0A"
        periph_b = "D0:00:00:00:00:0B"

        analyzer.process_packet(_make_connect(dev_a, periph_a, 0xAAAAAAAA, 1_000))
        analyzer.process_packet(_make_signed_write(CSRK_KEY_ALPHA, 100, 2_000, 0xAAAAAAAA))

        # Device B starts at SC=101 to peripheral B within 1 second
        analyzer.process_packet(_make_connect(dev_b, periph_b, 0xBBBBBBBB, 10_000))
        analyzer.process_packet(_make_signed_write(CSRK_KEY_BETA, 101, 11_000, 0xBBBBBBBB))

        rep = analyzer.finalize()
        assert len(rep.metrics["linked_rpa_groups"]) == 0
        assert rep.verdict == Verdict.SEQUENTIAL_MONOTONIC.value


# =============================================================================
# 2. Challenge Timing Oracle Edge Cases (Jitter, Tolerances, Packet Reordering)
# =============================================================================
class TestAdversarialTimingOracleEdgeCases:
    """Stress tests BAT allowlist timing oracle tolerances, probe matching under jitter and reordering."""

    def test_timing_jitter_sweep_boundary_tolerances(self) -> None:
        """Sweep response delay from 50us to 5500us to empirically map exact tolerance boundary.

        Asserts:
        - Delays in [100, 150, 200, 500, 2000, 4999, 5000] us correctly match probe (OPEN_ADVERTISER).
        - Delay >= 5001us exceeds 5ms window, causing probe to expire (INCONCLUSIVE).
        """
        periph = "D0:00:00:00:00:01"
        scanner = "C0:00:00:00:00:01"

        valid_delays = [100, 150, 170, 250, 1000, 3000, 4999, 5000]
        for delay in valid_delays:
            analyzer = BatAllowlistAnalyzer()
            analyzer.process_packet(BlePacketRecord(body=build_adv_ind(periph), channel=37, rssi=-50, timestamp_usec=1_000_000, access_address=BLE_ADV_AA))
            analyzer.process_packet(BlePacketRecord(body=build_scan_req(scanner, periph), channel=37, rssi=-50, timestamp_usec=1_010_000, access_address=BLE_ADV_AA))
            analyzer.process_packet(BlePacketRecord(body=build_scan_rsp(periph), channel=37, rssi=-50, timestamp_usec=1_010_000 + delay, access_address=BLE_ADV_AA))
            rep = analyzer.finalize()
            assert rep.verdict == Verdict.OPEN_ADVERTISER.value, f"Failed at delay {delay}us"
            assert rep.findings[0].details["response_delay_usec"] == delay

        # Test expiration at 5001us
        analyzer_exp = BatAllowlistAnalyzer()
        analyzer_exp.process_packet(BlePacketRecord(body=build_adv_ind(periph), channel=37, rssi=-50, timestamp_usec=1_000_000, access_address=BLE_ADV_AA))
        analyzer_exp.process_packet(BlePacketRecord(body=build_scan_req(scanner, periph), channel=37, rssi=-50, timestamp_usec=1_010_000, access_address=BLE_ADV_AA))
        analyzer_exp.process_packet(BlePacketRecord(body=build_scan_rsp(periph), channel=37, rssi=-50, timestamp_usec=1_010_000 + 5001, access_address=BLE_ADV_AA))
        rep_exp = analyzer_exp.finalize()
        assert rep_exp.verdict == Verdict.INCONCLUSIVE.value

    def test_negative_delay_reordered_packets_within_tolerance(self) -> None:
        """Adversarial test: SCAN_RSP timestamped slightly before SCAN_REQ (-40us) due to clock skew."""
        periph = "D0:00:00:00:00:01"
        scanner = "C0:00:00:00:00:01"

        analyzer = BatAllowlistAnalyzer()
        # Ingestion where SCAN_REQ arrives first in queue, but with timestamp 1000, and SCAN_RSP has timestamp 960 (-40us)
        analyzer.process_packet(BlePacketRecord(body=build_adv_ind(periph), channel=37, rssi=-50, timestamp_usec=500_000, access_address=BLE_ADV_AA))
        analyzer.process_packet(BlePacketRecord(body=build_scan_req(scanner, periph), channel=37, rssi=-50, timestamp_usec=1_000_000, access_address=BLE_ADV_AA))
        # SCAN_RSP with timestamp 999_960 (-40us delay within [-50, 5000])
        analyzer.process_packet(BlePacketRecord(body=build_scan_rsp(periph), channel=37, rssi=-50, timestamp_usec=999_960, access_address=BLE_ADV_AA))

        rep = analyzer.finalize()
        assert rep.verdict == Verdict.OPEN_ADVERTISER.value
        assert rep.findings[0].details["response_delay_usec"] == -40

    def test_concurrent_scanner_probes_matching_accuracy(self) -> None:
        """Adversarial test: 3 distinct scanners probe peripheral within 10us window.

        Peripheral responds to Scanner A at 150us.
        Analyzer matches Scanner A and correctly marks Scanners B and C as silenced.
        """
        periph = "D0:00:00:00:00:01"
        scanner_a = "C0:00:00:00:00:0A"
        scanner_b = "C0:00:00:00:00:0B"
        scanner_c = "C0:00:00:00:00:0C"

        analyzer = BatAllowlistAnalyzer()
        t_base = 1_000_000
        analyzer.process_packet(BlePacketRecord(body=build_adv_ind(periph), channel=37, rssi=-50, timestamp_usec=t_base, access_address=BLE_ADV_AA))
        # 3 probes closely spaced
        analyzer.process_packet(BlePacketRecord(body=build_scan_req(scanner_a, periph), channel=37, rssi=-50, timestamp_usec=t_base + 10_000, access_address=BLE_ADV_AA))
        analyzer.process_packet(BlePacketRecord(body=build_scan_req(scanner_b, periph), channel=37, rssi=-50, timestamp_usec=t_base + 10_005, access_address=BLE_ADV_AA))
        analyzer.process_packet(BlePacketRecord(body=build_scan_req(scanner_c, periph), channel=37, rssi=-50, timestamp_usec=t_base + 10_010, access_address=BLE_ADV_AA))

        # Single SCAN_RSP at exactly 150us after scanner A
        analyzer.process_packet(BlePacketRecord(body=build_scan_rsp(periph), channel=37, rssi=-50, timestamp_usec=t_base + 10_150, access_address=BLE_ADV_AA))

        # Advance time to flush expired probes
        analyzer.process_packet(BlePacketRecord(body=build_adv_ind(periph), channel=37, rssi=-50, timestamp_usec=t_base + 30_000, access_address=BLE_ADV_AA))

        rep = analyzer.finalize()
        assert rep.verdict == Verdict.ALLOWLIST_CONFIRMED.value
        assert rep.metrics["allowlist_confirmed_peripherals"] == 1

    def test_rapid_advertising_jittered_interval_transitions(self) -> None:
        """Adversarial stress: Advertising packets with synthetic Gaussian-like jitter."""
        periph = "D0:00:00:00:00:02"
        events: list[SyntheticEvent] = []

        rng = random.Random(1337)
        # Fast advertising burst (30ms nominal +/- 8ms jitter)
        t = 1_000_000
        for _ in range(10):
            events.append(SyntheticEvent(ts_usec=t, chan=37, aa=BLE_ADV_AA, body=build_adv_ind(periph)))
            t += int((30.0 + rng.uniform(-8.0, 8.0)) * 1000)

        # Transition to slow advertising (1200ms nominal +/- 50ms jitter)
        for _ in range(5):
            events.append(SyntheticEvent(ts_usec=t, chan=37, aa=BLE_ADV_AA, body=build_adv_ind(periph)))
            t += int((1200.0 + rng.uniform(-50.0, 50.0)) * 1000)

        pcap = generate_synthetic_pcap(events)
        report = analyze_pcap(pcap, analyzers=["bat"])
        rep = report.reports["bat_allowlist"]
        assert rep.metrics["fast_slow_transition_peripherals"] == 1


# =============================================================================
# 3. Challenge CSRK Rollover & Parallel Connection State Isolation
# =============================================================================
class TestAdversarialCsrkRolloverAndParallelIsolation:
    """Stress tests CSRK 32-bit counter progression near 0xFFFFFFFF and connection state isolation."""

    def test_csrk_monotonic_near_max_boundary(self) -> None:
        """Sequential increment 0xFFFFFFFD -> 0xFFFFFFFE -> 0xFFFFFFFF is valid SEQUENTIAL_MONOTONIC."""
        analyzer = CsrkCounterAnalyzer()
        periph = "D0:00:00:00:00:01"
        central = "C0:00:00:00:00:01"
        conn_aa = 0x55555555

        analyzer.process_packet(_make_connect(central, periph, conn_aa, 1_000))
        analyzer.process_packet(_make_signed_write(CSRK_KEY_ALPHA, 0xFFFFFFFD, 2_000, conn_aa))
        analyzer.process_packet(_make_signed_write(CSRK_KEY_ALPHA, 0xFFFFFFFE, 3_000, conn_aa))
        analyzer.process_packet(_make_signed_write(CSRK_KEY_ALPHA, 0xFFFFFFFF, 4_000, conn_aa))

        rep = analyzer.finalize()
        assert rep.verdict == Verdict.SEQUENTIAL_MONOTONIC.value
        assert rep.metrics["total_signed_writes"] == 3
        assert rep.metrics["total_anomalies"] == 0

    def test_csrk_wrapping_to_zero_triggers_rollback(self) -> None:
        """Per BLE spec, SignCounter exhaustion wraps to 0, which MUST be flagged as ANOMALY_ROLLBACK."""
        analyzer = CsrkCounterAnalyzer()
        periph = "D0:00:00:00:00:01"
        central = "C0:00:00:00:00:01"
        conn_aa = 0x55555555

        analyzer.process_packet(_make_connect(central, periph, conn_aa, 1_000))
        analyzer.process_packet(_make_signed_write(CSRK_KEY_ALPHA, 0xFFFFFFFF, 2_000, conn_aa))
        # Wrap to 0
        analyzer.process_packet(_make_signed_write(CSRK_KEY_ALPHA, 0x00000000, 3_000, conn_aa))

        rep = analyzer.finalize()
        assert rep.verdict == Verdict.ANOMALY_ROLLBACK.value
        assert rep.metrics["rollback_anomalies"] == 1

    def test_parallel_connections_distinct_centrals_complete_isolation(self) -> None:
        """Three concurrent parallel connections with distinct centrals and peripherals.

        Verifies:
        - Connection 1 (C1 -> P1): Sequential writes SC=1..5
        - Connection 2 (C2 -> P2): Replay attack SC=10, 11, 11 (ANOMALY_REPLAY)
        - Connection 3 (C3 -> P3): Large jump SC=50, 500 (ANOMALY_JUMP)
        - State is strictly maintained per sender with accurate anomaly accounting.
        """
        analyzer = CsrkCounterAnalyzer()

        # Connect 3 sessions
        analyzer.process_packet(_make_connect("C0:00:00:00:00:01", "D0:00:00:00:00:01", 0x11111111, 1_000))
        analyzer.process_packet(_make_connect("C0:00:00:00:00:02", "D0:00:00:00:00:02", 0x22222222, 2_000))
        analyzer.process_packet(_make_connect("C0:00:00:00:00:03", "D0:00:00:00:00:03", 0x33333333, 3_000))

        # Interleave packets across all 3
        # Conn 1: 1
        analyzer.process_packet(_make_signed_write(CSRK_KEY_ALPHA, 1, 10_000, 0x11111111))
        # Conn 2: 10
        analyzer.process_packet(_make_signed_write(CSRK_KEY_BETA, 10, 11_000, 0x22222222))
        # Conn 3: 50
        analyzer.process_packet(_make_signed_write(CSRK_KEY_GAMMA, 50, 12_000, 0x33333333))

        # Conn 1: 2
        analyzer.process_packet(_make_signed_write(CSRK_KEY_ALPHA, 2, 20_000, 0x11111111))
        # Conn 2: 11
        analyzer.process_packet(_make_signed_write(CSRK_KEY_BETA, 11, 21_000, 0x22222222))
        # Conn 3: 500 (Jump)
        analyzer.process_packet(_make_signed_write(CSRK_KEY_GAMMA, 500, 22_000, 0x33333333))

        # Conn 1: 3
        analyzer.process_packet(_make_signed_write(CSRK_KEY_ALPHA, 3, 30_000, 0x11111111))
        # Conn 2: 11 (Replay)
        analyzer.process_packet(_make_signed_write(CSRK_KEY_BETA, 11, 31_000, 0x22222222))

        rep = analyzer.finalize()
        assert rep.metrics["total_signed_writes"] == 8
        assert rep.metrics["replay_anomalies"] == 1
        assert rep.metrics["jump_anomalies"] == 1
        assert rep.metrics["total_anomalies"] == 2

    def test_corrupted_mac_in_one_parallel_connection_does_not_poison_others(self) -> None:
        """Corrupted signature in Connection 2 does NOT poison or halt Connection 1.

        Verifies:
        - Known CSRK key checked on Connection 1 and Connection 2.
        - Connection 2 receives corrupted MAC; flagged as VERIFICATION_FAILED.
        - Connection 1 continues to process sequential writes normally.
        """
        analyzer = CsrkCounterAnalyzer(csrk=CSRK_KEY_ALPHA)
        analyzer.process_packet(_make_connect("C0:00:00:00:00:01", "D0:00:00:00:00:01", 0x11111111, 1_000))
        analyzer.process_packet(_make_connect("C0:00:00:00:00:02", "D0:00:00:00:00:02", 0x22222222, 2_000))

        # Conn 1: SC=1 (valid)
        analyzer.process_packet(_make_signed_write(CSRK_KEY_ALPHA, 1, 10_000, 0x11111111))
        # Conn 2: SC=10 (corrupted MAC)
        analyzer.process_packet(_make_signed_write(CSRK_KEY_ALPHA, 10, 11_000, 0x22222222, corrupt_mac=True))
        # Conn 1: SC=2 (valid)
        analyzer.process_packet(_make_signed_write(CSRK_KEY_ALPHA, 2, 12_000, 0x11111111))

        rep = analyzer.finalize()
        assert rep.verdict == Verdict.VERIFICATION_FAILED.value
        assert rep.metrics["mac_verification_failures"] == 1
        assert rep.metrics["total_signed_writes"] == 3

    def test_differential_encryption_state_isolation_concurrent_handshakes(self) -> None:
        """Interleaved encryption handshakes across 4 parallel connections maintain state isolation."""
        analyzer = DifferentialEncryptionAnalyzer()

        connections = [
            ("C0:00:00:00:00:01", "D0:00:00:00:00:01", 0x11111111, True),   # Shared LTK
            ("C0:00:00:00:00:02", "D0:00:00:00:00:02", 0x22222222, False),  # Rejected
            ("C0:00:00:00:00:03", "D0:00:00:00:00:03", 0x33333333, True),   # Shared LTK
            ("C0:00:00:00:00:04", "D0:00:00:00:00:04", 0x44444444, False),  # Rejected
        ]

        # Connect all 4
        for idx, (central, periph, aa, _) in enumerate(connections):
            analyzer.process_packet(_make_connect(central, periph, aa, 1000 + idx * 100))

        # Interleave ENC_REQ
        for idx, (_, _, aa, _) in enumerate(connections):
            analyzer.process_packet(BlePacketRecord(
                body=build_ll_enc_req(rand=bytes([idx]*8), ediv=idx, skdm=bytes([idx]*8), ivm=bytes([idx]*4)),
                channel=1,
                rssi=-60,
                timestamp_usec=10_000 + idx * 1000,
                access_address=aa,
                direction=0,
            ))

        # Handshake outcomes interleaved
        # Conn 0 (Shared)
        analyzer.process_packet(BlePacketRecord(body=build_ll_enc_rsp(skds=b"\x01"*8, ivs=b"\x02"*4), channel=1, rssi=-60, timestamp_usec=20_000, access_address=0x11111111, direction=1))
        # Conn 1 (Reject)
        analyzer.process_packet(BlePacketRecord(body=build_ll_reject_ind(ERROR_PIN_OR_KEY_MISSING), channel=1, rssi=-60, timestamp_usec=21_000, access_address=0x22222222, direction=1))
        # Conn 2 (Shared)
        analyzer.process_packet(BlePacketRecord(body=build_ll_enc_rsp(skds=b"\x03"*8, ivs=b"\x04"*4), channel=1, rssi=-60, timestamp_usec=22_000, access_address=0x33333333, direction=1))
        # Conn 3 (Reject)
        analyzer.process_packet(BlePacketRecord(body=build_ll_reject_ind(ERROR_PIN_OR_KEY_MISSING), channel=1, rssi=-60, timestamp_usec=23_000, access_address=0x44444444, direction=1))

        # Complete Conn 0 and Conn 2
        analyzer.process_packet(BlePacketRecord(body=build_ll_start_enc_req(), channel=1, rssi=-60, timestamp_usec=30_000, access_address=0x11111111, direction=1))
        analyzer.process_packet(BlePacketRecord(body=build_ll_start_enc_rsp(), channel=1, rssi=-60, timestamp_usec=31_000, access_address=0x11111111, direction=0))
        analyzer.process_packet(BlePacketRecord(body=build_ll_start_enc_rsp(mic=b"\xAA"*4), channel=1, rssi=-60, timestamp_usec=32_000, access_address=0x11111111, direction=1))

        analyzer.process_packet(BlePacketRecord(body=build_ll_start_enc_req(), channel=1, rssi=-60, timestamp_usec=33_000, access_address=0x33333333, direction=1))
        analyzer.process_packet(BlePacketRecord(body=build_ll_start_enc_rsp(), channel=1, rssi=-60, timestamp_usec=34_000, access_address=0x33333333, direction=0))
        analyzer.process_packet(BlePacketRecord(body=build_ll_start_enc_rsp(mic=b"\xBB"*4), channel=1, rssi=-60, timestamp_usec=35_000, access_address=0x33333333, direction=1))

        rep = analyzer.finalize()
        assert rep.verdict == Verdict.CONFIRMED_EXCLUSIVE.value
        assert rep.metrics["shared_ltk_sessions"] == 2
        assert rep.metrics["rejected_sessions"] == 2
        assert rep.metrics["total_connections"] == 4
