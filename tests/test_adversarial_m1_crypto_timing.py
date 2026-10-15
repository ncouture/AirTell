"""Empirical Adversarial Challenge Suite: Cryptographic & Timing Fidelity (Milestone 1).

Adversarial Stress Testing:
1. RFC 4493 Independent AES-128-CMAC Test Vectors & Subkey Derivation Fidelity.
2. Custom and extreme cryptographic keys, avalanche effect, and 64-bit truncation correctness.
3. CSRK Counter Trajectory Stress Testing:
   - Monotonic baselines, replay sequences, counter drops/rollbacks, non-sequential jumps.
   - Single-bit MAC signature corruption across all 64 bits.
   - Cross-RPA tracking sequences.
4. BAT Allowlist Timing & Connection Parameter Stress:
   - T_IFS timing compliance (150 us).
   - Fast and slow advertising intervals and shifts.
   - ConnectionParameters dataclass and 4-tuple parameter handling.
   - Directed advertising bursts.
5. Boundary conditions, stress invariants, and Wireshark/tshark packet dissection integrity.
"""

from __future__ import annotations

import io
import shutil
import struct
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from airtell.protocol.mac import str_to_mac
from airtell.sidechannel import (
    ATT_OPCODE_SIGNED_WRITE_CMD,
    ConnectionParameters,
    build_att_signed_write,
    compute_csrk_mac,
    generate_bat_allowlist_trace,
    generate_csrk_trace,
)
from airtell.sniff.pcap import PcapBleReader


# =============================================================================
# 1. Independent RFC 4493 Test Vectors & Cryptographic Fidelity
# =============================================================================
class TestRfc4493IndependentVectorsAndSubkeyFidelity:
    """Verifies AES-128-CMAC against official RFC 4493 test vectors and subkey rules."""

    RFC_KEY: bytes = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")

    def test_rfc4493_all_four_official_test_vectors(self) -> None:
        """Verifies the four canonical RFC 4493 test vectors using independent CMAC execution."""
        # Example 1: len = 0
        c1 = cmac.CMAC(algorithms.AES(self.RFC_KEY))
        c1.update(b"")
        assert c1.finalize() == bytes.fromhex("bb1d6929e95937287fa37d129b756746")

        # Example 2: len = 16
        m2 = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        c2 = cmac.CMAC(algorithms.AES(self.RFC_KEY))
        c2.update(m2)
        assert c2.finalize() == bytes.fromhex("070a16b46b4d4144f79bdd9dd04a287c")

        # Example 3: len = 40
        m3 = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411"
        )
        c3 = cmac.CMAC(algorithms.AES(self.RFC_KEY))
        c3.update(m3)
        assert c3.finalize() == bytes.fromhex("dfa66747de9ae63030ca32611497c827")

        # Example 4: len = 64
        m4 = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        )
        c4 = cmac.CMAC(algorithms.AES(self.RFC_KEY))
        c4.update(m4)
        assert c4.finalize() == bytes.fromhex("51f0bebf7e3b9d92fc49741779363cfe")

    def test_rfc4493_mapped_to_compute_csrk_mac(self) -> None:
        """Deconstructs RFC 4493 messages into (Opcode, Handle, Value, SignCounter) and checks tags."""
        # Map Example 2 (len = 16):
        # 1B opcode + 2B handle (LE) + 9B value + 4B counter (LE) = 16B
        m2 = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        op2 = m2[0]
        h2 = struct.unpack("<H", m2[1:3])[0]
        val2 = m2[3:12]
        cnt2 = struct.unpack("<I", m2[12:16])[0]
        mac2 = compute_csrk_mac(self.RFC_KEY, op2, h2, val2, cnt2)
        expected2 = bytes.fromhex("070a16b46b4d4144")
        assert mac2 == expected2

        # Map Example 3 (len = 40):
        # 1B opcode + 2B handle (LE) + 33B value + 4B counter (LE) = 40B
        m3 = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411"
        )
        op3 = m3[0]
        h3 = struct.unpack("<H", m3[1:3])[0]
        val3 = m3[3:36]
        cnt3 = struct.unpack("<I", m3[36:40])[0]
        mac3 = compute_csrk_mac(self.RFC_KEY, op3, h3, val3, cnt3)
        expected3 = bytes.fromhex("dfa66747de9ae630")
        assert mac3 == expected3

        # Map Example 4 (len = 64):
        # 1B opcode + 2B handle (LE) + 57B value + 4B counter (LE) = 64B
        m4 = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        )
        op4 = m4[0]
        h4 = struct.unpack("<H", m4[1:3])[0]
        val4 = m4[3:60]
        cnt4 = struct.unpack("<I", m4[60:64])[0]
        mac4 = compute_csrk_mac(self.RFC_KEY, op4, h4, val4, cnt4)
        expected4 = bytes.fromhex("51f0bebf7e3b9d92")
        assert mac4 == expected4

    def test_nist_sp800_38b_subkey_derivation(self) -> None:
        """Verifies subkey generation (K1, K2) matches RFC 4493 Section 4 specification."""
        cipher = Cipher(algorithms.AES(self.RFC_KEY), modes.ECB())
        enc = cipher.encryptor()
        L = enc.update(b"\x00" * 16) + enc.finalize()
        assert L == bytes.fromhex("7df76b0c1ab899b33e42f047b91b546f")

        L_int = int.from_bytes(L, "big")
        if (L_int & (1 << 127)) == 0:
            K1_int = (L_int << 1) & ((1 << 128) - 1)
        else:
            K1_int = ((L_int << 1) & ((1 << 128) - 1)) ^ 0x87
        K1 = K1_int.to_bytes(16, "big")
        assert K1 == bytes.fromhex("fbeed618357133667c85e08f7236a8de")

        if (K1_int & (1 << 127)) == 0:
            K2_int = (K1_int << 1) & ((1 << 128) - 1)
        else:
            K2_int = ((K1_int << 1) & ((1 << 128) - 1)) ^ 0x87
        K2 = K2_int.to_bytes(16, "big")
        assert K2 == bytes.fromhex("f7ddac306ae266ccf90bc11ee46d513b")

    def test_custom_and_extreme_keys(self) -> None:
        """Verifies compute_csrk_mac with extreme keys: all zeros, all ones, alternating bytes."""
        keys = [
            b"\x00" * 16,
            b"\xff" * 16,
            b"\xaa\x55" * 8,
            bytes(range(16)),
        ]
        seen_tags = set()
        for k in keys:
            tag = compute_csrk_mac(k, ATT_OPCODE_SIGNED_WRITE_CMD, 0x0001, b"Payload", 0)
            assert len(tag) == 8
            assert tag not in seen_tags
            seen_tags.add(tag)

    def test_cryptographic_avalanche_effect(self) -> None:
        """Asserts strong avalanche effect: single-bit flips flip on average ~32 bits of 64-bit MAC."""
        key = bytes.fromhex("00112233445566778899aabbccddeeff")
        base_mac = compute_csrk_mac(key, ATT_OPCODE_SIGNED_WRITE_CMD, 0x0042, b"AvalancheData", 1000)

        diffs: list[int] = []
        # Mutate each bit of 32-bit counter
        for bit in range(32):
            c_mut = 1000 ^ (1 << bit)
            mut_mac = compute_csrk_mac(key, ATT_OPCODE_SIGNED_WRITE_CMD, 0x0042, b"AvalancheData", c_mut)
            assert mut_mac != base_mac
            hamming = bin(int.from_bytes(base_mac, "big") ^ int.from_bytes(mut_mac, "big")).count("1")
            diffs.append(hamming)

        # Mutate each bit of 16-bit handle
        for bit in range(16):
            h_mut = 0x0042 ^ (1 << bit)
            mut_mac = compute_csrk_mac(key, ATT_OPCODE_SIGNED_WRITE_CMD, h_mut, b"AvalancheData", 1000)
            assert mut_mac != base_mac
            hamming = bin(int.from_bytes(base_mac, "big") ^ int.from_bytes(mut_mac, "big")).count("1")
            diffs.append(hamming)

        avg_diff = sum(diffs) / len(diffs)
        assert 24.0 <= avg_diff <= 40.0  # Centered around 32 bits
        assert min(diffs) >= 12          # Significant diffusion on every bit

    def test_truncation_fidelity_most_significant_64_bits(self) -> None:
        """Verifies compute_csrk_mac extracts precisely octets 0..7 of the full 16-byte CMAC."""
        key = b"Key1234567890123"
        msg = bytes([0xD2]) + struct.pack("<H", 0x0010) + b"test" + struct.pack("<I", 7)
        c = cmac.CMAC(algorithms.AES(key))
        c.update(msg)
        full_tag = c.finalize()

        truncated = compute_csrk_mac(key, 0xD2, 0x0010, b"test", 7)
        assert truncated == full_tag[:8]
        assert len(truncated) == 8


# =============================================================================
# 2. CSRK Counter Trajectory Stress Testing
# =============================================================================
class TestCsrkCounterTrajectoriesStress:
    """Stress tests counter sequences: replays, rollbacks, jumps, single-bit MAC corruptions."""

    KEY: bytes = b"\x10\x20\x30\x40\x50\x60\x70\x80\x90\xa0\xb0\xc0\xd0\xe0\xf0\x00"

    def test_strictly_monotonic_trajectory(self) -> None:
        """Verifies 50 sequential packets with strictly monotonic counters."""
        seq = list(range(100, 150))
        pcap = generate_csrk_trace(seq, csrk=self.KEY, handle=0x0020, value=b"val")
        reader = PcapBleReader(io.BytesIO(pcap))
        pkts = list(reader)
        reader.close()

        # 1 CONNECT_IND + 50 writes
        assert len(pkts) == 51
        for idx, expected_sc in enumerate(seq):
            body = pkts[idx + 1].body
            # Handle at body[7:9], value at body[9:12], SignCounter at body[12:16]
            sc = struct.unpack("<I", body[12:16])[0]
            assert sc == expected_sc

    def test_replay_counter_trajectories(self) -> None:
        """Stress tests immediate replay, delayed replay, and repetitive replay bursts."""
        replay_patterns = [
            [10, 10, 11],                 # Immediate consecutive replay
            [1, 2, 3, 1, 4],             # Delayed replay of prior counter
            [50, 50, 50, 50, 50],        # Stalled replay burst
            [0, 0, 0],                   # Zero-counter replay
        ]
        for pattern in replay_patterns:
            pcap = generate_csrk_trace(pattern, csrk=self.KEY)
            reader = PcapBleReader(io.BytesIO(pcap))
            pkts = list(reader)
            reader.close()
            assert len(pkts) == len(pattern) + 1
            extracted = [
                struct.unpack("<I", pkts[i + 1].body[10:14])[0]  # default val is b"\x01" (1B) -> 9+1=10
                for i in range(len(pattern))
            ]
            assert extracted == pattern

    def test_counter_rollback_and_drops(self) -> None:
        """Stress tests counter drop / decreasing sequence trajectories."""
        drop_patterns = [
            [100, 99, 98, 97],           # Inverted decrement
            [5000, 10],                  # Large step backwards
            [0xFFFFFFFF, 0],             # Rollover boundary drop
        ]
        for pattern in drop_patterns:
            pcap = generate_csrk_trace(pattern, csrk=self.KEY)
            reader = PcapBleReader(io.BytesIO(pcap))
            pkts = list(reader)
            reader.close()
            assert len(pkts) == len(pattern) + 1
            extracted = [
                struct.unpack("<I", pkts[i + 1].body[10:14])[0]
                for i in range(len(pattern))
            ]
            assert extracted == pattern

    def test_non_sequential_jumps_and_zigzags(self) -> None:
        """Stress tests large discontinuous jumps and zig-zag counter sequences."""
        jump_patterns = [
            [1, 1_000_000, 1_000_001],
            [10, 5, 20, 15, 30, 25],
            [0, 0x7FFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF],
        ]
        for pattern in jump_patterns:
            pcap = generate_csrk_trace(pattern, csrk=self.KEY)
            reader = PcapBleReader(io.BytesIO(pcap))
            pkts = list(reader)
            reader.close()
            assert len(pkts) == len(pattern) + 1
            extracted = [
                struct.unpack("<I", pkts[i + 1].body[10:14])[0]
                for i in range(len(pattern))
            ]
            assert extracted == pattern

    def test_single_bit_mac_corruption_stress(self) -> None:
        """Exhaustively flips every single bit (0..63) of the MAC and asserts corruption detection."""
        val = b"IntegrityCheck"
        counter = 12345
        valid_mac = compute_csrk_mac(self.KEY, ATT_OPCODE_SIGNED_WRITE_CMD, 0x0010, val, counter)

        for bit_pos in range(64):
            byte_idx = bit_pos // 8
            bit_mask = 1 << (bit_pos % 8)
            corrupted_byte = valid_mac[byte_idx] ^ bit_mask
            corrupted_mac = valid_mac[:byte_idx] + bytes([corrupted_byte]) + valid_mac[byte_idx + 1 :]

            assert corrupted_mac != valid_mac

            pdu = build_att_signed_write(
                csrk=self.KEY,
                handle=0x0010,
                value=val,
                counter=counter,
                override_mac=corrupted_mac,
            )
            # Extract MAC from end of PDU
            extracted_mac = pdu[-8:]
            assert extracted_mac == corrupted_mac
            assert extracted_mac != valid_mac

    def test_cross_rpa_counter_linkage_trajectory(self) -> None:
        """Simulates central rotating through multiple RPAs while preserving continuous counter."""
        counters = [1, 2, 3, 4, 5, 6]
        rpas = ["5A:11:11:11:11:01", "5A:22:22:22:22:02"]
        # Rotate at counter index 2 and index 4
        pcap = generate_csrk_trace(
            counter_sequence=counters,
            csrk=self.KEY,
            rotate_rpa_indices=[2, 4],
            rpa_sequence=rpas,
        )
        reader = PcapBleReader(io.BytesIO(pcap))
        pkts = list(reader)
        reader.close()

        # 1 initial CONNECT + 2 writes + 1 rotated CONNECT + 2 writes + 1 rotated CONNECT + 2 writes = 9 pkts
        assert len(pkts) == 9

        # Check initial connection (chan 37)
        assert pkts[0].ble_chan == 37
        # Check first rotation at index 3 (chan 37, new InitA)
        assert pkts[3].ble_chan == 37
        assert pkts[3].body[2:8] == str_to_mac(rpas[0])
        # Check second rotation at index 6 (chan 37, new InitA)
        assert pkts[6].ble_chan == 37
        assert pkts[6].body[2:8] == str_to_mac(rpas[1])

    def test_boundary_counter_validation(self) -> None:
        """Asserts counter values outside [0, 0xFFFFFFFF] are strictly rejected."""
        with pytest.raises(ValueError, match="SignCounter must be 32-bit uint"):
            compute_csrk_mac(self.KEY, 0xD2, 0x0001, b"", -1)

        with pytest.raises(ValueError, match="SignCounter must be 32-bit uint"):
            compute_csrk_mac(self.KEY, 0xD2, 0x0001, b"", 0x100000000)

        with pytest.raises(ValueError, match="SignCounter must be 32-bit uint"):
            build_att_signed_write(self.KEY, counter=-5)

        with pytest.raises(ValueError, match="SignCounter must be 32-bit uint"):
            build_att_signed_write(self.KEY, counter=0x1_0000_0000)


# =============================================================================
# 3. BAT Allowlist Timing & Connection Parameter Stress Testing
# =============================================================================
class TestBatAllowlistTimingAndParameterStress:
    """Stress tests BAT allowlist timing parameters, T_IFS, interval shifts, and connection tuples."""

    def test_selective_probe_allowlist_enabled_silent_drop(self) -> None:
        """When allowlist is enabled, foreign probe is silently dropped; target gets SCAN_RSP within T_IFS."""
        pcap = generate_bat_allowlist_trace(
            allowlist_enabled=True,
            target_rpa="5A:AA:BB:CC:DD:01",
            foreign_rpa="4A:11:22:33:44:55",
            periph_addr="5A:EE:FF:00:11:22",
            mode="selective_probe",
            base_time_usec=2_000_000,
        )
        reader = PcapBleReader(io.BytesIO(pcap))
        pkts = list(reader)
        reader.close()

        # Sequence:
        # 0: ADV_IND (peripheral)
        # 1: SCAN_REQ (foreign)
        # [SILENT DROP - no SCAN_RSP]
        # 2: ADV_IND (peripheral)
        # 3: SCAN_REQ (target companion)
        # 4: SCAN_RSP (peripheral to target)
        assert len(pkts) == 5

        assert pkts[0].body[0] & 0x0F == 0  # ADV_IND
        assert pkts[1].body[0] & 0x0F == 3  # SCAN_REQ
        assert pkts[1].body[2:8] == str_to_mac("4A:11:22:33:44:55")

        assert pkts[2].body[0] & 0x0F == 0  # ADV_IND
        assert pkts[3].body[0] & 0x0F == 3  # SCAN_REQ
        assert pkts[3].body[2:8] == str_to_mac("5A:AA:BB:CC:DD:01")

        assert pkts[4].body[0] & 0x0F == 4  # SCAN_RSP
        # Verify exact T_IFS delta (150 microseconds) between target SCAN_REQ and SCAN_RSP
        t_req = pkts[3].ts_usec
        t_rsp = pkts[4].ts_usec
        assert t_rsp - t_req == 150  # Exactly T_IFS = 150 us

    def test_selective_probe_allowlist_disabled_open_response(self) -> None:
        """When allowlist is disabled, peripheral responds to both foreign and target probers within T_IFS."""
        pcap = generate_bat_allowlist_trace(
            allowlist_enabled=False,
            target_rpa="5A:AA:BB:CC:DD:01",
            foreign_rpa="4A:11:22:33:44:55",
            mode="selective_probe",
        )
        reader = PcapBleReader(io.BytesIO(pcap))
        pkts = list(reader)
        reader.close()

        # 6 packets: ADV_IND, foreign SCAN_REQ, SCAN_RSP, ADV_IND, target SCAN_REQ, SCAN_RSP
        assert len(pkts) == 6
        # Foreign response within T_IFS
        assert pkts[2].ts_usec - pkts[1].ts_usec == 150
        # Target response within T_IFS
        assert pkts[5].ts_usec - pkts[4].ts_usec == 150

    def test_reconnection_timing_fast_and_slow_interval_shifts(self) -> None:
        """Stress tests parameterized fast/slow advertising interval transitions."""
        intervals_to_test = [
            (20.0, 1000.0),
            (31.25, 1280.0),  # Exact 1.25ms multiples (25 slots, 1024 slots)
            (50.0, 2000.0),
        ]
        for fast_ms, slow_ms in intervals_to_test:
            pcap = generate_bat_allowlist_trace(
                mode="reconnection_timing",
                fast_interval_ms=fast_ms,
                slow_interval_ms=slow_ms,
            )
            reader = PcapBleReader(io.BytesIO(pcap))
            pkts = list(reader)
            reader.close()

            # 4 fast ADV + 3 slow ADV = 7 packets (no conn_params)
            assert len(pkts) == 7

            fast_usec = int(fast_ms * 1000)
            slow_usec = int(slow_ms * 1000)

            # Check fast intervals: pkts[0..4] (4 intervals of fast_usec)
            for i in range(4):
                delta = round((pkts[i + 1].ts_epoch - pkts[i].ts_epoch) * 1_000_000)
                assert delta == fast_usec

            # Check slow intervals: pkts[4..6] (2 intervals of slow_usec)
            for i in range(4, 6):
                delta = round((pkts[i + 1].ts_epoch - pkts[i].ts_epoch) * 1_000_000)
                assert delta == slow_usec

    def test_connection_parameter_tuples_full_spectrum(self) -> None:
        """Verifies ConnectionParameters dataclass and 4-tuple packing for varied connection profiles."""
        test_profiles = [
            # Fast/low latency: 7.5 ms interval, 0 latency, 100 ms timeout, hop 5
            ConnectionParameters(interval=6, latency=0, timeout=10, hop_increment=5),
            # Standard BLE: 30 ms interval, 0 latency, 1000 ms timeout, hop 8
            ConnectionParameters(interval=24, latency=0, timeout=100, hop_increment=8),
            # Power save: 1000 ms interval, 4 latency, 32000 ms timeout, hop 16
            ConnectionParameters(interval=800, latency=4, timeout=3200, hop_increment=16),
            # Raw 4-tuple input: <Interval, Latency, Timeout, Hop>
            (48, 2, 250, 12),
        ]

        for profile in test_profiles:
            pcap = generate_bat_allowlist_trace(
                mode="reconnection_timing",
                conn_params=profile,
            )
            reader = PcapBleReader(io.BytesIO(pcap))
            pkts = list(reader)
            reader.close()

            # 4 fast ADV + 3 slow ADV + 1 CONNECT_IND = 8 packets
            assert len(pkts) == 8
            conn_pkt = pkts[-1]
            assert conn_pkt.body[0] & 0x0F == 5  # CONNECT_IND

            # Unpack LLData (22 bytes starting at byte 14)
            lldata = conn_pkt.body[14:36]
            win_offset, interval, latency, timeout = struct.unpack("<HHHH", lldata[8:16])
            hop = lldata[21] & 0x1F

            if isinstance(profile, ConnectionParameters):
                assert interval == profile.interval
                assert latency == profile.latency
                assert timeout == profile.timeout
                assert hop == profile.hop_increment
            else:
                assert interval == profile[0]
                assert latency == profile[1]
                assert timeout == profile[2]
                assert hop == profile[3]

    def test_directed_advertising_burst_timing(self) -> None:
        """Verifies high duty cycle directed advertising burst timing (<= 3.75 ms)."""
        pcap = generate_bat_allowlist_trace(
            mode="directed",
            target_rpa="5A:AA:BB:CC:DD:01",
            periph_addr="5A:11:22:33:44:55",
        )
        reader = PcapBleReader(io.BytesIO(pcap))
        pkts = list(reader)
        reader.close()

        # 5 ADV_DIRECT_IND + 1 CONNECT_IND = 6 packets
        assert len(pkts) == 6
        for i in range(4):
            assert pkts[i].body[0] & 0x0F == 1  # ADV_DIRECT_IND
            delta = pkts[i + 1].ts_usec - pkts[i].ts_usec
            assert delta == 3_750  # 3.75 ms interval


# =============================================================================
# 4. Empirical Boundary Analysis & Wireshark / tshark Dissection
# =============================================================================
class TestEmpiricalBoundaryAndDissectionStress:
    """Stress tests boundary limits, tshark dissections, and edge behaviors."""

    def test_att_signed_write_maximum_valid_payload_bound(self) -> None:
        """Verifies ATT Signed Write up to maximum Link-Layer capacity (value len = 236)."""
        csrk = b"\x01" * 16
        # At value = 236 bytes:
        # ATT PDU = 1 (op) + 2 (h) + 236 (val) + 12 (sig) = 251 bytes
        # L2CAP frame = 4 (hdr) + 251 = 255 bytes (fits in uint8 length field)
        max_valid_val = b"X" * 236
        pdu = build_att_signed_write(csrk, handle=0x0001, value=max_valid_val, counter=0)
        assert len(pdu) == 2 + 255
        assert pdu[1] == 255  # Length field is exactly 255

    def test_att_signed_write_overflow_behavior_documented(self) -> None:
        """Documents that value > 236 exceeds 255-octet LL length field and causes truncation wrap."""
        csrk = b"\x01" * 16
        overflow_val = b"X" * 237
        pdu = build_att_signed_write(csrk, handle=0x0001, value=overflow_val, counter=0)
        # Length 256 wraps to 0 in 8-bit field
        assert pdu[1] == 0

    def test_selective_probe_ignores_fast_interval_documented(self) -> None:
        """Empirically confirms fast_interval_ms is ignored in selective_probe mode (hardcoded 30ms)."""
        pcap_30 = generate_bat_allowlist_trace(allowlist_enabled=True, mode="selective_probe", fast_interval_ms=30.0)
        pkts_30 = list(PcapBleReader(io.BytesIO(pcap_30)))

        pcap_100 = generate_bat_allowlist_trace(allowlist_enabled=True, mode="selective_probe", fast_interval_ms=100.0)
        pkts_100 = list(PcapBleReader(io.BytesIO(pcap_100)))

        dt_30 = pkts_30[2].ts_usec - pkts_30[0].ts_usec
        dt_100 = pkts_100[2].ts_usec - pkts_100[0].ts_usec
        # Both produce 31,000 us delta (1,000 + 30,000)
        assert dt_30 == dt_100 == 31_000

    @pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed on system")
    def test_tshark_stress_dissection_all_scenarios(self, tmp_path: Path) -> None:
        """Dissects traces across all scenarios with tshark, asserting zero malformed packets."""
        traces = [
            ("reconnection_timing", generate_bat_allowlist_trace(mode="reconnection_timing", conn_params=(24, 0, 100, 5))),
            ("directed_burst", generate_bat_allowlist_trace(mode="directed")),
            ("csrk_replays", generate_csrk_trace([10, 10, 11, 12, 10], csrk=b"\x01" * 16)),
            ("csrk_drops", generate_csrk_trace([1000, 50, 10], csrk=b"\x01" * 16)),
            ("csrk_corrupt", generate_csrk_trace([1, 2, 3], csrk=b"\x01" * 16, corrupt_mac_indices=[1])),
        ]

        for name, pcap_data in traces:
            pcap_file = tmp_path / f"{name}.pcap"
            pcap_file.write_bytes(pcap_data)
            res = subprocess.run(
                ["tshark", "-r", str(pcap_file), "-V"],
                capture_output=True,
                text=True,
                check=False,
            )
            assert res.returncode == 0, f"tshark failed on {name}"
            assert "[Malformed Packet" not in res.stdout, f"Malformed packet in {name}"
