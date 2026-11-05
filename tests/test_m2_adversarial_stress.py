"""Milestone M2 Adversarial Stress and Empirical Verification Test Suite.

Author: Challenger M2-1 (Adversarial Critic)
Target Scope:
  - Issue #93: collections.deque O(1) popping in Anomaly, Baseline, Features, and Matrix engines
  - Issue #94: dataclass serialization (asdict), keyword init, inheritance across beacon hierarchy
  - Issue #98: PcapBleWriter buffered I/O, rapid packet throughput, and buffer flushing
"""

from __future__ import annotations

import io
import math
import os
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from uuid import UUID

import pytest

# Ensure source trees are in import path
sys.path.insert(0, os.path.abspath("src/airtell"))
sys.path.insert(0, os.path.abspath("src/sniffle/src"))

from sniffle.pcap import PcapBleReader, PcapBleWriter  # noqa: E402
from sniffle.radar.anomaly import RobustAnomalyEngine  # noqa: E402
from sniffle.radar.baseline import BaselineTracker  # noqa: E402
from sniffle.radar.features import FeatureExtractor  # noqa: E402
from sniffle.radar.matrix import MxNLinkMatrixManager  # noqa: E402

from airtell.adversarial.rogue_beacon import (  # noqa: E402
    SyntheticBeaconSpec,
    SyntheticPacket,
)
from airtell.protocol.wire import (  # noqa: E402
    DebugMessage,
    MarkerMessage,
    MeasurementMessage,
    PacketMessage,
    StateMessage,
)
from airtell.sniff.dissector import (  # noqa: E402
    AltBeaconInfo,
    BeaconInfo,
    EddystoneTlmInfo,
    EddystoneUidInfo,
    EddystoneUrlInfo,
    GaenInfo,
    IBeaconInfo,
)


# ---------------------------------------------------------------------------
# Test Classes for Crowdsourced Tracking Beacons (Inheriting BeaconInfo)
# ---------------------------------------------------------------------------
@dataclass
class AppleFindMyBeacon(BeaconInfo):
    """Synthetic Apple Find My offline-finding beacon record."""

    public_key: bytes
    status_byte: int = 0x00

    def __post_init__(self) -> None:
        self.beacon_type = "Apple Find My"


@dataclass
class GoogleFindHubBeacon(BeaconInfo):
    """Synthetic Google Fast Pair / Find Hub beacon record."""

    service_data: bytes
    salt: int = 0x00

    def __post_init__(self) -> None:
        self.beacon_type = "Google Find Hub"


@dataclass
class SamsungSmartThingsBeacon(BeaconInfo):
    """Synthetic Samsung SmartThings Find beacon record."""

    privacy_id: bytes
    vendor_flags: int = 0x00

    def __post_init__(self) -> None:
        self.beacon_type = "Samsung SmartThings Find"


@dataclass
class TileBeacon(BeaconInfo):
    """Synthetic Tile tracker beacon record."""

    tile_id: bytes
    measured_power: int = -59

    def __post_init__(self) -> None:
        self.beacon_type = "Tile"


# ===========================================================================
# 1. Stress Tests for collections.deque O(1) Popping in Radar Engines (#93)
# ===========================================================================
class TestRadarDequePoppingO1Workload:
    """Empirical verification of bounded memory and O(1) performance under high-frequency load."""

    def test_robust_anomaly_engine_100k_workload(self) -> None:
        """Feed 100,000 packets into RobustAnomalyEngine.

        Verifies:
        1. Bounded memory: link_history buffer does not exceed history_len (30).
        2. Execution speed: per-packet latency is well below 1.0 ms (sub-millisecond).
        3. O(1) complexity: later slices (90k-100k) execute with same latency as early slices (10k-20k).
        """
        history_len = 30
        engine = RobustAnomalyEngine(history_len=history_len)
        total_packets = 100_000

        times: list[float] = []
        checkpoint_steps = 10_000

        t_start = time.perf_counter()
        t_checkpoint = t_start

        for i in range(total_packets):
            rssi = -60.0 + (i % 20) * 0.1
            engine.update_link_sample(
                rx_id="dongle_01",
                tx_mac="AA:BB:CC:DD:EE:01",
                channel=37,
                rssi=rssi,
            )

            if (i + 1) % checkpoint_steps == 0:
                t_now = time.perf_counter()
                times.append(t_now - t_checkpoint)
                t_checkpoint = t_now

        t_total = time.perf_counter() - t_start
        avg_us_per_pkt = (t_total / total_packets) * 1e6

        # 1. Bounded memory assertion
        key = ("dongle_01", "AA:BB:CC:DD:EE:01", 37)
        assert key in engine.link_history
        hist = engine.link_history[key]
        assert len(hist) == history_len, f"History length {len(hist)} exceeds maxlen {history_len}"
        assert hist.maxlen == history_len

        # 2. Sub-millisecond execution assertion (< 1000 µs/pkt; expected < 5 µs/pkt)
        assert avg_us_per_pkt < 1000.0, f"Average latency {avg_us_per_pkt:.2f} µs exceeded 1ms threshold"

        # 3. O(1) complexity assertion: slice 10k-20k vs slice 90k-100k
        slice_early = times[1]  # 10k-20k
        slice_late = times[-1]  # 90k-100k
        ratio = slice_late / slice_early
        # Due to CPU caching and garbage collection jitter, allow generous 3.0x bound (O(N) would be > 8x)
        assert ratio < 3.0, (
            f"Latency degraded significantly between early ({slice_early:.4f}s) and late ({slice_late:.4f}s) slices"
        )

    def test_baseline_tracker_100k_workload(self) -> None:
        """Feed 100,000 packets into BaselineTracker.

        Verifies:
        1. Bounded memory: history buffer does not exceed history_size (50).
        2. Execution speed: per-packet latency is well below 1.0 ms.
        3. Statistical convergence: EMA baseline converges to expected value.
        """
        history_size = 50
        tracker = BaselineTracker(history_size=history_size, outlier_threshold=15.0, alpha=0.1)
        total_packets = 100_000

        t_start = time.perf_counter()
        for i in range(total_packets):
            rssi = -65.0 + (i % 7) * 0.2
            tracker.update(rx_id="dongle_01", tx_mac="11:22:33:44:55:66", rssi=rssi, channel=37)

        t_total = time.perf_counter() - t_start
        avg_us_per_pkt = (t_total / total_packets) * 1e6

        key = ("dongle_01", "11:22:33:44:55:66", 37)
        assert key in tracker.history
        hist = tracker.history[key]
        assert len(hist) <= history_size, f"History length {len(hist)} exceeded maxlen {history_size}"
        assert hist.maxlen == history_size

        # Verify sub-millisecond execution
        assert avg_us_per_pkt < 1000.0, f"Average latency {avg_us_per_pkt:.2f} µs exceeded 1ms threshold"

        # Verify baseline convergence around -64.4 dBm
        baseline = tracker.get_baseline("dongle_01", "11:22:33:44:55:66", channel=37)
        assert -66.0 <= baseline <= -63.0, f"Baseline {baseline} drifted outside expectation"

    def test_feature_extractor_and_matrix_manager_bounded_deque(self) -> None:
        """Verify FeatureExtractor and MxNLinkMatrixManager maintain bounded deque memory under 20k packets."""
        extractor = FeatureExtractor(window_size=15)
        rx_configs = {"rx1": (37, (0.0, 0.0))}
        matrix = MxNLinkMatrixManager(rx_configs=rx_configs, window_size=25)

        for i in range(20_000):
            ts = 1000.0 + i * 0.05
            rssi = -55.0 + (i % 5) * 0.5
            extractor.add_sample("rx1", "tx1", rssi, ts, channel=37)
            matrix.register_packet(timestamp=ts, rssi=rssi, rx_id="rx1", tx_mac="tx1", channel=37)

        key = ("rx1", "tx1", 37)
        assert len(extractor.rssi_buffers[key]) == 15
        assert extractor.rssi_buffers[key].maxlen == 15

        link_key = ("tx1", "rx1")
        rec = matrix.links[link_key]
        assert len(rec.rssi_history) == 25
        assert rec.rssi_history.maxlen == 25

    def test_multilink_churn_and_zero_variance(self) -> None:
        """Verify memory boundedness and numerical stability under multi-link churn and zero variance."""
        engine = RobustAnomalyEngine(history_len=20)
        tracker = BaselineTracker(history_size=20)

        # 50 concurrent active links with 500 packets each (25,000 packets total)
        for link_id in range(50):
            tx_mac = f"C0:00:00:00:00:{link_id:02X}"
            for _ in range(500):
                engine.update_link_sample("rx_0", tx_mac, 37, -70.0)
                tracker.update("rx_0", tx_mac, -70.0, 37)

        # Ensure all 50 links are tracked and each has exactly 20 elements
        assert len(engine.link_history) == 50
        for _key, hist in engine.link_history.items():
            assert len(hist) == 20

        # Zero variance check (all samples exactly -70.0)
        z_rob, z_drop, combined = engine.compute_link_robust_z("rx_0", "C0:00:00:00:00:00", 37, -70.0)
        assert z_rob == 0.0
        assert z_drop == 0.0
        assert not math.isnan(combined)
        assert not math.isinf(combined)


# ===========================================================================
# 2. Stress Tests for Dataclass Hierarchy, asdict(), and Inheritance (#94)
# ===========================================================================
class TestDataclassBeaconHierarchyAndSerialization:
    """Empirical verification of dataclass keyword initialization, inheritance, and asdict()."""

    def test_core_dissector_beacon_hierarchy(self) -> None:
        """Verify standard dataclass properties across dissector.py beacon classes."""
        # 1. IBeaconInfo
        uid = UUID("e2c56db5-dffb-48d2-b060-d0f5a71096e0")
        ib = IBeaconInfo(uuid=uid, major=10, minor=20, tx_power=-59)
        assert isinstance(ib, BeaconInfo)
        assert ib.beacon_type == "iBeacon"
        ib_dict = asdict(ib)
        assert ib_dict["beacon_type"] == "iBeacon"
        assert ib_dict["uuid"] == uid
        assert ib_dict["major"] == 10
        assert ib_dict["minor"] == 20
        assert ib_dict["tx_power"] == -59

        # 2. AltBeaconInfo
        ab = AltBeaconInfo(
            mfg_id=0x0118,
            beacon_code=0xBEAC,
            beacon_id=b"\x01" * 20,
            ref_rssi=-59,
            mfg_reserved=0x05,
        )
        assert isinstance(ab, BeaconInfo)
        assert ab.beacon_type == "AltBeacon"
        ab_dict = asdict(ab)
        assert ab_dict["mfg_id"] == 0x0118
        assert ab_dict["beacon_code"] == 0xBEAC
        assert ab_dict["beacon_id"] == b"\x01" * 20
        assert ab_dict["mfg_reserved"] == 0x05

        # 3. EddystoneUidInfo
        ed_uid = EddystoneUidInfo(namespace=b"1234567890", instance=b"abcdef", tx_power=-20)
        assert isinstance(ed_uid, BeaconInfo)
        assert ed_uid.beacon_type == "Eddystone-UID"
        assert asdict(ed_uid)["namespace"] == b"1234567890"

        # 4. EddystoneUrlInfo
        ed_url = EddystoneUrlInfo(url="https://airtell.local", tx_power=-18)
        assert isinstance(ed_url, BeaconInfo)
        assert ed_url.beacon_type == "Eddystone-URL"
        assert asdict(ed_url)["url"] == "https://airtell.local"

        # 5. EddystoneTlmInfo
        ed_tlm = EddystoneTlmInfo(version=0, vbatt_mv=3100, temp_c=24.5, adv_cnt=5000, sec_cnt=50000)
        assert isinstance(ed_tlm, BeaconInfo)
        assert ed_tlm.beacon_type == "Eddystone-TLM"
        assert asdict(ed_tlm)["vbatt_mv"] == 3100
        assert asdict(ed_tlm)["temp_c"] == 24.5

        # 6. GaenInfo
        gaen = GaenInfo(rpi=b"\xaa" * 16, aem=b"\xbb" * 4)
        assert isinstance(gaen, BeaconInfo)
        assert gaen.beacon_type == "GAEN"
        assert asdict(gaen)["rpi"] == b"\xaa" * 16

    def test_tracking_beacon_models_inheritance_and_asdict(self) -> None:
        """Verify subclassing BeaconInfo with Apple, Google, Samsung, and Tile beacon types."""
        apple = AppleFindMyBeacon(public_key=b"\x4c" * 22, status_byte=0x19)
        google = GoogleFindHubBeacon(service_data=b"\xfe\x9f" * 10, salt=0x01)
        samsung = SamsungSmartThingsBeacon(privacy_id=b"\x75\x00" * 8, vendor_flags=0x02)
        tile = TileBeacon(tile_id=b"\xfe\xed" * 8, measured_power=-55)

        beacons: list[BeaconInfo] = [apple, google, samsung, tile]

        for b in beacons:
            assert isinstance(b, BeaconInfo)
            d = asdict(b)
            assert "beacon_type" in d
            assert d["beacon_type"] == b.beacon_type
            assert len(d) >= 2

        # Verify high-frequency serialization: 50,000 asdict calls
        t0 = time.perf_counter()
        for _ in range(50_000):
            asdict(apple)
        t_total = time.perf_counter() - t0
        us_per_call = (t_total / 50_000) * 1e6
        assert us_per_call < 50.0, f"asdict took {us_per_call:.2f} µs/call"

    def test_synthetic_beacon_spec_and_packet_serialization(self) -> None:
        """Verify SyntheticBeaconSpec and SyntheticPacket dataclasses from rogue_beacon.py."""
        spec = SyntheticBeaconSpec(
            network_type="Apple Find My",
            ephemeral_key="0102030405060708090a0b0c0d0e0f10",
            mac_address="40:11:22:33:44:55",
            rssi=-68,
            channel=38,
        )
        spec_dict = asdict(spec)
        assert spec_dict["network_type"] == "Apple Find My"
        assert spec_dict["channel"] == 38

        pkt = SyntheticPacket(
            mac_address="40:11:22:33:44:55",
            rssi=-68,
            channel=38,
            payload_bytes=b"\x00" * 31,
            timestamp=1234567.89,
            network_type="Apple Find My",
            ephemeral_key="010203040506",
        )
        pkt_dict = asdict(pkt)
        assert pkt_dict["mac_address"] == "40:11:22:33:44:55"
        assert pkt_dict["payload_bytes"] == b"\x00" * 31

    def test_wire_protocol_dataclass_constructors_and_asdict(self) -> None:
        """Verify PacketMessage, MarkerMessage, StateMessage, MeasurementMessage."""
        # Keyword initialization for PacketMessage
        pm = PacketMessage(ts=987654, chan=38, rssi=-72, body=b"\x02\x01\x06")
        assert pm.ts == 987654
        assert pm.chan == 38
        assert pm.rssi == -72
        assert pm.body == b"\x02\x01\x06"

        pm_dict = asdict(pm)
        assert pm_dict["ts"] == 987654
        assert pm_dict["body"] == b"\x02\x01\x06"

        # Round-trip reconstruction from dictionary
        pm_rebuilt = PacketMessage(**pm_dict)
        assert pm_rebuilt.ts == pm.ts
        assert pm_rebuilt.chan == pm.chan
        assert pm_rebuilt.rssi == pm.rssi
        assert pm_rebuilt.body == pm.body

        # MarkerMessage
        mm = MarkerMessage(ts=123, marker_data=b"TIMESTAMP_SYNC")
        assert asdict(mm)["ts"] == 123
        mm_rebuilt = MarkerMessage(**asdict(mm))
        assert mm_rebuilt.marker_data == b"TIMESTAMP_SYNC"

        # StateMessage
        sm = StateMessage(state=2)
        assert asdict(sm)["state"] == 2

        # MeasurementMessage
        meas = MeasurementMessage(measure_type=1, data=b"\x01\x02\x03\x04")
        assert asdict(meas)["measure_type"] == 1

    def test_debug_message_manual_init_vulnerability(self) -> None:
        """Empirically test that DebugMessage still overrides __init__ with raw bytes.

        Critic finding: DebugMessage in wire.py was not updated to standard dataclass
        initialization. Passing text='...' or unpacking asdict(dm) fails with TypeError.
        """
        # Parsing raw bytes succeeds
        dm = DebugMessage(b"Firmware ready")
        assert dm.text == "Firmware ready"
        assert asdict(dm)["text"] == "Firmware ready"

        # Keyword initialization succeeds
        dm_kw = DebugMessage(text="Firmware ready")
        assert dm_kw.text == "Firmware ready"

        dm_unpacked = DebugMessage(**asdict(dm))
        assert dm_unpacked.text == "Firmware ready"

    def test_beacon_info_init_false_unpack_caveat(self) -> None:
        """Empirical check documenting that init=False fields cannot be passed to __init__.

        Because beacon_type in BeaconInfo is defined as field(init=False),
        IBeaconInfo(**asdict(ib)) raises TypeError, while filtering beacon_type succeeds.
        """
        ib = IBeaconInfo(uuid=UUID(int=1), major=1, minor=2, tx_power=-50)
        ib_dict = asdict(ib)

        with pytest.raises(TypeError, match="unexpected keyword argument 'beacon_type'"):
            IBeaconInfo(**ib_dict)

        # Correct reconstruction filters init=False fields
        filtered_dict = {k: v for k, v in ib_dict.items() if k != "beacon_type"}
        ib_reconstructed = IBeaconInfo(**filtered_dict)
        assert ib_reconstructed.beacon_type == "iBeacon"
        assert ib_reconstructed.uuid == UUID(int=1)


# ===========================================================================
# 3. Stress Tests for PcapBleWriter Buffered I/O and Flushing (#98)
# ===========================================================================
class TestPcapBleWriterBufferedIO:
    """Empirical verification of PcapBleWriter buffered I/O, rapid writes, and flushing."""

    def test_rapid_packet_writes_50k(self) -> None:
        """Stress-test writing 50,000 packets rapidly and reading them back."""
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            pcap_path = f.name

        try:
            total_pkts = 50_000
            # Link Layer ADV_IND packet: header=0x00, len=6, AdvA=6 bytes
            adv_body = bytes([0x00, 6, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66])

            t0 = time.perf_counter()
            with PcapBleWriter(pcap_path) as writer:
                for i in range(total_pkts):
                    writer.write_packet(
                        ts_usec=1_000_000 + i * 100,
                        aa=0x8E89BED6,
                        chan=37 + (i % 3),
                        rssi=-60 - (i % 10),
                        packet=adv_body,
                    )
            t_write = time.perf_counter() - t0
            write_rate = total_pkts / t_write

            # Verify write throughput is substantial (> 50,000 pkts/s)
            assert write_rate > 50_000.0, f"Write throughput {write_rate:.0f} pkts/s was sluggish"

            # Verify file exists and is populated
            file_size = os.path.getsize(pcap_path)
            assert file_size > total_pkts * 20

            # Read back every packet with PcapBleReader
            with PcapBleReader(pcap_path) as reader:
                read_pkts = list(reader)

            assert len(read_pkts) == total_pkts
            # Verify first and last packet integrity
            p0 = read_pkts[0]
            assert p0.chan == 37
            assert p0.rssi == -60
            assert p0.body == adv_body

            plast = read_pkts[-1]
            assert plast.chan == 37 + ((total_pkts - 1) % 3)
            assert plast.body == adv_body

        finally:
            if os.path.exists(pcap_path):
                os.unlink(pcap_path)

    def test_buffer_flush_behavior(self) -> None:
        """Verify that flush() pushes buffered packet data to disk."""
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            pcap_path = f.name

        try:
            writer = PcapBleWriter(pcap_path)

            # Write 3 small packets (< 200 bytes, well below 8KB buffer)
            adv_body = bytes([0x00, 6, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
            for i in range(3):
                writer.write_packet(1_000_000 + i * 100, 0x8E89BED6, 37, -55, adv_body)

            size_before_flush = os.path.getsize(pcap_path)

            # Flush explicitly
            writer.flush()
            size_after_flush = os.path.getsize(pcap_path)

            assert size_after_flush > size_before_flush, (
                f"flush() did not commit buffered data: {size_after_flush} == {size_before_flush}"
            )

            writer.close()

            # Confirm reader can parse the 3 flushed packets
            with PcapBleReader(pcap_path) as reader:
                pkts = list(reader)
                assert len(pkts) == 3

        finally:
            if os.path.exists(pcap_path):
                os.unlink(pcap_path)

    def test_bytesio_buffered_stream(self) -> None:
        """Verify PcapBleWriter and PcapBleReader operate cleanly with in-memory BytesIO."""
        bio = io.BytesIO()
        adv_body = bytes([0x00, 4, 0x01, 0x02, 0x03, 0x04])

        with PcapBleWriter(bio) as writer:
            for i in range(10):
                writer.write_packet(1_000_000 + i * 100, 0x8E89BED6, 38, -65, adv_body)

        # BytesIO stream should remain open for reading
        assert not bio.closed
        bio.seek(0)

        with PcapBleReader(bio) as reader:
            pkts = list(reader)
            assert len(pkts) == 10

    def test_double_close_idempotency_vulnerability(self) -> None:
        """Empirically test whether close() is idempotent.

        Critic finding: PcapBleWriter.close() should be idempotent and not raise
        ValueError('flush of closed file') on subsequent calls.
        """
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            pcap_path = f.name

        try:
            writer = PcapBleWriter(pcap_path)
            writer.write_packet(1000, 0x8E89BED6, 37, -60, bytes([0x00, 2, 0x01, 0x02]))
            writer.close()

            # Calling close() a second time is idempotent and does not raise
            writer.close()

        finally:
            if os.path.exists(pcap_path):
                os.unlink(pcap_path)
