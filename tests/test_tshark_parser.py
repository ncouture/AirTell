"""Unit tests for Tshark BLE JSON stream parser and field normalizer."""

from __future__ import annotations

import json

from app.queue_bridge import EventQueue
from bluetooth_sniffle.extcap.parser import TsharkBleJsonParser


class TestTsharkBleJsonParser:
    """Tests covering TsharkBleJsonParser for EK lines, JSON objects, and network classification."""

    def test_ignore_ek_index_line(self) -> None:
        """Elasticsearch bulk index header lines should be safely skipped."""
        parser = TsharkBleJsonParser()
        index_line = '{"index":{"_index":"packets-2026-10-02","_type":"doc"}}'
        result = parser.parse_line(index_line)
        assert result is None

    def test_parse_ek_document_line(self) -> None:
        """Parse standard Elasticsearch line-delimited doc line with BLE fields."""
        parser = TsharkBleJsonParser(default_channel=37)
        ek_doc = json.dumps({
            "timestamp": "1790988227568",
            "layers": {
                "frame": {
                    "frame_frame_time_epoch": "1790988227.568183000",
                    "frame_frame_time": "2026-10-03T00:43:47.568183000Z",
                },
                "btle": {
                    "btle_btle_advertising_address": "ec:6f:03:c6:17:6e",
                    "btle_btle_advertising_header_pdu_type": "0x00",
                    "btcommon_btcommon_eir_ad_entry_company_id": "0x8802",
                    "btcommon_btcommon_eir_ad_entry_data": "ec:00:0a:01:00",
                },
                "btle_rf": {
                    "btle_rf_btle_rf_channel": "37",
                    "btle_rf_btle_rf_signal_dbm": "-59",
                },
            },
        })

        obs = parser.parse_line(ek_doc)
        assert obs is not None
        assert obs["mac_address"] == "EC:6F:03:C6:17:6E"
        assert obs["rssi"] == -59
        assert obs["channel"] == 37
        assert obs["pdu_type"] == "ADV_IND"
        assert obs["company_id"] == "0x8802"
        assert obs["network_type"] == "Unknown"
        assert "timestamp" in obs
        assert "datetime_str" in obs

    def test_parse_standard_json_format(self) -> None:
        """Parse standard streaming -T json packet object."""
        parser = TsharkBleJsonParser()
        json_obj = {
            "_index": "packets-2026-10-02",
            "_source": {
                "layers": {
                    "frame": {
                        "frame.time_epoch": "1790988227.569025000",
                        "frame.time": "Oct 2, 2026 20:43:47.569025000 EDT",
                    },
                    "btle": {
                        "btle.advertising_address": "11:22:33:44:55:66",
                        "btle.advertising_header_tree": {
                            "btle.advertising_header.pdu_type": "0x04",
                        },
                        "btle.scan_response_data": "11:09:47:6f:76:65:65",
                    },
                    "btle_rf": {
                        "btle_rf.channel": "38",
                        "btle_rf.signal_dbm": "-72",
                    },
                },
            },
        }

        obs = parser.parse_packet_dict(json_obj)
        assert obs is not None
        assert obs["mac_address"] == "11:22:33:44:55:66"
        assert obs["rssi"] == -72
        assert obs["channel"] == 38
        assert obs["pdu_type"] == "SCAN_RSP"
        assert "766565" in obs["raw_payload"].replace(":", "").lower()

    def test_apple_find_my_detection(self) -> None:
        """Apple Find My beacons (Company ID 0x004c, Type 0x12) should be classified correctly."""
        parser = TsharkBleJsonParser()
        doc = {
            "layers": {
                "frame": {"frame_frame_time_epoch": "1790000000.123"},
                "btle": {
                    "btle_btle_advertising_address": "ff:ee:dd:cc:bb:aa",
                    "btle_btle_advertising_header_pdu_type": "0x00",
                    "btcommon_btcommon_eir_ad_entry_company_id": "0x004c",
                    "btcommon_btcommon_eir_ad_entry_data": "12:19:10:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16",
                },
                "btle_rf": {
                    "btle_rf_btle_rf_signal_dbm": "-65",
                    "btle_rf_btle_rf_channel": "37",
                },
            },
        }

        obs = parser.parse_packet_dict(doc)
        assert obs is not None
        assert obs["network_type"] == "Apple Find My"
        assert obs["company_id"] == "0x004c"
        assert len(obs["ephemeral_key"]) > 0

    def test_google_find_hub_detection(self) -> None:
        """Google Fast Pair / Find Hub (UUID 0xFE9F or payload) should be classified."""
        parser = TsharkBleJsonParser()
        doc = {
            "layers": {
                "frame": {"frame_frame_time_epoch": "1790000001.000"},
                "btle": {
                    "btle_btle_advertising_address": "00:11:22:33:44:55",
                    "btle_btle_advertising_header_pdu_type": "0x00",
                    "btcommon_btcommon_eir_ad_entry_data": "fe:9f:aa:bb:cc:dd:ee:ff:01:02:03:04:05:06:07:08:09:0a",
                },
                "btle_rf": {"btle_rf_btle_rf_signal_dbm": "-80", "btle_rf_btle_rf_channel": "39"},
            },
        }
        obs = parser.parse_packet_dict(doc)
        assert obs is not None
        assert obs["network_type"] == "Google Find Hub"

    def test_samsung_smartthings_detection(self) -> None:
        """Samsung SmartThings (Company ID 0x0075) should be classified."""
        parser = TsharkBleJsonParser()
        doc = {
            "layers": {
                "frame": {"frame_frame_time_epoch": "1790000002.000"},
                "btle": {
                    "btle_btle_advertising_address": "12:34:56:78:9a:bc",
                    "btcommon_btcommon_eir_ad_entry_company_id": "0x0075",
                    "btcommon_btcommon_eir_ad_entry_data": "01:02:03:04:05:06:07:08",
                },
                "btle_rf": {"btle_rf_btle_rf_signal_dbm": "-55", "btle_rf_btle_rf_channel": "37"},
            },
        }
        obs = parser.parse_packet_dict(doc)
        assert obs is not None
        assert obs["network_type"] == "Samsung SmartThings Find"

    def test_tile_tracker_detection(self) -> None:
        """Tile tracker (UUID 0xFEED) should be classified."""
        parser = TsharkBleJsonParser()
        doc = {
            "layers": {
                "frame": {"frame_frame_time_epoch": "1790000003.000"},
                "btle": {
                    "btle_btle_advertising_address": "aa:bb:cc:11:22:33",
                    "btcommon_btcommon_eir_ad_entry_data": "fe:ed:10:20:30:40:50:60",
                },
                "btle_rf": {"btle_rf_btle_rf_signal_dbm": "-70", "btle_rf_btle_rf_channel": "38"},
            },
        }
        obs = parser.parse_packet_dict(doc)
        assert obs is not None
        assert obs["network_type"] == "Tile"

    def test_event_queue_bridge_integration(self) -> None:
        """Parser configured with an EventQueue should automatically push parsed records."""
        queue = EventQueue(maxsize=100)
        parser = TsharkBleJsonParser(event_queue=queue)

        doc = {
            "layers": {
                "frame": {"frame_frame_time_epoch": "1790000004.000"},
                "btle": {"btle_btle_advertising_address": "de:ad:be:ef:00:01"},
                "btle_rf": {"btle_rf_btle_rf_signal_dbm": "-62", "btle_rf_btle_rf_channel": "37"},
            },
        }

        obs = parser.parse_packet_dict(doc)
        assert obs is not None
        assert queue.size() == 1
        drained = queue.drain()
        assert len(drained) == 1
        assert drained[0]["mac_address"] == "DE:AD:BE:EF:00:01"

    def test_memory_bounds_enforced(self) -> None:
        """Internal buffer in parser should drop oldest items when maxlen is exceeded."""
        parser = TsharkBleJsonParser(max_buffered_records=5)
        for i in range(10):
            doc = {
                "layers": {
                    "frame": {"frame_frame_time_epoch": str(1790000000 + i)},
                    "btle": {"btle_btle_advertising_address": f"00:00:00:00:00:{i:02x}"},
                    "btle_rf": {"btle_rf_btle_rf_signal_dbm": "-60", "btle_rf_btle_rf_channel": "37"},
                },
            }
            parser.parse_packet_dict(doc)

        observations = parser.drain_observations()
        assert len(observations) == 5
        # The oldest items (0..4) should have dropped; 5..9 should remain
        macs = [o["mac_address"] for o in observations]
        assert macs == [
            "00:00:00:00:00:05",
            "00:00:00:00:00:06",
            "00:00:00:00:00:07",
            "00:00:00:00:00:08",
            "00:00:00:00:00:09",
        ]

    def test_malformed_json_handling(self) -> None:
        """Malformed or incomplete lines should not crash parser."""
        parser = TsharkBleJsonParser()
        assert parser.parse_line("INVALID NOT JSON {") is None
        assert parser.parse_line("") is None
        assert parser.parse_line("   ") is None
        assert parser.parse_packet_dict({}) is None
