# Filtering Wireshark BLE JSON with JQ

This guide explains how to parse, extract, and filter Bluetooth Low Energy (BLE) packet data from Wireshark and TShark JSON streams (`tshark -T json`) using `jq`.

---

## 1. Matching Device Names in Packets

### A. Match Packets Where `device_name` is Present Anywhere
Matches packets where the device name appears either in the primary advertisement (`ADV_IND`) or in the scan response (`SCAN_RSP`):

```bash
jq '.[] | select(.. | ."btcommon.eir_ad.entry.device_name"? != null)' /tmp/ble.json
```

### B. Match Packets Where `device_name` is in `scan_response_data_tree` Only
If you only want packets where the device name came specifically from the scan response payload:

```bash
jq '.[] | select(._source.layers.btle["btle.scan_response_data_tree"]? | .. | ."btcommon.eir_ad.entry.device_name"? != null)' /tmp/ble.json
```

---

## 2. Formatting Output

### Keep Output as a Valid JSON Array
By default, `jq .[] | select(...)` streams standalone JSON objects (line-delimited JSON). Wrap the expression in brackets `[...]` to output a single valid JSON array:

```bash
jq '[.[] | select(.. | ."btcommon.eir_ad.entry.device_name"? != null)]' /tmp/ble.json
```

### Strip Metadata Wrappers (Show Only Dissected `layers`)
Wireshark JSON wraps each packet in `_index`, `_type`, `_score`, and `_source`. To output only the dissected protocol layers:

```bash
jq '.[]._source.layers | select(.. | ."btcommon.eir_ad.entry.device_name"? != null)' /tmp/ble.json
```

### Interactive Colored Paging
To browse matching packets with syntax highlighting in your terminal:

```bash
jq -C '.[] | select(.. | ."btcommon.eir_ad.entry.device_name"? != null)' /tmp/ble.json | less -R
```

---

## 3. Extracting Specific Attributes

### Device Names from Scan Responses Only
```bash
# Recursive search within the scan response tree
jq -r '.[]._source.layers.btle["btle.scan_response_data_tree"]? | .. | ."btcommon.eir_ad.entry.device_name"? // empty' /tmp/ble.json

# Explicit hierarchical path
jq -r '.[]._source.layers.btle["btle.scan_response_data_tree"]["btcommon.eir_ad.advertising_data"]["btcommon.eir_ad.entry"]["btcommon.eir_ad.entry.device_name"] // empty' /tmp/ble.json
```

### Unique Device Names Across All Packets
```bash
jq -r '.. | ."btcommon.eir_ad.entry.device_name"? // empty' /tmp/ble.json | sort -u
```

### Pair Advertising Address with Device Name
```bash
jq -r '.[]._source.layers.btle | select(.. | ."btcommon.eir_ad.entry.device_name"? != null) | "\(.["btle.advertising_address"]): \(.. | ."btcommon.eir_ad.entry.device_name"? // empty)"' /tmp/ble.json | sort -u
```

### Extract MAC, RSSI, and Channel
```bash
jq -r '.[]._source.layers | [ .btle["btle.advertising_address"], .btle_rf["btle_rf.signal_dbm"], .btle_rf["btle_rf.rf_channel"] ] | @tsv' /tmp/ble.json
```

---

## 4. Key Rules & Common Pitfalls

1. **Dots in JSON Key Names**: Wireshark fields contain literal periods (e.g. `btcommon.eir_ad.entry.device_name`). In `jq`, accessing these requires quotes or bracket indexing:
   - Correct: `."btcommon.eir_ad.entry.device_name"` or `["btcommon.eir_ad.entry.device_name"]`
   - Incorrect: Escaping with backslashes like `btle\.scan_response_data_tree` will cause a `jq: error: syntax error`.
2. **Null Traversal**: Packets that do not contain the target field evaluate to `null`. Always use `?` (optional indexing) or `// empty` to prevent runtime indexing errors on null objects.
3. **Hierarchy**: In BLE captures, advertising entries reside inside `btcommon.eir_ad.advertising_data` -> `btcommon.eir_ad.entry`. Using recursive descent (`..`) makes searches resilient against structural variations across Wireshark versions.
