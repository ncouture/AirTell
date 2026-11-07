# Changelog

## [0.3.0](https://github.com/ncouture/AirTell/compare/v0.2.0...v0.3.0) (2026-11-07)


### Features

* add sniff subpackage (dissector, PCAP, correlation, telemetry), unified CLI, and e2e test suite ([9f41dec](https://github.com/ncouture/AirTell/commit/9f41dec69f0a9045f668367889c29cf6311978ad))
* **adversarial:** expand adversarial M1-M4 testbed suite for crypto timing and relay evaluation ([04ea624](https://github.com/ncouture/AirTell/commit/04ea624b66df9efd9580fbddf86088c3a027958b))
* **ci:** enforce codeowner authorization on code review workflow and runner ([a51134d](https://github.com/ncouture/AirTell/commit/a51134d6e20d79747513e4185d0f9dd626241acd))
* **cli:** add sidechannel subcommand and dual binary support to AirTell CLI ([cae8929](https://github.com/ncouture/AirTell/commit/cae892996c798520a363873fae2dc0e977f201ca))
* **code-review:** authorize codeowner reviews on non-codeowner pull requests ([#235](https://github.com/ncouture/AirTell/issues/235)) ([7b83022](https://github.com/ncouture/AirTell/commit/7b8302217520f95b38c1ad781dbf1e7dd04812e5))
* **github:** add issue templates, chooser config, and community discussions guide ([e5ac598](https://github.com/ncouture/AirTell/commit/e5ac598d17e0842039199b93e133050d92ed8bf7))
* implement Tracks 1–5 (Side-Channel Visualizer, CLI Adversarial Ingestion, Single-Dongle Topology-A, Alert Dispatchers, DuckDB Analytics) ([#58](https://github.com/ncouture/AirTell/issues/58)) ([db6e056](https://github.com/ncouture/AirTell/commit/db6e0564f2c5eb0bf1f892f0c71e875e862d1890))
* monitoring and adversarial ([#3](https://github.com/ncouture/AirTell/issues/3)) ([88d2ce9](https://github.com/ncouture/AirTell/commit/88d2ce90cee33e1a6596aceec73bdf03a200d1bd))
* **ouidb:** integrate spectra mesh oui database and pcap mac timeline generator ([340322e](https://github.com/ncouture/AirTell/commit/340322e938c8a501f19a09529a70bad2f40a77a6))
* **pcap:** add PCAPNG block parsing, writing, and DLT 256 link-layer support ([3e4e2b6](https://github.com/ncouture/AirTell/commit/3e4e2b68e9d5a7cc5b9e99be7a32383a26ff264e))
* **relay:** unify master and slave pairing relay into single airtell relay cli ([90baa1f](https://github.com/ncouture/AirTell/commit/90baa1fdd594b190cebe4cf1f1c96a60b5e406f9))
* **sidechannel:** implement BLE exclusive-use side-channel detection and analysis suite ([ace5f10](https://github.com/ncouture/AirTell/commit/ace5f109808f9a92314bc53f8e57ac2929082a6b))
* **test:** enable dual real Sniffle USB device test execution ([f8a38f5](https://github.com/ncouture/AirTell/commit/f8a38f515fd01bf741ee084c3b072d6cfc1c8e9d))
* **ui:** update dashboard branding and add web presentation matrix ([6742410](https://github.com/ncouture/AirTell/commit/6742410cb3d3f8e8552ff9bd42487ce9d6140f97))


### Bug Fixes

* **app:** p1 unclosed SQLite connection on view exception in Streamlit app ([#79](https://github.com/ncouture/AirTell/issues/79)) ([2ec4eda](https://github.com/ncouture/AirTell/commit/2ec4eda858ff5cd5753187d07462694e6f52d2b6))
* **cache:** pip cache 14 days ([#65](https://github.com/ncouture/AirTell/issues/65)) ([8ec53e3](https://github.com/ncouture/AirTell/commit/8ec53e37dd58d0963389f8dd002facd05a53a583))
* **ci:** fix ci bug on this branch ([a5507bf](https://github.com/ncouture/AirTell/commit/a5507bfd7fcc4b797050a489d9b89f4058466454))
* **conductor:** p1 correct broken bluetooth_sniffle module paths in ble_adversarial_relay plan ([#84](https://github.com/ncouture/AirTell/issues/84)) ([dc5441b](https://github.com/ncouture/AirTell/commit/dc5441bc59dcbea19ab275eb46663bba622f1b83))
* **conductor:** p1 correct broken extcap module paths in tshark_json_stream plan ([#85](https://github.com/ncouture/AirTell/issues/85)) ([5f501cf](https://github.com/ncouture/AirTell/commit/5f501cf8478ce817104385360396371c7f10c2e2))
* **conductor:** p1 reconcile completed status in ble_adversarial_relay metadata ([#87](https://github.com/ncouture/AirTell/issues/87)) ([01f8a53](https://github.com/ncouture/AirTell/commit/01f8a53ac3d15050bcaab5c51892306e128e75ee))
* **conductor:** p1 reconcile completed status in m3_dashboard metadata ([#86](https://github.com/ncouture/AirTell/issues/86)) ([f1ba0a4](https://github.com/ncouture/AirTell/commit/f1ba0a4a2b702462f675f5c2ec0cf82a2b2ab743))
* **conductor:** p1 resolve topology a and b definition collision in product definition ([#88](https://github.com/ncouture/AirTell/issues/88)) ([363be04](https://github.com/ncouture/AirTell/commit/363be041e7d3e8eeb558bf59cb047b79728a6c02))
* **conductor:** p2 add missing phase checkpoint markers to tshark_json_stream plan ([#117](https://github.com/ncouture/AirTell/issues/117)) ([37892b7](https://github.com/ncouture/AirTell/commit/37892b706153906bfbe2fe76816cacbb3081e39d))
* **conductor:** p2 fix missing app prefix in duckdb spec view paths ([#116](https://github.com/ncouture/AirTell/issues/116)) ([2dd9f0a](https://github.com/ncouture/AirTell/commit/2dd9f0a07911c3c651d5ec7c93dec9bd8fea7153))
* **docs:** p1 correct invalid command line examples and wrong argument flags for ble_antistalking_tracker.py and ble_parser.py ([#81](https://github.com/ncouture/AirTell/issues/81)) ([f313638](https://github.com/ncouture/AirTell/commit/f3136386ae4629555e778f4ad2729cbb5b8ef7b6))
* **docs:** p1 fix unexpected indentation syntax errors in python code snippets in docs/howto.md and docs/scripts_reference.md ([#80](https://github.com/ncouture/AirTell/issues/80)) ([fc4189f](https://github.com/ncouture/AirTell/commit/fc4189f2929bb1c2f7c849ec29cae3baf6a28c7f))
* **docs:** p1 remove invalid single-dongle verify-hardware command in docs/CLI.md ([#82](https://github.com/ncouture/AirTell/issues/82)) ([66ca539](https://github.com/ncouture/AirTell/commit/66ca53904b99e405d8ed9bd5d18bc3447f7d9ffe))
* **docs:** p1 resolve direct factual contradiction on Moniteur 1 in response.md ([#83](https://github.com/ncouture/AirTell/issues/83)) ([d2d27d8](https://github.com/ncouture/AirTell/commit/d2d27d874ee4e70e4b32b0947c0ec09e87137fbb))
* **docs:** p2 fix 35 broken relative links in docs/2D_tomographic_sensing.md ([#107](https://github.com/ncouture/AirTell/issues/107)) ([d4d25f5](https://github.com/ncouture/AirTell/commit/d4d25f58a25b6f002aeeb66c2a383d9f1c081900))
* **docs:** p2 fix corrupted LaTeX math block closing delimiter in docs/2D_tomographic_sensing.md ([#108](https://github.com/ncouture/AirTell/issues/108)) ([7c28219](https://github.com/ncouture/AirTell/commit/7c28219faab639b12dd686066f74c17530d199d3))
* **docs:** p2 remove dead reference to non-existent TEST_INFRA.md in TEST_READY.md ([#109](https://github.com/ncouture/AirTell/issues/109)) ([716af32](https://github.com/ncouture/AirTell/commit/716af32ef9bc2a76b3252a3c50e6606eb3991f7e))
* **docs:** p2 remove non-existent file reference sniffle_exclusive_use_commands.org in docs/AirTell-PoPETs.md ([#111](https://github.com/ncouture/AirTell/issues/111)) ([de5ceb8](https://github.com/ncouture/AirTell/commit/de5ceb8df2ef596593cf22f99690954b0c2535e3))
* **docs:** p2 sanitize local file URIs and dead ephemeral brain link in response.md ([#110](https://github.com/ncouture/AirTell/issues/110)) ([dcef7fc](https://github.com/ncouture/AirTell/commit/dcef7fcdaf722a0faa7692aeb371da10aee3e388))
* **extcap:** p1 unbuffered tshark subprocess deadlock on unconsumed stderr ([#75](https://github.com/ncouture/AirTell/issues/75)) ([4935a4b](https://github.com/ncouture/AirTell/commit/4935a4b5a294b089ca46059219a6a44852fdbe7a))
* **pcap:** p1 assertion crashes on malformed packets in sniffle PCAP reader ([#78](https://github.com/ncouture/AirTell/issues/78)) ([2b3662d](https://github.com/ncouture/AirTell/commit/2b3662d9385e2076926a7ba464f5188ceaf0f98e))
* **pcap:** p2 buffer length check off-by-one in PcapBleReader global header ([#106](https://github.com/ncouture/AirTell/issues/106)) ([dfb7623](https://github.com/ncouture/AirTell/commit/dfb76238d1c3edafe8ddacb5df431a8e08bf1558))
* **radar:** p2 hardcoded python3.13 shebang in radar_tomography.py ([#105](https://github.com/ncouture/AirTell/issues/105)) ([38fada9](https://github.com/ncouture/AirTell/commit/38fada9fdc88294db34959aba053d533a25a5e2e))
* **scanner:** restore Advertiser helper class in scanner script ([265e50f](https://github.com/ncouture/AirTell/commit/265e50ffeaf5ade9fc8bcb78faaee7657f07122b))
* **scripts:** p1 broken relative script path traversal in code_review and extract_traffic_metadata ([#76](https://github.com/ncouture/AirTell/issues/76)) ([4524a4d](https://github.com/ncouture/AirTell/commit/4524a4d520b11da9842d9db7f8a39e1733a58fcc))
* **scripts:** p2 incomplete MAC validation in sniff_receiver.py ([#103](https://github.com/ncouture/AirTell/issues/103)) ([7094232](https://github.com/ncouture/AirTell/commit/709423261c372dcd913c482aaeb2cdaf27e94061))
* **scripts:** p2 missing sys.executable and orphan process leak in ble_parser.py ([#102](https://github.com/ncouture/AirTell/issues/102)) ([f2b29f2](https://github.com/ncouture/AirTell/commit/f2b29f27adf3de46dec11a0d04fd1ac5c2fc60f1))
* **scripts:** p2 unhandled payload buffer overflow in advertiser.py ([#104](https://github.com/ncouture/AirTell/issues/104)) ([6970376](https://github.com/ncouture/AirTell/commit/6970376f5d51c934e56e8b7f783299fa0a0633ed))
* **storage:** allow cross-thread close by disabling check_same_thread in SQLiteBackend ([#73](https://github.com/ncouture/AirTell/issues/73)) ([b77f14b](https://github.com/ncouture/AirTell/commit/b77f14bd92f5b3759b10641ec6b9c2f697ff855d))
* **storage:** p1 connection leak across threads in SQLiteBackend.close() ([#73](https://github.com/ncouture/AirTell/issues/73)) ([e721286](https://github.com/ncouture/AirTell/commit/e7212864c0dbe3ce7353f6a4d7082a1ec9040fea))
* **storage:** p1 SQL injection and unescaped path in DuckDB SQLite ATTACH ([#74](https://github.com/ncouture/AirTell/issues/74)) ([9a4ec0f](https://github.com/ncouture/AirTell/commit/9a4ec0f3be3ffe724a6974c42b7b253ecfb95411))
* **test:** eliminate hardware test flakiness and reader thread termination ([7638af5](https://github.com/ncouture/AirTell/commit/7638af52bcaf6d1e46c97432cf840586744722bc))
* **test:** eliminate marker token thrashing and broad exceptions in hardware fixtures ([337da76](https://github.com/ncouture/AirTell/commit/337da76e2623566a9fe4228a76d76f4016065426))
* **tests:** p0 missing Path import causes collection crash in test suites ([#72](https://github.com/ncouture/AirTell/issues/72)) ([72bd579](https://github.com/ncouture/AirTell/commit/72bd5794ae71131e0e2afd26bd33da99ed94a8ca))
* **tests:** p1 broken imports in standalone radar test scripts ([#77](https://github.com/ncouture/AirTell/issues/77)) ([3e9c0a9](https://github.com/ncouture/AirTell/commit/3e9c0a97b34882c28fa7249429ec5c995d5b3532))
* **tests:** resolve cli version flag, telemetry schema, and empirical test failures ([#239](https://github.com/ncouture/AirTell/issues/239)) ([ad41721](https://github.com/ncouture/AirTell/commit/ad417218fc0cc76544fab62ffefda2aadfc13cc0))


### Performance Improvements

* **app:** move classify_payload import outside per-packet loop in queue_bridge ([#97](https://github.com/ncouture/AirTell/issues/97)) ([6b339d9](https://github.com/ncouture/AirTell/commit/6b339d9118665a45114d8037ca780b399d0a81bf))
* **pcap:** eliminate unbuffered I/O on new files in sniffle PcapBleWriter ([#98](https://github.com/ncouture/AirTell/issues/98)) ([de84720](https://github.com/ncouture/AirTell/commit/de84720e2b0ac5393182145966f8e1682bbc4653))
* **radar:** p3 replace numpy.median on small lists with statistics.median ([#132](https://github.com/ncouture/AirTell/issues/132)) ([0a9eefe](https://github.com/ncouture/AirTell/commit/0a9eefe40fc8218c70e210c07ab6673b658c5642))
* **radar:** replace O(N) list.pop(0) with collections.deque in Anomaly and Stream engines ([#93](https://github.com/ncouture/AirTell/issues/93)) ([c13beea](https://github.com/ncouture/AirTell/commit/c13beeac5394ac50b3ef514b14c6b813bb18e4cc))
* **stream:** avoid quadratic string concatenation in tshark JSON buffer ([#99](https://github.com/ncouture/AirTell/issues/99)) ([36fb654](https://github.com/ncouture/AirTell/commit/36fb654414213839aca5947d0cc75db857a5ce62))


### Documentation

* **contribute:** add CONTRIBUTE.md developer workflow and pre-commit guide ([db1ac66](https://github.com/ncouture/AirTell/commit/db1ac66e39cef7ba426166e62aebc009d1f1926a))
* **github:** add docs/GITHUB.md guide and update documentation index ([7d29c6a](https://github.com/ncouture/AirTell/commit/7d29c6a6281addda8423ff8b388fe93b7a77881e))
* **rssi-radar:** adds docs/2D_tomographic_sensing.md ([4f6ea0f](https://github.com/ncouture/AirTell/commit/4f6ea0fefb097cf8e5a98b71aa8df6a343510897))
* **skill:** update .github/skills/code-review/SKILL.md to use Gemini 4 Argon (Thinking = High) and optimize review protocol ([#229](https://github.com/ncouture/AirTell/issues/229)) ([b7e91a8](https://github.com/ncouture/AirTell/commit/b7e91a8e4b6edab293f755bbb7831f378e244764))
* update documentation, CLI reference, and PoPETs research artifacts ([a120610](https://github.com/ncouture/AirTell/commit/a120610029c74bbda16d03bb2efe676058457805))
