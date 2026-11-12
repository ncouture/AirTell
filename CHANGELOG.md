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

## [0.2.100](https://github.com/ncouture/AirTell/compare/v0.2.99...v0.2.100) (2026-11-07)


### Continuous Integration

* **release:** fix release-please workflow permissions, deprecated actions, and runner label ([#241](https://github.com/ncouture/AirTell/issues/241)) ([e64c1cc](https://github.com/ncouture/AirTell/commit/e64c1cc13f62dbe26317ab1c4a9718a2db69322d))

## [0.2.99](https://github.com/ncouture/AirTell/compare/v0.2.98...v0.2.99) (2026-11-06)


### Bug Fixes

* **tests:** resolve cli version flag, telemetry schema, and empirical test failures ([#239](https://github.com/ncouture/AirTell/issues/239)) ([ad41721](https://github.com/ncouture/AirTell/commit/ad417218fc0cc76544fab62ffefda2aadfc13cc0))

## [0.2.98](https://github.com/ncouture/AirTell/compare/v0.2.97...v0.2.98) (2026-11-06)


### Continuous Integration

* **release:** integrate release-please-action with codeowner gating and release automation ([#237](https://github.com/ncouture/AirTell/issues/237)) ([ef722ab](https://github.com/ncouture/AirTell/commit/ef722ab6f9d1988030951add7952860300517e60))

## [0.2.97](https://github.com/ncouture/AirTell/compare/v0.2.96...v0.2.97) (2026-11-06)


### Features

* **code-review:** authorize codeowner reviews on non-codeowner pull requests ([#235](https://github.com/ncouture/AirTell/issues/235)) ([7b83022](https://github.com/ncouture/AirTell/commit/7b8302217520f95b38c1ad781dbf1e7dd04812e5))

## [0.2.96](https://github.com/ncouture/AirTell/compare/v0.2.95...v0.2.96) (2026-11-06)


### Continuous Integration

* **code-review:** update .github/workflows/code-review.yml to use Gemini 4 Argon (thinking level = HIGH) and optimize workflow ([#228](https://github.com/ncouture/AirTell/issues/228)) ([79e690c](https://github.com/ncouture/AirTell/commit/79e690cf0d73f030c8df8ffc31c72a0cad1fd4cd))

## [0.2.95](https://github.com/ncouture/AirTell/compare/v0.2.94...v0.2.95) (2026-11-06)


### Documentation

* **skill:** update .github/skills/code-review/SKILL.md to use Gemini 4 Argon (Thinking = High) and optimize review protocol ([#229](https://github.com/ncouture/AirTell/issues/229)) ([b7e91a8](https://github.com/ncouture/AirTell/commit/b7e91a8e4b6edab293f755bbb7831f378e244764))

## [0.2.94](https://github.com/ncouture/AirTell/compare/v0.2.93...v0.2.94) (2026-11-06)


### Features

* **relay:** unify master and slave pairing relay into single airtell relay cli ([90baa1f](https://github.com/ncouture/AirTell/commit/90baa1fdd594b190cebe4cf1f1c96a60b5e406f9))

## [0.2.93](https://github.com/ncouture/AirTell/compare/v0.2.92...v0.2.93) (2026-11-06)


### Features

* **ouidb:** integrate spectra mesh oui database and pcap mac timeline generator ([340322e](https://github.com/ncouture/AirTell/commit/340322e938c8a501f19a09529a70bad2f40a77a6))

## [0.2.92](https://github.com/ncouture/AirTell/compare/v0.2.91...v0.2.92) (2026-11-05)


### Bug Fixes

* **test:** eliminate marker token thrashing and broad exceptions in hardware fixtures ([337da76](https://github.com/ncouture/AirTell/commit/337da76e2623566a9fe4228a76d76f4016065426))

## [0.2.91](https://github.com/ncouture/AirTell/compare/v0.2.90...v0.2.91) (2026-11-05)


### Bug Fixes

* **test:** eliminate hardware test flakiness and reader thread termination ([7638af5](https://github.com/ncouture/AirTell/commit/7638af52bcaf6d1e46c97432cf840586744722bc))

## [0.2.90](https://github.com/ncouture/AirTell/compare/v0.2.89...v0.2.90) (2026-11-05)


### Features

* **test:** enable dual real Sniffle USB device test execution ([f8a38f5](https://github.com/ncouture/AirTell/commit/f8a38f515fd01bf741ee084c3b072d6cfc1c8e9d))

## [0.2.89](https://github.com/ncouture/AirTell/compare/v0.2.88...v0.2.89) (2026-11-05)


### Tests

* **audit:** eliminate broad exception suppression and require specific exceptions ([9b6ff84](https://github.com/ncouture/AirTell/commit/9b6ff84422038d02384a0c28909851d81dbc4922))

## [0.2.88](https://github.com/ncouture/AirTell/compare/v0.2.87...v0.2.88) (2026-11-04)


### Styles

* **format:** apply codebase-wide ruff formatting and whitespace hygiene ([9a30189](https://github.com/ncouture/AirTell/commit/9a30189c0edefb5dc31722f4bca5f090972ce48b))

## [0.2.87](https://github.com/ncouture/AirTell/compare/v0.2.86...v0.2.87) (2026-11-04)


### Tests

* **adversarial:** add M1 and M2 bounds stress test suites ([47644d1](https://github.com/ncouture/AirTell/commit/47644d1bc472f877ae279e5f4de5d86f328112eb))

## [0.2.86](https://github.com/ncouture/AirTell/compare/v0.2.85...v0.2.86) (2026-11-04)


### Miscellaneous Chores

* **deps:** synchronize packaging configurations and uv lockfile ([f5f980a](https://github.com/ncouture/AirTell/commit/f5f980aa71c4c8b324731aa45617622b7ed67c9f))

## [0.2.85](https://github.com/ncouture/AirTell/compare/v0.2.84...v0.2.85) (2026-11-04)


### Documentation

* **contribute:** add CONTRIBUTE.md developer workflow and pre-commit guide ([db1ac66](https://github.com/ncouture/AirTell/commit/db1ac66e39cef7ba426166e62aebc009d1f1926a))

## [0.2.84](https://github.com/ncouture/AirTell/compare/v0.2.83...v0.2.84) (2026-11-04)


### Bug Fixes

* **scanner:** restore Advertiser helper class in scanner script ([265e50f](https://github.com/ncouture/AirTell/commit/265e50ffeaf5ade9fc8bcb78faaee7657f07122b))

## [0.2.83](https://github.com/ncouture/AirTell/compare/v0.2.82...v0.2.83) (2026-11-04)


### Miscellaneous Chores

* **review:** ensure unit & integration tests pass without uv dependency ([#68](https://github.com/ncouture/AirTell/issues/68)) ([12abcd8](https://github.com/ncouture/AirTell/commit/12abcd8594bdd3be4a39fda56afd2fe1e2b6f41e))

## [0.2.82](https://github.com/ncouture/AirTell/compare/v0.2.81...v0.2.82) (2026-11-04)


### Miscellaneous Chores

* **review:** ensure ruff lint clean without uv dependency ([#67](https://github.com/ncouture/AirTell/issues/67)) ([e46961c](https://github.com/ncouture/AirTell/commit/e46961cec77460fdc4d9815550053f35eea04ba7))

## [0.2.81](https://github.com/ncouture/AirTell/compare/v0.2.80...v0.2.81) (2026-11-04)


### Optimizations

* **conductor:** p3 consolidate repetitive documentation reconciliation tasks into automated pre-commit check ([#143](https://github.com/ncouture/AirTell/issues/143)) ([d95a418](https://github.com/ncouture/AirTell/commit/d95a4186b42da4051c923dbe799c8526649b4bf7))

## [0.2.80](https://github.com/ncouture/AirTell/compare/v0.2.79...v0.2.80) (2026-11-04)


### Miscellaneous Chores

* **conductor:** p3 prune unused google html/css and javascript styleguides ([#142](https://github.com/ncouture/AirTell/issues/142)) ([ded883c](https://github.com/ncouture/AirTell/commit/ded883cdfb0e4740b7a714a5b279249beab3eb01))

## [0.2.79](https://github.com/ncouture/AirTell/compare/v0.2.78...v0.2.79) (2026-11-04)


### Miscellaneous Chores

* **conductor:** p3 align link list formatting in tshark_json_stream index ([#141](https://github.com/ncouture/AirTell/issues/141)) ([40bcca6](https://github.com/ncouture/AirTell/commit/40bcca6a73780daa3ce41024249189d5769798a6))

## [0.2.78](https://github.com/ncouture/AirTell/compare/v0.2.77...v0.2.78) (2026-11-04)


### Miscellaneous Chores

* **conductor:** p3 standardize commit sha bracket formatting in tshark_json_stream plan ([#140](https://github.com/ncouture/AirTell/issues/140)) ([bcec395](https://github.com/ncouture/AirTell/commit/bcec3950effeaf0789ad4b38e8dcc166a0687141))

## [0.2.77](https://github.com/ncouture/AirTell/compare/v0.2.76...v0.2.77) (2026-11-04)


### Miscellaneous Chores

* **conductor:** p3 standardize utc iso-8601 timestamps in metadata files ([#139](https://github.com/ncouture/AirTell/issues/139)) ([af2b5c3](https://github.com/ncouture/AirTell/commit/af2b5c3cda5f73b80f8b6a7c870c24e5379f4ea4))

## [0.2.76](https://github.com/ncouture/AirTell/compare/v0.2.75...v0.2.76) (2026-11-04)


### Optimizations

* **docs:** p3 consolidate Wireshark extcap installation instructions to single source of truth ([#138](https://github.com/ncouture/AirTell/issues/138)) ([2d82cc4](https://github.com/ncouture/AirTell/commit/2d82cc4ee97ef49fddb751e4b9a3b956a1c9c217))

## [0.2.75](https://github.com/ncouture/AirTell/compare/v0.2.74...v0.2.75) (2026-11-04)


### Optimizations

* **docs:** p3 add uv package manager workflows to README.md and installation documentation ([#137](https://github.com/ncouture/AirTell/issues/137)) ([016b752](https://github.com/ncouture/AirTell/commit/016b75272bd50682d4e6ebecb1bc39184942bb65))

## [0.2.74](https://github.com/ncouture/AirTell/compare/v0.2.73...v0.2.74) (2026-11-04)


### Miscellaneous Chores

* **conductor:** p3 correct outdated baud rates, chip models, and notifications dependency in tech-stack.md and pyproject ([#136](https://github.com/ncouture/AirTell/issues/136)) ([b78aab9](https://github.com/ncouture/AirTell/commit/b78aab9f0bffd07369136f1ff51937acf90c0f30))

## [0.2.73](https://github.com/ncouture/AirTell/compare/v0.2.72...v0.2.73) (2026-11-04)


### Miscellaneous Chores

* **docs:** p3 reconcile outdated test suite counts in TEST_READY.md and conductor/tech-stack.md ([#135](https://github.com/ncouture/AirTell/issues/135)) ([d094110](https://github.com/ncouture/AirTell/commit/d0941108bbab9bff8f21e38f2dc1028a47d3615d))

## [0.2.72](https://github.com/ncouture/AirTell/compare/v0.2.71...v0.2.72) (2026-11-04)


### Miscellaneous Chores

* **docs:** p3 fix empty status shield badge link in README.md ([#134](https://github.com/ncouture/AirTell/issues/134)) ([758418c](https://github.com/ncouture/AirTell/commit/758418c3c632cf2959d5baa52bd3f5e0a7c3d080))

## [0.2.71](https://github.com/ncouture/AirTell/compare/v0.2.70...v0.2.71) (2026-11-04)


### Miscellaneous Chores

* **docs:** p3 remove chatty conversational artifact from docs/AirTell-PoPETs.md ([#133](https://github.com/ncouture/AirTell/issues/133)) ([478db32](https://github.com/ncouture/AirTell/commit/478db32edb81e2ac62af931dba640fb275ba19b4))

## [0.2.70](https://github.com/ncouture/AirTell/compare/v0.2.69...v0.2.70) (2026-11-04)


### Performance Improvements

* **radar:** p3 replace numpy.median on small lists with statistics.median ([#132](https://github.com/ncouture/AirTell/issues/132)) ([0a9eefe](https://github.com/ncouture/AirTell/commit/0a9eefe40fc8218c70e210c07ab6673b658c5642))

## [0.2.69](https://github.com/ncouture/AirTell/compare/v0.2.68...v0.2.69) (2026-11-04)


### Code Refactoring

* **pep8:** p3 fix anti-idiomatic comparisons and ambiguous variable names ([#131](https://github.com/ncouture/AirTell/issues/131)) ([e08913e](https://github.com/ncouture/AirTell/commit/e08913e72f62db94d443b491ad7ab3c41dcc0a55))

## [0.2.68](https://github.com/ncouture/AirTell/compare/v0.2.67...v0.2.68) (2026-11-04)


### Code Refactoring

* **pep8:** p3 eliminate global mutable hardware state across CLI scripts ([#130](https://github.com/ncouture/AirTell/issues/130)) ([e3228ea](https://github.com/ncouture/AirTell/commit/e3228ea5427d376c310edf615c46bbba7c78722b))

## [0.2.67](https://github.com/ncouture/AirTell/compare/v0.2.66...v0.2.67) (2026-11-04)


### Miscellaneous Chores

* **shebang:** p3 update legacy python shebangs to python3 ([#129](https://github.com/ncouture/AirTell/issues/129)) ([813d17d](https://github.com/ncouture/AirTell/commit/813d17d75e0475720fdd20ece32022ab55fddefa))

## [0.2.66](https://github.com/ncouture/AirTell/compare/v0.2.65...v0.2.66) (2026-11-04)


### Miscellaneous Chores

* **clean:** p3 remove unused imports and wildcard imports ([#128](https://github.com/ncouture/AirTell/issues/128)) ([6cc1437](https://github.com/ncouture/AirTell/commit/6cc14371746724e823eb2fe6fc8a8e7b81425b46))

## [0.2.65](https://github.com/ncouture/AirTell/compare/v0.2.64...v0.2.65) (2026-11-04)


### Miscellaneous Chores

* **typing:** p3 modernize legacy typing to PEP 585 and PEP 604 across codebase ([#127](https://github.com/ncouture/AirTell/issues/127)) ([4ccc880](https://github.com/ncouture/AirTell/commit/4ccc8806efba57cc2218eab1f72d198a2cf68dbc))

## [0.2.64](https://github.com/ncouture/AirTell/compare/v0.2.63...v0.2.64) (2026-11-04)


### Code Refactoring

* **conductor:** p2 remove irrelevant node/go/mobile boilerplate and populate python commands in workflow.md ([#126](https://github.com/ncouture/AirTell/issues/126)) ([15b3fd4](https://github.com/ncouture/AirTell/commit/15b3fd48318899e5909c60646650908dbfac3dde))

## [0.2.63](https://github.com/ncouture/AirTell/compare/v0.2.62...v0.2.63) (2026-11-04)


### Miscellaneous Chores

* **docs:** p2 index unlisted documentation files in docs/index.md ([#125](https://github.com/ncouture/AirTell/issues/125)) ([233ff52](https://github.com/ncouture/AirTell/commit/233ff528527890768060faae00856d21b6a8ca95))

## [0.2.62](https://github.com/ncouture/AirTell/compare/v0.2.61...v0.2.62) (2026-11-03)


### Miscellaneous Chores

* **docs:** p2 update project version numbers in docs and init to match pyproject.toml (0.2.0) ([#124](https://github.com/ncouture/AirTell/issues/124)) ([fd860f3](https://github.com/ncouture/AirTell/commit/fd860f33eaa8b2363b0b2f495375b71a2337b957))

## [0.2.61](https://github.com/ncouture/AirTell/compare/v0.2.60...v0.2.61) (2026-11-03)


### Miscellaneous Chores

* **sniffle:** p2 fix mutable default arguments in hardware and relay scripts ([#123](https://github.com/ncouture/AirTell/issues/123)) ([59c7780](https://github.com/ncouture/AirTell/commit/59c77809792a5400974ae2d5a5b7638274d9f46d))

## [0.2.60](https://github.com/ncouture/AirTell/compare/v0.2.59...v0.2.60) (2026-11-03)


### Miscellaneous Chores

* **conductor:** p2 normalize status enum values and type casing in metadata files ([#122](https://github.com/ncouture/AirTell/issues/122)) ([7549521](https://github.com/ncouture/AirTell/commit/7549521b66e02b5c1efb7dacbe02c1437b8a50fd))

## [0.2.59](https://github.com/ncouture/AirTell/compare/v0.2.58...v0.2.59) (2026-11-03)


### Miscellaneous Chores

* **conductor:** p2 standardize track title key name across all metadata files ([#121](https://github.com/ncouture/AirTell/issues/121)) ([a5dfd47](https://github.com/ncouture/AirTell/commit/a5dfd47450f45c30d4d957d185fbce926c6c2a23))

## [0.2.58](https://github.com/ncouture/AirTell/compare/v0.2.57...v0.2.58) (2026-11-03)


### Optimizations

* **conductor:** p2 collapse ceremony-heavy 7-phase plans into realistic milestones ([#120](https://github.com/ncouture/AirTell/issues/120)) ([e2de094](https://github.com/ncouture/AirTell/commit/e2de0940c0ced2cf4231a93366a24b02b08902d0))

## [0.2.57](https://github.com/ncouture/AirTell/compare/v0.2.56...v0.2.57) (2026-11-03)


### Code Refactoring

* **conductor:** p2 formalize single-dongle passive capture mode in product architecture ([#119](https://github.com/ncouture/AirTell/issues/119)) ([5b4a7e3](https://github.com/ncouture/AirTell/commit/5b4a7e35557d653217a857fc9d2ebcca73b49d22))

## [0.2.56](https://github.com/ncouture/AirTell/compare/v0.2.55...v0.2.56) (2026-11-03)


### Code Refactoring

* **conductor:** p2 align python styleguide with ruff config and modern pep 8 idioms ([#118](https://github.com/ncouture/AirTell/issues/118)) ([d10822e](https://github.com/ncouture/AirTell/commit/d10822eb722b58526e8ed1da1730c1b6dd76bccb))

## [0.2.55](https://github.com/ncouture/AirTell/compare/v0.2.54...v0.2.55) (2026-11-03)


### Bug Fixes

* **conductor:** p2 add missing phase checkpoint markers to tshark_json_stream plan ([#117](https://github.com/ncouture/AirTell/issues/117)) ([37892b7](https://github.com/ncouture/AirTell/commit/37892b706153906bfbe2fe76816cacbb3081e39d))

## [0.2.54](https://github.com/ncouture/AirTell/compare/v0.2.53...v0.2.54) (2026-11-03)


### Bug Fixes

* **conductor:** p2 fix missing app prefix in duckdb spec view paths ([#116](https://github.com/ncouture/AirTell/issues/116)) ([2dd9f0a](https://github.com/ncouture/AirTell/commit/2dd9f0a07911c3c651d5ec7c93dec9bd8fea7153))

## [0.2.53](https://github.com/ncouture/AirTell/compare/v0.2.52...v0.2.53) (2026-11-03)


### Optimizations

* **docs:** p2 expand README.md project layout tree to cover sidechannel, sniff, telemetry, and idbleed ([#115](https://github.com/ncouture/AirTell/issues/115)) ([1633dab](https://github.com/ncouture/AirTell/commit/1633dab4922fb4b188a9809ee8b453aa2a77c08c))

## [0.2.52](https://github.com/ncouture/AirTell/compare/v0.2.51...v0.2.52) (2026-11-03)


### Code Refactoring

* **docs:** p2 document parameter semantic divergence of --json between sidechannel and other subcommands in docs/CLI.md ([#114](https://github.com/ncouture/AirTell/issues/114)) ([2c33d5e](https://github.com/ncouture/AirTell/commit/2c33d5e39f39aee6383c87b7983ffd2e9c69a6b4))

## [0.2.51](https://github.com/ncouture/AirTell/compare/v0.2.50...v0.2.51) (2026-11-03)


### Code Refactoring

* **docs:** p2 eliminate duplicate and divergent markdown documentation in src/sniffle/docs/ ([#113](https://github.com/ncouture/AirTell/issues/113)) ([9e753b4](https://github.com/ncouture/AirTell/commit/9e753b449a75d301e32e58b9f1ff421b70a8cd0a))

## [0.2.50](https://github.com/ncouture/AirTell/compare/v0.2.49...v0.2.50) (2026-11-03)


### Code Refactoring

* **docs:** p2 reconcile conflicting root HOWTO.md and harmonize with docs/howto.md ([#112](https://github.com/ncouture/AirTell/issues/112)) ([dcff136](https://github.com/ncouture/AirTell/commit/dcff13683e95bee93ce9adc6addc448387894382))

## [0.2.49](https://github.com/ncouture/AirTell/compare/v0.2.48...v0.2.49) (2026-11-03)


### Bug Fixes

* **docs:** p2 remove non-existent file reference sniffle_exclusive_use_commands.org in docs/AirTell-PoPETs.md ([#111](https://github.com/ncouture/AirTell/issues/111)) ([de5ceb8](https://github.com/ncouture/AirTell/commit/de5ceb8df2ef596593cf22f99690954b0c2535e3))

## [0.2.48](https://github.com/ncouture/AirTell/compare/v0.2.47...v0.2.48) (2026-11-03)


### Bug Fixes

* **docs:** p2 sanitize local file URIs and dead ephemeral brain link in response.md ([#110](https://github.com/ncouture/AirTell/issues/110)) ([dcef7fc](https://github.com/ncouture/AirTell/commit/dcef7fcdaf722a0faa7692aeb371da10aee3e388))

## [0.2.47](https://github.com/ncouture/AirTell/compare/v0.2.46...v0.2.47) (2026-11-03)


### Bug Fixes

* **docs:** p2 remove dead reference to non-existent TEST_INFRA.md in TEST_READY.md ([#109](https://github.com/ncouture/AirTell/issues/109)) ([716af32](https://github.com/ncouture/AirTell/commit/716af32ef9bc2a76b3252a3c50e6606eb3991f7e))

## [0.2.46](https://github.com/ncouture/AirTell/compare/v0.2.45...v0.2.46) (2026-11-03)


### Bug Fixes

* **docs:** p2 fix corrupted LaTeX math block closing delimiter in docs/2D_tomographic_sensing.md ([#108](https://github.com/ncouture/AirTell/issues/108)) ([7c28219](https://github.com/ncouture/AirTell/commit/7c28219faab639b12dd686066f74c17530d199d3))

## [0.2.45](https://github.com/ncouture/AirTell/compare/v0.2.44...v0.2.45) (2026-11-03)


### Bug Fixes

* **docs:** p2 fix 35 broken relative links in docs/2D_tomographic_sensing.md ([#107](https://github.com/ncouture/AirTell/issues/107)) ([d4d25f5](https://github.com/ncouture/AirTell/commit/d4d25f58a25b6f002aeeb66c2a383d9f1c081900))

## [0.2.44](https://github.com/ncouture/AirTell/compare/v0.2.43...v0.2.44) (2026-11-03)


### Bug Fixes

* **pcap:** p2 buffer length check off-by-one in PcapBleReader global header ([#106](https://github.com/ncouture/AirTell/issues/106)) ([dfb7623](https://github.com/ncouture/AirTell/commit/dfb76238d1c3edafe8ddacb5df431a8e08bf1558))

## [0.2.43](https://github.com/ncouture/AirTell/compare/v0.2.42...v0.2.43) (2026-11-03)


### Bug Fixes

* **radar:** p2 hardcoded python3.13 shebang in radar_tomography.py ([#105](https://github.com/ncouture/AirTell/issues/105)) ([38fada9](https://github.com/ncouture/AirTell/commit/38fada9fdc88294db34959aba053d533a25a5e2e))

## [0.2.42](https://github.com/ncouture/AirTell/compare/v0.2.41...v0.2.42) (2026-11-03)


### Bug Fixes

* **scripts:** p2 unhandled payload buffer overflow in advertiser.py ([#104](https://github.com/ncouture/AirTell/issues/104)) ([6970376](https://github.com/ncouture/AirTell/commit/6970376f5d51c934e56e8b7f783299fa0a0633ed))

## [0.2.41](https://github.com/ncouture/AirTell/compare/v0.2.40...v0.2.41) (2026-11-03)


### Bug Fixes

* **scripts:** p2 incomplete MAC validation in sniff_receiver.py ([#103](https://github.com/ncouture/AirTell/issues/103)) ([7094232](https://github.com/ncouture/AirTell/commit/709423261c372dcd913c482aaeb2cdaf27e94061))

## [0.2.40](https://github.com/ncouture/AirTell/compare/v0.2.39...v0.2.40) (2026-11-03)


### Bug Fixes

* **scripts:** p2 missing sys.executable and orphan process leak in ble_parser.py ([#102](https://github.com/ncouture/AirTell/issues/102)) ([f2b29f2](https://github.com/ncouture/AirTell/commit/f2b29f27adf3de46dec11a0d04fd1ac5c2fc60f1))

## [0.2.39](https://github.com/ncouture/AirTell/compare/v0.2.38...v0.2.39) (2026-11-03)


### Code Refactoring

* **app:** replace blocking time.sleep rerun with Streamlit native auto-refresh ([#101](https://github.com/ncouture/AirTell/issues/101)) ([8349bbe](https://github.com/ncouture/AirTell/commit/8349bbe3a1136b03b0e7acefb5077e789125ee2a))

## [0.2.38](https://github.com/ncouture/AirTell/compare/v0.2.37...v0.2.38) (2026-11-03)


### Code Refactoring

* **tests:** relocate test scripts out of src/airtell/scripts into tests directory ([#100](https://github.com/ncouture/AirTell/issues/100)) ([38d5de0](https://github.com/ncouture/AirTell/commit/38d5de08a8089cf1c5aa79f4509f0d55a7cd7050))

## [0.2.37](https://github.com/ncouture/AirTell/compare/v0.2.36...v0.2.37) (2026-11-03)


### Performance Improvements

* **stream:** avoid quadratic string concatenation in tshark JSON buffer ([#99](https://github.com/ncouture/AirTell/issues/99)) ([36fb654](https://github.com/ncouture/AirTell/commit/36fb654414213839aca5947d0cc75db857a5ce62))

## [0.2.36](https://github.com/ncouture/AirTell/compare/v0.2.35...v0.2.36) (2026-11-03)


### Performance Improvements

* **pcap:** eliminate unbuffered I/O on new files in sniffle PcapBleWriter ([#98](https://github.com/ncouture/AirTell/issues/98)) ([de84720](https://github.com/ncouture/AirTell/commit/de84720e2b0ac5393182145966f8e1682bbc4653))

## [0.2.35](https://github.com/ncouture/AirTell/compare/v0.2.34...v0.2.35) (2026-11-03)


### Performance Improvements

* **app:** move classify_payload import outside per-packet loop in queue_bridge ([#97](https://github.com/ncouture/AirTell/issues/97)) ([6b339d9](https://github.com/ncouture/AirTell/commit/6b339d9118665a45114d8037ca780b399d0a81bf))

## [0.2.34](https://github.com/ncouture/AirTell/compare/v0.2.33...v0.2.34) (2026-11-03)


### Code Refactoring

* **core:** remove sys.modules mutation side-effect in airtell init ([#96](https://github.com/ncouture/AirTell/issues/96)) ([6a9691e](https://github.com/ncouture/AirTell/commit/6a9691eb656bc432d8ba8627cc43a04a9354e9bf))

## [0.2.33](https://github.com/ncouture/AirTell/compare/v0.2.32...v0.2.33) (2026-11-03)


### Code Refactoring

* **errors:** replace bare except clauses with explicit exception handling ([#95](https://github.com/ncouture/AirTell/issues/95)) ([5e72e98](https://github.com/ncouture/AirTell/commit/5e72e986619c3241dd17d687107a24ddd46b8b1e))

## [0.2.32](https://github.com/ncouture/AirTell/compare/v0.2.31...v0.2.32) (2026-11-03)


### Code Refactoring

* **dissector:** refactor dataclass manual __init__ anti-pattern across beacon hierarchy ([#94](https://github.com/ncouture/AirTell/issues/94)) ([765d0cf](https://github.com/ncouture/AirTell/commit/765d0cf351c5ea4953271025463a15980fca7a6d))

## [0.2.31](https://github.com/ncouture/AirTell/compare/v0.2.30...v0.2.31) (2026-11-03)


### Performance Improvements

* **radar:** replace O(N) list.pop(0) with collections.deque in Anomaly and Stream engines ([#93](https://github.com/ncouture/AirTell/issues/93)) ([c13beea](https://github.com/ncouture/AirTell/commit/c13beeac5394ac50b3ef514b14c6b813bb18e4cc))

## [0.2.30](https://github.com/ncouture/AirTell/compare/v0.2.29...v0.2.30) (2026-11-03)


### Bug Fixes

* **storage:** allow cross-thread close by disabling check_same_thread in SQLiteBackend ([#73](https://github.com/ncouture/AirTell/issues/73)) ([b77f14b](https://github.com/ncouture/AirTell/commit/b77f14bd92f5b3759b10641ec6b9c2f697ff855d))

## [0.2.29](https://github.com/ncouture/AirTell/compare/v0.2.28...v0.2.29) (2026-11-03)


### Code Refactoring

* **conductor:** p1 replace fictitious sqlalchemy/sqlmodel claims with real databasebackend abstraction ([#92](https://github.com/ncouture/AirTell/issues/92)) ([d9c47c1](https://github.com/ncouture/AirTell/commit/d9c47c1f46e3622ed5ada02aaa6caa8bc26b537b))

## [0.2.28](https://github.com/ncouture/AirTell/compare/v0.2.27...v0.2.28) (2026-11-03)


### Code Refactoring

* **conductor:** p1 harmonize global track numbering across registry and track plans ([#91](https://github.com/ncouture/AirTell/issues/91)) ([d270932](https://github.com/ncouture/AirTell/commit/d2709321aa8370827975e3cff7a495fe19ca3507))

## [0.2.27](https://github.com/ncouture/AirTell/compare/v0.2.26...v0.2.27) (2026-11-03)


### Code Refactoring

* **conductor:** p1 decompose oversized ble_adversarial_relay track into cohesive modular tracks ([#90](https://github.com/ncouture/AirTell/issues/90)) ([2fa858c](https://github.com/ncouture/AirTell/commit/2fa858c2ef65a22cefcac57399887a2bac59f067))

## [0.2.26](https://github.com/ncouture/AirTell/compare/v0.2.25...v0.2.26) (2026-11-03)


### Code Refactoring

* **scripts:** p1 eliminate 484 lines of duplicated code between airtell and sniffle radar_tomography ([#89](https://github.com/ncouture/AirTell/issues/89)) ([a8d592e](https://github.com/ncouture/AirTell/commit/a8d592e9030987d355073905863b9cd83d4109f4))

## [0.2.25](https://github.com/ncouture/AirTell/compare/v0.2.24...v0.2.25) (2026-11-03)


### Bug Fixes

* **conductor:** p1 resolve topology a and b definition collision in product definition ([#88](https://github.com/ncouture/AirTell/issues/88)) ([363be04](https://github.com/ncouture/AirTell/commit/363be041e7d3e8eeb558bf59cb047b79728a6c02))

## [0.2.24](https://github.com/ncouture/AirTell/compare/v0.2.23...v0.2.24) (2026-11-03)


### Bug Fixes

* **conductor:** p1 reconcile completed status in ble_adversarial_relay metadata ([#87](https://github.com/ncouture/AirTell/issues/87)) ([01f8a53](https://github.com/ncouture/AirTell/commit/01f8a53ac3d15050bcaab5c51892306e128e75ee))

## [0.2.23](https://github.com/ncouture/AirTell/compare/v0.2.22...v0.2.23) (2026-11-03)


### Bug Fixes

* **conductor:** p1 reconcile completed status in m3_dashboard metadata ([#86](https://github.com/ncouture/AirTell/issues/86)) ([f1ba0a4](https://github.com/ncouture/AirTell/commit/f1ba0a4a2b702462f675f5c2ec0cf82a2b2ab743))

## [0.2.22](https://github.com/ncouture/AirTell/compare/v0.2.21...v0.2.22) (2026-11-03)


### Bug Fixes

* **conductor:** p1 correct broken extcap module paths in tshark_json_stream plan ([#85](https://github.com/ncouture/AirTell/issues/85)) ([5f501cf](https://github.com/ncouture/AirTell/commit/5f501cf8478ce817104385360396371c7f10c2e2))

## [0.2.21](https://github.com/ncouture/AirTell/compare/v0.2.20...v0.2.21) (2026-11-03)


### Bug Fixes

* **conductor:** p1 correct broken bluetooth_sniffle module paths in ble_adversarial_relay plan ([#84](https://github.com/ncouture/AirTell/issues/84)) ([dc5441b](https://github.com/ncouture/AirTell/commit/dc5441bc59dcbea19ab275eb46663bba622f1b83))

## [0.2.20](https://github.com/ncouture/AirTell/compare/v0.2.19...v0.2.20) (2026-11-03)


### Bug Fixes

* **docs:** p1 resolve direct factual contradiction on Moniteur 1 in response.md ([#83](https://github.com/ncouture/AirTell/issues/83)) ([d2d27d8](https://github.com/ncouture/AirTell/commit/d2d27d874ee4e70e4b32b0947c0ec09e87137fbb))

## [0.2.19](https://github.com/ncouture/AirTell/compare/v0.2.18...v0.2.19) (2026-11-03)


### Bug Fixes

* **docs:** p1 remove invalid single-dongle verify-hardware command in docs/CLI.md ([#82](https://github.com/ncouture/AirTell/issues/82)) ([66ca539](https://github.com/ncouture/AirTell/commit/66ca53904b99e405d8ed9bd5d18bc3447f7d9ffe))

## [0.2.18](https://github.com/ncouture/AirTell/compare/v0.2.17...v0.2.18) (2026-11-03)


### Bug Fixes

* **docs:** p1 correct invalid command line examples and wrong argument flags for ble_antistalking_tracker.py and ble_parser.py ([#81](https://github.com/ncouture/AirTell/issues/81)) ([f313638](https://github.com/ncouture/AirTell/commit/f3136386ae4629555e778f4ad2729cbb5b8ef7b6))

## [0.2.17](https://github.com/ncouture/AirTell/compare/v0.2.16...v0.2.17) (2026-11-03)


### Bug Fixes

* **docs:** p1 fix unexpected indentation syntax errors in python code snippets in docs/howto.md and docs/scripts_reference.md ([#80](https://github.com/ncouture/AirTell/issues/80)) ([fc4189f](https://github.com/ncouture/AirTell/commit/fc4189f2929bb1c2f7c849ec29cae3baf6a28c7f))

## [0.2.16](https://github.com/ncouture/AirTell/compare/v0.2.15...v0.2.16) (2026-11-03)


### Bug Fixes

* **app:** p1 unclosed SQLite connection on view exception in Streamlit app ([#79](https://github.com/ncouture/AirTell/issues/79)) ([2ec4eda](https://github.com/ncouture/AirTell/commit/2ec4eda858ff5cd5753187d07462694e6f52d2b6))

## [0.2.15](https://github.com/ncouture/AirTell/compare/v0.2.14...v0.2.15) (2026-11-03)


### Bug Fixes

* **pcap:** p1 assertion crashes on malformed packets in sniffle PCAP reader ([#78](https://github.com/ncouture/AirTell/issues/78)) ([2b3662d](https://github.com/ncouture/AirTell/commit/2b3662d9385e2076926a7ba464f5188ceaf0f98e))

## [0.2.14](https://github.com/ncouture/AirTell/compare/v0.2.13...v0.2.14) (2026-11-03)


### Bug Fixes

* **tests:** p1 broken imports in standalone radar test scripts ([#77](https://github.com/ncouture/AirTell/issues/77)) ([3e9c0a9](https://github.com/ncouture/AirTell/commit/3e9c0a97b34882c28fa7249429ec5c995d5b3532))

## [0.2.13](https://github.com/ncouture/AirTell/compare/v0.2.12...v0.2.13) (2026-11-03)


### Bug Fixes

* **scripts:** p1 broken relative script path traversal in code_review and extract_traffic_metadata ([#76](https://github.com/ncouture/AirTell/issues/76)) ([4524a4d](https://github.com/ncouture/AirTell/commit/4524a4d520b11da9842d9db7f8a39e1733a58fcc))

## [0.2.12](https://github.com/ncouture/AirTell/compare/v0.2.11...v0.2.12) (2026-11-03)


### Bug Fixes

* **extcap:** p1 unbuffered tshark subprocess deadlock on unconsumed stderr ([#75](https://github.com/ncouture/AirTell/issues/75)) ([4935a4b](https://github.com/ncouture/AirTell/commit/4935a4b5a294b089ca46059219a6a44852fdbe7a))

## [0.2.11](https://github.com/ncouture/AirTell/compare/v0.2.10...v0.2.11) (2026-11-03)


### Bug Fixes

* **storage:** p1 SQL injection and unescaped path in DuckDB SQLite ATTACH ([#74](https://github.com/ncouture/AirTell/issues/74)) ([9a4ec0f](https://github.com/ncouture/AirTell/commit/9a4ec0f3be3ffe724a6974c42b7b253ecfb95411))

## [0.2.10](https://github.com/ncouture/AirTell/compare/v0.2.9...v0.2.10) (2026-11-03)


### Bug Fixes

* **storage:** p1 connection leak across threads in SQLiteBackend.close() ([#73](https://github.com/ncouture/AirTell/issues/73)) ([e721286](https://github.com/ncouture/AirTell/commit/e7212864c0dbe3ce7353f6a4d7082a1ec9040fea))

## [0.2.9](https://github.com/ncouture/AirTell/compare/v0.2.8...v0.2.9) (2026-11-03)


### Bug Fixes

* **tests:** p0 missing Path import causes collection crash in test suites ([#72](https://github.com/ncouture/AirTell/issues/72)) ([72bd579](https://github.com/ncouture/AirTell/commit/72bd5794ae71131e0e2afd26bd33da99ed94a8ca))

## [0.2.8](https://github.com/ncouture/AirTell/compare/v0.2.7...v0.2.8) (2026-10-18)


### Bug Fixes

* **cache:** pip cache 14 days ([#65](https://github.com/ncouture/AirTell/issues/65)) ([8ec53e3](https://github.com/ncouture/AirTell/commit/8ec53e37dd58d0963389f8dd002facd05a53a583))

## [0.2.7](https://github.com/ncouture/AirTell/compare/v0.2.6...v0.2.7) (2026-10-18)


### Bug Fixes

* **ci:** fix ci bug on this branch ([a5507bf](https://github.com/ncouture/AirTell/commit/a5507bfd7fcc4b797050a489d9b89f4058466454))

## [0.2.6](https://github.com/ncouture/AirTell/compare/v0.2.5...v0.2.6) (2026-10-18)


### Documentation

* **rssi-radar:** adds docs/2D_tomographic_sensing.md ([4f6ea0f](https://github.com/ncouture/AirTell/commit/4f6ea0fefb097cf8e5a98b71aa8df6a343510897))

## [0.2.5](https://github.com/ncouture/AirTell/compare/v0.2.4...v0.2.5) (2026-10-18)


### Features

* **ci:** enforce codeowner authorization on code review workflow and runner ([a51134d](https://github.com/ncouture/AirTell/commit/a51134d6e20d79747513e4185d0f9dd626241acd))

### Documentation

* **github:** add docs/GITHUB.md guide and update documentation index ([7d29c6a](https://github.com/ncouture/AirTell/commit/7d29c6a6281addda8423ff8b388fe93b7a77881e))

## [0.2.4](https://github.com/ncouture/AirTell/compare/v0.2.3...v0.2.4) (2026-10-17)


### Features

* **github:** add issue templates, chooser config, and community discussions guide ([e5ac598](https://github.com/ncouture/AirTell/commit/e5ac598d17e0842039199b93e133050d92ed8bf7))

## [0.2.3](https://github.com/ncouture/AirTell/compare/v0.2.2...v0.2.3) (2026-10-17)


### Features

* implement Tracks 1–5 (Side-Channel Visualizer, CLI Adversarial Ingestion, Single-Dongle Topology-A, Alert Dispatchers, DuckDB Analytics) ([#58](https://github.com/ncouture/AirTell/issues/58)) ([db6e056](https://github.com/ncouture/AirTell/commit/db6e0564f2c5eb0bf1f892f0c71e875e862d1890))

## [0.2.2](https://github.com/ncouture/AirTell/compare/v0.2.1...v0.2.2) (2026-10-16)


### Code Refactoring

* **core:** migrate package structure from bluetooth-sniffle to airtell ([#57](https://github.com/ncouture/AirTell/issues/57)) ([6f7aab1](https://github.com/ncouture/AirTell/commit/6f7aab182d07fa75e3b82cd13eba32bb50ce7daf))

## [0.2.1](https://github.com/ncouture/AirTell/compare/v0.2.0...v0.2.1) (2026-10-15)


### Features

* **pcap:** add PCAPNG block parsing, writing, and DLT 256 link-layer support ([3e4e2b6](https://github.com/ncouture/AirTell/commit/3e4e2b68e9d5a7cc5b9e99be7a32383a26ff264e))
* **sidechannel:** implement BLE exclusive-use side-channel detection and analysis suite ([ace5f10](https://github.com/ncouture/AirTell/commit/ace5f109808f9a92314bc53f8e57ac2929082a6b))
* **adversarial:** expand adversarial M1-M4 testbed suite for crypto timing and relay evaluation ([04ea624](https://github.com/ncouture/AirTell/commit/04ea624b66df9efd9580fbddf86088c3a027958b))
* **cli:** add sidechannel subcommand and dual binary support to AirTell CLI ([cae8929](https://github.com/ncouture/AirTell/commit/cae892996c798520a363873fae2dc0e977f201ca))
* **ui:** update dashboard branding and add web presentation matrix ([6742410](https://github.com/ncouture/AirTell/commit/6742410cb3d3f8e8552ff9bd42487ce9d6140f97))

### Documentation

* update documentation, CLI reference, and PoPETs research artifacts ([a120610](https://github.com/ncouture/AirTell/commit/a120610029c74bbda16d03bb2efe676058457805))

## [0.2.0](https://github.com/ncouture/AirTell/compare/v0.1.0...v0.2.0) (2026-10-14)


### Features

* monitoring and adversarial ([#3](https://github.com/ncouture/AirTell/issues/3)) ([88d2ce9](https://github.com/ncouture/AirTell/commit/88d2ce90cee33e1a6596aceec73bdf03a200d1bd))

## 0.1.0 (2026-10-01)


### Features

* add sniff subpackage (dissector, PCAP, correlation, telemetry), unified CLI, and e2e test suite ([9f41dec](https://github.com/ncouture/AirTell/commit/9f41dec69f0a9045f668367889c29cf6311978ad))
