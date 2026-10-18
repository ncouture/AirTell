# AirTell Community Discussions & Guidelines

This document contains the community onboarding announcement and maintainer tips for GitHub Discussions on [ncouture/AirTell](https://github.com/ncouture/AirTell).

---

## Maintainer Operational Tips

```markdown
<!-- 
  =============================================================================
  AIRTELL DISCUSSIONS // MAINTAINER INTEL & OPERATIONAL PROTOCOL 📡⚡
  =============================================================================
-->

<!--
  📡 TIP 1: EMIT THE BEACON (Announce & Ignite the Spectrum)
  Signal to the communities where the real practitioners lurk:
  - Post across Infosec Mastodon/Bluesky, X, DEF CON Discord / Wireless Village channels,
    r/ReverseEngineering, r/SDR, and wireless privacy research circles (e.g., IEEE S&P, USENIX Sec).
  - Angle the callout: "We're treating BLE privacy as an RF side-channel and timing problem, 
    not just MAC-rotation theatre. Come dissect the digital body language with us in Discussions."

  🔗 TIP 2: SEGREGATE YOUR CHANNELS (Declutter Link-Layer Issues vs. Strategic Talk)
  - Keep GitHub Issues laser-focused: reproducible firmware race conditions, CC2652 UART buffer 
    underruns, parser panic traces, and concrete CI/testbed bugs.
  - Route open-ended signal analysis, adversarial methodology, rig showcases, and privacy threat 
    models straight to Discussions.
  - Handled via `.github/ISSUE_TEMPLATE/config.yml` (blank issues disabled, contact links pointing here).

  ➡️ TIP 3: TRIAGE & CONVERT (Keep the Wire Clean)
  - Don't close inquisitive issues with cold rejections. Re-route them: convert issues labeled 
    "question", "research", or "hardware-rig" into Discussions with one click.
  - Celebrate the hackers who build custom mock harnesses, solder custom SMA leads to CC2652 dongles, 
    or surface novel RF timing correlations. Pin their threads as Category Highlights.
-->
```

---

## Pinned Welcome Announcement

*(Copy and paste this markdown into a new pinned discussion under **Announcements** or **General**)*

```markdown
# 📡 AirTell: The Spectrum Has a Voice. Welcome to Discussions.

> *"Hackers are like painters. They don't start with a complete plan; they start with a stroke, paint a line, and see how the canvas responds. But our canvas is 2.4 GHz of unshielded air, microsecond timing deltas, and the unintended confessions of silicon."*

---

## ⚡ Why We’re Here

Modern mobile operating systems tell the world that Bluetooth Low Energy privacy is solved by randomized MAC addresses. **Anyone who has looked at raw IQ samples or microsecond-level link-layer timing knows better.**

Across advertising intervals, deterministic scan request bursts, and proprietary payload anomalies, every device broadcasts an unmistakable **digital body language**. 

**AirTell** was built to banish the single-dongle blind spots of legacy sniffers. By orchestrating synchronized multi-dongle CC2652 radios (via [NCC Group's Sniffle](https://github.com/nccgroup/Sniffle)) and in-memory virtual radio buses, we pair active stimuli with passive observers to expose, measure, and audit BLE tracking surfaces and protocol-level privacy leakage.

GitHub Issues are reserved for kernel panics, firmware lockups, UART framing desyncs, and code bugs. 

**Discussions is where the craft lives.** This is our open RF salon—where exploit developers, RF hackers, reverse engineers, red-team operators, blue-team architects, and privacy governance leaders converge to push the boundary of link-layer analysis.

---

## 🧭 What Belongs Here (Pick Your Channel)

### 🎙️ 1. RF Tradecraft & Signal Forensics
*Dissecting the physics and protocols of the air interface.*
- Timing side-channels, inter-arrival jitter, and clock drift profiling.
- Reverse engineering proprietary manufacturer payloads (Apple Continuity, Google Fast Pair, SmartTags, bespoke IoT beacons).
- Sanitized `.pcap` teardowns, packet captures, and RF behavioral heuristics.

### 🛠️ 2. Hardware Rigs & Testbed Engineering
*From breadboards to anechoic chambers.*
- CC2652P/CC2652R1 / LaunchPad / Sonoff dongle configurations, firmware flashes, and UART bridge quirks.
- Custom SMA antenna mods, attenuators, faraday enclosures, and multi-radio physical topologies (Topology A, B, and C).
- Extending `VirtualRadioBus` and synthetic mock harnesses for headless CI testbeds.

### ⚔️ 3. Red Team Tradecraft & Stimulus Chains
*Turning passive observation into deterministic audit.*
- Active probing: crafted `SCAN_REQ` stimulus timing without breaking OPSEC or violating radio etiquette.
- Tracking persistence across MAC address rotation intervals.
- Chaining multi-dongle observers to pinpoint physical perimeter traversals.

### 🛡️ 4. Risk, Governance & Privacy Engineering
*Bridging hacker tradecraft with rigorous empirical privacy science.*
- Evaluating corporate device fleets against real-world tracking threats vs. paper compliance.
- Aligning AirTell telemetry with empirical privacy benchmarks and threat models.
- Threat modeling for executive protection, defense-in-depth, and air-gapped SCADA/sensitive facilities.

### 💡 5. Ideas, Feature Requests & Wild Experiments
- Dream features, protocol extensions, Wireshark dissector Lua scripts, Streamlit visualization enhancements, and machine learning models for fingerprint classification.

---

## 📜 Rules of the Airwaves

1. **Craft Above Ego:** Whether you just bought your first $10 CC2652 stick or you’ve spent 30 years doing SIGINT and defensive signal analysis, respect the curiosity. We teach, we mentor, we build.
2. **Responsible Disclosure & Ethics:** We operate under legitimate defensive, research, and authorized red-teaming mandates. Do not post operational target data, unsanitized surveillance captures containing sensitive personal identifiers, or actionable zero-day exploit payloads targeting critical infrastructure. 
3. **Signal over Noise:** Back your theories with captures, logic, logs, or physics. Speculation is welcome, but reproducible telemetry is gold.

---

## 🎯 Roll Call: Introduce Yourself Below

Drop a comment below and let the community know where you sit on the wire:

```yaml
Handle / Call Sign: "Your handle or alias"
Role / Craft: [Red Team / Exploit Dev / Firmware Eng / RF Enthusiast / GRC & Privacy / Student]
Current Hardware Rig: [e.g., 2x Sonoff Dongle Plus-E, TI CC2652RB LaunchPad, HackRF, Virtual Bus only]
Current Mission: [What are you looking to track, test, audit, or dissect with AirTell?]
```

The spectrum is unshielded, and the radios are listening. **Welcome to AirTell.**
```
