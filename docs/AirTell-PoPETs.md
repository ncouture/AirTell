

# Overview of Notebook Context

The notebook ****"AirTell Intel - All 2026 PoPETs + 2018 to 2026 Bluetooth related PDFs"**** contains 259 total sources, 2 saved notes, and 2 Studio artifacts. Below is a detailed, structured categorization of all data sources, saved notes, paper titles, and workspace artifacts within this notebook that directly include or focus on the word ****"Bluetooth"****.


# 1. Notebook Container & Saved Notes


## Notebook Title

-   **Title:** `AirTell Intel - All 2026 PoPETs + 2018 to 2026 Bluetooth related PDFs`
-   **Description:** Explicitly designates this collection as a repository for Bluetooth-related proceedings and research PDFs spanning 2018 through 2026.


## Saved Notes

-   **Note 1:** `Bluetooth Protocol Security`
    -   **Content:** Contains a systematized summary of Bluetooth and wireless radio protocol topics from PoPETs & NDSS proceedings (2025–2026), focusing on crowdsourced offline finding networks, side-channels in exclusive-use communication, physical-layer fingerprinting, and OS-level BLE leakages.
-   **Note 2:** `Wireless Protocol Security`
    -   **Content:** Covers related Bluetooth Low Energy (BLE) and Wi-Fi protocol security research.


# 2. PDF Papers and Document Sources Containing "Bluetooth"

While PDF sources are indexed by their symposium URL filenames in the notebook list, their paper titles, keywords, and core metadata directly include the word ****"Bluetooth"****:


## 1. Tracking Anonymized Bluetooth Devices

-   **Source URL:** `https://petsymposium.org/popets/2019/popets-2019-0036.pdf`
-   **Document Title:** **Tracking Anonymized Bluetooth Devices**
-   **Keywords:** `Bluetooth, tracking, privacy, information leakage, side-channels, correlation attacks, traffic analysis`
-   **Core Focus:** Evaluates physical-layer and link-layer tracking vectors against Bluetooth Low Energy (BLE) address randomization mechanisms across Windows, iOS, macOS, and Android platforms.


## 2. Review of Apple's Bluetooth Low Energy Continuity Protocol

-   **Source URL:** `https://petsymposium.org/popets/2019/popets-2019-0057.pdf`
-   **Document Title:** **Handoff All Your Privacy – A Review of Apple’s Bluetooth Low Energy Continuity Protocol**
-   **Keywords:** `BLE, Bluetooth, privacy, tracking`
-   **Core Focus:** Reverse-engineers unencrypted Apple Continuity protocol message types broadcast over Bluetooth Low Energy, demonstrating device fingerprinting and tracking across space and time.


## 3. Leaks in Apple Bluetooth-Low-Energy Continuity Protocols

-   **Source URL:** `https://petsymposium.org/popets/2020/popets-2020-0003.pdf`
-   **Document Title:** **Discontinued Privacy: Personal Data Leaks in Apple Bluetooth-Low-Energy Continuity Protocols**
-   **Keywords:** `Bluetooth Low Energy; Privacy; Tracking; Activity inference; Inventory attacks`
-   **Core Focus:** Analyzes privacy vulnerabilities in Apple BLE Continuity advertisement packets across 1+ billion active devices.


## 4. Security and Privacy of Apple's Crowd-Sourced Bluetooth Location Tracking System

-   **Source URL:** `https://petsymposium.org/popets/2021/popets-2021-0045.pdf`
-   **Document Title:** **Who Can Find My Devices? Security and Privacy of Apple’s Crowd-Sourced Bluetooth Location Tracking System**
-   **Keywords:** `Apple, Bluetooth, location privacy, reverse engineering, tracking tags, user identification`
-   **Core Focus:** Provides a security analysis and reverse-engineering of Apple's Find My offline finding network and custom Bluetooth tracking beacons.


## 5. Beacon SDK Ecosystem and Wireless Scanning

-   **Source URL:** `https://petsymposium.org/popets/2025/popets-2025-0103.pdf`
-   **Document Title:** **Your Signal, Their Data: Uncovering the Beacon SDK Ecosystem**
-   **Core Focus:** Documents third-party mobile SDKs that secretly scan for Bluetooth Low Energy (BLE) beacons (such as iBeacon, AltBeacon, and Eddystone) to track user location and build behavioral profiles.


## 6. Apple Watch Bluetooth Protocol Reverse Engineering

-   **Source URL:** `https://petsymposium.org/popets/2025/popets-2025-0121.pdf`
-   **Document Title:** **WatchWitch: Reverse Engineering Apple Watch Communication**
-   **Core Focus:** Analyzes the Network Relay Link Protocol (NRLP) and Magnet protocol stack used for Bluetooth and Wi-Fi communication between iPhones and Apple Watches.


## 7. Systematization of Offline Finding Networks (BLE)

-   **Source URL:** `https://petsymposium.org/popets/2026/popets-2026-0113.pdf`
-   **Document Title:** **SoK: Offline Finding Protocols for Lightweight Location Tracking**
-   **Core Focus:** Systematizes Bluetooth Low Energy (BLE) offline finding protocols across Apple Find My, Google Find Hub, Samsung SmartThings Find, and Tile.


## 8. BLE & Wi-Fi Wireless Protocol Security Analysis

-   **Source URL:** `https://www.ndss-symposium.org/wp-content/uploads/2025-703-paper.pdf`
-   **Core Focus:** Evaluates exclusive-use wireless communication, side-channel vulnerabilities, and allowlist tracking across Bluetooth Low Energy (BLE) and Wi-Fi networks.


# 3. Generated Code & Workspace Artifacts

The following workspace artifacts were developed specifically to parse and control live Bluetooth packet captures using Sniffle hardware dongles:

1.  `sniffle_exclusive_use_commands.org`
    -   **Description:** A curated suite of 50 `sniffle_extcap.py` Wireshark plugin commands for analyzing exclusive-use Bluetooth Low Energy (BLE) link-layer protocols.
2.  `tshark_stream_runner.py`
    -   **Description:** An asynchronous Python backend module that executes `tshark` subprocesses wrapping the Sniffle extcap plugin to stream live Bluetooth JSON data to a Streamlit web application.

💡 Would you like to generate a detailed comparative report or mind map summarizing all Bluetooth privacy vulnerabilities identified across these papers?

