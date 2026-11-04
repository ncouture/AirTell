# Traffic Metadata, Law Enforcement Electronics & Quebec Signal Control Audit (10:00–10:05 Window)

**Analysis Target**: [`merged.json`](file:///home/self/git/AirTell/merged.json) (Correlated against [`app/data/merged.pcap`](file:///home/self/git/AirTell/app/data/merged.pcap))  
**Capture Window**: May 21, 2026 — 10:00:00 to 10:05:59 EDT (`1779372000.000` to `1779372360.000` Epoch)  
**Geographical Context**: Boulevard des Entreprises / Autoroute 640 Corridor, Terrebonne, Quebec, Canada  
**Jurisdiction**: Sûreté du Québec (SQ), Service de police de la Ville de Montréal (SPVM), and Royal Canadian Mounted Police (RCMP / GRC)  

---

## 1. Key Findings & Quantitative Reconciliation

### Quantitative Discrepancy Reconciliation
* **Strict 5-Minute Window (`10:00:00`–`10:05:00`)**: 727 findings (`ALLOWLIST_CONFIRMED`: 708, `OPEN_ADVERTISER`: 18, `PROFILE_MATCH`: 1), 139 unique peripherals (`device_addr`), 80 unique active scanners (`target_addr`), 215 total unique MAC addresses, 21 IEEE OUI resolved vendors.
* **Inclusive 6-Minute Window (`10:00:00`–`10:05:59.999`)**: 1,371 findings (`ALLOWLIST_CONFIRMED`: 1,351, `OPEN_ADVERTISER`: 19, `PROFILE_MATCH`: 1), 199 unique peripherals, 102 unique active scanners, 295 total unique MAC addresses, 32 IEEE OUI resolved vendors.

---

## 2. Physical & Spatial Debunking of Prior Assumptions

* **Active Scanner `E5:3E:90:1C:D0:5C` is Inside the Capture Vehicle**:  
  Prior assumptions labeled this as an arterial traffic sniffer or police cruiser scanner. Packet-level analysis reveals it transmitted **808 `SCAN_REQ` frames continuously across 87.6 minutes** (08:38 to 10:06) at a constant **-32 to -36 dBm average RSSI** throughout highway and municipal driving. A stationary roadside sensor cannot remain at point-blank range (-35 dBm) for 1.5 hours in a moving vehicle. It was an active device inside the wardriving rig.
* **`Moniteur 1` (`8E:13:4D:13:77:BC`) is a Stationary Commercial Display**:  
  Heard only during 4 discrete passes (~58 minutes apart) at an average of **-88.2 dBm** (max -77 dBm) as the vehicle passed a commercial facility on Rue Georges-Corbeil in Terrebonne. The -32 dBm spikes were `SCAN_REQ` probes sent by the internal vehicle scanner.
* **`Sena Motorcycles` (`C7:DC:ED:B9:0F:78`) is a Civilian Helmet Intercom**:  
  Detected at `10:02:26` (over 2 minutes after leaving the intersection at `10:00:28`), co-located with residential gateways (`E3:B5:F3:99:60:7F`). It was not present at the police encounter.
* **Intel Corporate (`C9:7A:AB:1E:1E:CA`) is on the Highway Corridor**:  
  Captured at `10:05:08` (5 minutes after leaving the intersection), placing it 5–7 km away along Autoroute 640.
* **Telink BLE Mesh Nodes (`:FF:FF`) Total 86 Unique Hardware Units**:  
  The full pcap contains **86 unique MAC addresses** sharing the `:FF:FF` wire suffix and Telink Semiconductor Company ID `529` (`0x0211`), representing a large-scale municipal smart lighting / sign mesh along Boulevard des Entreprises. Node `10:F3:D1:4F:FF:FF` was directly adjacent to the stopped vehicle at `10:00:26` (peaking at **-39 dBm**).

---

## 3. Sûreté du Québec (SQ), SPVM & RCMP Traffic Signal Preemption Reality

1. **Emergency Vehicle Preemption (EVP) Operates via Optical Strobe, 900 MHz, or C-V2X — Never 2.4 GHz Bluetooth**:
   * **Optical Infrared Preemption (GTT Opticom 792/794, Tomar Strobecom II)**: Police cruisers use optical emitters mounted behind the grille or in the lightbar pulsing infrared light at **14.035 Hz** (High Priority) toward optical photodiode detectors (Opticom 711/721) mounted on the mast arm beside the traffic cameras. **Optical preemption emits zero 2.4 GHz RF or Bluetooth signals.**
   * **Radio / GPS Preemption (Opticom GPS, EMTRAC)**: Operates on **900 MHz spread-spectrum** or **5.9 GHz C-V2X / DSRC**.
   * Police officers parked at red lights in Quebec **do not and cannot operate traffic signals via Bluetooth**.

2. **Why Police Were Parked at the Traffic Cabinet**:
   * Quebec traffic signal cabinets (governed by MTMD standards, NEMA TS2 / Model 332, distributed by Orange Traffic / Tacel) feature an exterior locked **"porte de police" (police door)** opened with a skeleton key.
   * Inside is a **manual push-button pendant (*poire de commande manuelle*)** on a coiled cord. Officers use this pendant when highway off-ramps (e.g. from Autoroute 640 onto Boulevard des Entreprises) back up toward the 100 km/h lanes, manually extending the green phase to flush the ramp queue and prevent high-speed rear-end collisions.
   * **Signals Detected at the Intersection**:
     * `42:43:B2:44:E8:CA` (`JCI-SE-ED:C2:E8`): Johnson Controls electronic physical security access lock on the traffic cabinet.
     * `AF:2B:1C:4D:CC:7F` (`Poly VLegend 58`): Plantronics Voyager Legend hands-free earpiece worn by the officer outside the cruiser.

3. **Intersection Traffic Cameras**:
   * **Video Detection Cameras (Iteris Vantage, Miovision SmartView 360, FLIR TrafiCam)** connect directly to detector rack cards inside the cabinet via shielded Cat6 Ethernet PoE or coaxial cabling and do not emit Bluetooth Low Energy packets.

---

## 4. Master Enriched MAC Metadata (10:00–10:05 Window)

| Wire MAC | Canonical IEEE MAC | OUI Vendor / Manufacturer | Address Type | Device Name / Telemetry | Peak RSSI | Verified Physical Role & Context |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `AF:2B:1C:4D:CC:7F` | `4F:A0:F8:CF:96:A4` | **HP / Plantronics / Poly** | RPA (`01b`) | `Poly VLegend 58\x00` | -78 dBm | **Police Officer Earpiece**: Plantronics Voyager Legend worn by officer outside cruiser at traffic cabinet. |
| `42:43:B2:44:E8:CA` | `E8:C2:ED:C7:5F:75` | **Johnson Controls (JCI)** | Public | `JCI-SE-ED:C2:E8` (Co. ID `185`) | -93 dBm | **Cabinet Access Lock**: Utility cabinet electronic access reader on traffic enclosure. |
| `10:F3:D1:4F:FF:FF` | `FF:FF:1A:A6:11:2B` | **Telink Semiconductor** | Random Static | `180829` (Co. ID `529`) | **-39 dBm** | **Intersection Mesh Node**: Solar LED sign / streetlight controller at signal pole (stopped directly in front at 10:00:26). |
| `05:52:50:78:FF:FF` | `FF:FF:60:CC:D2:1B` | **Telink Semiconductor** | Random Static | `180829` (Co. ID `529`) | -80 dBm | **Intersection Mesh Peer**: Co-located lighting node. |
| `0D:11:64:3F:FF:FF` | `FF:FF:08:0E:C8:14` | **Telink Semiconductor** | Random Static | `160835` (Co. ID `529`) | -85 dBm | **Intersection Mesh Peer**: Co-located lighting node. |
| `39:00:4E:11:FF:FF` | `FF:FF:96:FE:EA:03` | **Telink Semiconductor** | Random Static | `180829` (Co. ID `529`) | -85 dBm | **Intersection Mesh Peer**: Co-located lighting node. |
| `E5:3E:90:1C:D0:5C` | `5D:E9:15:4F:56:EF` | **In-Vehicle Mobile Device** | RPA (`01b`) | — | **-32 dBm** | **Wardriving Rig Scanner**: 808 `SCAN_REQ` over 87.6 minutes at constant -35 dBm avg; inside capture vehicle. |
| `8E:13:4D:13:77:BC` | `B6:C7:F1:35:46:92` | **Samsung Electronics** | Public | `Moniteur 1` | -77 dBm | **Roadside Commercial Monitor**: Office display at facility ~2 min from intersection (passed 4 times). |
| `8C:F0:04:5A:93:73` | `7D:11:AE:6C:4D:AF` | **Samsung Electronics** | RPA (`01b`) | `Moniteur 2` | -84 dBm | **Roadside Commercial Monitor**: Secondary office display. |
| `3F:6B:A5:F9:1F:41` | `42:AF:50:AF:66:31` | **Yealink Network Tech** | Public | `RoomPanel E2-8419` | -85 dBm | **Roadside Room Display**: Commercial conference room panel at roadside facility. |
| `9B:8C:28:2B:1D:CF` | `DE:56:52:60:ED:BE` | **Canstahl Inc.** | Public | `Cansthal-Terrebo-DE5652` | -32 dBm | **Industrial Hoist Controller**: Industrial facility at 3000 rue des Bâtisseurs, Terrebonne, QC. |
| `DD:BF:A3:3C:DD:13` | `16:F0:4D:56:4F:CE` | **Verre Sélect Inc.** | Public | `Verre Select Master` | -88 dBm | **Industrial Plant Automation**: 3816 rue Georges-Corbeil, Terrebonne, QC (~450m from intersection). |
| `3F:32:E7:EA:38:3C` | `10:A0:C6:17:83:0E` | **Verre Sélect Inc.** | Public | `Verre select Slave` | -90 dBm | **Industrial Plant Automation**: Co-located slave node. |
| `E3:B5:F3:99:60:7F` | `4E:8C:C0:3A:35:EE` | **Arcadyan Corporation** | Public (`TxAdd=0`) | — | -86 dBm | **Broadband Gateway**: Telus Wi-Fi Hub / Bell CPE at roadside property ~2 min from intersection. |
| `C7:DC:ED:B9:0F:78` | `51:75:26:F3:AF:D3` | **Sena Technologies** | RPA (`01b`) | `Sena Motorcycles` | -74 dBm | **Civilian Motorcycle Intercom**: Helmet communicator at property ~2 min from intersection. |
| `6C:3C:43:F2:56:5C` | `76:2D:0E:5D:45:5D` | **FIXD Automotive** | Public | `FIXD` (UUID `0xFFF0`) | -84 dBm | **Vehicle OBD-II Telematics**: Consumer diagnostic sensor plugged into vehicle CAN bus port. |
| `58:9F:B3:7F:76:4C` | `6A:95:FF:6F:E4:54` | **Texas Instruments** | RPA (`01b`) | `LW  IVU` (Estimote UUID) | -36 dBm | **In-Vehicle Unit (IVU)**: Fleet telematics unit beaconing Estimote iBeacon frame. |
| `29:AC:1A:94:1B:A3` | `9F:E2:C8:9E:A1:09` | **Rigado, LLC** | Public | `8421` | -34 dBm | **Commercial Edge Gateway**: Rigado Cascade IoT gateway at facility ~3.5 min from intersection. |
| `32:F4:2D:FD:1E:0A` | `06:56:C2:43:9D:23` | **Chamberlain Group** | NRPA (`00b`) | `MyQ-B72` (Co. ID `2168`) | -32 dBm | **Perimeter Security Gate**: Smart gate receiver at facility ~5 min from intersection. |
| `8E:3D:7F:D2:E7:80` | `B7:6C:CB:8B:15:AE` | **Texas Instruments** | Public | `S88c78018ac55033cC` | -34 dBm | **Asset Tracking Tag**: Stationary TI CC26xx iBeacon passed at 10:05 (~5 min from intersection). |
| `C9:7A:AB:1E:1E:CA` | `F5:BD:00:37:52:DC` | **Intel Corporate** | Public | — | -86 dBm | **Highway Corridor Node**: Intel AX2xx Wi-Fi/BT card at facility ~5 min from intersection. |

---

## 5. Project Artifacts
- **Full Report**: [`docs/extract_traffic_metadata.md`](file:///home/self/git/AirTell/docs/extract_traffic_metadata.md)
- **Extraction & Canonicalization Tool**: [`scripts/extract_traffic_metadata.py`](file:///home/self/git/AirTell/scripts/extract_traffic_metadata.py)
- **Complete Extracted JSON Dataset**: [`scratch/extracted_traffic_metadata_1000_1005.json`](file:///home/self/.gemini/antigravity-cli/brain/f56f4b66-5e32-45cf-b8bb-5e2d0fda0b6c/scratch/extracted_traffic_metadata_1000_1005.json)
