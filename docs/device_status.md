# Sniffle Device Status Detection & LSOF Validation

## Overview

In operational testbeds and multi-dongle environments, determining whether a physical serial device (such as `/dev/ttyUSB0` or `/dev/ttyUSB1`) is actively locked by a capture process, sniffer daemon, or relay script is critical to prevent device contention, I/O collisions, and port lockups.

Within the **Bluetooth-Sniffle** framework, device status can be determined **at all times** using standard Linux system commands and `airtell.device.serial_port` helpers.

---

## System Command Validation (`lsof`)

Device utilization is determined by querying open file descriptors on the device node using `lsof`:

```bash
lsof /dev/ttyUSB0
lsof /dev/ttyUSB1
```

### Return Code Contract

| Return Code | Meaning | Hardware Status | Status Label |
| :---: | :--- | :--- | :--- |
| **`0`** | Process holds an open file descriptor on the device node. | **Device is OPEN and BEING USED** | `IN USE` |
| **Non-Zero (`1`, `2`, `127`)** | No active process has the device open, or device node is not present. | **Device is NOT OPEN and NOT IN USE** | `IDLE` |

### Terminal Verification Examples

#### 1. Device Idle (Not in Use)
```bash
$ lsof /dev/ttyUSB0
$ echo $?
1
```
*Because the exit code is non-zero (1), the device is free, idle, and safe to allocate.*

#### 2. Device Busy (Actively Captured by Sniffer)
```bash
$ lsof /dev/ttyUSB0
COMMAND     PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
python3   12345 analyst 3u   CHR  188,0      0t0  642 /dev/ttyUSB0

$ echo $?
0
```
*Because the exit code is 0, the device is currently opened by PID 12345 (`python3`). Attempting to start another capture on this port will fail with `serial.serialutil.SerialException: Device or resource busy`.*

---

## Framework Implementation

The device status detection logic is implemented in `airtell.device.serial_port`:

### Python API

```python
from airtell.device.serial_port import (
    check_device_usage,
    get_device_status,
    get_sniffle_devices_status,
)

# 1. Boolean check (True if in use, False if idle)
is_busy = check_device_usage("/dev/ttyUSB0")

# 2. Detailed status dictionary
status = get_device_status("/dev/ttyUSB0")
# Returns:
# {
#     "device": "/dev/ttyUSB0",
#     "in_use": True,
#     "status": "IN USE",
#     "label": "/dev/ttyUSB0: IN USE"
# }

# 3. Dual-device topology batch status
statuses = get_sniffle_devices_status(["/dev/ttyUSB0", "/dev/ttyUSB1"])
```

### Implementation Details

```python
def check_device_usage(device_path: str = "/dev/ttyUSB0") -> bool:
    """Determine if a serial device is currently open and in use via lsof.

    Executes system command: `lsof <device_path>`.
    If returncode is 0, the device is open and being used.
    If returncode is non-zero, it is not being used / not open.
    """
    try:
        res = subprocess.run(
            ["lsof", device_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2.0,
        )
        return res.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError, PermissionError, OSError):
        return False
```

---

## Diagnostic Checklist

If `check_device_usage` reports unexpected results:
1. **Ensure `lsof` is installed:**
   ```bash
   which lsof || sudo apt-get install -y lsof
   ```
2. **Check user permissions:** Ensure your user account is in the `dialout` group to inspect device nodes:
   ```bash
   groups | grep dialout || sudo usermod -aG dialout $USER
   ```
3. **Inspect zombie or orphan processes:** If a device remains `IN USE` after terminating a script:
   ```bash
   lsof /dev/ttyUSB0
   kill -9 <PID>
   ```
