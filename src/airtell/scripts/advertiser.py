#!/usr/bin/env python3

# Written by Sultan Qasim Khan
# Copyright (c) 2020-2025, NCC Group plc
# Released as open source under GPLv3

import argparse
import sys

from sniffle.constants import BLE_ADV_AA
from sniffle.sniffle_hw import SniffleHW

# global variable to access hardware
hw = None


class AdvertiserSession:
    """Encapsulates Sniffle hardware BLE advertiser session."""

    def __init__(self, serport=None, baudrate=None) -> None:
        self.serport = serport
        self.baudrate = baudrate
        self.hw = None

    def setup(self, args) -> None:
        global hw
        self.hw = SniffleHW(args.serport, baudrate=args.baudrate)
        hw = self.hw

        # set the advertising channel (and return to ad-sniffing mode)
        self.hw.cmd_chan_aa_phy(37, BLE_ADV_AA, 0)

        # pause after sniffing
        self.hw.cmd_pause_done(True)

        # Accept/follow connections
        self.hw.cmd_follow(True)

        # turn off RSSI filter
        self.hw.cmd_rssi()

        # Turn off MAC filter
        self.hw.cmd_mac()

        # initiator doesn't care about this setting, it always accepts aux
        self.hw.cmd_auxadv(False)

        # advertiser needs a MAC address
        self.hw.random_addr()

        # advertise roughly every 200 ms
        self.hw.cmd_adv_interval(200)

        # transmit power of +5 dBm
        self.hw.cmd_tx_power(5)

        # reset preloaded encrypted connection interval changes
        self.hw.cmd_interval_preload()

        # zero timestamps and flush old packets
        self.hw.mark_and_flush()

        # advertising and scan response data
        advData = bytes([
            0x02, 0x01, 0x1A, 0x02, 0x0A, 0x0C, 0x11, 0x07,
            0x64, 0x14, 0xEA, 0xD7, 0x2F, 0xDB, 0xA3, 0xB0,
            0x59, 0x48, 0x16, 0xD4, 0x30, 0x82, 0xCB, 0x27,
            0x05, 0x03, 0x0A, 0x18, 0x0D, 0x18])
        devName = args.devName
        if devName is None:
            devName = b'NCC Goat'
        elif isinstance(devName, str):
            devName = devName.encode('utf-8')

        if len(devName) > 29:
            print(
                f"Warning: Device name exceeds 29 bytes ({len(devName)} bytes). "
                "Truncating to 29 bytes to fit in 31-byte legacy BLE advertisement limit.",
                file=sys.stderr,
            )
            devName = devName[:29]

        scanRspData = bytes([len(devName) + 1, 0x09]) + devName

        # now enter advertiser mode
        self.hw.cmd_advertise(advData, scanRspData)

    def run(self, args) -> None:
        self.setup(args)
        while True:
            msg = self.hw.recv_and_decode()
            if msg is not None:
                print(msg, end='\n\n')

    def reset(self) -> None:
        self.hw = None
        global hw
        hw = None


def reset_globals() -> None:
    """Reset module-level global hardware state."""
    global hw
    hw = None


def main():
    aparse = argparse.ArgumentParser(description="Advertiser test script for Sniffle BLE5 sniffer")
    aparse.add_argument("-s", "--serport", default=None, help="Sniffer serial port name")
    aparse.add_argument("-b", "--baudrate", default=None, help="Sniffer serial port baud rate")
    aparse.add_argument("-n", "-d", "--name", "--devname", "--devName", "--device-name",
                        dest="devName", default="NCC Goat", help="Device name to advertise")
    args = aparse.parse_args()
    args.name = args.devName
    args.devname = args.devName

    session = AdvertiserSession(args.serport, baudrate=args.baudrate)
    session.run(args)

if __name__ == "__main__":
    main()
