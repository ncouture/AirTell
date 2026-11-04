#!/usr/bin/env python3

# Written by Sultan Qasim Khan
# Copyright (c) 2020-2025, NCC Group plc
# Released as open source under GPLv3

import argparse
import sys
from binascii import unhexlify

from sniffle.constants import BLE_ADV_AA
from sniffle.packet_decoder import (
    AdvaMessage,
    AdvDirectIndMessage,
    AdvExtIndMessage,
    ScanRspMessage,
    str_mac,
)
from sniffle.sniffle_hw import (
    DebugMessage,
    PacketMessage,
    SnifferState,
    SniffleHW,
    StateMessage,
)

# global variable to access hardware
hw = None
_aa = 0
msg_ctr = 0


class InitiatorSession:
    """Encapsulates Sniffle connection initiator test session."""

    def __init__(self, serport=None, baudrate=None) -> None:
        self.serport = serport
        self.baudrate = baudrate
        self.hw = None
        self._aa = 0
        self.msg_ctr = 0

    def setup(self, args) -> bool:
        global hw
        self.hw = SniffleHW(args.serport, baudrate=args.baudrate)
        hw = self.hw

        targ_specs = bool(args.mac) + bool(args.irk) + bool(args.string)
        if targ_specs < 1:
            print("Must specify target MAC address, IRK, or advertisement string", file=sys.stderr)
            return False
        elif targ_specs > 1:
            print("IRK, MAC, and advertisement string filters are mutually exclusive!", file=sys.stderr)
            return False

        if args.public and args.irk:
            print("IRK only works on RPAs, not public addresses!", file=sys.stderr)
            return False
        elif args.public and args.string:
            print("Can't specify string search target MAC publicness", file=sys.stderr)
            return False

        # set the advertising channel (and return to ad-sniffing mode)
        self.hw.cmd_chan_aa_phy(args.advchan, BLE_ADV_AA, 2 if args.longrange else 0)

        # pause after sniffing
        self.hw.cmd_pause_done(True)

        # capture advertisements only
        self.hw.cmd_follow(False)

        # turn off RSSI filter
        self.hw.cmd_rssi()

        # initiator doesn't care about this setting, it always accepts aux
        self.hw.cmd_auxadv(True)

        if args.mac:
            try:
                mac_bytes = [int(h, 16) for h in reversed(args.mac.split(":"))]
                if len(mac_bytes) != 6:
                    raise ValueError("Wrong length!")
            except (ValueError, TypeError):
                print("MAC must be 6 colon-separated hex bytes", file=sys.stderr)
                return False
            self.hw.cmd_mac(mac_bytes, False)
        elif args.irk:
            mac_bytes = self.get_mac_from_irk(unhexlify(args.irk))
        else:
            search_str = args.string.encode('latin-1').decode('unicode_escape').encode('latin-1')
            mac_bytes, args.public = self.get_mac_from_string(search_str)
            self.hw.cmd_mac(mac_bytes, False)

        # initiator needs a MAC address
        self.hw.random_addr()

        # transmit power of +5 dBm
        self.hw.cmd_tx_power(5)

        # reset preloaded encrypted connection interval changes
        self.hw.cmd_interval_preload()

        # zero timestamps and flush old packets
        self.hw.mark_and_flush()

        # now enter initiator mode
        global _aa
        self._aa = self.hw.initiate_conn(mac_bytes, not args.public)
        _aa = self._aa
        return True

    def get_mac_from_irk(self, irk):
        self.hw.cmd_irk(irk, False)
        self.hw.mark_and_flush()
        print("Waiting for advertisement with suitable RPA...")
        while True:
            msg = self.hw.recv_and_decode()
            if isinstance(msg, (AdvaMessage, AdvDirectIndMessage, AdvExtIndMessage)) and msg.AdvA is not None:
                print("Found target MAC: %s" % str_mac(msg.AdvA))
                return msg.AdvA

    def get_mac_from_string(self, s):
        self.hw.cmd_mac()
        self.hw.cmd_scan()
        self.hw.mark_and_flush()
        print("Waiting for advertisement containing specified string...")
        while True:
            msg = self.hw.recv_and_decode()
            if isinstance(msg, (AdvaMessage, AdvDirectIndMessage, ScanRspMessage, AdvExtIndMessage)) and msg.AdvA is not None:
                if s in msg.body:
                    print("Found target MAC: %s" % str_mac(msg.AdvA))
                    return msg.AdvA, not msg.TxAdd

    def print_message(self, msg) -> None:
        if isinstance(msg, PacketMessage):
            self.print_packet(msg)
        elif isinstance(msg, DebugMessage):
            print(msg)
        elif isinstance(msg, StateMessage):
            print(msg)
            if msg.new_state == SnifferState.CENTRAL:
                self.hw.decoder_state.cur_aa = self._aa
        print()

    def print_packet(self, dpkt) -> None:
        print(dpkt)

        # do a ping every fourth message
        MCMASK = 3
        if (self.msg_ctr & MCMASK) == MCMASK:
            self.hw.cmd_transmit(3, b'\x12')  # LL_PING_REQ
        self.msg_ctr += 1

        global msg_ctr
        msg_ctr = self.msg_ctr

        if self.msg_ctr == 0x40:
            self.hw.cmd_transmit(3, b'\x00\x04\x08\x00\x30\x00\x03\x00\x80\x00\x80\x00')
            print("sent change!")

    def run(self, args) -> None:
        if not self.setup(args):
            return
        while True:
            msg = self.hw.recv_and_decode()
            self.print_message(msg)

    def reset(self) -> None:
        self.hw = None
        self._aa = 0
        self.msg_ctr = 0
        reset_globals()


def reset_globals() -> None:
    """Reset module-level global hardware state."""
    global hw, _aa, msg_ctr
    hw = None
    _aa = 0
    msg_ctr = 0


def main():
    aparse = argparse.ArgumentParser(description="Connection initiator test script for Sniffle BLE5 sniffer")
    aparse.add_argument("-s", "--serport", default=None, help="Sniffer serial port name")
    aparse.add_argument("-b", "--baudrate", default=None, help="Sniffer serial port baud rate")
    aparse.add_argument("-c", "--advchan", default=37, choices=[37, 38, 39], type=int,
            help="Advertising channel to listen on")
    aparse.add_argument("-m", "--mac", default=None, help="Specify target MAC address")
    aparse.add_argument("-i", "--irk", default=None, help="Specify target IRK")
    aparse.add_argument("-S", "--string", default=None,
            help="Specify target by advertisement search string")
    aparse.add_argument("-l", "--longrange", action="store_const", default=False, const=True,
            help="Use long range (coded) PHY for primary advertising")
    aparse.add_argument("-P", "--public", action="store_const", default=False, const=True,
            help="Supplied MAC address is public")
    args = aparse.parse_args()

    session = InitiatorSession(args.serport, baudrate=args.baudrate)
    session.run(args)

def get_mac_from_irk(irk):
    hw.cmd_irk(irk, False)
    hw.mark_and_flush()
    print("Waiting for advertisement with suitable RPA...")
    while True:
        msg = hw.recv_and_decode()
        if isinstance(msg, (AdvaMessage, AdvDirectIndMessage,
                            AdvExtIndMessage)) and msg.AdvA is not None:
            print("Found target MAC: %s" % str_mac(msg.AdvA))
            return msg.AdvA

def get_mac_from_string(s):
    hw.cmd_mac()
    hw.cmd_scan()
    hw.mark_and_flush()
    print("Waiting for advertisement containing specified string...")
    while True:
        msg = hw.recv_and_decode()
        if isinstance(msg, (AdvaMessage, AdvDirectIndMessage, ScanRspMessage,
                            AdvExtIndMessage)) and msg.AdvA is not None:
            if s in msg.body:
                print("Found target MAC: %s" % str_mac(msg.AdvA))
                return msg.AdvA, not msg.TxAdd

def print_message(msg):
    if isinstance(msg, PacketMessage):
        print_packet(msg)
    elif isinstance(msg, DebugMessage):
        print(msg)
    elif isinstance(msg, StateMessage):
        print(msg)
        if msg.new_state == SnifferState.CENTRAL:
            hw.decoder_state.cur_aa = _aa
    print()

msg_ctr = 0
def print_packet(dpkt):
    print(dpkt)

    # do a ping every fourth message
    global msg_ctr
    MCMASK = 3
    if (msg_ctr & MCMASK) == MCMASK:
        hw.cmd_transmit(3, b'\x12') # LL_PING_REQ
    msg_ctr += 1

    # also test sending LL_CONNECTION_UPDATE_IND
    if msg_ctr == 0x40:
        # WinSize = 0x04
        # WinOffset = 0x0008
        # Interval = 0x0030
        # Latency = 0x0003
        # Timeout = 0x0080
        # Instant = 0x0080
        hw.cmd_transmit(3, b'\x00\x04\x08\x00\x30\x00\x03\x00\x80\x00\x80\x00')
        print("sent change!")

if __name__ == "__main__":
    main()
