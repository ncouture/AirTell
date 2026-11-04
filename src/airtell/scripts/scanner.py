#!/usr/bin/env python3

# Written by Sultan Qasim Khan
# Copyright (c) 2020-2025, NCC Group plc
# Released as open source under GPLv3

import argparse
import signal

from sniffle.advdata.decoder import decode_adv_data
from sniffle.errors import SourceDone
from sniffle.packet_decoder import (
    AdvaMessage,
    AdvDirectIndMessage,
    AdvertMessage,
    AdvExtIndMessage,
    AuxScanRspMessage,
    ScanRspMessage,
    str_mac2,
)
from sniffle.pcap import PcapBleWriter
from sniffle.sniffle_hw import (
    DebugMessage,
    PacketMessage,
    SnifferMode,
    make_sniffle_hw,
)

# global variables
hw = None
pcwriter = None
advertisers = {}
done_scan = False


class ScannerSession:
    """Encapsulates BLE scanning hardware, captured advertisers, and PCAP output."""

    def __init__(self, serport=None, baudrate=None) -> None:
        self.serport = serport
        self.baudrate = baudrate
        self.hw = None
        self.pcwriter = None
        self.advertisers: dict[str, Advertiser] = {}
        self.done_scan: bool = False

    def sigint_handler(self, sig, frame) -> None:
        self.done_scan = True
        global done_scan
        done_scan = True
        if self.hw:
            self.hw.cancel_recv()

    def handle_packet(self, dpkt, decode_ad: bool = False) -> None:
        if not isinstance(dpkt, AdvertMessage):
            print("Unexpected packet")
            print(dpkt)
            print()
            return

        if self.pcwriter:
            self.pcwriter.write_packet_message(dpkt)

        if isinstance(dpkt, (AdvaMessage, AdvDirectIndMessage)) or (
            isinstance(dpkt, AdvExtIndMessage) and dpkt.AdvA is not None
        ):
            adva = str_mac2(dpkt.AdvA, dpkt.TxAdd)

            if adva not in self.advertisers:
                self.advertisers[adva] = Advertiser()
                print("Found %s..." % adva)

            self.advertisers[adva].add_hit(dpkt.rssi)

            if isinstance(dpkt, (ScanRspMessage, AuxScanRspMessage)):
                self.advertisers[adva].scan_rsp = dpkt
            else:
                self.advertisers[adva].adv = dpkt

            global advertisers
            advertisers = self.advertisers

    def run(self, args) -> None:
        self.advertisers.clear()
        self.done_scan = False

        global hw, pcwriter, advertisers, done_scan
        advertisers = self.advertisers
        done_scan = False

        self.hw = make_sniffle_hw(args.serport, baudrate=args.baudrate)
        hw = self.hw

        self.hw.setup_sniffer(
            mode=SnifferMode.ACTIVE_SCAN,
            chan=args.advchan,
            ext_adv=True,
            coded_phy=args.longrange,
            rssi_min=args.rssi,
        )
        self.hw.mark_and_flush()

        if args.output is not None:
            self.pcwriter = PcapBleWriter(args.output)
            pcwriter = self.pcwriter

        signal.signal(signal.SIGINT, self.sigint_handler)
        print("Starting scanner. Press CTRL-C to stop scanning and show results.")

        try:
            while not self.done_scan:
                try:
                    msg = self.hw.recv_and_decode()
                except SourceDone:
                    break
                if isinstance(msg, DebugMessage):
                    print(msg)
                elif isinstance(msg, PacketMessage):
                    self.handle_packet(msg, args.decode)
        finally:
            self.close()

        if self.hw:
            self.hw.setup_sniffer()

        self.print_results(args.decode)

    def print_results(self, decode_ad: bool = False) -> None:
        print("\n\nScan Results:")
        for a in sorted(self.advertisers.keys(), key=lambda k: self.advertisers[k].rssi_avg, reverse=True):
            print("=" * 80)
            print("AdvA: %s Avg/Min/Max RSSI: %.1f/%i/%i Hits: %i" % (
                a, self.advertisers[a].rssi_avg, self.advertisers[a].rssi_min, self.advertisers[a].rssi_max,
                self.advertisers[a].hits))
            if self.advertisers[a].adv:
                print("\nAdvertisement:")
                print(self.advertisers[a].adv.str_header())
                print(self.advertisers[a].adv.str_decode())
                if decode_ad:
                    for ad in decode_adv_data(self.advertisers[a].adv.adv_data):
                        print(ad)
                print(self.advertisers[a].adv.hexdump())
            else:
                print("\nAdvertisement: None")
            if self.advertisers[a].scan_rsp:
                print("\nScan Response:")
                print(self.advertisers[a].scan_rsp.str_header())
                print(self.advertisers[a].scan_rsp.str_decode())
                if decode_ad:
                    for ad in decode_adv_data(self.advertisers[a].scan_rsp.adv_data):
                        print(ad)
                print(self.advertisers[a].scan_rsp.hexdump())
            else:
                print("\nScan Response: None")
            print("=" * 80, end="\n\n")

    def close(self) -> None:
        if self.pcwriter is not None:
            self.pcwriter.close()
            self.pcwriter = None
        global pcwriter
        pcwriter = None

    def reset(self) -> None:
        self.close()
        self.hw = None
        self.advertisers.clear()
        self.done_scan = False
        reset_globals()


def reset_globals() -> None:
    """Reset module-level global hardware and scanner state."""
    global hw, pcwriter, advertisers, done_scan
    if pcwriter is not None:
        pcwriter.close()
    hw = None
    pcwriter = None
    advertisers = {}
    done_scan = False


def sigint_handler(sig, frame):
    global done_scan
    done_scan = True
    if hw:
        hw.cancel_recv()


def main():
    aparse = argparse.ArgumentParser(description="Scanner utility for Sniffle BLE5 sniffer")
    aparse.add_argument("-s", "--serport", default=None, help="Sniffer serial port name")
    aparse.add_argument("-b", "--baudrate", default=None, help="Sniffer serial port baud rate")
    aparse.add_argument("-c", "--advchan", default=37, choices=[37, 38, 39], type=int,
            help="Advertising channel to listen on")
    aparse.add_argument("-r", "--rssi", default=-128, type=int,
            help="Filter packets by minimum RSSI")
    aparse.add_argument("-l", "--longrange", action="store_true",
            help="Use long range (coded) PHY for primary advertising")
    aparse.add_argument("-d", "--decode", action="store_true",
            help="Decode advertising data")
    aparse.add_argument("-o", "--output", default=None, help="PCAP output file name")
    args = aparse.parse_args()

    session = ScannerSession(args.serport, baudrate=args.baudrate)
    session.run(args)

def handle_packet(dpkt):
    # Ignore non-advertisements (shouldn't get any)
    if not isinstance(dpkt, AdvertMessage):
        print("Unexpected packet")
        print(dpkt)
        print()
        return

    # Record the packet if PCAP writing is enabled
    if pcwriter:
        pcwriter.write_packet_message(dpkt)

    global advertisers

    if isinstance(dpkt, AdvaMessage) or isinstance(dpkt, AdvDirectIndMessage) or (
            isinstance(dpkt, AdvExtIndMessage) and dpkt.AdvA is not None):
        adva = str_mac2(dpkt.AdvA, dpkt.TxAdd)

        if adva not in advertisers:
            advertisers[adva] = Advertiser()
            print("Found %s..." % adva)

        advertisers[adva].add_hit(dpkt.rssi)

        if isinstance(dpkt, (ScanRspMessage, AuxScanRspMessage)):
            advertisers[adva].scan_rsp = dpkt
        else:
            advertisers[adva].adv = dpkt

if __name__ == "__main__":
    main()
