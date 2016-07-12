#!/usr/bin/env python
#
# Copyright (c) 2016 Roberto Riggio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.

"""Discover the EmPOWER controller address."""

import socket
import struct
import sys
import time

ETH_P_ALL = 0x0003


def main(iface):

    try:

        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                             socket.htons(ETH_P_ALL))

        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        sock.bind((iface, ETH_P_ALL))

    except socket.error as msg:
        msg = list(msg)
        print('Unable to create socket: ' + msg[1] + ' (' + str(msg[0]) + ')')
        sys.exit(1)

    found = None
    start = time.time()

    while not found:

        if time.time() > start + 2:
            sys.exit(1)

        pkt = sock.recvfrom(1500)
        pkt = pkt[0]

        eth_header = struct.unpack("!6s6sH", pkt[0:14])
        eth_type = socket.ntohs(eth_header[2])

        if eth_type != 0xeeee:
            continue

        payload = struct.unpack("!4sH", pkt[14:])
        found = (socket.inet_ntoa(payload[0]), payload[1])

    print("%s %u" % found)
    sys.exit(0)


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Invalid argument, usage: %s <iface>" % sys.argv[0])
        sys.exit(-1)

    main(sys.argv[1])
