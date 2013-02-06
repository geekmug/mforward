#!/usr/bin/env python

__license__ = """
Copyright 2011 Scott A. Dial <scott@scottdial.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import sys

from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from twisted.python import usage

class MulticastServer(DatagramProtocol):
    def __init__(self, group, port, ttl=1, loopback=False):
        self.group = group
        self.port = port
        self.ttl = ttl
        self.loopback = loopback

    def startProtocol(self):
        self.transport.setTTL(self.ttl)
        #self.transport.setLoopbackMode(self.loopback)

    def forwardData(self, data):
        self.transport.write(data, (self.group, self.port))

class MulticastClient(DatagramProtocol):
    def __init__(self, group, server):
        self.group = group
        self.server = server

    def startProtocol(self):
        self.transport.joinGroup(self.group)

    def datagramReceived(self, datagram, address):
        self.server.forwardData(datagram)

# TODO: Support IPv6 mutlicast groups (ff00::/8)
def multicastGroup(val):
    parts = map(int, val.split('.'))
    if len(parts) != 4:
        raise ValueError('Not a multicast group address')
    is_bad_address = (parts[0] < 224 or parts[0] > 255)
    is_bad_address |= (parts[1] < 0 or parts[1] > 255)
    is_bad_address |= (parts[2] < 0 or parts[2] > 255)
    is_bad_address |= (parts[3] < 0 or parts[3] > 255)
    if is_bad_address:
        raise ValueError('Not a multicast group address')
    return val

class Options(usage.Options):
    optFlags = [
        ["loopback", "l", "Loopback multicast packets"],
    ]

    optParameters = [
        ["src-group", "s", None, "Source multicast group", multicastGroup],
        ["src-port", "p", None, "Source multicast port", int],
        ["dst-group", "d", None, "Destination multicast group", multicastGroup],
        ["dst-port", "o", None, "Destination mutlicast port", int],
        ["ttl", "t", 1, "Time-to-live for outgoing packets", int],
    ]

def main():
    config = Options()
    try:
        config.parseOptions()
        if not config['src-group']:
            raise usage.UsageError('No source group provided')
        if not config['src-port']:
            raise usage.UsageError('No source port provided')
        if not config['dst-group']:
            raise usage.UsageError('No destiantion group provided')
        if not config['dst-port']:
            config['dst-port'] = config['src-port']
        if config['loopback'] and config['src-port'] == config['dst-port']:
            raise usage.UsageError(
                'Loopback would be infinite because ports are the same)')
    except usage.UsageError, errortext:
        print '%s: %s' % (sys.argv[0], errortext)
        print '%s: Try --help for usage details.' % (sys.argv[0])
        sys.exit(1)

    config['loopback'] = bool(config['loopback'])

    server = MulticastServer(config['dst-group'],
                             config['dst-port'],
                             config['ttl'],
                             config['loopback'])
    reactor.listenMulticast(0, server, listenMultiple=True)
    reactor.listenMulticast(config['src-port'],
                            MulticastClient(config['src-group'], server),
                            listenMultiple=True)
    reactor.run()

if __name__ == '__main__':
    main()
