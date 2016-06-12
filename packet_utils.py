'''Packet utilities module.

Contains functions to parse and generate a very limited range of ICMP and UDP packet types.
'''

# pylint: disable=missing-docstring

import random
import struct

__all__ = [
    'AbstractPacket', 'IPPacket', 'UDPPacket', 'ICMPPacket',
    'ICMPTTLExpiredPacket', 'ICMPEchoRequestPacket', 'ICMPEchoReplyPacket',
    'ICMPDestinationPortUnreachablePacket',
]

# Needing this class is gross, but it's the only way I know of to have the ICMPPacket be able to
# create subclasses when you try to instantiate it
class AbstractPacket(object):
  '''Abstract class that all packets in this module are derived from.'''

  @classmethod
  def from_packet_data(cls, data):
    return cls(data)

class UDPPacket(AbstractPacket):
  def __init__(self, packet_data=None):
    if packet_data is None:
      self.source_port = 0
      self.dest_port = 0
      self.payload = ''

      self._checksum = None
      self._length = len(self.payload)
    else:
      index, self.source_port = _parse_short(packet_data, 0)
      index, self.dest_port = _parse_short(packet_data, index)
      index, self._length = _parse_short(packet_data, index)
      index, self._checksum = _parse_short(packet_data, index)
      self.payload = packet_data[index:]

  def generate_packet_data(self):
    packet = []

    packet.append(_generate_short(self.source_port))
    packet.append(_generate_short(self.dest_port))

    self._length = 8 + len(self.payload)
    packet.append(_generate_short(self._length))

    # Checksum gets inserted here

    packet.append(self.payload)

    # Generate and insert checksum
    self._checksum = _calculate_checksum(''.join(packet))
    packet.insert(3, _generate_short(self._checksum))

    return ''.join(packet)

class ICMPPacket(AbstractPacket):
  # The ICMP type and code together encode which message is being sent in an ICMP request
  TYPE_ECHO_REPLY = (0, 0)
  TYPE_DEST_PORT_UNREACHABLE = (3, 3)
  TYPE_ECHO_REQUEST = (8, 0)
  TYPE_TTL_EXPIRED = (11, 0)

  @classmethod
  def from_packet_data(cls, data):
    pair_to_packet_class = {
        cls.TYPE_ECHO_REPLY: ICMPEchoReplyPacket,
        cls.TYPE_DEST_PORT_UNREACHABLE: ICMPDestinationPortUnreachablePacket,
        cls.TYPE_ECHO_REQUEST: ICMPEchoRequestPacket,
        cls.TYPE_TTL_EXPIRED: ICMPTTLExpiredPacket,
    }

    icmp_packet = ICMPPacket(data)
    pair = (icmp_packet.icmp_type, icmp_packet.code)
    if pair in pair_to_packet_class:
      icmp_packet = pair_to_packet_class[pair](data)
    return icmp_packet

  def __init__(self, packet_data=None):
    if packet_data is None:
      self.icmp_type = 0
      self.code = 0
      self.payload = ''
      self._checksum = None

    else:
      index, self.icmp_type = _parse_byte(packet_data, 0)
      index, self.code = _parse_byte(packet_data, index)
      index, self._checksum = _parse_short(packet_data, index)
      self.payload = packet_data[index:]

  def generate_packet_data(self):
    packet = []

    packet.append(_generate_byte(self.icmp_type))
    packet.append(_generate_byte(self.code))

    # Checksum gets inserted here

    packet.append(self.payload)

    # Generate and insert checksum
    self._checksum = _calculate_checksum(''.join(packet))
    packet.insert(2, _generate_short(self._checksum))

    return ''.join(packet)

class ICMPTTLExpiredPacket(ICMPPacket):
  ICMP_TYPE = 11 # Time exceeded
  ICMP_CODE = 0 # TTL exceeded in transit

  def __init__(self, packet_data=None):
    super(ICMPTTLExpiredPacket, self).__init__(packet_data)

    if packet_data is None:
      self.icmp_type = self.ICMP_TYPE
      self.code = self.ICMP_CODE

    else:
      assert self.icmp_type == self.ICMP_TYPE, \
        'Packet type is %d, not %d (Time exceeded)!' % (self.icmp_type, self.ICMP_TYPE)
      assert self.code == self.ICMP_CODE, \
        'Packet code is %d, not %d (TTL exceeded in transit)' % (self.code, self.ICMP_CODE)
      index, _ = _parse_int(self.payload, 0) # Unused
      self.payload = self.payload[index:]

  def generate_packet_data(self):
    self.payload = ''.join([
        _generate_int(0), # Unused
        self.payload,
    ])
    return super(ICMPTTLExpiredPacket, self).generate_packet_data()

class ICMPEchoRequestPacket(ICMPPacket):
  ICMP_TYPE = 8 # Echo request
  ICMP_CODE = 0 # Echo reply

  def __init__(self, packet_data=None):
    super(ICMPEchoRequestPacket, self).__init__(packet_data)

    if packet_data is None:
      self.icmp_type = self.ICMP_TYPE
      self.code = self.ICMP_CODE
      self.identifier = 0
      self.sequence_number = 0

    else:
      assert self.icmp_type == self.ICMP_TYPE, \
        'Packet type is %d, not %d (Echo reply)!' % (self.icmp_type, self.ICMP_TYPE)
      assert self.code == self.ICMP_CODE, \
        'Packet code is %d, not %d (Echo reply)' % (self.code, self.ICMP_CODE)
      index, self.identifier = _parse_short(self.payload, 0)
      index, self.sequence_number = _parse_short(self.payload, index)
      self.payload = self.payload[index:]

  def generate_packet_data(self):
    self.payload = ''.join([
        _generate_short(self.identifier),
        _generate_short(self.sequence_number),
        self.payload,
    ])
    return super(ICMPEchoRequestPacket, self).generate_packet_data()

class ICMPEchoReplyPacket(ICMPPacket):
  ICMP_TYPE = 0 # Echo reply
  ICMP_CODE = 0 # Echo reply

  def __init__(self, packet_data=None):
    super(ICMPEchoReplyPacket, self).__init__(packet_data)

    if packet_data is None:
      self.icmp_type = self.ICMP_TYPE
      self.code = self.ICMP_CODE
      self.identifier = 0
      self.sequence_number = 0

    else:
      assert self.icmp_type == self.ICMP_TYPE, \
        'Packet type is %d, not %d (Echo reply)!' % (self.icmp_type, self.ICMP_TYPE)
      assert self.code == self.ICMP_CODE, \
        'Packet code is %d, not %d (Echo reply)' % (self.code, self.ICMP_CODE)
      index, self.identifier = _parse_short(self.payload, 0)
      index, self.sequence_number = _parse_short(self.payload, index)
      self.payload = self.payload[index:]

  def generate_packet_data(self):
    self.payload = ''.join([
        _generate_short(self.identifier),
        _generate_short(self.sequence_number),
        self.payload,
    ])
    return super(ICMPEchoReplyPacket, self).generate_packet_data()


class ICMPDestinationPortUnreachablePacket(ICMPPacket):
  ICMP_TYPE = 3 # Destination unreachable
  ICMP_CODE = 3 # Port unreachable

  def __init__(self, packet_data=None):
    super(ICMPDestinationPortUnreachablePacket, self).__init__(packet_data)

    if packet_data is None:
      self.icmp_type = self.ICMP_TYPE
      self.code = self.ICMP_CODE
      self.next_hop_mtu = 0

    else:
      assert self.icmp_type == self.ICMP_TYPE, \
        'Packet type is %d, not %d (Destination unreachable)!' % (self.icmp_type, self.ICMP_TYPE)
      assert self.code == self.ICMP_CODE, \
        'Packet code is %d, not %d (Port unreachable)' % (self.code, self.ICMP_CODE)
      index, _ = _parse_int(self.payload, 0) # Unused
      self.payload = self.payload[index:]

  def generate_packet_data(self):
    self.payload = ''.join([
        _generate_short(0), # Unused
        _generate_short(self.next_hop_mtu),
        self.payload,
    ])
    return super(ICMPDestinationPortUnreachablePacket, self).generate_packet_data()

class IPPacket(AbstractPacket):
  # Protocol numbers, as defined in the "Assigned numbers" RFC: https://tools.ietf.org/html/rfc1340
  PROTO_ICMP = 1
  PROTO_UDP = 17

  DEFAULT_TTL = 64

  PROTO_TO_PACKET_CLASS = {
      PROTO_ICMP: ICMPPacket,
      PROTO_UDP: UDPPacket,
  }

  def __init__(self, packet_data=None):
    if packet_data is None:
      self.ttl = self.DEFAULT_TTL
      self.protocol = self.PROTO_ICMP
      self.source_ip = '127.0.0.1'
      self.dest_ip = '127.0.0.1'
      self.child_packet = None

      self._version = 4         # Default version: IPv4
      self._ihl = 20 / 4        # Default internet header length: 20 words (of 4 bytes each)
      self._dscp = 0            # Default differentiated services code point: "Routine" priority
      self._ecn = 0             # Default explicit congestion notification: We don't understand this
      self._flags = 0           # Default flags: Don't fragment = 0, More fragments = 0
      self._fragment_offset = 0 # Default fragment offset: 0 (our data is small, it won't fragment)
      self._checksum = None     # Checksum is overridden on send
      self._total_length = None # Total length is overriden on send
      self._id = random.SystemRandom().randint(0, 2**16) # Random per-fragment-group ID

    else:
      index, tmp = _parse_byte(packet_data, 0)
      self._version = tmp >> 4
      self._ihl = tmp & 0xF

      index, tmp = _parse_byte(packet_data, index)
      self._dscp = tmp >> 2
      self._ecn = tmp & 0x3

      index, self._total_length = _parse_short(packet_data, index)
      index, self._id = _parse_short(packet_data, index)

      index, tmp = _parse_short(packet_data, index)
      self._flags = tmp >> 13
      self._fragment_offset = tmp & 0x1FFF

      index, self.ttl = _parse_byte(packet_data, index)
      index, self.protocol = _parse_byte(packet_data, index)
      index, self._checksum = _parse_short(packet_data, index)

      index, source_ip = _parse_int(packet_data, index)
      self.source_ip = _num_to_dotted_quad(source_ip)
      index, dest_ip = _parse_int(packet_data, index)
      self.dest_ip = _num_to_dotted_quad(dest_ip)

      payload = packet_data[max(self._ihl * 4, 0):min(self._total_length, len(packet_data))]
      child_packet_class = self.PROTO_TO_PACKET_CLASS.get(self.protocol, None)
      if child_packet_class is not None:
        self.child_packet = child_packet_class.from_packet_data(payload)
      else:
        self.child_packet = None

  def generate_packet_data(self):
    packet = []

    assert self._version >= 0 and self._version < 0x10
    assert self._ihl >= 0 and self._ihl < 0x10
    packet.append(_generate_byte((self._version << 4) | self._ihl))

    assert self._dscp >= 0 and self._dscp < 0x4F
    assert self._ecn >= 0 and self._ecn < 0x4
    packet.append(_generate_byte((self._dscp) << 2 | self._ecn))

    packet.append(_generate_short(self._ihl * 4))
    packet.append(_generate_short(self._id))

    assert self._flags >= 0 and self._flags < 0x8
    packet.append(_generate_short((self._flags << 13) | self._fragment_offset))

    packet.append(_generate_byte(self.ttl))
    packet.append(_generate_byte(self.protocol))
    # Checksum gets inserted here
    packet.append(_generate_int(_dotted_quad_to_num(self.source_ip)))
    packet.append(_generate_int(_dotted_quad_to_num(self.dest_ip)))

    # Calculate and insert checksum
    self._checksum = _calculate_checksum(''.join(packet))
    packet.insert(7, _generate_short(self._checksum))

    packet.append(self.payload())

    return ''.join(packet)

  def header(self):
    return self.generate_packet_data()[:self._ihl * 4]

  def payload(self):
    if self.child_packet:
      return self.child_packet.generate_packet_data()
    else:
      return ''

def _num_to_dotted_quad(num):
  return '%d.%d.%d.%d' % (num >> 24, (num >> 16) & 0xFF, (num >> 8) & 0xFF, num & 0xFF)

def _dotted_quad_to_num(dotted_quad):
  num = 0
  for part in dotted_quad.split('.'):
    num <<= 8
    num += int(part)
  return num

def _calculate_checksum(data):
  fmt = '!%dH' % (len(data) / 2)
  unpacked = struct.unpack(fmt, data)
  if len(data) % 2 != 0:
    unpacked.append(struct.unpack('B', data[-1])[0])
  result = sum(unpacked)

  while (result >> 16) != 0:
    result = (result & 0xffff) + (result >> 16)

  return (~result) & 0xffff

def _parse_byte(data, index):
  return index + 1, struct.unpack('B', data[index])[0]

def _generate_byte(data):
  return struct.pack('B', data)

def _parse_short(data, index):
  return index + 2, struct.unpack('!H', data[index:index + 2])[0]

def _generate_short(data):
  return struct.pack('!H', data)

def _parse_int(data, index):
  return index + 4, struct.unpack('!I', data[index:index + 4])[0]

def _generate_int(data):
  return struct.pack('!I', data)
