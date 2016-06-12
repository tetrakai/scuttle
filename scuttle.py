import select
import socket
import sys

from packet_utils import IPPacket, ICMPEchoRequestPacket, ICMPTTLExpiredPacket, \
                         ICMPEchoReplyPacket, ICMPDestinationPortUnreachablePacket

MAX_PACKET_SIZE = 2048

def main(argv):
  assert len(sys.argv) > 1, 'Please pass a filename to read IPs from'
  traceroute_ips = open(argv[1], 'r').read().strip().split('\n')

  udp_socket = create_socket(socket.IPPROTO_UDP)
  icmp_socket = create_socket(socket.IPPROTO_ICMP)

  while True:
    ready_to_read, _, _ = select.select([udp_socket, icmp_socket], [], [])

    for sock in ready_to_read:
      data, (addr, _) = sock.recvfrom(MAX_PACKET_SIZE)
      response = generate_reply(data, traceroute_ips)
      if response:
        sock.sendto(response, (addr, 0))

def create_socket(sock_type):
  sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, sock_type)
  sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
  return sock

def generate_reply(packet_data, traceroute_ips):
  request = IPPacket.from_packet_data(packet_data)

  # Ignore UDP packets destined to this server but with a TTL so great that they're not from
  # traceroute. This stops this script from breaking all other UDP traffic on the server (which it
  # would otherwise do, since it's very insistent that no UDP ports exist)
  if request.protocol == IPPacket.PROTO_UDP and request.ttl > len(traceroute_ips) + 1:
    return None

  # Ignore ICMP packets destined to this server that are not ping or ICMP traceroute requests, since
  # this script has no idea how to handle them
  if request.protocol == IPPacket.PROTO_ICMP and not isinstance(request.child_packet, ICMPEchoRequestPacket):
    return None

  reply = IPPacket()
  reply.protocol = IPPacket.PROTO_ICMP
  reply.source_ip = request.dest_ip
  reply.dest_ip = request.source_ip

  if request.ttl > 0 and request.ttl <= len(traceroute_ips):
    reply.child_packet = ICMPTTLExpiredPacket()
    reply.child_packet.payload = request.header() + request.payload()[:8]
    reply.source_ip = traceroute_ips[request.ttl - 1]

  elif request.protocol == IPPacket.PROTO_ICMP:
    reply.child_packet = ICMPEchoReplyPacket()
    reply.child_packet.identifier = request.child_packet.identifier
    reply.child_packet.sequence_number = request.child_packet.sequence_number
    reply.child_packet.payload = request.child_packet.payload

  else:
    reply.child_packet = ICMPDestinationPortUnreachablePacket()
    reply.child_packet.payload = request.header() + request.payload()[:8]

  return reply.generate_packet_data()

if __name__ == '__main__':
  main(sys.argv)
