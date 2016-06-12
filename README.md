# Scuttle
Scuttle is a tool that lets you control the output when your server is `traceroute`d. It currently
supports both ICMP and UDP `traceroute`.

## Setup
You'll need a set of IP addresses you can control the reverse DNS entries for, and a Linux server
that supports IP spoofing.

[Vultr](https://www.vultr.com/) will let you buy as many IPs as you want, and control their reverse
DNS entries, for $3/month each. [AWS EC2](https://aws.amazon.com/ec2/) will let you spoof IPs
&ndash; make sure you enable all inbound UDP and ICMP traffic, and disable the source/dest check (in
the console, right click => Networking => Change source/dest check). Note that `us-west-2` (Oregon)
has unreliable route lengths, which breaks scuttle, but `us-west-1` (N. California) works fine.

Run the following commands on your server, to disable kernel-level ICMP and UDP replies:
```bash
# Disable the kernel's responses to ICMP echo packets, which would interfere with our own replies.
sudo echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all

# Prevent the kernel from sending "destination port unreachable" messages, which would interfere
# with our UDP traceroute implementation. FreeBSD has a blackhole sysctl that would do this for
# us, but on Linux we don't have as much luck, so have to resort to this hack.
# Allow all outbound ICMP packets except "destination port unreachable".
sudo iptables -A OUTPUT -p icmp -m icmp ! --icmp-type port-unreachable -j ACCEPT

# Drop all outbound "destination port unreachable" packets except those sent by root.
sudo iptables -A OUTPUT -p icmp -m owner ! --uid-owner root -j DROP
```

Add the IPs you'd like to a newline delimited file named `redirect_ips.txt`, for example
```
123.1.1.1
123.1.1.2
123.1.1.3
```

## Usage
Run `sudo python scuttle.py redirect_ips.txt` to serve responses infinitely.
