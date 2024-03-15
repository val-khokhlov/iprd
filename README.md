# iprd - a FreeBSD IP header rewriting daemon

This simple daemon allows customized rewriting IP headers of packets that come to the specific port. To use it you need to setup a divert/tee rule in ipfw to move/copy the packets for rewriting to the port iprd listenes to. After that, iprd can be used to modify any IP header field of the packets going through this port. iprd makes use of Perl hook so that customized logic can be easily implemented with a Perl script. Alternatively, you can turn the Perl hook off and hardcode the logic in a C code, which is much faster and takes much less memory space.

Building iprd is quite straightforward with Makefile. To build with Perl 5.6+ use WITH_PERL=1 and WITH_PERL56=1. To build without Perl hooks, use WITH_PERL=0. To create a static binary, use STATIC=1.

## Use cases for iprd:

### 1. Masquerading SMTP connections.

Suppose you need to conceal connections from 10.0.0.11 to any SMTP server (tcp port 25), so you pretend 10.0.0.11 sends packets to this host on port 9925. When getting a packet for port 9925 you rewrite the IP header as if the packet originated from this system and port 7000. When getting a packet on this system with destination port 7000 you rewrite the header back so that the destination address is 10.0.0.11 and the destination port is the saved port.

Add the divert rules to /etc/firewall assuming fxp0 is the interface on which 10.0.0.11 is located and the natd rules are in 05010-05040 range (iprd must be outside of NAT scope):
```
05005 divert 9999 all from any to any out via fxp0
...
05045 divert 9999 all from any to any in via fxp0
```
Run iprd as a daemon on port 9999:
```
/usr/sbin/iprd -d -P 9999
```
Add the following logic to Perl script or C code:
```
if (proto == TCP && src_addr == 10.0.0.11 && dst_port == 9925) {
 saved_port = src_port; src_port = 7000; dst_port = 25; src_addr = our_addr; modified = 1;
}
if (proto == TCP && src_port == 25 && dst_port == 7000) {
 dst_port = saved_port; src_port = 9925; dst_addr = 10.0.0.11; src_addr = our_addr; modified = 1;
}
```

### 2. Two-way address-port concealing gateway

Suppose you have a network topology A <--X--> B <--Y--> C (A can be subnet/addrmask) and you do not want any X, Y to know that A accesses web server on C (ports 80, 443). In that case you tell A to connect to B on ports 7080, 7443 instead and can setup iprd on B with the following Perl logic:

Add the divert rules to /etc/firewall assuming fxp0 is the interface on which A and C reside and the natd rules are in 05010-05040 range (if A or C are within NAT scope):
```
05005 divert 9999 all from any to any out via fxp0
...
05045 divert 9999 all from any to any in via fxp0
```
Run iprd as a daemon on port 9999 with Perl hooks file /etc/iprd.pl:
```
/usr/sbin/iprd -d -P 9999 -f /etc/iprd.pl
```
Add the following logic to Perl script:
```
# if incoming packet matches map[B:rand] do reverse mapping to A:port<-B:7xxx
if ($pkg{src} eq C && defined $map{"$pkt{dst}:$pkt{dport}"}) {
  $a = $map{"$pkt{dst}:$pkt{dport}"};
  $pkt{src} = B; $pkt{sport} += 7000; $pkt{dst} = $a->[0]; $pkt{dport} = $a->[1];
  $modified = 1;
}
# rewrite A:port->B:7xxx as B:rand->C:xxx, map[B:rand] saves original A:port, remap[A:port] saves port for reusing
elseif ( $pkt{src} eq A && $pkt{dst} eq B && ($pkt{dport} == 7080 || $pkt{dport} == 7443) ) { 
  if (defined $remap{"$pkt{src}:$pkt{sport}"}) { $port = $remap{"$pkt{src}:$pkt{sport}"}; }
  else {
    do { $port = 5000 + int(rand 60000); } while (defined $map{"$B:$port"}); }
    $map{"$B:$port"} = [$pkt{src}, $pkt{sport}]; 
    $remap["$pkt{src}:$pkt{sport}"] = $port;
  }
  $pkt{src} = B; $pkt{sport} = $port; $pkt{dst} = C; $pkt{dport} -= 7000;
  $modified = 1;
}
```
