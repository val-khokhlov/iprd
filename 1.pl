# sample perl-hook to masquerade all tcp reqs for 127.0.0.0:7000
# as originating from random port on localhost direct them to port 25
if ( $pkt{p} == $TCP ) {
  if (defined $map{"$pkt{dst}:$pkt{dport}"}) {
    $a = $map{"$pkt{dst}:$pkt{dport}"};
    print "Re-mapping $pkt{dst}:$pkt{dport} to $pkt{dst}:$a->[1]\n";
    $pkt{sport} = 7000; $pkt{dport} = $a->[1];
    update_hdr();
  }
  elsif (defined $revmap{"$pkt{src}:$pkt{sport}"}) {
    $port = $revmap{"$pkt{src}:$pkt{sport}"};
    print "Matched old map $pkt{src}:$pkt{sport} to $port\n";
    $pkt{sport} = $port; $pkt{dport} = 25;
    update_hdr();
  }
  elsif ($pkt{src} eq '127.0.0.1' && $pkt{dport} == 7000) {
    $port = int(rand 9999)+50000;
    print "Creating map $pkt{src}:$pkt{sport} to $pkt{src}:$port\n";
    $map{"127.0.0.1:$port"} = [$pkt{src}, $pkt{sport}];
    $revmap{"$pkt{src}:$pkt{sport}"} = $port;
    $pkt{sport} = $port; $pkt{dport} = 25;
    update_hdr();
  }
}
