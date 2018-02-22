#!/usr/bin/perl

use strict;
use warnings;

my $L2 = shift;
my %ipHASH;

open (FH2, "<", $L2) or die "Shit 2\n";
while (<FH2>) {
    chomp $_;

    # MassScan
    # <address addr="191.168.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="21"><state state="open" reason="syn-ack" reason_ttl="51"/></port></ports></host>
    if ($_ =~ /addr=\"(\d+.\d+.\d+.\d+)\".*protocol=\"(\w+)\".*portid=\"(\d+)\".*state=\"(\w+)\"/){
      # 1:IP #2:proto #3:port#4:open
      # IP,Service,port,proto
      my $k = "$1" . "." . "$3";
      if( exists($ipHASH{"$k"} ) ) { next }
      my $v = "$1" . "," . "??" ."," . "$3" . "," . "$2";
      $ipHASH{"$k"} = "$v" ;
    }

    # Nmap 
    # Host: 192.168.0.2 ()	Ports: 21/open/tcp//ftp///, 22/open/tcp//ssh///, 2024/open/tcp//xinuexpansion4///
    elsif ($_ =~ /Host: (\d+.\d+.\d+.\d+).*Ports:\s*(.*)/){
    	my $aPorts;
    	my $IP = $1;
      my @ports = split(/,/,$2);
      foreach my $p (@ports){
        # 80/open/tcp//http///, 443/open/tcp//https///
       	if ($p =~ /(\d+)\/(open)\/(\w+)\/\w*\/(\w+)\//){  
            # 1:port #2:open #3:tcp|udp #4:service desc
            # IP,Service,port,proto
            my $k = "$IP" . "." . "$1";
            if( exists($ipHASH{"$k"} ) ) { next }
            my $v = "$IP" . "," . "$4" ."," . "$1" . "," . "$3";
            $ipHASH{"$k"} = "$v" ;
       	}
      }
    }

    # Unicornscan 
    # TCP open            https[  443]   from 192.168.0.3  ttl 64
    elsif ($_ =~ /(TCP|UDP) (open)\s+(\S+)\[\s+(\d+)\].*from (\d+.\d+.\d+.\d+).*/){
      
      #5:IP #3:proto #4:port #2:open
      # IP,Service,port,proto
      my $k = "$5" . "." . "$4";
      if( exists($ipHASH{"$k"} ) ) { next }
      my $v = "$5" . "," . "$3" ."," . "$4" . "," . "$1";
      $ipHASH{"$k"} = "$v" ;
    }

    else { 
    	#print "*$_\n"; 
    	next 
    }
}
close FH2 or die "Cannot close $L2: $!";

my @sorted_keys = map  {$_->[0]}
                  sort {$a->[1] <=> $b->[1]
                     || $a->[2] <=> $b->[2]
                     || $a->[3] <=> $b->[3]
                     || $a->[4] <=> $b->[4]}
                  map  { [ $_, split /\./ ] }
                  keys %ipHASH;
foreach (@sorted_keys) {
  $_ =~ /(\d+.\d+.\d+.\d+).(\d+)/;
  my $p = lc $ipHASH{$_};
  print "$p\n"
}
