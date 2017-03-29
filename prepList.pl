#!perl

use strict;
use File::Basename;

my $file = shift; 
my $out = "/root/Tools/prepList/" . basename($file) . ".lst";
open (FH, "<", $file) or die "Cant read scan file\n";
open (WO, ">", $out) or die "Cant write $out\n";

while (<FH>) {
   my $host = undef;
   # nMap grep output
   # Host: 10.10.10.10 () Ports: 135/open/tcp//msrpc///, 137/filtered/tcp//netbios-ns///
   if ($_ =~ /Host: (\d+.\d+.\d+.\d+).*Ports: (.*)/){
      $host = $1;
      print "nMap:Working on: $host\n";
      my @ports = split(/,/,$2);
      foreach my $p (@ports){
         if ($p =~ /(\d+).*(http)(s?)/){            
           print WO "$2$3://$host:$1\n";
         }
      }
   # Unicornscan output
   # TCP open	           https[  443]		from 38.127.201.95  ttl 64
   } elsif ($_ =~ /.*(http)(s?)\[\s+(\d+)\].*from (\d+.\d+.\d+.\d+).*/){
   		$host = $4;
      	print "unicornscan:Working on: $host\n";
        print WO "$1$2://$4:$3\n";
   }
}

print "Output saved at: $out\n"
