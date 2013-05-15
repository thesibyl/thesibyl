#!/usr/bin/perl -w
use lib qw{lib /etc/sibyl ../lib};
use strict;
use sibyl;
use File::Slurp;
use IO::Socket;

my $keyID;
my $verify_f;

# command-line arguments: -ip
ARG:
while (local $_ = shift @ARGV) {

  /^-i$/ && do {
    $sibyl::SERVER = shift @ARGV;
    next ARG;
  };

  /^-p$/ && do {
    $sibyl::PORT = shift @ARGV;
    next ARG;
  };

  do {
    print <<EOU;
Usage: -i server IP -p port
EOU
    exit 1;
  };

}

my $socket = IO::Socket::INET->new("$sibyl::SERVER:$sibyl::PORT") or
  die "Unable to contact server: $!";

# Receive nonce
my $nonce;
recv $socket, $nonce, 1024,0;
chomp $nonce;
$nonce =~ s/(\@|\000)//g;

my $msg = join(';', ("[-]", $nonce, "\@\@"));

send $socket, $msg, 0;

my $ans;

recv $socket, $ans, 10240,0;

close $socket;

print $ans;
