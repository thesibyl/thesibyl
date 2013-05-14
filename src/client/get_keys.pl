#!/usr/bin/perl -w
use lib qw{lib /etc/sibyl ../lib};
use strict;
use sibyl;
use File::Slurp;
use IO::Socket;

my $keyID;
my $verify_f;

# command-line arguments: -SPiv
ARG:
while (local $_ = shift @ARGV) {

  /^-S$/ && do {
    $sibyl::SERVER = shift @ARGV;
    next ARG;
  };

  /^-p$/ && do {
    $sibyl::PORT = shift @ARGV;
    next ARG;
  };

  do {
    print <<EOU;
Usage: -d decryption key -s sign key -m1 first message -m2 second message
-S server -p port -D digest.

m1 is a base64 codification of an RSA encrypted text
m2 is a plaintext
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
