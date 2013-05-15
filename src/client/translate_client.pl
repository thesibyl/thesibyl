#!/usr/bin/perl -w
use lib qw{lib /etc/sibyl ../lib};
use strict;
use Crypt::OpenSSL::RSA;
use MIME::Base64;
use Digest::SHA1 qw /sha1_hex/;
use sibyl;
use File::Slurp;
use IO::Socket;

# Default values...
my $keyID = "1";
my $verify_f = "sign.pub";

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

  /^-i$/ && do {
    $keyID = shift @ARGV;
    next ARG;
  };

  /^-s$/ && do {
    $verify_f = shift @ARGV;
    next ARG;
  };

  do {
    print <<EOU;
Usage: -S server -p port -i keyID -s sign key.
EOU
    exit 1;
  };

}


my $verify = read_file("$verify_f") or
  die "Unable to read file: $!";
my $verify_key = Crypt::OpenSSL::RSA->new_public_key($verify) or
  die "Malformed RSA key: $!";

while (<>) {
  do {
    print;
    next;
  } if /\A[^:]+:(\*|\!)+:/;
  chomp;
  my @item = split /:/;
  my ($salt, $pwd) = ($item[1] =~ /(.*\$)(.*)$/);
  # Connect to the sibyl
  my $socket = IO::Socket::INET->new("$sibyl::SERVER:$sibyl::PORT") or
    die "Unable to contact server: $!";

#  my $stdout = select;
#  select $socket;

  # Receive nonce
  my $nonce;
  recv $socket, $nonce, 1024,0;
  chomp $nonce;
  $nonce =~ s/(\@|\000)//g;
  my $msg = join(';', ("[$keyID]", $nonce, "$pwd\@\@"));

  # Send message
  print stderr "sending: {$msg}\n";
  send $socket, $msg, 0;


  # Receive answer
  my $ans;
  recv $socket, $ans, 2048, 0;
  close $socket;

  my ($newpwd, $signature) = split(';', $ans);
  my $OK = $verify_key->verify($newpwd, decode_base64($signature));
  next unless $OK;
  $item[1] = "$salt$newpwd";
  print join(':', @item) . "\n";

}

