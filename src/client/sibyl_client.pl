#!/usr/bin/env perl
use strict;
use warnings;
use Crypt::OpenSSL::RSA;
use MIME::Base64;
use File::Slurp;
use IO::Socket;

use lib qw{lib /etc/sibyl ../lib};
use sibyl;

my $DEBUG=1;

my @message;

# command-line arguments: -dsSP -m1 -m2
ARG:
while (local $_ = shift @ARGV) {

  /^-d$/ && do {
    $sibyl::DECR_KEY = shift @ARGV;
    next ARG;
  };

  /^-s$/ && do {
    $sibyl::SIGN_KEY = shift @ARGV;
    next ARG;
  };

  /^-m1$/ && do {
    $message[0] = shift @ARGV;
    next ARG;
  };

  /^-m2$/ && do {
    $message[1] = shift @ARGV;
    next ARG;
  };

  /^-S$/ && do {
    $sibyl::SERVER = shift @ARGV;
    next ARG;
  };

  /^-p$/ && do {
    $sibyl::PORT = shift @ARGV;
    next ARG;
  };

  /^-D$/ && do {
    $sibyl::DIGEST = shift @ARGV;
    $sibyl::DIGEST = "none" unless defined $sibyl::DIGEST;
    do {
      print "Sorry, only " . join (',', sort keys %sibyl::DIGEST_AV) . " are available.";
    } unless $sibyl::DIGEST_AV{$sibyl::DIGEST};
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

$message[0] ||= <stdin>;
$message[1] ||= <stdin>;
chomp $message[1]; # just in case

print "m1: $message[0]\n" if $DEBUG;
print "m2: $message[1]\n" if $DEBUG;

# Read the decrypt and sign public keys
my $encr_f = read_file("$sibyl::DECR_KEY.pub") or
  die "Unable to read file: $!";
my $verify_f = read_file("$sibyl::SIGN_KEY.pub") or 
  die "Unable to read file: $!";

my $encr_key = Crypt::OpenSSL::RSA->new_public_key($encr_f) or
  die "Malformed RSA key: $!";
my $verify_key = Crypt::OpenSSL::RSA->new_public_key($verify_f) or
  die "Malformed RSA key: $!";

# Connect to the sibyl
my $socket = IO::Socket::INET->new("$sibyl::SERVER:$sibyl::PORT") or 
  die "Unable to contact server: $!";

print "Connected to $sibyl::SERVER:$sibyl::PORT\n" if $DEBUG;

# Get the nonce
my $nonce;
recv($socket, $nonce, 1024, 0);
$nonce =~ /\A([.0-9A-Za-z]+)/;
$nonce = $1;
print "nonce received: $nonce\n" if $DEBUG;

# This is an undercover 'case' statement...
DIGEST_CASES: {

   print "digest: $sibyl::DIGEST\n" if $DEBUG;

  "crypt" eq $sibyl::DIGEST && do {
    # notice that the crypt function is essentially different on
    # Linux machines and Apples...
    # message[1] needs to be digested. It is SALT$PASSWD
    $message[1] =~ /^(.*)\$([^\$]+)\Z/;
    my $salt = "$1\$";
    my $pass = $2;
    print "m2: $message[1]\n" if $DEBUG;
    print "m2 -> salt: $salt hash: $pass\n" if $DEBUG;

    $message[1] = crypt $pass, "$salt";
    
    last DIGEST_CASES;
  };

  "none" eq $sibyl::DIGEST && do {
    # 'none' means 'no need to digest the second message', but it
    # MUST be rsa-encrypted and base64-ed afterwards. This is done after the do
    # loop.

    last DIGEST_CASES;
  };

};

# Encrypt and encode (base64) 'm2'
$encr_key->use_pkcs1_oaep_padding();
print "base64(encrypt($nonce:$message[1]): " if $DEBUG;
$message[1] = encode_base64($encr_key->encrypt("$nonce:$message[1]"));
print "$message[1]\n";

# Generate nonce and add it to the message
unshift @message, rand();
print "client nonce: $message[0]\n" if $DEBUG;

# Send message
my $stdout = select;
select $socket;
print join(';', @message);
print "\n\@\@\n";

# Receive answer
my $ans = <$socket>;
select $stdout;
print "message sent: " . join(';',@message) . "\n" if $DEBUG;
print "received: [$ans]\n";

# answer = message;signature
my @part = split /;/, $ans;
print "message: [$part[0]]\n";
print "signature: [$part[1]]\n";

# Verify the message
my $decr = $verify_key->verify($part[0], decode_base64($part[1]));
if ($decr) {
  print "Verification OK\n";
} else {
  print "Signed by a felon\n";
  exit $sibyl::FELON;
}

# Check the nonce and the authentication result (0 or 1)
my @retval = split /:/, $part[0];
my $success = $retval[1];
if ($success && $retval[0] eq $message[0]) {
  print "Authenticated\n";
  exit 0;
} else {
  print "You have not been authenticated\n";
  exit $sibyl::MISAUTH;
}

exit 0;
