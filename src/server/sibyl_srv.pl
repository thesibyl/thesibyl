#!/usr/bin/env perl
use strict;
use warnings;
use Crypt::OpenSSL::RSA;
use MIME::Base64;
use File::Slurp;
use IO::Socket qw/IPPROTO_TCP TCP_NODELAY SO_RCVTIMEO SOCK_STREAM/;
use warnings "all";

use lib qw{lib /etc/sibyl ../lib};

use sibyl;

my $DEBUG=1;

# command-line arguments: -d:s:i:p:D:
ARG:
while (local $_ = shift @ARGV) {

  /^-d\Z/ && do {
    $sibyl::DECR_KEY = shift @ARGV;
    next ARG;
  };

  /^-s\Z/ && do {
    $sibyl::SIGN_KEY = shift @ARGV;
    next ARG;
  };

  /^-i\Z/ && do {
    $sibyl::IP = shift @ARGV;
    next ARG;
  };

  /^-p\Z/ && do {
    $sibyl::PORT = shift @ARGV;
    next ARG;
  };

  /^-D\Z/ && do {
    $sibyl::CONF_DIR = shift @ARGV;
    next ARG;
  };

  do {
    print "Usage: -d decryption key -s signing key -i addres to listen on -p port
-D directory\n";
    exit 1;
  };

}


# base64 enconding of decryption and encryption keys
my @b64;

my $i=0;
foreach ($sibyl::DECR_KEY, $sibyl::SIGN_KEY) {
  $b64[$i++] = read_file("$sibyl::CONF_DIR/$_") or
    die "Unable to read file: $!";
}

my $decr_key = Crypt::OpenSSL::RSA->new_private_key($b64[0]) or
  die "Not a private RSA key: $!";
print "Read decrypt private key\n" if $DEBUG;
my $sign_key = Crypt::OpenSSL::RSA->new_private_key($b64[1]) or
  die "Not a private RSA key: $!";
print "Read sign private key\n" if $DEBUG;

my $server = IO::Socket::INET->new(
				   LocalPort    => $sibyl::PORT,
				   LocalAddress => $sibyl::IP,
				   Type         => SOCK_STREAM,
				   Reuse        => 1,
				   Listen       => 5,
                                   Timeout      => undef,
				  ) or
  die "Unable to create and bind socket:$!";
print "Listening on $sibyl::IP:$sibyl::PORT\n" if $DEBUG;

# prevent zombies
$SIG{CHLD} = 'IGNORE';

# this is the standard fork for servers
my $client;
my $kidpid;
REQUEST:
while ($client = $server->accept()) {
  print "Accepted connection from " . $client->peerhost() . ":" . $client->peerport() . "\n" if $DEBUG;

  if ($kidpid = fork) { # parent process, just accept another connection
    close $client;
    next REQUEST;
  }
  # child process: cleanup first
  defined($kidpid) or die "Unable to fork: $!";
  close $server;

  local $SIG{ALRM} = sub {die "Timeout";};

  $client->timeout(5);

  # and do some work afterwards
  my $nonce;
  my $msg;
  my $length;
  my $received = "";

  # send a nonce. For now, a random number is enough
  $nonce = rand();
  
  select $client;
  print $nonce . "\@";

  # get the complete message: ID; base641; base642 (supposedly);
  # everything adds up to less than 64k
  #my $file;
  #open($file, "+>/var/log/sibyl");
  alarm 5;
  # 0x40 -> MSG_WAITALL
  while (defined recv($client, $msg, 65535, 0)) {
    print STDERR "$msg\n" if $DEBUG;
    if ($msg =~ /\@\@.*$/) {
      $msg =~ s/\@\@.*$//;
      $received .= $msg;
      last;
    }
    $msg && ($received .= $msg);
    # prevent overflow
    if (length $received > 65535) {
      my $stdout = select;
      select $client;
      print $client, "Message too long.";
      close $client;
      exit $sibyl::MESSAGE_TOO_LONG;
    }
  }
  alarm 0;

  $received =~ s/\n//gm;
  print STDERR "received: [$received]\n" if $DEBUG;
  # ID; base64 1st message; base64 2nd message
  my @message = split(/;/, $received);
  do {
    select $client;
    print $client, "Malformed message.";
    close $client;
    exit $sibyl::MALFORMED_MESSAGE;
  } unless (scalar @message == 3);

  my $id = shift @message;

  my @plain = map {print STDERR "decrypting...\n$_\n" if $DEBUG; $decr_key->decrypt(decode_base64($_))} @message;

  # $plain[1] contains the nonce
  print STDERR "plain[1]: [$plain[1]]\n plain[0]: [$plain[0]]\n" if $DEBUG;
  $plain[1] =~ /^(.*?):(.*)$/;
  my $nonce_back = $1;
  $plain[1] = $2;

  print STDERR "plain0: [$plain[0]]\n" if $DEBUG;
  print STDERR "nonce: [$nonce_back], plain: [$plain[1]]\n" if $DEBUG;

  # Check if the password is ok (plain[0] == plain[1])
  my ($ret, $sgn);
  if (($plain[0] eq $plain[1]) && ($nonce_back eq $nonce)) {
    $ret = "$id:$sibyl::AUTH_OK";
  } else {
    $ret = "$id:$sibyl::AUTH_NO";
  }

  # Send response with signature
  $sgn = encode_base64($sign_key->sign($ret));
  $sgn =~ s/\n//g;
  send($client, join(';',($ret,$sgn)) . "\@", 0);
  print STDERR "Sent [$ret;$sgn]\@\n" if $DEBUG;
  close($client);
  exit 1;
}

exit 0;
