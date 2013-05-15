#!/usr/bin/perl
use strict;
use Crypt::OpenSSL::RSA;
use MIME::Base64;
use Digest::SHA1 qw /sha1_hex/;
use sibyl;
use File::Slurp;

my $keyb64   = read_file("$sibyl::DECR_KEY.pub") or
  die "Unable to open public key: $!";
my $encr_key = Crypt::OpenSSL::RSA->new_public_key($keyb64) or
  die "Not a private RSA key: $!";

my $os = "shadow-file";
ARG:
while (local $_ = shift @ARGV) {
  /^-k$/ && do {
    $keyID = shift @ARGV;
    next ARG;
  };

  /^-snow-leopard$/ && do {
    $os = "snow-leopard";
    next ARG;
    };

  /^-leopard$/ && do {
    $os = "leopard";
    next ARG;
  };

  /^-h$/ && do {
    print <<EOM;
Usage: shadow2rsa64.pl [-snow-leopard] [-leopard]

EOM
  }
}

# if os = "shadow-file", parse a file, which will probably be from
# the OS /etc directory.
if ($os eq "shadow-file") {
  while (<>) {
    do {
      print ;
      next;
    } if /\A[^:]+:(\*|\!)+:/;
    chomp;
    my @item = split /:/;
    my @new2;
    if ($item[1] =~ /\$.*/) {
      @new2 = split(/\$/, $item[1]);
    }
    $new2[-1] = encode_base64($encr_key->encrypt(join('$', @new2)));
    $new2[-1] =~ s/\n//g;
    #unshift @new2, '';
    $item[1] = join('$', @new2);
    print (join ':', @item);
    # my $keyb64 = read_file("$sibyl::DECR_KEY");
    #   my $encr_key = Crypt::OpenSSL::RSA->new_private_key($keyb64);
    #   print $new2[-1];
    #   print $encr_key->decrypt(decode_base64($new2[-1]));
    print "\n";
  }
}


# snow-leopard. Creepy....
if ($os eq "snow-leopard") {
  my $command = `dscl . -list /Users GeneratedUID`;
  my @user    = split "\n", $command;
 USER:
  foreach (@user) {
    my ($name, $uid) = split /\s+/;
    my $salted_hash = `cut -n -b 169-216 /var/db/shadow/hash/$uid 2>/dev/null`;
    my $salt = substr $salted_hash, 0, 8;
    my $hash = substr $salted_hash, 8;
    next USER unless $salted_hash;
    my $b64_hash = encode_base64($encr_key->encrypt($salted_hash));
    $b64_hash =~ s/\n//gm;
    print "$name:$salt\$${b64_hash}::::::\n";
    # print "$salt, $hash\n";
    # my $bsalt = pack("H8", $salt);
    # my $bsalt = `echo -n $salt | xxd -r -p `;
    # the following outputs $salted hash
    # print $salt . uc sha1_hex($bsalt,'[here comes the password]') . "\n";
  }
}
