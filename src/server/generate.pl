#!/usr/bin/env perl

use warnings;
use Crypt::OpenSSL::Random;
use Crypt::OpenSSL::RSA;
use File::Slurp;

my $input = read_file("../keys/sign");



my $decr_key = Crypt::OpenSSL::RSA->new_private_key($input) or
  die "Not a private RSA key: $!";

#my $sign = Crypt::OpenSSL::RSA->new_private_key($decr_key);
#my $decrypt = Crypt::OpenSSL::RSA->generate_key(2048);

my $decr_string = $decr_key->get_private_key_string();

print "$decr_string\n";
