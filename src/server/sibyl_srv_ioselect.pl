#!/usr/bin/env perl
use strict;
use warnings;
use threads;
use threads::shared;
use Crypt::OpenSSL::Common;
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::Random qw/random_pseudo_bytes/;
use MIME::Base64;
use File::Slurp;
use IO::Socket qw/IPPROTO_TCP TCP_NODELAY SO_RCVTIMEO SOCK_STREAM/;
use IO::Select;

use warnings "all";

use lib qw{lib /etc/sibyl ../lib};

use sibyl;

# seed the PRNG
Crypt::OpenSSL::RSA->import_random_seed();


# base64 enconding of decryption and encryption keys
my @pem;

# socket lists
my $r_s;
my $w_s;
my $e_s;

#bless($r_s, 'IO::Select');
#bless($w_s, 'IO::Select');
#bless($e_s, 'IO::Select');

$r_s = IO::Select->new();
$w_s = IO::Select->new();
$e_s = IO::Select->new();

# prevent zombies
# no childs with IO::Select()
# $SIG{CHLD} = 'IGNORE';

# hash containing all connected clients.
# keys are just the file descriptor returned
# by accept()
my $client;
#my %client : shared;
my %data         : shared;
my %stat         : shared;
my %offset : shared;
my %nonce        : shared;

# each client has two keys:
# STATUS -> read/write
# STAGE        -> 0, 1, 2....




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


# read pem (presumably) encodings of private keys
my $i=0;
foreach ($sibyl::DECR_KEY, $sibyl::SIGN_KEY) {
        $pem[$i++] = read_file("$sibyl::CONF_DIR/$_") or
                die "Unable to read file: $!";
}

my $decr_key = Crypt::OpenSSL::RSA->new_private_key($pem[0]) or
        die "Not a private RSA key: $!";
my $sign_key = Crypt::OpenSSL::RSA->new_private_key($pem[1]) or
        die "Not a private RSA key: $!";


my $server = IO::Socket::INET->new(
				   LocalPort    => $sibyl::PORT,
				   LocalAddress => $sibyl::IP,
				   Type         => SOCK_STREAM,
				   Reuse        => 1,
				   Listen       => 5,
				   Timeout      => undef,
				  ) or
        die "Unable to create and bind socket:$!";

# server is always part of the read sockets
$r_s->add($server);


FOREVER:
while (1) {
        my ($r, $w, $e) = IO::Select::select($r_s, $w_s, undef, undef);
 READ:
        foreach (@$r) {
                if ($_ eq $server) {
                        accept($client, $server) or do {
			        print stderr "Unable to accept!\n";
			        exit(0);
                        };

                        # only write, because we are going to
                        # send a nonce.
                        $w_s->add($client);

			# no error checking for now
                        # $e_s->add($client);

                        $data{$client} = "";
                        $stat{$client} = "startup";
                        $offset{$client} = 0;
                        process_client($client);
                        next READ;
                }

                # if we know we are reading, we should just
                # read until either EOF or error happen, which
                # are easily identifiable
                my $datum;
                if ((my $status = sysread($_, $datum, 4096)) == -1) {
                        print stderr "Error reading from socket [$_]: $!\n";
                        nix($_);
                        next READ;
                } elsif ($status != 0) {
                        $data{$_} .= $datum;
                        if (length($data{$_}) > $sibyl::MAX_LEN) {
			        print stderr "Too many data from socket $_\n";
				# kill it and forget about it
				nix($_);
				next READ;
			} else {
				$r_s->remove($_);
				process_client($_);
				next READ;
                        }
                }
        }


 WRITE:
        foreach (@$w) {
                next WRITE unless ($data{$_} and length($data{$_}));
                my $written = syswrite($_, $data{$_}, 4096, $offset{$_});
                unless ($written) {
                        print stderr "Error writing on socket [$_]: $!\n";
                        nix($_);
                        $offset{$_} = 0;
                        next WRITE;
                }

                $offset{$_} += $written;

		# at this point we can only either write on
		# or have done with this socket's writing
                if (length($data{$_}) && ($offset{$_} >= length($data{$_}))) {
                        process_client($_);
                        next WRITE;
                }
        }
}

exit 0;

sub nix {
        my $_ = shift;
        $r_s->remove($_);
        $w_s->remove($_);
        $e_s->remove($_);
        shutdown $_, 0;
        close $_;
        delete $data{$_};
        delete $stat{$_};
        delete $offset{$_};
        #undef $client{$_};
        delete $nonce{$_};
}


# status can be:
# startup -> send a nonce m
# receive_data -> receive n;rsa1;rsa2
# send_answer -> send n:T:signature
sub process_client {
        my $client = shift;

	# from now one we have a classical 'case' depending on the
	# present status of the $client.
	local $_ = $stat{$client};


	# Notice that we get to this point when the status 'must change',
	# so the 'status' means NOW what has just finished happening.

	# 'startup' means nothing done yet (only created the socket
	# successfully) : must send the nonce first of all.
	/^startup$/ && do {
   	        # random string, decimal numbers;
	        my $rand1 = Crypt::OpenSSL::Random::random_pseudo_bytes(4);
		my $rand2 = Crypt::OpenSSL::Random::random_pseudo_bytes(4);
		$nonce{$client} = unpack "II", join('', $rand1, $rand2);
		$data{$client} = "$nonce{$client}\@";
		$stat{$client} = "sending_nonce";
		$offset{$client} = 0;
		# the socket should now write instead of read
		$r_s->remove($client);
		$w_s->add($client);
	};

	# sending_nonce: this means we must now receive the relevant data
	/^sending_nonce$/ && do {
	        $stat{$client} = "receive_data";
		$data{$client} = "";
		$offset{$client} = 0;
		$r_s->add($client);
		$w_s->remove($client);
	};

	# receive_data: so we now have all the necessary data to compare
	# and decide whether the authentication tokens match or not.
	# then, we shall send the answer. Notice how the status is
	# modified inside the critical_thread, because it NEEDS to
	# be done before sending any data
	/^receive_data$/ && do {
	        $r_s->remove($client);
		$w_s->remove($client);
		$e_s->remove($client);
		# this is useless with the present threads implementation
		# which does not allow objects to be : shared. Will try
		# to update asap.
		#threads->create('critical_thread', $client)->join();
		#$w_s->add($client);
		# so, critical_thread is not a thread....
		critical_thread($client);
		#$w_s->add($client);
	};

	# if we arrive here, we have replied to the client
	# and must shut down gracefully
	/^send_answer$/ && do {
	        print stderr "Shutting down [$client]\n";
		nix($client);
	};

}

# this does the dirty work (well, delegates it to parse_data)
# will be needed once we set up threads properly
sub critical_thread {
        my $cl = shift;
        #print stderr "Thread for [$cl] data: [$data{$cl}]\n";
        $offset{$cl} = 0;
        $stat{$cl} = "send_answer";
        $data{$cl} =
                parse_data($cl);
        do {
                nix($cl);
                return();
        } unless ($data{$cl});
        $w_s->add($cl);
}


# do all the dirty job, should be self-explanatory. If you
# really do not understand it, try and read all the documentation
# (the algorithm and data encapsulation is explained there).
sub parse_data {
        my $client = shift;
        my $received = $data{$client};

	# take all newlines away for simplicity.
        $received =~ s/\n//gm;

	# the message MUST conform to the following encapsulation:
        # ID;base64_1;base64_2@@
	# where ID is a nonce without ';'
	# base64_1 is a bas64 string (so it has no ';')
	# base64_2 is again a base64 string (no '@' either)
	# @@ (that is two '@') mark the end of the message
        my @message = split(/;/, $received);

        # something to do with bad answers. It must have 3 parts
        do {
                print stderr "Malformed message from client.\n";
                # print stderr "received: " . join ';', @message;
                return(undef);
        } unless (scalar @message == 3);

        my $id = shift @message;

        my @plain = map {# print stderr "$_\n" ; # (debug)
		         $decr_key->decrypt(decode_base64($_))} @message;

	# $plain[0] is (supposedly) the correct authentication token,
	#     as stored in the shadow file, as 'salt$password'
        # $plain[1] is (supposedly) the string "nonce:salt$password1",
	#     where nonce is the nonce WE sent at the beginning of the
	#     protocol and salt$password1 is the salt and the encrypted
	#     token introduced by the user (so password1 needs to be
	#     compared with password)

	#print stderr "plan[1]: [$plain[1]]\n plain[0]: [$plain[0]]\n";

	# take the nonce away from $plain[1]:
        $plain[1] =~ /^(.*?):(.*)$/;
        my $nonce_back = $1;
        $plain[1] = $2;

        # debugging purposes
        # print stderr "plain0: [$plain[0]]\n";
        # print stderr "Nonce: [$nonce_back], plain: [$plain[1]]\n";

	# this is the core: compare passwords and nonces. If both
	# are correct, send a signed message with the nonce sent
	# by the client and '1', otherwise, with nonce:'0'.
	# signature done with the signing key.
        if (($plain[0] eq $plain[1]) && ($nonce_back eq $nonce{$client})) {
                my $ret = "$id:$sibyl::AUTH_OK";
                my $sgn = encode_base64($sign_key->sign($ret));
                $sgn =~ s/\n//g;
                return(join(';',($ret,$sgn)) . "\@");
        } else {
                my $ret = "$id:$sibyl::AUTH_NO";
                my $sgn = encode_base64($sign_key->sign($ret));
                $sgn =~ s/\n//g;
                return(join(';',($ret, $sgn)) . "\@");
        }
}


