package sibyl;

require Exporter;
our @ISA = ("Exporter");

our @EXPORT = qw($DECR_KEY $SIGN_KEY $SERVER $PORT $FELON $MISAUTH);

# $DIGEST:
# can be:
# crypt (standard Unix/Perl for shadow files)
# sha1

$DIGEST   = "none";
%DIGEST_AV = (none  => 1,
	      crypt => 1,
	      );

$CONF_DIR = "./";
$DECR_KEY = "decrypt";
$SIGN_KEY = "sign";
$SERVER = "localhost"; # for testing and build purposes
$IP     = "127.0.0.1";
$PORT   = "9999"; # default

$MAX_LEN = 16385;


$FELON   = 2;
$MISAUTH = 3;
$MESSAGE_TOO_LONG = 4;
$MALFORMED_MESSAGE = 5;

$AUTH_OK = 1;
$AUTH_NO = 0;



1;

