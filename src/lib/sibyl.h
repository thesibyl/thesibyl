#ifndef __SIBYL_SRV
#define __SIBYL_SRV
#endif

/* most of this file is a copy-paste from pam_sibyl.h
 * this should change, obviously, in the future
 */

/* limits for different parameters */
#define SIBYL_ARG_LENGTH  256
#define SIBYL_PAR_LENGTH   16
#define SIBYL_VAL_LENGTH  240
#define SIBYL_PORT_LENGTH   6
#define SIBYL_IP_LENGTH   128
#define SIBYL_NONCE_LENGTH 65 /* much more than needed: 8 bytes */

/* nonce (64) + bs64(128bytes) + bs64(128bytes) + extra (and A LOT MORE) */
#define SIBYL_MAX_MSG    2120

/* next one should depend on RSA_size()
 * much much more than needed: 128*4/3
 * 1024 is enough for a 512 bytes key
 * that is, 4096 bits..., and more
 */
#define SIBYL_B64_PWD_LENGTH 1024 


#ifndef PASS_MAX
#ifdef BUFSIZ
#define PASS_MAX BUFSIZ
#else
#define PASS_MAX 128
#endif
#endif

/* no hash function gives this so long an output to date */
#define SIBYL_CRYPTD_PWD_MAX 1024

/* use custom size, large enough */
#define SIBYL_NAME_MAX 1024
#define SIBYL_SALT_MAX   40

#define FETCH_USER 1
#define DONT_FETCH_USER 0

/* some other constants */
#define OPTS "d:f:s:p:"
#define FILE_LEN strlen("decrypt.pub")
#define SALT_REGEXP "^(\$.*\$)";

/* root_ok? *should* not be sibyl-dependent,
 * but this may be configurable later on
 */
#define ROOT_OK_NO 0

/*#define _IP    "127.0.0.1"*/
/* this is a reasonable default, and it can
 * be configured ip=... in the pam file
 */

#define SIBYL_IP "192.168.1.2"
#define SIBYL_PORT  "9999"

#ifndef _OPENPAM
static char password_prompt[] = "Password:";
#endif

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

/* sibyl_srv specific constants */

/* number of pending connections in the queue */
#define SIBYL_BACKLOG 20		

/* default configuration directory and key names */
#define SIBYL_DIR "/etc/sibyl"	
#define SIBYL_DECR_KEY "decrypt"
#define SIBYL_SIGN_KEY "sign"


/* server error messages */
#define SIBYL_SUCCESS       0
#define SIBYL_RECV_ERROR    10000
#define SIBYL_NASTY_CLIENT  10001
#define SIBYL_MALFORMED_MSG 10002
#define SIBYL_OPENSSL_ERROR 10003
#define SIBYL_KEYS_ERROR    10004
#define SIBYL_LISTEN_ERROR  10005

/* convenience */
#define MAX(a,b) ((a) >= (b)) ? (a) : (b)
#define MIN(a,b) ((a) <= (b)) ? (a) : (b)

/* debugging */
#ifdef DEBUG          
#define D(x) syslog(LOG_NOTICE, (x))
#define D1(x,y) syslog(LOG_NOTICE, (x),(y))
#else
#define D(x) /**/
#define D1(x,y) /**/
#endif

