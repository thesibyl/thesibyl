#ifndef __PAM_SIBYL
#define __PAM_SIBYL
#endif

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

/* directory, filename, server, port */
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

#define _IP "192.168.1.2"
#define _PORT  "9999"

#ifndef _OPENPAM
static char password_prompt[] = "Password:";
#endif

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

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



/* API */
int pam_sm_authenticate(pam_handle_t *, 
                        int, 
                        int, 
                        const char *[]);

int pam_sm_chauthtok(pam_handle_t *, 
                     int, 
                     int, 
                     const char *[]);

int _sibyl_setup(pam_handle_t* pamh, 
                 int * socket, 
                 RSA ** sign_pub, 
                 RSA ** encrypt, 
                 char * nonce,
                 const char * IP, 
                 const char * port, 
                 const char * conf_dir);

int _sibyl_get_username_authtok(pam_handle_t * pamh, 
                                char * user,
                                char * salt, 
                                char * shadow_pwd,
                                const int root_ok,
                                const int fetch_user,
                                const char * dir);

int _sibyl_conv(int, 
                RSA *, 
                RSA *, 
                const char *, 
                const char *);

#ifndef _OPENPAM
int _sibyl_passwd_conv(pam_handle_t *pamh, 
                       char * message, 
                       char ** password, 
                       struct pam_conv * conv);
#else
int _sibyl_passwd_conv(pam_handle_t * pamh, 
                       char * message, 
                       char ** password);
#endif

int _sibyl_dialogue(pam_handle_t * pamh, 
                    const int sock, 
                    const RSA * sign, 
                    const RSA * encrypt, 
                    const char * salt, 
                    const char * cryptd_pwd, 
                    const char * shadow_pwd, 
                    const char * nonce);


int _sibyl_encrypt(char * cryptd_pwd, 
                   const char * password, 
                   const char * salt);

int _sibyl_rsa_b64(char * dest, 
                   const u_char * cryptd_pwd, 
                   const RSA * encrypt);

char * _sibyl_make_salt(char * salt);

int fwritepwent(FILE * pwd_file, 
                struct passwd * entry, 
                char * new_shadow_token, 
                char * salt);

#ifdef __APPLE__
struct passwd *fgetpwent(FILE *pwd_file);
#endif
          

