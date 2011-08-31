/* notice that one cannot assume Linux has OpenPAM implemented */

/* we are going to use crypt_r, and this requires _GNU_SOURCE */
/* the following does not work on Darwin/  BSD? */
/* crypt.h does not exist in Darwin */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef __APPLE__
#ifndef __AVAILABILITYMACROS__
#include <AvailabilityMacros.h>
#endif
#endif

#include <limits.h>
#include <time.h>
#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>
#include <syslog.h>
#include <signal.h>
#include <sys/types.h>
#include <ctype.h>

#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/des.h>

#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <security/pam_modules.h>
#include <security/pam_appl.h>

/* strange, the other systems include crypt() in unistd.h */
#ifdef linux
#include <crypt.h>
#endif

#include "pam_sibyl.h"
#include "bsd-base64.h"

/* _sibyl_setup:
 * setup all the needed infrastructure to perform the communication
 * protocol:
 *
 * INPUT:
 *   *pam_h -> PAM handle for possible communication (unused)
 *   [the following get modified]
 *   *sock  -> socket for connecting with the Sibyl
 *   **sign_pub, **encrypt -> pointers to the public keys (signing/encryption)
 *   *nonce -> nonce received FROM the Sibyl upon start of the protocol
 *             MUST point to AT LEAST SIBYL_NONCE_LENGTH bytes. This is NOT
 *             checked!
 *   [the following are const]
 *   *IP     -> Sibyl's IP
 *   *port   -> Sibyl's listening port
 *   *dir    -> configuration dir
 *
 * OUTPUT:
 *   PAM_SUCCESS upon successful setup
 *   PAM_SYSTEM_ERR if something went wrong
 *
 * COLLATERAL EFFECTS
 *   The non-constant variables *sock, **sign_pub, **encrypt, *nonce are
 *       modified according to their nature
 *
 */
int _sibyl_setup(pam_handle_t *pamh,
                 int *sock, 
                 RSA **sign_pub, 
                 RSA **encrypt, 
                 char *nonce,
                 const char *IP, 
                 const char *port, 
                 const char *dir){
	int status;
        struct addrinfo hints, *sibyl_adds;

        memset(&hints, 0, sizeof hints);
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

	/* just in case, but useless as of today */
	/* struct sockaddr_in *sibyl_addrv4; */
	/* struct sockaddr_in6 *sibyl_addrv6; */

        /* Try and do connect with the Sibyl */
        status = getaddrinfo(IP, port, &hints, &sibyl_adds);
        if(status != 0){
                syslog(LOG_NOTICE, "Unable to connect to the Sibyl: %s", 
                       gai_strerror(status));
                return(PAM_SYSTEM_ERR);
        }

	if ((*sock = socket(sibyl_adds->ai_family, 
                           sibyl_adds->ai_socktype,
                           sibyl_adds->ai_protocol)) < 0){
		syslog(LOG_NOTICE, "Unable to create the socket");
		return(PAM_SYSTEM_ERR);
	}

	if (connect(*sock, sibyl_adds->ai_addr, sibyl_adds->ai_addrlen) < 0){
		syslog(LOG_NOTICE, "Unable to establish socket with the Sibyl");
		return(PAM_SYSTEM_ERR);
	}
	
	/* connection open */
	D("Socket established with the Sibyl");
	freeaddrinfo(sibyl_adds);


	/* RSA public keys */
	char *encr_fname, *sign_fname;
	encr_fname = (char *)calloc(_POSIX_PATH_MAX, sizeof(char));
	sign_fname = (char *)calloc(_POSIX_PATH_MAX, sizeof(char));
	if(encr_fname == NULL || sign_fname == NULL)
		return(PAM_SYSTEM_ERR);


	if(strlen(dir) >= _POSIX_PATH_MAX ||
	   FILE_LEN >= _POSIX_PATH_MAX ||
	   (strlen(dir) + 1 + FILE_LEN) >= _POSIX_PATH_MAX)
		return(PAM_SYSTEM_ERR);


	/* following names should? be configurable */
        /* and obviously < FILE_LEN */
	strncat(encr_fname, dir, _POSIX_PATH_MAX);
	strncat(encr_fname, "/decrypt.pub", strlen("/decrypt.pub"));
	strncat(sign_fname, dir, _POSIX_PATH_MAX);
	strncat(sign_fname, "/sign.pub", strlen("/sign.pub"));


        D("About to read the keys");

	/* fetch the RSA keys */
	FILE *encr_f, *sign_f;
	encr_f = fopen(encr_fname, "r");
	sign_f = fopen(sign_fname, "r");    
	if(encr_f == NULL || sign_f == NULL){
                syslog(LOG_NOTICE, "Unable to allocate memory for encry_f"
                       " or sign_f");
		return(PAM_SYSTEM_ERR);
        }
	D("Key files open");

	/*RSA *encrypt, *sign;*/
	*encrypt     = RSA_new();
	*sign_pub    = RSA_new();
	if(*sign_pub == NULL || *encrypt == NULL){
                syslog(LOG_NOTICE, "Unable to RSA_new() encrypt or sign_pub");
		return(PAM_SYSTEM_ERR);
        }
        /* try and read the keys twice if once fails,
         * using two different PEM formats
         */
        /* first try */
	PEM_read_RSAPublicKey(encr_f, encrypt, NULL, NULL);
	PEM_read_RSAPublicKey(sign_f, sign_pub, NULL, NULL);

        /* second try */
	if((*encrypt)->n == NULL || (*sign_pub)->n == NULL){
		rewind(encr_f);
		rewind(sign_f);
		PEM_read_RSA_PUBKEY(encr_f, encrypt, NULL, NULL);
		PEM_read_RSA_PUBKEY(sign_f, sign_pub, NULL, NULL);
	}
	if((*encrypt)->n == NULL || (*sign_pub)->n == NULL){
		syslog(LOG_NOTICE, "Unable to read the RSA Keys");
                fclose(sign_f);
                fclose(encr_f);
		return(PAM_SYSTEM_ERR);
	}
	fclose(sign_f);
	fclose(encr_f);


	/* Get the nonce, be careful with the number of bytes received
         * and the answer (must end in '@', otherwise ERR)
	 */
        int count_bytes = 0;
        int bytes_rcvd  = 0;
        while(count_bytes == 0 || *(nonce+(count_bytes-1)) != '@'){
                count_bytes += (bytes_rcvd = recv(*sock, nonce+count_bytes, SIBYL_NONCE_LENGTH - 1, 0)); 
                if(bytes_rcvd <=0 || count_bytes >= SIBYL_NONCE_LENGTH){
                        syslog(LOG_NOTICE, "Error while getting nonce from the Sibyl");
                        return(PAM_SYSTEM_ERR);
                }
        }
	/* chomp nonce, just in case: 
         * we are effectively deleting the '@' at the end
	 */
        *(nonce+(count_bytes-1)) = 0;
        D("Exiting sibyl_setup");
        /* can only get here upon success */
        return(PAM_SUCCESS);
}



/* _sibyl_get_username_authtok:
 * get both the username and the stored authentication token (that is, the
 * token in /etc/sibyl/shadow associated with the target user, which contains
 * a salt as well).
 *
 * INPUT:
 *   *pamh-> PAM handle for PAM messaging
 * [the following get modified]
 *   *user      -> target user. If not empty, it will be filled with the
 *                 result of pam_get_user(). Must point to at least
 *                 SIBYL_NAME_MAX bytes
 *   *salt      -> salt used for the hashing
 *                 MUST POINT TO a chunk of memory able to hold the salt
 *                 (SIBYL_SALT_MAX bytes)
 *   *shadow_pwd-> shadow token (the b64(RSA(crypt('pass','salt'))) in Linux)
 *                 MUST POINT TO at least SIBYL_B64_PWD_LENGTH bytes
 * [the following are const]
 *   root_ok    -> is the Sibyl configured as root_ok? (see man pam_sibyl)
 *   fetch_user -> ask for the user? (we may alredy know it): BOOL
 *   dir        -> configuration dir ("/etc/sibyl/" by now)
 *
 * OUTPUT:
 *   PAM_SUCCESS      if the username and authtok could be retrieved
 *   PAM_IGNORE       if target user is root and Sibyl configured to
 *                      ignore root (which is the default for security reasons)
 *   PAM_USER_UNKNOWN if the target user is NOT in the password 
 *                      database (and the running user is not root)
 *   PAM_SYSTEM_ERR   if any error occurred
 *
 * COLLATERAL EFFECTS:
 *   *user, *salt and *shadow_pwd are filled with the appropriate content
 */
int _sibyl_get_username_authtok(pam_handle_t *pamh, 
                                char *user,
                                char *salt, 
                                char *shadow_pwd,
                                const int root_ok,
                                const int fetch_user,
                                const char *dir){
        char *_user; /* local variable, either a copy of user or
                      * the result of pam_get_user()
                      */
	struct passwd *pwd;
	FILE *shadow;
        int pam_err;


        D1("Entering _get_username_authtok [%s]", user);
        /* if we have been already given a user, do not query for it */
        if(fetch_user){
                if(user == NULL){
                        syslog(LOG_NOTICE, "Cannot fetch user for a NULL variable");
                        return(PAM_SYSTEM_ERR);
                }
                /* identify user and get 'password' */
                if ((pam_err = pam_get_user(pamh, (const char **)&_user, NULL)) != PAM_SUCCESS){
                        syslog(LOG_NOTICE, "pam_get_user gives an error");
                        return (pam_err);
                }
                /* root user should be ingored, unless explicitely stated */
                if(!root_ok && strncmp(_user, "root", 4) == 0){
                        syslog(LOG_NOTICE, "root user ignored by sibyl");
                        return(PAM_IGNORE);
                }
        } else {
                if(user == NULL){
                        syslog(LOG_NOTICE, "NULL user");
                        return(PAM_SYSTEM_ERR);
                }
                _user = (char *)calloc(SIBYL_NAME_MAX, sizeof(char ));
                strncpy(_user, user, SIBYL_NAME_MAX - 1);
        }

        /* should be configurable (use dir: TODO) */
        shadow = fopen("/etc/sibyl/shadow", "r");
        if(shadow == NULL){
                syslog(LOG_NOTICE, "Unable to read the shadow database");
                return(PAM_SYSTEM_ERR);
        }
                
	/* this should be done with getpwnam, but does it do it OK? */
        /* Is the user in our shadow database? */
        int user_exists = 0;
	while((pwd = fgetpwent(shadow)) != NULL && pwd->pw_name != NULL){
		if(strcmp(pwd->pw_name, _user)==0){
                        user_exists = 1;
			break;
                }
	}
	fclose(shadow);

        if(user_exists == 0){
		D1("User does not exist, return: [%s]", user);
                return(PAM_USER_UNKNOWN);
	}            
	/* extract all the info from pwd->pw_passwd:
	 * pwd->pw_passwd is the b64(RSA(crypt(pwd))) preceded by the salt
         * (see the doc on the Sibyl protocol and storage of tokens)
	 */

        /* pwd->pw_passwd =~ /^(.*$)(.*)$/
         * and $1 -> salt
         *     $2 -> token
         */
	regex_t *salt_regex = (regex_t *)calloc(1,sizeof(regex_t));
	size_t nmatch = 2;
	regmatch_t pmatch[2];

	if(salt_regex == NULL){
                syslog(LOG_NOTICE, "Cannot compile salt regex, ??");
		return(PAM_SYSTEM_ERR);
        }
	/* salt is any sequence of characters up to the LAST '$' */
	if(regcomp(salt_regex, "(.*\\$)", REG_EXTENDED) != 0){
                syslog(LOG_NOTICE, "The salt does not conform to the standard regexp"
                       "for user [%s]", pwd->pw_name);
		return(PAM_SYSTEM_ERR);
        }
	/* get the salt from the shadow token */    
	if(regexec(salt_regex, pwd->pw_passwd, nmatch, pmatch, 0) != 0){
		syslog(LOG_NOTICE, "pwd->pw_passwd entry does not conform to salt "
		       "followed by code for user [%s]", pwd->pw_name);
		return(PAM_SYSTEM_ERR);
	}

	/* cut the shadow token into two: salt + b64_RSA_encrypted_password */
	int matchlen = pmatch[1].rm_eo - pmatch[1].rm_so;
	memcpy(salt, 
               pwd->pw_passwd+(pmatch[1].rm_so), 
               MIN(matchlen, SIBYL_SALT_MAX-1));

        if(fetch_user) /* user is not null (we know it from above) */
                memcpy(user,
                       pwd->pw_name,
                       MIN(strlen(pwd->pw_name), SIBYL_NAME_MAX-1));

        memcpy(shadow_pwd, 
               (pwd->pw_passwd)+(pmatch[1].rm_eo), 
               MIN(strlen(pwd->pw_passwd)-pmatch[1].rm_eo, SIBYL_B64_PWD_LENGTH-1));

        D("Exiting _get_username");

        return(PAM_SUCCESS);
}



/* _sibyl_passwd_conv:
 * Perform the password conversation.
 * This is delegated to PAM completely (more or less)
 *
 *
 * INPUT:
 *   *pamh     -> PAM handle for PAM messaging
 *   *message  -> Message to be shown
 *   **password-> pointer to store the password in. Will be filled with
 *                the authentication token retrieved by pam_get_authtok
 *                or (*conv)->conv (basically PAM's pwd converation)
 *   [*conv]   -> pam_conv (used only if not OPENPAM and not well done: TODO)
 *
 * OUTPUT:
 *   PAM_SUCCESS    -> Upon complete and proper conversation end
 *   PAM_SYSTEM_ERR -> Otherwise
 *
 * COLLATERAL EFFECTS:
 *   *password is filled with the cleartext password as entered by the user
 *             (if AUTHTOK was set by a previous module, use this one)
 *
 */
#ifndef _OPENPAM
int _sibyl_passwd_conv(pam_handle_t *pamh,
                       char *message,
                       char **password,
                       struct pam_conv *conv){
	struct pam_message msg;
	const struct pam_message *msgp;
	struct pam_response *resp;
        int pam_err;

	pam_err = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
	if (pam_err != PAM_SUCCESS){
                syslog(LOG_NOTICE, "Cannot get password from the user");
		return (PAM_SYSTEM_ERR);
        }
	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg = message;
	msgp = &msg;
#else
int _sibyl_passwd_conv(pam_handle_t *pamh,
                       char *message,
                       char **password){
        int pam_err;
#endif
        int retry=0;
        char *pass;
        
        /* get 'password' from the user, 
         * this is normally 
         * done by the pam libraries.
         */        
	for (retry = 0; retry < 3; ++retry) {
#ifdef _OPENPAM
		pam_err = pam_get_authtok(pamh, PAM_AUTHTOK,
					  (const char **)&pass, NULL);
#else
		resp = NULL;
		pam_err = (*conv->conv)(1, &msgp, &resp, conv->appdata_ptr);
		if (resp != NULL) {
			if (pam_err == PAM_SUCCESS)
				pass = resp->resp;
			else
				free(resp->resp);
			free(resp);
		}
#endif
		if (pam_err == PAM_SUCCESS)
			break;
	}

	if (pam_err == PAM_CONV_ERR){
                syslog(LOG_NOTICE, "Conversation error");
		return (pam_err);
        }
	if (pam_err != PAM_SUCCESS)
		return (PAM_AUTH_ERR);

        /* copy item to password and forget pass */
        *password = pass;

        return(PAM_SUCCESS);
}

/* _sibyl_dialogue:
 * perform the authentication step of the protocol. All the parameters
 * are constants because there are no collateral effects (apart from
 * possibly setting some value in pamh, which might happen anywhere).
 *
 * INPUT:
 *   *pamh       -> PAM handle for PAM messaging
 *   sock        -> socket connected with the Sibyl
 *   *sign       -> public key for signature verification
 *   *encrypt    -> public key for encryption
 *   *salt       -> salt the password was hashed with
 *   *cryptd_pwd -> the result of (crypt('password', 'salt') in Linux,
 *                     that is the hash of the password typed by the user
 *   *shadow_pwd -> the shadow token stored in the shadow file to be
 *                     tested against the typed password
 *
 * OUTPUT:
 *   PAM_SUCCESS -> if authentication was successful (i.e. the password
 *                     matches the shadow token
 *   PAM_SYSTEM_ERR  -> if there was any kind of error
 *   PAM_SERVICE_ERR -> error in communication with the Sibyl (which
 *                      includes signature error)
 *   PAM_PERM_DENIED -> password and shadow do not match
 */

int _sibyl_dialogue(pam_handle_t *pamh,
                    const int sock,
                    const RSA *sign,
                    const RSA *encrypt,
                    const char *salt,
                    const char *cryptd_pwd,
                    const char *shadow_pwd,
                    const char *nonce){

        int pam_err;
        int bytes_rcvd = 0;
        
	/* We send the Sibyl the following:
	 * n;b64_1;b64_2\n@@\n
	 * where 
	 * n     is a nonce we generate (usually diferent from 'nonce', the
	 *       one received from the Sibyl)
	 * b64_1 is the entry in the 'shadow' file corresponding to the user
	 * b64_2 is the ouput of b64_encode(RSA_encrypt("nonce:crypt(passwd, salt)"))
	 *       ---that is, b64_encode(RSA_encrypt("nonce:crypted_pwd"))
	 *       where, here, nonce is the nonce received from the Sibyl.
	 * The trailing \n@@\n is the end-of-message notification
	 */

	/* generate the b64_2 above first of all */ 
	char *nonce_pwd = (char *)calloc(SIBYL_MAX_MSG, sizeof(char));
	if(nonce_pwd == NULL){
		syslog(LOG_NOTICE, "Unable to allocate memory for nonce_pwd");
		return(PAM_SYSTEM_ERR);
	}

        D1("Crypted pwd [%s]", cryptd_pwd);
	strcat(nonce_pwd, nonce);
	strcat(nonce_pwd, ":");
	strcat(nonce_pwd, cryptd_pwd);

	char *rsa_pwd, *b64_pwd;
	rsa_pwd = (char *) calloc(RSA_size(encrypt)+1,1);
	if(rsa_pwd == NULL){
		syslog(LOG_NOTICE, "Unable to allocate memory for rsa_pwd");
		return(PAM_SYSTEM_ERR);
	}

	int rsa_e;
	rsa_e = RSA_public_encrypt(strlen(nonce_pwd),
				   (u_char *) nonce_pwd,
				   (u_char *) rsa_pwd,
				   (RSA *)    encrypt,
				   RSA_PKCS1_OAEP_PADDING);
	if(rsa_e != RSA_size(encrypt)){
		syslog(LOG_NOTICE, "RSA encryption error... this should not happen");
		return(PAM_SYSTEM_ERR);
	}

	b64_pwd = (char *)calloc(SIBYL_B64_PWD_LENGTH, sizeof(char ));
	if(b64_pwd == NULL){
		syslog(LOG_NOTICE, "Unable to allocate memory for b64_pwd");
		return(PAM_SYSTEM_ERR);
	}

	b64_ntop((u_char *)rsa_pwd, 
                 RSA_size(encrypt), 
                 b64_pwd, 
                 RSA_size(encrypt) * 4);

        
        /* generate a random nonce. 
         * The random engine was seeded 
         * in _sibyl_setup()
         */
	u_char my_nonce[9];
        int count;
	char *my_strnonce;
	my_strnonce = (char *) calloc(17, sizeof(char *));
	if(my_strnonce == NULL){
		syslog(LOG_NOTICE, "Unable to allocate memory for my_strnonce");
		return(PAM_SYSTEM_ERR);
	}
        RAND_bytes(my_nonce, 8);
        for(count = 0; count < 8; count++)
                sprintf(my_strnonce+count*2, "%02X", my_nonce[count]);
        D1("nonce: [%s]", my_strnonce);


	/* join with ';' all the strings... */    
	char *message;
	message = (char *) calloc(strlen(my_strnonce) + 
				  strlen(shadow_pwd) +
				  strlen(b64_pwd) + 
				  4, sizeof(char));

	if(message == NULL){
		syslog(LOG_NOTICE, "Unable to allocate memory for message");
		return(PAM_SYSTEM_ERR);
	}
	strncat(message, my_strnonce, SIBYL_NONCE_LENGTH-1);
	strncat(message, ";", 1);
	strncat(message, shadow_pwd, SIBYL_B64_PWD_LENGTH-1);
	strncat(message, ";", 1);
	strncat(message, b64_pwd, SIBYL_B64_PWD_LENGTH-1);


	/*
	 * should try several times? Yes, possibly should 
	 * and should make sure that the whole message is
	 * sent, probably. Let us rely on the network layer
	 */

        D1("Sending: [%s]", message);
	if(send(sock, message, strlen(message) + 4, 0) == -1){
		syslog(LOG_NOTICE, "Unable to send a message to the Sibyl");
		return(PAM_SYSTEM_ERR);
	}
    
	if(send(sock, "\n@@\n", 4, 0) ==-1){
		syslog(LOG_NOTICE, "Unable to send the termination sequence to the Sibyl");
		return(PAM_SYSTEM_ERR);
	}

	/* receive answer */
	char *ans;
        /* base64 encode RSA + enough space for nonce + ; */
	u_int ans_length = SIBYL_MAX_MSG; /*SIBYL_MAX_MSG-1;*/
	ans = (char *) calloc(SIBYL_MAX_MSG, sizeof(char));
	if(ans == NULL){
		syslog(LOG_NOTICE, "Unable to allocate memory for the Sibyl's answer");
		return(PAM_SYSTEM_ERR);
	}
	
	int count_bytes = 0;	
	while(count_bytes == 0 || ans[count_bytes-1] != '@'){
		if((bytes_rcvd = recv(sock, ans + count_bytes, ans_length - count_bytes, 0)) <= 0){
			syslog(LOG_NOTICE, "Connection error with the Sibyl, "
			       "received [%i] bytes through [%i], and till now "
			       "the answer was [%s]", bytes_rdcvd+count_bytes, sock, ans);
			return(PAM_SYSTEM_ERR);
		}
		if((count_bytes += bytes_rcvd) > ans_length){
			syslog(LOG_NOTICE, "Sibyl is sending more bytes than necessary");
			return(PAM_SYSTEM_ERR);
		};
	}
	ans[count_bytes-1] = 0;
	D1("Received: [%s]", ans);

	/* parse answer, which (supposedly) is as follows:
	 * M;signature
	 * where 
	 * M is a message (text without semicolons)
	 * signature is the RSA signature of M
	 *    actually (b64_enc(signature)), so we have to
	 *    b64-decode it.
	 */

	/* Also, M must conform to the following structure:
	 * M == n:X
	 * where
	 * n is the nonce sent by us before
	 * X is either '0' or '1', for 'Not authenticated', 'Authenticated'
	 */

	char *token[2];
	token[0] = strsep(&ans, ";");
	if(token[0] == NULL){
		syslog(LOG_NOTICE, "Malformed answer received from the Sibyl");
		return(PAM_SYSTEM_ERR);
	}

	token[1] = ans;
	if(token[1] == NULL){
		syslog(LOG_NOTICE, "Malformed answer received from the Sibyl");
		return(PAM_SYSTEM_ERR);
	}

        /* sha1 -> 20 bytes */
	char *sha1_m = (char *)calloc(20, sizeof(char));
	SHA1((u_char *)token[0], strlen(token[0]), (u_char *)sha1_m);
	char *signature = (char *)malloc(RSA_size(sign) + 1);
	if(sha1_m == NULL || signature == NULL){
		syslog(LOG_NOTICE, "Unable to allocate memory for sha1_m or signature");
		return(PAM_SYSTEM_ERR);
	}

	/* decode the signature */
	b64_pton(token[1],
		 (u_char *)signature, 
                 RSA_size(sign) + 1);

        /* sha1 -> 20 bytes */
	if(RSA_verify(NID_sha1,
		      (u_char *)sha1_m, 
                      20,
		      (u_char *)signature, 
                      RSA_size(sign),
		      (RSA *)sign) != 1){
		syslog(LOG_NOTICE, "Message wrongly signed");
		return(PAM_SERVICE_ERR);
	}


	/* parse the first part of the message (the answer stricto sensu) */
	/* reuse token[1] and token[0] */
	token[1] = token[0];
	token[0] = strsep(&token[1], ":");
	if(token[0] == NULL){
		syslog(LOG_NOTICE, "Malformed answer from the Sibyl");
		return(PAM_SERVICE_ERR);
	}
	/*token[1] = strtok(NULL, ":");*/
	if(token[1] == NULL){
		syslog(LOG_NOTICE, "Malformed answer from the Sibyl");
		return(PAM_SERVICE_ERR);
	}

	if(strcmp(token[0], my_strnonce) != 0){
		syslog(LOG_NOTICE, "Connection error: wrong nonce");
		return(PAM_SERVICE_ERR);
	}

	if(strcmp(token[1], "1") != 0){
		syslog(LOG_NOTICE, "Authentication error");
 		return(PAM_PERM_DENIED);
	}
	pam_err = PAM_SUCCESS;
        return(pam_err);
}



/* _sibyl_encrypt:
 * encrypt password following OS's uses
 * this means: 
 *    - on most Unices, use either crypt_r or crypt
 *    - on OS X (Snow Leopard, Leopard?) use a mix of SHA1 and
 *      salt
 *    - No more implementations to date
 *
 * INPUT:
 *  [gets modified]
 *  *cryptd_pwd   -> the output of the OS's encryption function
 *                   MUST have been allocated for SIBYL_CRYPTD_PWD_MAX
 *  [constants]
 *  *password     -> the password as typed by the user
 *  *salt         -> the salt parameter 
 *
 * OUTPUT:
 *   PAM_SYSTEM_ERR -> upon error
 *   PAM_SUCCESS    -> otherwise
 *
 * REMARK:
 * This function is obviously an amalgam of
 * #ifdefs
 *    LONG CODE
 * #endif
 * one for each operating system.
 *
 */
int _sibyl_encrypt(char *cryptd_pwd,
                   const char *password, 
                   const char *salt){
        int i;

	/* Following code for using crypt_r:
         * this is highly system-dependent, so
         * should be modified for each system.
         * The function crypt_r can be found only
         * on systems running glibc2. So, it is missing
         * on OS X, Free/Net/Open BSD, and quite a few
         * others. That is, it is only on Linux platforms.
         */


/* Systems with glibc2 including crypt_r (Linux) */
#ifdef  _CRYPT_H
        struct crypt_data *crd;
        crd = (struct crypt_data *) calloc(1, sizeof(struct crypt_data));
        if(crd == NULL){
                syslog(LOG_NOTICE, "Unable to allocate memory for crd");
                return(PAM_SYSTEM_ERR);
        }

	D1("About to crypt_r with salt [%s]", salt);

 	crd->initialized = 0; 
        crypt_r(password, salt, crd);
	D("Crypted");

        memcpy(cryptd_pwd, crd->keysched, 
               MIN(SIBYL_CRYPTD_PWD_MAX-1, strlen(crd->keysched)));

	/* The follwoing does not work: segfaults sshd... ? 
         * I still don't get it.
	 * It is because crypt(3) is not thread safe.
         *       [DOES NOT WORK]
	 *       strncpy(cryptd_pwd, crypt(password, salt), 1024); 
         *       [DOES NOT WORK]
	 */

	if(cryptd_pwd == NULL){
		syslog(LOG_NOTICE, "Unable to crypt_r() the password");
		return(PAM_SYSTEM_ERR);
	}
	memset(crd, 0, sizeof(crd));
	
#endif
/* End of systems with crypt_r */

/* Only Apple 10.6> */
#ifdef __APPLE__
#ifdef MAC_OS_X_VERSION_10_6
        char *cryptd_pwd_b = (char *)calloc(SIBYL_CRYPTD_PWD_MAX,sizeof(char));
        char *salt_b       = (char *)calloc(SIBYL_CRYPTD_PWD_MAX
                                            + 10 /* salt length in bytes + extra */,
                                            sizeof(char ));
        char *salt_buffer  = (char *)calloc(16, sizeof(char ));
        if(cryptd_pwd_b == NULL || salt_b == NULL || salt_buffer == NULL){
                syslog(LOG_NOTICE, "Unable to allocate memory for cryptd_pwd_b"
                        " or for salt_b or for salt_buffer");
                return(PAM_SYSTEM_ERR);
        }
        /* salt as an integer */
        u_int salt_i;

        /* follows a bit of hacking */
        snprintf(salt_buffer, 16, "0x%8s", salt);
        salt_i = strtol(salt_buffer,0,16);
        memset(salt_b, 0, 4);
        /* this one was a PITA */
        for(i=0; i<8; i++){
                salt_b[i/2] += ((salt[i] > '9' ) ? 
                                (toupper(salt[i]) - 'A' + 10) : 
                                (salt[i] - '0')) * (((i + 1) % 2) ? 16 : 1);
        }

        memcpy(salt_b + 4, password, strlen(password)+1);
	SHA1((u_char *)salt_b, 4 + strlen(password), (u_char *)cryptd_pwd_b);

        /* finally, this one took a while to be realized */
        for(i = 0; i < 24 ; i++){
                u_char p;
                if(i>=4)
                        p = *(cryptd_pwd_b+(i-4));
                else
                        p = salt_b[i];
                /* The following snprintf is safe because
                 * 2*i+1 < SIBYL_CRYPTD_PWD_MAX - 1 
                 * (47   < 1023) 
                 */
                sprintf(cryptd_pwd+2*i,"%02X", p);
        }
#endif
#endif
        return(PAM_SUCCESS);
}


/* Follow functions which should be taken from the OS but are defined
 * by us for convenience (each OS has a different utility)
 */

/* fwritepwent: add (or modify) an entry in a 'passwd' database
 * NOTICE: right now it only modifies the shadowed password and
 *         no other item... TODO
 *
 * INPUT:
 *   *pwd_file   -> the file descriptor (already open)
 *   *entry      -> the entry
 *   *new        -> NULL (just store entry) or the new shadow token
 *   *salt       -> salt corresponding to the token (store)
 *
 * OUTPUT:
 *   PAM_SUCCESS -> Upon success
 *   -1          -> Error
 *   number of chars printed (not too useful?)
 *
 * TODO: should check output from this function and 'errno'
 *       when using it
 */
int fwritepwent(FILE *pwd_file, 
                struct passwd *entry, 
                char *new, 
                char *salt){
        int retval = 0;
        char *salted;
        if(new != NULL){
                salted = (char *) calloc(strlen(new) + 1 + strlen(salt) +1, sizeof(char));
                snprintf(salted, 1024, "%s%s", salt, new);
        }
        if(entry == NULL){
		D("Called fwritepwent with NULL entry");
		return -1;
	}
	if(pwd_file == NULL){
		D("Called fwritepwent with NULL pwd_file");
                return -2;
	}
        /* TODO: store more data? useless? */
	/* TODO: we really should not need uid and gid */
	/* not pw_change because not such thing in Linux ? */
        retval = fprintf(pwd_file, "%s:%s:%i:%i::::::0\n",
                         entry->pw_name,
                         (new == NULL) ? entry->pw_passwd : salted,
                         entry->pw_uid,
                         entry->pw_gid);
        /* TODO: complete the entry or define a standard */
	/*,
	  (u_int ) entry->pw_change);*/
	if(retval < 0)
		D1("Error: [%s]", strerror(retval));
        return(retval);
}


/* fgetpwent for Apple systems... lack it. man getpwent but from a
 *   specified file descriptor (which must be already open)
 */
#ifdef __APPLE__
struct passwd *fgetpwent(FILE *pwd_file){
        struct passwd *entity = (struct passwd *) calloc(1, sizeof(struct passwd));
        if(entity == NULL)
                return NULL;

        char *entry = (char *) calloc(65535, sizeof(char));
        if(entry == NULL)
                return NULL;

        char **parse = (char **)calloc(1, sizeof(char *));

        if(feof(pwd_file))
                return NULL;

        if(fgets(entry, 65535, pwd_file) != NULL){
                *parse = entry;
                entity->pw_name = strsep(parse, ": \n\r\t");
                if(entity->pw_name == NULL || strlen(entity->pw_name) == 0)
                        return(NULL);
                entity->pw_passwd = strsep(parse, ":");
                if(entity->pw_passwd == NULL)
                        return(NULL);
                if(*parse != NULL)
                        entity->pw_uid    = strtol(strsep(parse, ":"), NULL, 10);
                else
                        return NULL;
                if(*parse != NULL)
                        entity->pw_gid    = strtol(strsep(parse, ":"), NULL, 10);
                else
                        return NULL;
                if(*parse != NULL)
                        entity->pw_change = (time_t) strtol(strsep(parse, ":"), NULL, 10);
                else
                        return NULL;
                entity->pw_class  = strsep(parse, ":");
                entity->pw_gecos  = strsep(parse, ":");
                entity->pw_dir    = strsep(parse, ":");
                entity->pw_shell  = strsep(parse, ":");
                if(*parse != NULL)
                        entity->pw_expire = (time_t ) strtol(strsep(parse, ":"), NULL, 10);
                /* entity->pw_fields = strtol(strsep(NULL, ":"), NULL, 10); */
        }
        if (entity->pw_name == NULL)
                return NULL;
        return(entity);
}
#endif


/* _sibyl_rsa_b64: the proper Sibyl's encoding function. Transform
 *   a crypted (crypt) password into a b64(rsa(data)).
 *
 * INPUT:
 *   [gets modified]
 *   *dest      -> where to store the result. Must point to at least
 *                 SIBYL_CRYPTD_PWD_MAX bytes
 *   [constants]
 *   cryptd_pwd -> the supposedly already (OS encrypted) password
 *   encrypt    -> the RSA public encryption key
 *
 * OUTPUT:
 *   PAM_SUCCESS    -> upon success
 *   PAM_SYSTEM_ERR -> upon error
 *
 * COLLATERAL EFFECTS:
 *   *dest contains the result of b64(rsa(cryptd_pwd))
 */
int _sibyl_rsa_b64(char *dest,
                   const u_char *cryptd_pwd,
                   const RSA  *encrypt){
        char *rsa_pwd;
        int rsa_e;

	if(encrypt == NULL){
		syslog(LOG_NOTICE, "Encrypt key is NULL!");
		return(PAM_SYSTEM_ERR);
	}

	if(encrypt->n == NULL){
		syslog(LOG_NOTICE, "encrypt->n is NULL...");
		return(PAM_SYSTEM_ERR);
	}

	rsa_pwd = (char *) calloc(2*RSA_size(encrypt)+1,sizeof(u_char));

	if(rsa_pwd == NULL){
		syslog(LOG_NOTICE, "Unable to allocate memory for rsa_pwd");
		return(PAM_SYSTEM_ERR);
	}

	rsa_e = RSA_public_encrypt(strlen(cryptd_pwd),
				   cryptd_pwd,
				   (u_char *)rsa_pwd,
				   encrypt,
				   RSA_PKCS1_OAEP_PADDING);

	if(rsa_e != RSA_size(encrypt)){
		syslog(LOG_NOTICE, "RSA encryption error... this should not happen");
		return(PAM_SYSTEM_ERR);
	}

	b64_ntop((u_char *)rsa_pwd, 
                 RSA_size(encrypt), 
                 dest, 
                 MIN(RSA_size(encrypt) * 4, SIBYL_CRYPTD_PWD_MAX));

        return(PAM_SUCCESS);
}

/* _sibyl_make_salt: create some salt for the hashing function
 *
 * INPUT:
 * [gets modified]
 * *salt  -> the sequence of salt bytes. Must point to at least
 *           9 bytes
 *
 * OUTPUT:
 * a pointer to the created salt
 *
 * COLLATERAL EFFECTS:
 * *salt gets filled with some bytes -depends on the OS-
 *     for convenience, we fix it between A-Z.
 */


char * _sibyl_make_salt(char *salt){
	D("Making some salt");
#ifdef __APPLE__
	int i;
	RAND_bytes(salt, 8);
	for(i=0; i<8; i++){
		/* make it ascii */
		salt[i] = abs(((salt[i] % 25) + 65)); 
	}
	salt[8] = '$';
	salt[9] = 0;
#endif
#ifdef  _CRYPT_H
	int i;
	/* TODO: this is fixed, should not be (think systems using $6$, etc.) */
	strcpy(salt, "$1$");
	RAND_bytes(&salt[3], 8);
	for(i=0; i<8; i++){
		/* make it ascii */
		salt[3+i] = (abs(salt[3+i]) % 25 ) + 65;
	}
	salt[11] = '$';
	salt[12] = 0;
#endif
	D1("Salt made: [%s]", salt);
	return(salt);
}
