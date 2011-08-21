/* notice that one cannot assume Linux has OpenPAM implemented */

#include <limits.h>
#include <time.h>
#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>
#include <syslog.h>
#include <sys/types.h>

#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>


#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <security/pam_modules.h>
#include <security/pam_appl.h>

#include "pam_sibyl.h"

int main(int argc, char *argv[]){
  pam_handle_t *pamh;
  int pam_err;
  char *dir  = "/etc/sibyl"; 
  char *IP   = "192.168.1.2";
  char *port = "9999";
  FILE *t1;
  t1 = fopen("/etc/sibyl/shadow", "r");
  if(t1==NULL){
    printf("Crap\n");
    exit(-1);
  }
  fclose(t1);
    
        /* connection */
        int sock;
        RSA *sign_pub;
        RSA *encrypt;
        char *nonce;
	char *user;
	user = (char *)calloc(1024,1);
	strcpy(user, argv[1]);
	
        openlog( "sibyl", LOG_CONS, LOG_AUTH);

	nonce = (char *)calloc(SIBYL_NONCE_LENGTH, sizeof(char));
        if(nonce == NULL){
                syslog(LOG_NOTICE, "Unable to allocate memory for nonce");
                return(PAM_SERVICE_ERR);
        }

	/* seed some bytes into the PRNG */
	FILE *rand_f;
	int seed;
	struct timeval tv;
	if ((rand_f = fopen("/dev/random","r")) == NULL) {
		gettimeofday(&tv,0);
		seed = tv.tv_sec + tv.tv_usec;
	} else {
		if (fread(&seed,sizeof(seed),1,rand_f) == 1) {
			fclose(rand_f);
		} else {
			gettimeofday(&tv,0);
			seed = tv.tv_sec + tv.tv_usec;
		}
	}
	
        RAND_seed((const void *)&seed, sizeof(seed));

        
        /* just in case, but useless as of today */
        /* struct sockaddr_in *sibyl_addrv4; */
        /* struct sockaddr_in6 *sibyl_addrv6; */

        pam_err = _sibyl_setup(pamh,
                               &sock, 
                               &sign_pub, 
                               &encrypt, 
                               nonce,
                               IP, 
                               port, 
                               dir);

        if(pam_err != PAM_SUCCESS)
                return(pam_err);

        /* get target user (which NOTICE: needs not be the same as uid)
         *
         * FAIL unless
         * user = root
         * or
         * uid  = uid of 'user' 
         */
	int root_ok = 1;
        uid_t uid = getuid();
	/*        char *user;*/
        struct passwd *target_pwd;
        char *salt, *shadow_pwd;
        
        /*user       = (char *) calloc(1024, sizeof(char));*/
        salt       = (char *) calloc(1024, sizeof(char));
        shadow_pwd = (char *) calloc(1024, sizeof(char));
	printf("User is [%s]\n", user);
	fflush(stdout);
        if(user == NULL || salt == NULL || shadow_pwd == NULL){
                syslog(LOG_NOTICE, "Unable to allocate memory for user or"
                       " salt or shadow_pwd");
                return(PAM_SYSTEM_ERR);
        }

	/*        if((pam_err = 
            pam_get_user(pamh, (const char **)&user, NULL)) != PAM_SUCCESS){
                syslog(LOG_NOTICE, "pam_get_user failed");
                return(pam_err);
        }
	*/
        errno = 0; /* to distinguish between 'nonexistent' and 'error' */
        target_pwd = getpwnam(user);
        if(errno){
                syslog(LOG_NOTICE, "Error reading password database");
                return(PAM_SYSTEM_ERR);
        }


        /* If the user is new, then uid should be 0 (that is,
         * the running user can only be root) and there is no need
         * to authenticate, only add the new token to /etc/sibyl/shadow
         * done below, when updating the shadow file
         */
        if(target_pwd == NULL && uid != 0)
                return(PAM_USER_UNKNOWN);

        if(uid && target_pwd->pw_uid != uid){
                syslog(LOG_NOTICE, "Cannot change other user's password"
                       " if uid != 0 and uid = [%i]", uid);
                return(PAM_PERM_DENIED);
        }


        /* get also the shadow token and the salt
         * for the target user
         */

        D("Calling get_username_authtok");
        pam_err = _sibyl_get_username_authtok(pamh,
                                              user,
                                              salt,
                                              shadow_pwd,
                                              root_ok,
                                              DONT_FETCH_USER,
                                              dir);
        if(pam_err != PAM_SUCCESS && uid != 0)
                return(pam_err);

        /* now 'user' is the target user, target_pwd holds his struct passwd 
         * entry and uid is the process's owner 
         * (either uid==target_pwd->uid or uid==0, otherwise we have 
         *         already ret'd).
         */
        D1("Changing password for user: [%s]", user);
        char *password   = (char *)calloc(PASS_MAX, sizeof(char));
        char *cryptd_pwd = (char *)calloc(SIBYL_CRYPTD_PWD_MAX, sizeof(char));

        if(password == NULL || cryptd_pwd == NULL){
                syslog(LOG_NOTICE, "Unable to allocate memory for password"
                       " or cryptd_pwd");
                return(PAM_SYSTEM_ERR);
        }

	/* We should? check if another module has already
	 * authenticated the user and also if it has already
	 * asked for the new password...
	 */

        if(uid != 0){
                /* authenticate: retrieve password, do all the
                 * sibyl stuff and check answer
                 * Upon failure, fail 
                 */
		D1("Authenticating user [%s]", user);
                /*pam_err = pam_get_item(pamh, 
                                       PAM_AUTHTOK,
                                       (const void **) &password);
                if(pam_err != PAM_SUCCESS)
                        return(pam_err);
		*/
                /* ask for password only if not already introduced */
/*                 if(password == NULL || strlen(password) == 0){ */
/*                         free(password); */
/*                         password = (char *)calloc(PASS_MAX, sizeof(char)); */
/*                         if(password == NULL){ */
/*                                 syslog(LOG_NOTICE, "Unable to allocate memory" */
/*                                        " for password"); */
/*                                 return(PAM_SYSTEM_ERR); */
/*                         }        */
/*                         char *msg = "Old Sibyl password:"; */
/* #ifndef _OPENPAM */
/*                         struct pam_conv *conv; */
/* 			pam_start("password", "pera", conv, &pamh); */
/*                         pam_err = _sibyl_passwd_conv(pamh, msg, password, conv); */
/* #else */
/*                         pam_err = _sibyl_passwd_conv(pamh, msg, password); */
/* #endif */
/*                         if (pam_err != PAM_SUCCESS) */
/*                                 return (PAM_AUTH_ERR); */
/*                 } */
		strcpy(password, argv[2]);

                
                /* Perform OS encryption */
                pam_err = _sibyl_encrypt(cryptd_pwd,
                                         password, 
                                         salt);
                if(pam_err != PAM_SUCCESS)
                        return(pam_err);
        

                /* perform authentication */
                pam_err = _sibyl_dialogue(pamh, 
                                          sock, 
                                          sign_pub, 
                                          encrypt,
                                          salt, 
                                          cryptd_pwd, 
                                          shadow_pwd, 
                                          nonce);

                shutdown(sock, SHUT_RDWR);
                close(sock);

                if(pam_err != PAM_SUCCESS)
                        return(pam_err);
                                
                /* If authentication is successful,
                 * set PAM_OLDAUTHTOK (compulsory by PAM rules)
                 * to the entered password.
                 */
                pam_set_item(pamh, PAM_OLDAUTHTOK, password);
        } /* end of if (uid != 0) */
        
        /* Forget 'password' asap, not absolutely useless */
        memset(password, 0, strlen(password));

        /* user has already been properly authenticated or is root */
        char *newpwd1, *newpwd2;
        newpwd1 = (char *) calloc(1024, sizeof(char));
        newpwd2 = (char *) calloc(1024, sizeof(char));
        if(newpwd1 == NULL || newpwd2 == NULL){
                return(PAM_SERVICE_ERR);
        }
        strcpy(newpwd1, argv[3]);
        int trials, MATCH;
        MATCH = 0;
/*         for(trials = 0; trials < 3; trials++){ */
/*                 char *msg = "Enter new Sibyl password:"; */
/*                 /\* TODO: This is mostly wrong *\/ */
/* #ifdef PAM_OLDAUTHTOK_PROMPT */
/*                 pam_set_item(pamh, PAM_OLDAUTHTOK_PROMPT, */
/*                              (void **) "Enter the old Sibyl password:"); */
/* #endif */
/* #ifdef PAM_AUTHTOK_PROMPT */
/*                 pam_set_item(pamh, PAM_AUTHTOK_PROMPT, */
/*                              (void **) "Enter the new Sibyl password:"); */
/* #endif */
/*                 /\* TODO: change the prompt somehow in OS X (OPENPAM) *\/ */
/* #ifndef _OPENPAM */
/*                 struct pam_conv *conv; */
/*                 pam_err = _sibyl_passwd_conv(pamh, msg, newpwd1, conv); */
/* #else */
/*                 pam_err = _sibyl_passwd_conv(pamh, msg, newpwd1); */
/* #endif */
/* /\* and repeat: TODO: should change the message, though *\/ */
/* #ifndef _OPENPAM */
/*                 pam_err = _sibyl_passwd_conv(pamh, msg, newpwd2, conv); */
/* #else */
/*                 pam_err = _sibyl_passwd_conv(pamh, msg, newpwd2); */
/* #endif */
                
/*                 /\* match? OK *\/ */
/*                 if(!strncmp(newpwd1, newpwd2, PASS_MAX)){ */
/*                         /\* sanity check: should use another module *\/ */
/*                         if(strlen(newpwd1) < 4){ */
/*                                 /\* how do I perror here? *\/ */
/*                                 continue; */
/*                         } */
/*                         MATCH = 1; */
/*                         break; */
/*                 } else { */
/*                         /\* TODO: How do I tell the user the passwords */
/*                          * do not match? */
/*                          *\/ */
/*                 } */
/*         } */
/*         if(MATCH != 1){ */
/*                 syslog(LOG_NOTICE, "Three trials, password do not match"); */
/*                 return(PAM_SYSTEM_ERR); */
/*         } */


        /* forget the second password asap */
        memset(newpwd2, 0, strlen(newpwd2));

	/* if user is new, salt is NULL, must create one */
	/* what shall we do? */
	_sibyl_make_salt(salt);

        /* OS encrypt the new password */
        pam_err = _sibyl_encrypt(cryptd_pwd,
                                 newpwd1, salt);
        if(pam_err != PAM_SUCCESS)
                return(pam_err);


        /* RSA + b64 encrypted password */
        char *b64_pwd;
        pam_err = _sibyl_rsa_b64(&b64_pwd, 
                                 (u_char *)cryptd_pwd,
                                 encrypt);
        if(pam_err != PAM_SUCCESS)
                return(pam_err);


        /* change the database, this does not require the sibyl
         * user       -> username whose password is to be changed
         * newpwd1    -> new password, plain, no salt
         * salt       -> previous salt, copy right now. TODO: rand.
         */
	D("About to open shadow files...");

        struct passwd *entry;
        char *new = NULL;
        FILE *shadow;
        FILE *shadow_bk;
        int found = 0;
        int unlink_bk = 1;
        /* TODO: directory should be configurable */
        shadow    = fopen("/etc/sibyl/shadow", "r");
        shadow_bk = fopen("/etc/sibyl/shadow.bk", "w");

        if (shadow == NULL || shadow_bk == NULL){
                syslog(LOG_NOTICE, "Unable to read the shadow database or the backup");
                return(PAM_AUTHINFO_UNAVAIL);
        }

        entry = fgetpwent(shadow);
        if(entry == NULL){
                syslog(LOG_NOTICE, "Unable to read the shadow database");
                return(PAM_AUTHINFO_UNAVAIL);
        }

        /* basically copy the shadow file into shadow_bk,
         * except for the target user entry, which gets a
         * new token made up from 'b64_pwd'
         */

        /* lock shadow file... all this process must
         * be thread safe.
         */
        if(lockf(fileno(shadow_bk), F_LOCK, 0) != 0){
                syslog(LOG_NOTICE, "Unable to lock shadow backup file");
                return(PAM_SYSTEM_ERR);
        }

        while(entry != NULL && entry->pw_name != NULL){
                if(strncmp(entry->pw_name, user, strlen(user)) == 0) {
                        found = 1;
                        new = b64_pwd;
                } else {
                        new = NULL;
                }

                if(fwritepwent(shadow_bk, entry, new, salt) < 0){
                        syslog(LOG_NOTICE, "Error processing shadow files while"
                               " copying");
                        pam_err = PAM_SYSTEM_ERR;
                        goto GONE_WRONG;
                }

                entry = fgetpwent(shadow);
        }

        /* if the user does not exist and uid is not 0,
         * someone is doing something quite anomalous...
         */
        if(found == 0 && uid != 0){
                syslog(LOG_NOTICE, "User not found while chauthtok");
                pam_err = PAM_USER_UNKNOWN;
                goto GONE_WRONG;
        }

        /* root user may ADD new users. However, we should
         * be able to check that the user DOES exist in the
         * OS's user database... ? Unless this is the only
         * one, which would be strange: TODO
         */
	int msg;
        if(found == 0 && uid == 0){
                syslog(LOG_NOTICE, "Adding user [%s] to Sibyl's shadow file", user);
		entry = (struct passwd *)calloc(1, sizeof(struct passwd));
		entry->pw_name    = (char *)calloc(1, strlen(user)+1);
		entry->pw_passwd  = (char *)calloc(1, strlen(salt) + strlen(b64_pwd) + 1);
		strncpy(entry->pw_name, user, strlen(user));
		strncpy(entry->pw_passwd, salt, strlen(salt));
		strncat(entry->pw_passwd, b64_pwd, strlen(b64_pwd));
		/* magic: all users get the same uid and gid :) TODO */
		entry->pw_uid = 9999;
		entry->pw_gid = 9999;
                if((msg = fwritepwent(shadow_bk, entry, new, salt)) < 0){
                        syslog(LOG_NOTICE, "Error processing shadow files while"
                               "copying, error [%i], [%s]", msg, strerror(errno));
			
                        pam_err = PAM_SYSTEM_ERR;
                        goto GONE_WRONG;
                }                
        }

        /* OOOPS, not feof but error */
        if(!feof(shadow) || ferror(shadow)){
                syslog(LOG_NOTICE, "Error processing shadow files"
                       "after copying");
                pam_err = PAM_SYSTEM_ERR;
                goto GONE_WRONG;
        }
        
        /* lock the whole backup file */
        if(fflush(shadow_bk) != 0){
                syslog(LOG_NOTICE, "Unable to flush the shadow backup file."
                       " Aborting.");
                goto GONE_WRONG;
                
        }

        int close_err = 0;
        if(fclose(shadow_bk) != 0) {
                syslog(LOG_NOTICE, "Error trying to close backup shadow file");
                close_err = 1;
        }

        if(fclose(shadow) != 0) {
                syslog(LOG_NOTICE, "Error trying to close shadow file");
                close_err = 1;
        }

        if(close_err)
                goto GONE_WRONG;


        /* everything has gone OK. rename shadow_bk */
        if(rename("/etc/sibyl/shadow.bk", "/etc/sibyl/shadow") < 0){
                /* unless we get here, in which case things have gone
                 * PRETTY wrong (rename did not work properly). Do NOT
                 * unlink bk file just in case...
                 */
                syslog(LOG_NOTICE, "Error processing shadow files:"
                       "Unable to move shadow.bk->shadow");
                pam_err   = PAM_SYSTEM_ERR;
                unlink_bk = 0;
                goto GONE_WRONG;
        }
        

        /* set PAM_AUTHTOK before leaving, this is
         * compulsory for PAM chauthtok modules 
         */
        D("Setting PAM_AUTHTOK");
        pam_set_item(pamh, PAM_AUTHTOK, newpwd1);
/*         memset(newpwd1, 0, strlen(newpwd1)); */
/*         /\* cleanup *\/ */
/*         memset(cryptd_pwd, 0, strlen(cryptd_pwd)); */
/*         free(cryptd_pwd); */
/* 	memset(shadow_pwd, 0, strlen(shadow_pwd)); */
/* 	free(shadow_pwd); */
/*         memset(salt, 0, strlen(salt)); */
/*         free(salt); */
/*         memset(nonce, 0, strlen(nonce)); */
/*         free(nonce); */
        return(PAM_SUCCESS);


        /* can only get here with a goto */
GONE_WRONG:
        
        /* either there is a probably unrecoverable error or
         * we have already checked errors on these fcloses, so 
         * don't worry about their return values (they will either
         * fail miserably or just close)
         */
        fclose(shadow);
        fclose(shadow_bk);
        /* do NOT remove bk file unless we are certain that 'shadow'
         * is in the correct state
         */
        if(unlink_bk)
                unlink("/etc/sibyl/shadow.bk");

        /* cleanup */
        memset(cryptd_pwd, 0, strlen(cryptd_pwd));
        free(cryptd_pwd);
        memset(shadow_pwd, 0, strlen(shadow_pwd));
        free(shadow_pwd);
        memset(salt, 0, strlen(salt));
        free(salt);
        memset(nonce, 0, strlen(nonce));
        free(nonce);

        return(pam_err);        
}

/* int */
/* pam_sibyl_authenticate(int flags, */
/*     int argc, const char *argv[]) */
/* { */
/* #ifndef _OPENPAM */
/*     struct pam_conv *conv; */
/*     struct pam_message msg; */
/*     const struct pam_message *msgp; */
/*     struct pam_response *resp; */
/* #endif */
/*     FILE *log; */
/*     log = fopen("/tmp/sibyl.log", "a"); */
/*     struct passwd *pwd; */
/*     char *user; */
/*     char *crypt_password, *password; */
/*     int pam_err, retry; */

/*     char *dir = "/etc/sibyl"; */

/*     /\* options *\/ */

/*      int bflag, ch, fd; */
/*      char *IP = (char *) calloc(128, sizeof(char)); */

/* 	openlog( "sibyl", LOG_CONS, LOG_AUTH); */
/* 	void syslog(int priority, const char *format, ...); */

/* 	warn("Entered module sibyl"); */
     
     
/*      strcpy(IP, _IP); */
/*      char *port = (char *)calloc(7, sizeof(char)); */
/*      strncpy(port, _PORT, 6); */

/*      bflag = 0; */

/*      if(argc<3){ */
/*        printf("need 2 arguments at least\n"); */
/*        return(-1); */
/*      } */

/*      while ((ch = getopt(argc, argv, OPTS)) != -1) { */
/*              switch (ch) { */
/*              case 's': */
/*                      strncpy(IP, optarg, 128); */
/*                      break; */
/*              case 'p': */
/*                      strncpy(port, 5, optarg); */
/*                      if(port > 65535) */
/*                              return(PAM_SERVICE_ERR); */
/*                      break; */

/*              case '?': */
/*              default: */
/* 		     err("usage()"); */
/*              } */
/*      } */
/*      argc -= optind; */
/*      argv += optind; */

/*      user = (char *)calloc(strlen(argv[1])+1, 1); */
/*      strcpy(user, argv[0]); */
/* 	/\* open connection *\/ */

/* 	int sock;                        */
/* 	/\*struct sockaddr_in sybil_addr; *\/ */
/* 	int bytes_rcvd; */
/*         struct addrinfo hints, *sibyl_adds; */
/* 	void *sibyl_addr; */
/* 	struct sockaddr_in *sibyl_addrv4; */
/* 	struct sockaddr_in6 *sibyl_addrv6; */
/*         int status; */

/*         memset(&hints, 0, sizeof hints); */
/*         hints.ai_family   = AF_INET; */
/*         hints.ai_socktype = SOCK_STREAM; */

/*         status = getaddrinfo(IP, port, &hints, &sibyl_adds); */
/*         if(status != 0){ */
/*                 syslog(LOG_NOTICE, "Unable to connect to the Sibyl: %s",  */
/*                        gai_strerror(status)); */
/*                 return(PAM_SERVICE_ERR); */
/*         } */


/* 	/\* IPv4 only here *\/ */
/* 	sibyl_addrv4 = (struct sockaddr_in *) sibyl_adds->ai_addr; */
/* 	sibyl_addr   = &(sibyl_addrv4->sin_addr); */

/* 	/\* Create a reliable, stream socket using TCP *\/ */
/* 	if ((sock = socket(sibyl_adds->ai_family,  */
/*                            sibyl_adds->ai_socktype, */
/*                            sibyl_adds->ai_protocol)) < 0){ */
/* 		return(PAM_SERVICE_ERR); */
/* 	} */


/* 	/\* Establish the connection to the sibyl server *\/ */
	
/* 	if (connect(sock, sibyl_adds->ai_addr, sibyl_adds->ai_addrlen) < 0){ */
/* 		warn("What the heck!"); */
/* 		syslog(LOG_NOTICE, "Unable to establish socket with the Sibyl"); */
/* 		return(PAM_SERVICE_ERR); */
/* 	} */
	
/* 	/\* connection open *\/ */
/* 	syslog(LOG_NOTICE, "Socket established"); */


/*     /\* RSA public keys *\/ */

/*     char *decr_fname, *sign_fname; */
/*     decr_fname = (char *)calloc(_POSIX_PATH_MAX, sizeof(char)); */
/*     sign_fname = (char *)calloc(_POSIX_PATH_MAX, sizeof(char)); */
/*     if(decr_fname == NULL || sign_fname == NULL) */
/*             return(PAM_SERVICE_ERR); */

/*     if(strlen(dir) >= _POSIX_PATH_MAX || */
/*        (strlen(dir) + 1 + FILE_LEN) >= _POSIX_PATH_MAX){ */
/*             return(PAM_SERVICE_ERR); */
/*     } */
/*     strncat(decr_fname, dir, _POSIX_PATH_MAX); */
/*     strncat(decr_fname, "/decrypt.pub", 64); */
/*     strncat(sign_fname, dir, _POSIX_PATH_MAX); */
/*     strncat(sign_fname, "/sign.pub", 64); */

/*     FILE *decr_f, *sign_f; */
/*     decr_f = fopen(decr_fname, "r"); */
/*     sign_f = fopen(sign_fname, "r"); */
    
/*     if(decr_f == NULL || sign_f == NULL) */
/*             return(PAM_SERVICE_ERR); */

/*     warn("Key files open"); */

/*     RSA *decrypt, *sign; */
/*     decrypt = RSA_new(); */
/*     sign    = RSA_new(); */

/*     if(decrypt == NULL || sign == NULL) */
/*             return(PAM_SERVICE_ERR); */

/*     PEM_read_RSAPublicKey(decr_f, &decrypt, NULL, NULL); */
/*     PEM_read_RSAPublicKey(sign_f, &sign, NULL, NULL); */

/*     if(decrypt->n == NULL || sign->n == NULL){ */
/*       rewind(decr_f); */
/*       rewind(sign_f); */
/*       PEM_read_RSA_PUBKEY(decr_f, &decrypt, NULL, NULL); */
/*       PEM_read_RSA_PUBKEY(sign_f, &sign, NULL, NULL); */
/*     } */
/*     if(decrypt->n == NULL || sign->n == NULL) */
/*             return(PAM_SERVICE_ERR); */

/*     fclose(sign_f); */
/*     fclose(decr_f); */

/*     warn("Keys read"); */

/*     char *nonce; */
/*     nonce = (char *)calloc(NONCE_L, sizeof(char)); */

/*     bytes_rcvd = recv(sock, nonce, NONCE_L - 1, 0); */
/*     if(bytes_rcvd <=0) */
/*             return(PAM_SERVICE_ERR); */

/*     /\* chomp nonce *\/ */
/*     nonce = strtok(nonce, "\n"); */

/*     FILE *shadow; */
/*     shadow = fopen("/etc/sibyl/shadow", "r"); */
/*     if(shadow == NULL){ */
/* 	    warn("Unable to read the shadow database"); */
/* 	    return(PAM_SERVICE_ERR); */
/*     } */
    
/*     while((pwd = fgetpwent(shadow)) != NULL){ */
/*       if(strcmp(pwd->pw_name, user) ==0) */
/* 	break; */
/*     }; */
/*     fclose(shadow); */
/*     if (pwd == NULL) */
/*             return(PAM_USER_UNKNOWN); */


/*     /\* pwd->pw_passwd is the RSA(crypt(pwd)) preceded by the salt *\/ */
/*     regex_t *salt_regex = (regex_t *)calloc(1,sizeof(regex_t)); */
/*     char *salt; */
/*     char *b64_cr_pwd; */
/*     if(salt_regex == NULL) */
/*             return(PAM_SERVICE_ERR); */


/*     if(regcomp(salt_regex, "(.*\\$)", REG_EXTENDED) != 0) */
/*             return(PAM_SERVICE_ERR); */
    
/*     int nmatch = 2; */
/*     regmatch_t pmatch[2]; */
    
/*     if(regexec(salt_regex, pwd->pw_passwd, nmatch, pmatch, NULL) != 0) */
/*             return(PAM_SERVICE_ERR); */

/*     /\* this is too Linux oriented, I guesss *\/ */
/*     if(nmatch == 0) */
/*             salt = (char *)calloc(10, sizeof(char)); */
/*     else{ */
/*             int matchlen = pmatch[1].rm_eo - pmatch[1].rm_so; */
/*             salt = (char *)calloc(matchlen + 2, sizeof(char)); */
/*             memcpy(salt, pwd->pw_passwd+(pmatch[1].rm_so), matchlen); */
/*             b64_cr_pwd = (char *) calloc(strlen(pwd->pw_passwd) - matchlen +1,  */
/*                                          sizeof(char)); */
/*             if(b64_cr_pwd == NULL) */
/*                     return(PAM_SERVICE_ERR); */
/* 	    b64_cr_pwd = pwd->pw_passwd+matchlen; */
/*     } */


/*     password = (char *)calloc(65535, 1); */
/*     strcpy(password, argv[1]); */

/*     /\* encrypt, RSA and base64 password... *\/ */

/*     char *cryptd_pwd; // = (char *)calloc(1024, sizeof(char)); */
/*         cryptd_pwd = crypt(password, salt);  */
/*     /\*cryptd_pwd = crypt("patata", "$1$.VzOSfla$");*\/ */
    
/*     if(cryptd_pwd == NULL){ */
/* 	    warn("Unable to crypt the password"); */
/*       return(PAM_SERVICE_ERR); */
/*     } */
      

/*       char *nonce_pwd = (char *)calloc(65535, sizeof(char)); */
/*       strcat(nonce_pwd, nonce); */
/*       strcat(nonce_pwd, ":"); */
/*       strcat(nonce_pwd, cryptd_pwd); */


/*     int rsa_e; */
/*     char *rsa_pwd, *b64_pwd; */
/*     rsa_pwd = (char *) calloc(RSA_size(decrypt)+1,1); */
/*     rsa_e = RSA_public_encrypt(strlen(nonce_pwd), */
/*                                nonce_pwd, */
/*                                rsa_pwd, */
/*                                decrypt, */
/*                                RSA_PKCS1_OAEP_PADDING); */


/*     if(rsa_e != RSA_size(decrypt)) */
/*             return(PAM_SERVICE_ERR); */

/*     b64_pwd = (char *)calloc(2 * RSA_size(decrypt)+1, sizeof(char)); */
/*     if(b64_pwd == NULL) */
/*             return(PAM_SERVICE_ERR); */
    
/*     b64_ntop(rsa_pwd, RSA_size(decrypt), b64_pwd, RSA_size(decrypt) * 4); */
    
/*     /\* get a 'reasonable' random number *\/ */
/*         FILE *urand_f = fopen("/dev/urandom", "r"); */
/*         if(urand_f == NULL){ */
/*                 time_t seed; */
/* 		warn("Using time() for random numbers"); */
/*                 seed = time(NULL); */
/*                 srandom(seed); */
/*         } else { */
/*                 unsigned int seed; */
/* 		int bytes; */
/*                 bytes = fread(&seed, sizeof(seed), 1, urand_f); */
/*                 srandom(seed); */
/*                 fclose(urand_f); */
/*         } */

/* 	int my_nonce = random(); */
/* 	char *my_strnonce = (char *) calloc(sizeof(my_nonce ) *4 + 1, sizeof(char *)); */
/* 	if(my_strnonce == NULL) */
/* 		return(PAM_SERVICE_ERR); */
/* 	snprintf(my_strnonce, 4*sizeof(my_nonce), "%i", my_nonce); */

/*     /\* join with ';' all the strings... *\/ */
    
/*     char *message; */
/*     message = (char *) calloc(strlen(my_strnonce) +  */
/*                               strlen(b64_cr_pwd) + */
/*                               strlen(b64_pwd) +  */
/*                               4, sizeof(char)); */
/*     if(message == NULL) */
/*             return(PAM_SERVICE_ERR); */

/*     strcat(message, my_strnonce); */
/*     strcat(message, ";"); */
/*     strcat(message, b64_cr_pwd); */
/*     strcat(message, ";"); */
/*     strcat(message, b64_pwd); */

/*     /\* should try several times? *\/ */
/*     if(send(sock, message, strlen(message) + 4, 0) == -1) */
/*             return(PAM_SERVICE_ERR); */
    
/*     if(send(sock, "\n@@\n", 4, 0) ==-1) */
/*             return(PAM_SERVICE_ERR); */

/*     /\* receive answer *\/ */
/*     char *ans; */
/*     ans = (char *) calloc(2*RSA_size(sign) + 32, sizeof(char)); */
/*     if((bytes_rcvd = recv(sock, ans, 2*RSA_size(sign) + 33, 0)) <= 0) */
/*             return(PAM_SERVICE_ERR); */
    
/*     /\* parse answer *\/ */
/*     char *token[2]; */
/*     token[0] = strtok(ans, ";"); */
/*     if(token[0] == NULL) */
/*             return(PAM_SERVICE_ERR); */
/*     token[1] = strtok(NULL, ";"); */
/*     if(token[1] == NULL) */
/*             return(PAM_SERVICE_ERR); */

/*     char *sha1_m = (char *)calloc(1024, sizeof(char)); */
/*     SHA1(token[0], strlen(token[0]), sha1_m); */


/*     BIO *b64, *bmem; */
    
/*     char *signature = (char *)malloc(2*RSA_size(sign)); */
/*     /\* memset(signature, 0, length);*\/ */
    
/*     b64_pton(token[1], */
/* 	     signature, 512); */

/*     if(RSA_verify(NID_sha1,  */
/*                   sha1_m, 20, */
/*                   signature, RSA_size(sign), */
/*                   sign) != 1) */
/*             return(PAM_SERVICE_ERR); */

/*     warn("Signature verified"); */

/*     char *token0; */
/*     token0 = (char *)calloc(strlen(token[0]) + 1, sizeof(char)); */
/*     strcpy(token0, token[0]); */
/*     token[0] = strtok(token0, ":"); */
/*     if(token[0] == NULL) */
/*             return(PAM_SERVICE_ERR); */
/*     token[1] = strtok(NULL, ":"); */
/*     if(token[1] == NULL) */
/*             return(PAM_SERVICE_ERR); */

/*     if(strcmp(token[1], "1") != 0) */
/*             return(PAM_AUTH_ERR); */

/*     if(strcmp(token[0], my_strnonce) != 0) */
/*             return(PAM_AUTH_ERR); */

/*     pam_err = PAM_SUCCESS; */

/*     warn("Authentication OK"); */

/*     return(PAM_SUCCESS); */
     

/* } */

/* PAM_EXTERN int */
/* pam_sm_setcred(pam_handle_t *pamh, int flags, */
/*     int argc, const char *argv[]) */
/* { */

/*     return (PAM_SUCCESS); */
/* } */

/* PAM_EXTERN int */
/* pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, */
/*     int argc, const char *argv[]) */
/* { */

/*     return (PAM_SUCCESS); */
/* } */

/* PAM_EXTERN int */
/* pam_sm_open_session(pam_handle_t *pamh, int flags, */
/*     int argc, const char *argv[]) */
/* { */

/*     return (PAM_SUCCESS); */
/* } */

/* PAM_EXTERN int */
/* pam_sm_close_session(pam_handle_t *pamh, int flags, */
/*     int argc, const char *argv[]) */
/* { */

/*     return (PAM_SUCCESS); */
/* } */

/* PAM_EXTERN int */
/* pam_sm_chauthtok(pam_handle_t *pamh, int flags, */
/*     int argc, const char *argv[]) */
/* { */

/*     return (PAM_SERVICE_ERR); */
/* } */

/* #ifdef PAM_MODULE_ENTRY */
/* PAM_MODULE_ENTRY("pam_unix"); */
/* #endif */



/* inline unsigned char to_uchar(char v){ */
/*   return(v); */
/* } */
/* void */
/* b64_encode (char * in, size_t inlen, */
/* 	       char * out, size_t outlen) */
/* { */
/*   static const char b64str[64] = */
/*     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; */

/*   while (inlen && outlen) */
/*     { */
/*       *out++ = b64str[(to_uchar (in[0]) >> 2) & 0x3f]; */
/*       if (!--outlen) */
/* 	break; */
/*       *out++ = b64str[((to_uchar (in[0]) << 4) */
/* 		       + (--inlen ? to_uchar (in[1]) >> 4 : 0)) */
/* 		      & 0x3f]; */
/*       if (!--outlen) */
/* 	break; */
/*       *out++ = */
/* 	(inlen */
/* 	 ? b64str[((to_uchar (in[1]) << 2) */
/* 		   + (--inlen ? to_uchar (in[2]) >> 6 : 0)) */
/* 		  & 0x3f] */
/* 	 : '='); */
/*       if (!--outlen) */
/* 	break; */
/*       *out++ = inlen ? b64str[to_uchar (in[2]) & 0x3f] : '='; */
/*       if (!--outlen) */
/* 	break; */
/*       if (inlen) */
/* 	inlen--; */
/*       if (inlen) */
/* 	in += 3; */
/*     } */

/*   if (outlen) */
/*     *out = '\0'; */
/* } */

