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
#include <sys/time.h>

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


/* notation:
 * user       -> destination user
 * shadow_pwd -> token stored in the shadow database
 * password   -> password introduced by the user
 * cryptd_pwd -> 'password' encrypted: (crypt('password', 'salt') on Linux)
 *                                     (sha(salt . password) on Snow Leopard)
 * salt       -> salt
 */

int
pam_sm_authenticate(pam_handle_t *pamh, 
                    int flags,
		    int argc, 
                    const char *argv[])
{
#ifndef _OPENPAM
	struct pam_conv *conv;
#endif
	char *user, *salt, *shadow_pwd, *password;
	int pam_err;

        /* open the log file first of all */
        openlog( "sibyl", LOG_CONS, LOG_AUTH);
	D("Entered module sibyl: pam_sm_authenticate");          
 
	/* options. TODO: 'dir' should be configurable */
	char *dir = "/etc/sibyl";
	char *IP    = (char *) calloc(SIBYL_IP_LENGTH, sizeof(char)); /* enough for IPv6 */
	char *port  = (char *) calloc(SIBYL_PORT_LENGTH, sizeof(char));
        int root_ok = ROOT_OK_NO;

	if(IP == NULL || port == NULL){
		syslog(LOG_NOTICE, "Unable to allocate memory for IP or PORT");
			return(PAM_AUTHINFO_UNAVAIL);
	}
        /* defaults, see pam_sibyl.h */
	strcpy(IP, _IP);
	strcpy(port, _PORT);

	/* parse options: these are of the form
	 * variable=param
	 * right now, only
	 * ip=a.b.c.d -> Sibyl's IP
	 * port=n     -> port the Sibyl listens on
	 */
        int my_argc    = argc;
	char *param    = (char *)calloc(SIBYL_PAR_LENGTH, sizeof(char));
	char *value    = (char *)calloc(SIBYL_VAL_LENGTH, sizeof(char));
	if(param == NULL || value == NULL){
		syslog(LOG_NOTICE, "Unable to allocate memory for"
                       " the parameters");
		return(PAM_AUTHINFO_UNAVAIL);
	}

	while(my_argc>0){

                strncpy(value, argv[--my_argc], SIBYL_VAL_LENGTH - 1);
		param = strsep(&value, "=");
		
		D1("parsing argument [%s]", param);
                D1("Value [%s]", value);

		if(strncmp(param, "ip", 2) == 0){
			if(value != NULL)
				strncpy(IP, value, SIBYL_IP_LENGTH - 1);
			continue;
		}

		if(strncmp(param, "port", 5) == 0){
			if(value != NULL)
				strncpy(port, value, SIBYL_PORT_LENGTH - 1);
			continue;
		}

                if(strncmp(param, "root_ok", 7) == 0){
                        if(strncmp(value, "yes", strlen("yes")) == 0){
                                root_ok = 1;
                        }
                }
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
	
	/* setup connection */
	int sock;         
	char *nonce;
        RSA *encrypt, *sign_pub;
	nonce      = (char *) calloc(SIBYL_NONCE_LENGTH,   sizeof(char));
        user       = (char *) calloc(SIBYL_NAME_MAX,       sizeof(char));
        salt       = (char *) calloc(SIBYL_SALT_MAX,       sizeof(char));
        shadow_pwd = (char *) calloc(SIBYL_B64_PWD_LENGTH, sizeof(char));
        if(nonce == NULL || 
           user == NULL || 
           salt == NULL ||
           shadow_pwd == NULL){
                syslog(LOG_NOTICE, "Error in calloc nonce, user,"
                       " salt, shadow_pwd");
                return(PAM_SYSTEM_ERR);
        }

        D("About to call sibyl_setup");
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

        /* get username and stored authtok (which includes salt)
         * from the Sibyl's shadow database /etc/sibyl/shadow
         * *user, *salt, *shadow_pwd are set to the appropriate
         *                           values
         * FETCH_USER -> fetch the user because we do not know it
         */
        pam_err = _sibyl_get_username_authtok(pamh, 
                                              user, 
                                              salt, 
                                              shadow_pwd, 
                                              root_ok,
                                              FETCH_USER, 
                                              dir);
        if(pam_err != PAM_SUCCESS)
                return(pam_err);

        /* if possible, get the 'typed' password from PAM */
        pam_err = pam_get_item(pamh, PAM_AUTHTOK,(const void **) &password);

        if(pam_err != PAM_SUCCESS){
		syslog(LOG_NOTICE, "Unsuccsessful pam_get_item for"
                        " PAM_AUTHTOK");
                return(pam_err);
	}
        /* 
         * empty password -> NULLify it (TODO: document)
         * but.... The first check is necessary because
         * strlen() segfaults if password is NULL
         */


/*         if(password == NULL || strlen(password) == 0){ */
/*                 password = NULL; */
/*         } */

/* 	if(password == NULL){ */
/* 		syslog(LOG_NOTICE, "null password? getting some space"); */
/* 		password = (char *)calloc(PASS_MAX, sizeof(char)); */
/* 		if(password == NULL){ */
/* 			syslog(LOG_NOTICE, "Unable to allocate memory for password"); */
/* 			return(PAM_SYSTEM_ERR); */
/* 		} */
/* 	} */

        /* ask for password only if not already introduced */
        /* TODO: document, zero-length passwords not allowed */
        if(password == NULL || strlen(password) == 0){
#ifndef _OPENPAM                
                char *msg = "Sibyl password:";
                pam_err = _sibyl_passwd_conv(pamh, 
                                             msg, 
                                             &password, 
                                             conv);
#else
		char *msg = "Sibyl password";
                pam_err = _sibyl_passwd_conv(pamh, 
                                             msg, 
                                             &password);
#endif
                if (pam_err != PAM_SUCCESS)
                        return (PAM_AUTH_ERR);
        }
        /* 
         * password points to the actual authentication token
         * 'typed' by the user
         */

        /* encrypt according to OS */
	char *cryptd_pwd = (char *)calloc(SIBYL_CRYPTD_PWD_MAX, sizeof(char));
        if(cryptd_pwd == NULL){
                syslog(LOG_NOTICE, "Unable to allocate memory for cryptd_pwd");
                return(PAM_SYSTEM_ERR);
        }

        pam_err = _sibyl_encrypt(cryptd_pwd, 
                                 password, 
                                 salt);
        if(pam_err != PAM_SUCCESS)
                return(pam_err);


	/* forget the password asap, not absolutely useless:
         * it is already set in pamh
         */
	D1("Got crypted pwd, & salt...[:)PASSW0DR!], [%s]", salt);


        /* Perform the dialogue with the Sibyl 
         * Proceed with fingers crossed
         */
        pam_err = _sibyl_dialogue(pamh, 
                                  sock, 
                                  sign_pub, 
                                  encrypt,
                                  salt, 
                                  cryptd_pwd, 
                                  shadow_pwd, 
                                  nonce);

        if(pam_err == PAM_SUCCESS)
                syslog(LOG_NOTICE, "Authentication OK for user: [%s]", user);

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

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
	       int argc, const char *argv[])
{

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
		 int argc, const char *argv[])
{

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
		    int argc, const char *argv[])
{

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
		     int argc, const char *argv[])
{

	return (PAM_SUCCESS);
}


/* From SCO's documentation:
3.5 Password management

To be correctly initialized, PAM_SM_PASSWORD must be #define'd prior
to including <security/pam_modules.h>. This will ensure that the
prototype for a static module is properly declared.

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int
argc, const char **argv); This function is used to (re-)set the
authentication token of the user. A valid flag, which may be logically
OR'd with PAM_SILENT, can be built from the following list,

PAM_CHANGE_EXPIRED_AUTHTOK This argument indicates to the module that
the users authentication token (password) should only be changed if it
has expired. This flag is optional and must be combined with one of
the following two flags. Note, however, the following two options are
mutually exclusive.

PAM_PRELIM_CHECK This indicates that the modules are being probed as
to their ready status for altering the user's authentication token. If
the module requires access to another system over some network it
should attempt to verify it can connect to this system on receiving
this flag. If a module cannot establish it is ready to update the
user's authentication token it should return PAM_TRY_AGAIN, this
information will be passed back to the application.

PAM_UPDATE_AUTHTOK This informs the module that this is the call it
should change the authorization tokens. If the flag is logically OR'd
with PAM_CHANGE_EXPIRED_AUTHTOK, the token is only changed if it has
actually expired.

Note, the Linux-PAM library calls this function twice in
succession. The first time with PAM_PRELIM_CHECK and then, if the
module does not return PAM_TRY_AGAIN, subsequently with
PAM_UPDATE_AUTHTOK. It is only on the second call that the
authorization token is (possibly) changed.

PAM_SUCCESS is the only successful return value, valid error-returns
are:

PAM_AUTHTOK_ERR The module was unable to obtain the new authentication
token.

PAM_AUTHTOK_RECOVERY_ERR The module was unable to obtain the old
authentication token.

PAM_AUTHTOK_LOCK_BUSY Cannot change the authentication token since it
is currently locked.

PAM_AUTHTOK_DISABLE_AGING Authentication token aging has been
disabled.

PAM_PERM_DENIED Permission denied.

PAM_TRY_AGAIN Preliminary check was unsuccessful. Signals an immediate
return to the application is desired.

PAM_USER_UNKNOWN The user is not known to the authentication token
changing service.
*/

/* (as a matter of fact, we use 'items' and not for this module)
 * so, the following does not apply to us.
 *     But it is useful advice nontheless
 * Not to dwell too little on this concern; should the module store
 * the authentication tokens either as (automatic) function variables
 * or using pam_[gs]et_data() the associated memory should be
 * over-written explicitly before it is released. In the case of the
 * latter storage mechanism, the associated cleanup() function should
 * explicitly overwrite the *data before free()'ing it: for example,
 */


/* (same as above, does not apply to us).
 *     But it is useful advice nontheless
 * An example cleanup() function for releasing memory that was used to
 * store a password. 
 */

/* int cleanup(pam_handle_t *pamh, void *data, int error_status) */
/* { */
/*     char *xx; */

/*     if ((xx = data)) { */
/*         while (*xx) */
/*             *xx++ = '\0'; */
/*         free(data); */
/*     } */
/*     return PAM_SUCCESS; */
/* } */



PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
		 int argc, const char *argv[])
{
        /* error by default */
        int pam_err = PAM_SYSTEM_ERR;

        openlog( "sibyl", LOG_CONS, LOG_AUTH);
	D("Entered module sibyl: pam_sm_chauthtok");           

	/* options. dir should be customizable */
	char *dir = "/etc/sibyl";
	char *IP    = (char *) calloc(SIBYL_IP_LENGTH, sizeof(char));
	char *port  = (char *) calloc(SIBYL_PORT_LENGTH, sizeof(char));
        int root_ok = ROOT_OK_NO;

	if(IP == NULL || port == NULL){
		syslog(LOG_NOTICE, "Unable to allocate memory for IP or PORT");
			return(PAM_AUTHINFO_UNAVAIL);
	}
        /* default options, see pam_sibyl.h */
	strcpy(IP, _IP);
	strcpy(port, _PORT);

	/* parse options: these are of the form
	 * variable=param
	 * right now, only
	 * ip=a.b.c.d -> Sibyl's IP
	 * port=n     -> port the Sibyl listens on
	 */
        int my_argc    = argc;
	char *param      = (char *)calloc(SIBYL_PAR_LENGTH, sizeof(char));
	char *value      = (char *)calloc(SIBYL_VAL_LENGTH, sizeof(char));
	if(param == NULL || value == NULL){
		syslog(LOG_NOTICE, "Unable to allocate memory for the parameters");
		return(PAM_SYSTEM_ERR);
	}

	while(my_argc>0){
		
                strncpy(value, argv[--my_argc], SIBYL_VAL_LENGTH - 1);
 		param = strsep(&value, "=");
		
		D1("parsing argument [%s]", param);
                D1("Value: [%s]", value);

		if(strncmp(param, "ip", 2) == 0){
			if(value != NULL)
				strncpy(IP, value, SIBYL_IP_LENGTH - 1);
			continue;
		}

		if(strncmp(param, "port", 5) == 0){
			if(value != NULL)
				strncpy(port, value, SIBYL_PORT_LENGTH - 1);
			continue;
		}

                if(strncmp(param, "root_ok", 7) == 0){
                        if(strncmp(value, "yes", strlen("yes")) == 0){
                                root_ok = 1;
                        }
                }
	}


        /* connection */
        int sock;
        RSA *sign_pub;
        RSA *encrypt;
        char *nonce;

	nonce = (char *)calloc(SIBYL_NONCE_LENGTH, sizeof(char));
        if(nonce == NULL){
                syslog(LOG_NOTICE, "Unable to allocate memory for nonce");
                return(PAM_SYSTEM_ERR);
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
	
	D1("Seeding rand with [%i]", seed);
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

        /* check connection availability and return
         * if this is the first time we are called
         * (this is the protocol)
         */
        if(flags & PAM_PRELIM_CHECK) {
                shutdown(sock, SHUT_RDWR);
                close(sock);
                D("Returning, 'pam_prelim_check'");
                return(PAM_SUCCESS);
        }
        
        if(! (flags & PAM_UPDATE_AUTHTOK)) {
                /* cannot update unless told to */
                D("Flags strange... ignoring");
                /*return(PAM_SERVICE_ERR);*/
        }

        /* check if it MUST have expired */
        if(flags & PAM_CHANGE_EXPIRED_AUTHTOK) {
                pam_err = PAM_PERM_DENIED;
                /* return the above unless the password has really expired */
                /* TODO: there must exist a utility to check this, for sure */
                D("Returning 'pam_change_expired_authtok'");
                return(pam_err);
        }
	D("Going on to update authtok");

        /* get target user (which NOTICE: needs not be the same as uid)
         *
         * FAIL unless
         * user = root
         * or
         * uid  = uid of 'user' 
         */
        uid_t uid = getuid();
        char *user;
        struct passwd *target_pwd;
        char *salt, *shadow_pwd;
        
        /*user       = (char *) calloc(SIBYL_NAME_MAX, sizeof(char));*/
        salt       = (char *) calloc(SIBYL_SALT_MAX, sizeof(char));
        shadow_pwd = (char *) calloc(SIBYL_B64_PWD_LENGTH, sizeof(char));

        if(salt == NULL || shadow_pwd == NULL){
                syslog(LOG_NOTICE, "Unable to allocate memory for user or"
                       " salt or shadow_pwd");
                return(PAM_SYSTEM_ERR);
        }

        if((pam_err = 
            pam_get_user(pamh, (const char **)&user, NULL)) != PAM_SUCCESS){
                syslog(LOG_NOTICE, "pam_get_user failed");
                return(pam_err);
        }

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
        char *password = NULL;
        /*char *password   = (char *)calloc(PASS_MAX, sizeof(char));*/
        char *cryptd_pwd = (char *)calloc(SIBYL_CRYPTD_PWD_MAX, sizeof(char));

        if(cryptd_pwd == NULL){
                syslog(LOG_NOTICE, "Unable to allocate memory for cryptd_pwd");
                return(PAM_SYSTEM_ERR);
        }

	/* We should? check if another module has already
	 * authenticated the user and also if it has already
	 * asked for the new password...
	 */
/* 	pam_err = pam_get_item(pamh,  */
/* 			       PAM_OLDAUTHTOK, */
/* 			       (const void **) &password); */
/* 	if(pam_err != PAM_SUCCESS) */
/* 		return(pam_err); */

        if(uid != 0){
                /* authenticate: retrieve password, do all the
                 * sibyl stuff and check answer
                 * Upon failure, fail 
                 */
                int using_OLDAUTHTOK = 0;
		D1("Authenticating user [%s]", user);
                pam_err = pam_get_item(pamh, 
                                       PAM_OLDAUTHTOK,
                                       (const void **) &password);
                if(pam_err != PAM_SUCCESS)
                        return(pam_err);

                if(password == NULL || strlen(password) == 0){
                        password = NULL;
                } else {
                        using_OLDAUTHTOK = 1;
                }
                
                /* ask for password only if not already introduced */
                if(password == NULL){
                        char *msg = "Old Sibyl password:";
#ifndef _OPENPAM
                        struct pam_conv *conv;
                        pam_err = _sibyl_passwd_conv(pamh, msg, &password, conv);
#else
                        pam_err = _sibyl_passwd_conv(pamh, msg, &password);
#endif
                        if (pam_err != PAM_SUCCESS)
                                return (PAM_AUTH_ERR);
                }
                
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

                /* IMPORTANT: REPEAT IF FAILURE */
                /* if dialogue was unsuccessful using old authtok,
                 * it may well be that the Sibyl's password is 
                 * not the same as the previous module's
                 */
                if(pam_err != PAM_SUCCESS && using_OLDAUTHTOK){
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
                        
                        char *msg = "Old Sibyl password:";
#ifndef _OPENPAM
                        struct pam_conv *conv;
                        pam_err = _sibyl_passwd_conv(pamh, msg, &password, conv);
#else
                        pam_err = _sibyl_passwd_conv(pamh, msg, &password);
#endif
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
                }
                                
                /* If authentication is successful,
                 * set PAM_OLDAUTHTOK (compulsory by PAM rules)
                 * to the entered password. Notice that this
                 * must be done even if it had already been done
                 * by another module: these are PAM's rules, not
                 * ours.
                 */
                pam_set_item(pamh, PAM_OLDAUTHTOK, password);
        } /* end of if (uid != 0) */
        
	if(uid == 0) 
		D("Running user is root");
	
        /* user has already been properly authenticated or is root */
        char *newpwd1, *newpwd2;
        int trials, MATCH;
        MATCH = 0;

        char *msg1 = "Enter the new Sibyl password: ";
        char *msg2 = "Repeat the new Sibyl password: ";
        for(trials = 0; trials < 3; trials++){
                /* TODO: clarify messages is mostly wrong */
#ifdef PAM_AUTHTOK_PROMPT
                pam_set_item(pamh, PAM_AUTHTOK_PROMPT,
                             (void **) "Enter the new Sibyl password: ");
#endif
                /* TODO: change the prompt somehow in OS X (OPENPAM) */
#ifndef _OPENPAM
                struct pam_conv *conv;
                pam_err = _sibyl_passwd_conv(pamh, msg1, &newpwd1, conv);
#else
                pam_err = _sibyl_passwd_conv(pamh, msg1, &newpwd1);
#endif
                /* and repeat */
#ifndef _OPENPAM
                pam_err = _sibyl_passwd_conv(pamh, msg2, &newpwd2, conv);
#else
                pam_err = _sibyl_passwd_conv(pamh, msg2, &newpwd2);
#endif
                
                /* match? OK */
                if(!strncmp(newpwd1, newpwd2, PASS_MAX)){
                        /* sanity check: should use another module */
                        if(strlen(newpwd1) < 4){
                                /* how do I perror here? */
                                continue;
                        }
                        MATCH = 1;
                        break;
                } else {
                        msg1 = "Passwords do not match. Enter the "
                                "new Sibyl password again: ";
                }
        }
        if(MATCH != 1){
                syslog(LOG_NOTICE, "Three trials, password do not match.");
                return(PAM_SYSTEM_ERR);
        }

        /* forget the second password asap */
        memset(newpwd2, 0, strlen(newpwd2));

	/* if user is new, salt is NULL, must create one */
	/* what shall we do? */
	if(strlen(salt) == 0)
                strcpy(salt, _sibyl_make_salt(salt));

        /* OS encrypt the new password */
        pam_err = _sibyl_encrypt(cryptd_pwd,
                                 newpwd1, salt);
        if(pam_err != PAM_SUCCESS)
                return(pam_err);


        /* RSA + b64 encrypted password */
        char *b64_pwd = (char *) calloc(SIBYL_B64_PWD_LENGTH, sizeof(char));
        pam_err = _sibyl_rsa_b64(b64_pwd, 
                                 (u_char *)cryptd_pwd,
                                 encrypt);
        if(pam_err != PAM_SUCCESS)
                return(pam_err);


        /* change the database, this does not require the sibyl
         * user       -> username whose password is to be changed
         * newpwd1    -> new password, plain, no salt
         * salt       -> previous salt, copy right now. TODO?: rand? necessary?.
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
                syslog(LOG_NOTICE, "Unable to read the shadow database");
                fclose(shadow);
                fclose(shadow_bk);
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
         * one, which would be strange: TODO (but need some
         * clarifying)
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
        
        /* before unlocking the whole backup file */
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
        memset(newpwd1, 0, strlen(newpwd1));
        /* cleanup */
        memset(cryptd_pwd, 0, strlen(cryptd_pwd));
        free(cryptd_pwd);
	memset(shadow_pwd, 0, strlen(shadow_pwd));
	free(shadow_pwd);
        memset(salt, 0, strlen(salt));
        free(salt);
        memset(nonce, 0, strlen(nonce));
        free(nonce);
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

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_unix");
#endif


