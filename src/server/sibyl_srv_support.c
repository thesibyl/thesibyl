/* 
 * Sibyl server functions
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <limits.h>
#include <sys/time.h>
#include <syslog.h>
#include <termios.h>

#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "sibyl.h"
#include "bsd-base64.h"
#include "sibyl_srv_support.h"

void 
sigchld_handler(int s)
{
	while (waitpid(-1, NULL, WNOHANG) > 0);
}


/*
 * Passphrase callback (not used by us)
 */
int
pass_cb(char *buf, int size, int rwflag, void *u)
{
        
	char pass[PASSPHRASE_MAX_LENGTH + 1];
	struct termios oflags, nflags;
        int retval = SIBYL_SUCCESS;
	int len;
        char fmt[20];

	/* Disabling echo */
	tcgetattr(fileno(stdin), &oflags);
	nflags = oflags;
	nflags.c_lflag &= ~ECHO;
	nflags.c_lflag |= ECHONL;

	if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0) {
		D("Error: Disabling echo (tcsetattr)");
		return (errno);
	}

	printf("Enter PEM pass phrase for '%s': ", (char*)u);
        sprintf(fmt, "%%%is", PASSPHRASE_MAX_LENGTH);
	scanf(fmt, pass);

	/* Restore terminal */
	if (tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0) {
		D("Error: Restoring echo (tcsetattr)");
		return (errno);
	}

	len = strlen(pass);
	if (len <= 0)
		retval = 0;
	if (len > size)
		retval = size;

	memset(buf, '\0', size);
	memcpy(buf, pass, len);

	return (retval);
}

/* read_keys: 
 * read the private keys
 *
 * INPUT:
 *   **decrypt, **sign -> pointer to the private keys (decrypting/signing)
 *
 * OUTPUT:
 *   SIBYL_SUCCESS if the privates keys could being retrieved
 *   SIBYL_KEYS_ERROR if any error ocurred
 * 
 * COLLATERAL EFFECTS:
 *   The variables **decrypt and **sign are filled with the appropriate content
 *
 */
int
read_keys(RSA **decrypt, const char *decr_filename, RSA **sign,
		const char *sign_filename, const char *dir)
{
	/* RSA private keys fnames & files */
	char decr_fname[_POSIX_PATH_MAX];
        char sign_fname[_POSIX_PATH_MAX];
	FILE *decr_f = NULL;
        FILE *sign_f = NULL;

	if ((strlen(SIBYL_DIR) + 1 + FILE_LEN) >= _POSIX_PATH_MAX) {
		D("Error: dir length");
                return (SIBYL_KEYS_ERROR);
	}

        snprintf(decr_fname, _POSIX_PATH_MAX, "%s/%s", dir, decr_filename);
        snprintf(sign_fname, _POSIX_PATH_MAX, "%s/%s", dir, sign_filename);


	/* RSA *decrypt *sign */
        *decrypt = RSA_new();
        *sign = RSA_new();

	if (*decrypt == NULL || *sign == NULL) {
		D("Error: Unable to RSA_new() decrypt");
		return (SIBYL_KEYS_ERROR);
	}

	/* Fetch the private keys */
        decr_f = fopen(decr_fname, "r");
        sign_f = fopen(sign_fname, "r");

        if (decr_f == NULL || sign_f == NULL) {
		D("Error: Unable to open some key file\n");
                return (SIBYL_KEYS_ERROR);
	}

	/* Read the private keys */
	OpenSSL_add_all_algorithms();
	PEM_read_RSAPrivateKey(decr_f, decrypt, pass_cb, NULL);
	PEM_read_RSAPrivateKey(sign_f, sign, pass_cb, NULL);

	/* Close file descriptors */
	fclose(decr_f);
	fclose(sign_f);

	if ((*decrypt)->n == NULL || (*sign)->n == NULL) {
		D("Error reading the RSA decrypt key");
                return (SIBYL_KEYS_ERROR);
	}

	return (SIBYL_SUCCESS);
}


/* start_server:
 *   Create the socket where the sibyl will be listening
 *
 * INPUT:
 *   *sock -> socket where the server will be listening
 *
 * OUTPUT:
 *   SIBYL_SUCCESS if the socket is created sucessfully
 *   SIBYL_LISTEN_ERROR if any error ocurred
 *
 * COLLATERAL EFFECTS:
 *   The *sock variable is filled with the appropriate content
 *
 */
int
start_server(int *sock, /* UNUSED */ const char *ip, const char *port)
{

	struct sigaction sa;
	struct addrinfo hints, *srvinfo, *p;
	int status; 
	int yes = 1;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if ((status = getaddrinfo(NULL, port, &hints, &srvinfo)) != 0) {
		D1("Error: getaddrinfo  %s\n", gai_strerror(status));
		freeaddrinfo(srvinfo);
                return (SIBYL_LISTEN_ERROR);
	}

	/* loop through all the results and bind to the first we can */
	for (p = srvinfo; p != NULL; p = p->ai_next) {
		if ((*sock = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			D("Error: server socket");
			continue;
		}

		if (setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, &yes,
				sizeof(int)) == -1) {
			D("Error: server setsockopt");
			continue;
		}

	  	if (bind(*sock, p->ai_addr, p->ai_addrlen) == -1) {
			close((int)*sock);
			D("Error: server bind");
			continue;
		}

		break;
	}

	if (p == NULL) {
		D("Error: server failed to bind");
		freeaddrinfo(srvinfo);
                return (SIBYL_LISTEN_ERROR);
	}

	/* Start listening */
	if (listen(*sock, SIBYL_BACKLOG) == -1) {
		D("Error: listening");
		freeaddrinfo(srvinfo);
                return (SIBYL_LISTEN_ERROR);
	}

	sa.sa_handler = sigchld_handler; /* reap all dead processes */
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		D("Error: sigaction");
		freeaddrinfo(srvinfo);
                return (SIBYL_LISTEN_ERROR);
	}

	freeaddrinfo(srvinfo);
	return (SIBYL_SUCCESS);
}


/* send_nonce
 *   Once the client's connection is accepted the server send a random nonce
 * 
 * INPUT:
 *   sock -> socket connected to the client
 *   strnonce -> pointer to the string where the nonce will be stored
 *
 * OUTPUT:
 *   SIBYL_SUCCESS if the nonce is generated and sent with no errors
 *   SIBYL_NONCE_ERROR if any error ocurred
 *
 * COLLATERAL EFFECTS:
 *   The strnonce is filled with the nonce
 *
 */
int
send_nonce(int sock, char *strnonce)
{
	u_char nonce[9];
	int count;

	/*
	 * generate a random nonce.
	 * this may need to be larger than 8 bytes
	 * we get bytes until the process succeeds (i.e. there
	 * has been enough entropy in the pool).
	 */
	while (!RAND_bytes(nonce, 8));

	for (count = 0; count < 8; count++)
		sprintf((strnonce)+count*2, "%02X", nonce[count]);

        strncat(strnonce, "@", 1);
        
	/* send the nonce */
	if (send(sock, strnonce, strlen(strnonce), 0) == -1) {
		D("Error: sending strnonce");
                return (SIBYL_NONCE_ERROR);
	}

        /* remove trailing @ for comparing */
        strnonce[16] = 0;

        return (SIBYL_SUCCESS);
}

/* receive_msg
 *   
 *
 * INPUT:
 *   *msg -> message [to be] received: must be a sufficiently large (char *)
 *   sock -> socket connected to the client
 *   token[4] -> array where the 3 items parsed from the message will be stored,
 *   	      they are:
 *   	      token[0] = m
 *   	      token[1] = p1
 *   	      token[2] = p2
 *
 * OUTPUT:
 *   SIBYL_SUCCESS if the message is received and parsed with no errors
 *   SIBYL_RECV_ERROR if there is any error receiving the message from the client
 *   SIBYL_NASTY_CLIENT if the client is sending more bytes than necessary
 *   SIBYL_MALFORMED_MSG if the message received is malformed
 *
 * COLLATERAL EFFECTS:
 *   The token array is filled with the item parsed from the message.
 *
 */
int
receive_msg(char *msg, int sock, char *command, char *token[3])
{
        int retval = SIBYL_SUCCESS;

	int count_bytes = 0;
	int bytes_rcvd  = 0;

        char *full_cmd = NULL;
        char *new_msg  = NULL;
        char *new_ptr  = NULL;

	/* Receive the client's message */
	while (count_bytes == 0 || 
	      !(msg[count_bytes-1] == '@' &&
                msg[count_bytes-2] == '@')) {

		if ((bytes_rcvd = recv(sock, &(msg[count_bytes]),
				      SIBYL_MAX_MSG - count_bytes, 0)) <= 0) {
			perror("Connection error with the client.");
                        return (SIBYL_OSERR);
		}

		if ((count_bytes += bytes_rcvd) > SIBYL_MAX_MSG) {
			perror("Sibyl's client is sending more bytes than"
			       "necessary");
                        /* we exit here because the client is cheating */
                        return (SIBYL_NASTY_CLIENT);
		}
	}

	/* remove the end-of-message notification */
	new_msg = (char *)calloc(count_bytes-1, sizeof(char));

        if (new_msg == NULL) {
		D("Error: Unable to allocate memory for new_msg");
		return (SIBYL_RECV_ERROR);
        }
        new_ptr = new_msg;

	memcpy(new_msg, msg, count_bytes-2);
        D1("received: {%s}\n", new_msg);


	/* parse message, which is as follows: 
	 * c;m;p1;p2@@
 	 * where
         * c    command ([C]...)
 	 * m	nonce generated by the client, usually different from
 	 * 	the one generated by us (the sibyl).
 	 * p1	the entry in the 'shadow' file corresponding to
 	 * 	the user
 	 * p2	is the output of 
 	 * 	b64_encode(RSA_encrypt("nonce:crypt(passwd,salt)"))
 	 * 	where nonce is the nonce generated by the sibyl
 	 * the trailing @@ is the end-of-message notification
 	 */

        /* get the first parameter (command) */
        full_cmd = strsep(&new_msg, ";");
        if (full_cmd == NULL) {
                D("Error: Malformed message received from the client");
		return (SIBYL_MALFORMED_MSG);
	}

        /* return immediately if just asking for public keys */
        if (strcmp(full_cmd, "[]") == 0) {
           *command = 0;
        } else {
                sscanf(full_cmd, "[%c]", command);
	}

        if (*command != 0 && *command != '-' && !('0' <= *command &&
             *command <= '9')) {
                D1("Wrong command:{%c}", *command);
                return (SIBYL_MALFORMED_MSG);
        }

        if (*command == '-')
                return (SIBYL_SUCCESS);

	/* token[0] = m */
	token[0] = strsep(&new_msg, ";");
	if (token[0] == NULL) {
		D("Error: Malformed message received from the client 0");
                return (SIBYL_MALFORMED_MSG);
	}

	/* token[1] = p1 */
	token[1] = strsep(&new_msg, ";");
	if (token[1] == NULL) {
		D("Error: Malformed message received from the client 1");
                return (SIBYL_MALFORMED_MSG);
	}

        /* return immediately if asking for a transformation */
        if (*command != 0) {
                return (SIBYL_SUCCESS);
        }

	/* token[2] = p2, only if command is 'verify' */
	token[2] = strsep(&new_msg, ";");
	if (token[2] == NULL) {
		D("Error: Malformed message received from the client");
                return (SIBYL_MALFORMED_MSG);
	}

	/* there should not be more tokens */
	if (strsep(&new_msg, ";") != NULL) {
		D("Error: Malformed message received from the client");
                return (SIBYL_MALFORMED_MSG);
	}

        /* Cannot free new_ptr: THESE ARE THE TOKENS! */
        /*  free(new_ptr); */

	return (retval);
}

/* decrypt_token
 *   decrypt the token (p1 or p2) received and parsed from the client's message
 *
 * INPUT:
 *   *p_data -> pointer to store the decrypted token in
 *   *key -> indicates the decryption file (0..9)
 *   *token -> string with the token (p1 or p2) 
 *   *decrypt -> default private key for decryption
 *
 * OUTPUT:
 *   SIBYL_SUCCESS if the decryption is successful
 *   SIBYL_OPENSSL_ERROR if there is any error decrypting the token
 *
 * COLLATERAL EFFECTS:
 *   *p_data is filled with the decrypted token
 *
 */
int
decrypt_token(char *p_data, /* UNUSED */ char key, char *tkn, RSA *decrypt)
{
	int rsa_d;
        char *p_rsa = NULL;

	p_rsa = (char *)calloc(RSA_size(decrypt) + 1, 1);
	if (p_rsa == NULL) {
		D("Error: Unable to allocate memory for tkn_rsa");
		free(p_rsa);
                return (errno);
	}

        printf("Decrypt: {%s}\n", tkn);


	b64_pton(tkn, (u_char *)p_rsa, RSA_size(decrypt) + 1);

	rsa_d = RSA_private_decrypt(RSA_size(decrypt), (u_char *)p_rsa,
				    (u_char *)p_data, decrypt,
				    RSA_PKCS1_OAEP_PADDING);
	if (rsa_d == -1) {
                D("Error decrypting data");
		free(p_rsa);
                return (SIBYL_OPENSSL_ERROR);
	}


	free(p_rsa);
	return (SIBYL_SUCCESS);
}


/* is_pwd_ok
 *   Check if the password is ok, that is, check if p1_data equals
 *   to v1 (p2_data = n:v1)
 *
 * INPUT:
 *   *p1_data -> string with the entry in the 'shadow' file corresponding
 *               to the user
 *   *p2_data -> n:v1 where n is the nonce generated by the sibyl and v1 is
 *               crypt(passwd,salt) of the password type by the user
 *   **auth_result -> '0' is the authentication is OK and '1' otherwise
 *   *strnonce -> string with the nonce generated by the sibyl
 *
 * OUTPUT:
 *   SIBYL_SUCCESS if there were no problems
 *   SIBYL_MALFORMED_MSG if the p2_data is malformed
 *
 * COLLATERAL EFFECTS:
 *   *auth_result is filled with the result of the password check
 *
 */
int
is_pwd_ok(const char *p1_data, char *p2_data, char *auth_result,
		const char *strnonce)
{
	/* Calculates v1, that is: p2_data = n:v1 */
	char *p2_token[2];

	/* p2_token[0] = nonce */
	p2_token[0] = strsep(&p2_data, ":");
	p2_token[1] = strsep(&p2_data, ":");

	if (p2_token[0] == NULL || p2_token[1] == NULL) {
		D("Error: Malformed p2_data");
                return (SIBYL_MALFORMED_MSG);
	}

	D1("nonce: %s\n", p2_token[0]);
	D1("v1: %s\n", p2_token[1]);

	/* Is the password correct? */
	if ((strcmp(p1_data, p2_token[1]) == 0) && 
	   (strcmp(strnonce, p2_token[0]) == 0)) {
		*auth_result = '1';
		D("auth ok");
	} else {
		*auth_result = '0';
		D("auth NOok");
	}

	return (SIBYL_SUCCESS);
}

/* send_response
 *   creates and send the response to the client
 *
 * INPUT:
 *   sock -> socket connected to the client
 *   token[3] -> array with m; p1 and p2
 *   auth_result -> char with the result of the authentication
 *   sign -> private key for signing
 *
 * OUTPUT:
 *   SIBYL_SUCCESS if the response is created and sent with no problems
 *   SIBYL_SSL_ERROR if there is any problem signing the response
 *
 */
int
send_response(int *sock, const char *token[3], const char *auth_result,
		RSA *sign)
{
	int retval;

	/* Create the response, which is as follows:
 	 * M;signature
 	 * where M is a message (text without semicolons)
 	 * 	M has the following structure:
 	 * 	M = n:X
 	 * 	where
 	 * 	n is the nonce received from the client before
 	 * 	X is either '0' or '1', for 'Not authenticated' or 'Authenticated'
 	 * signature is the RSA signature of M
 	 * 	actually (b64_encode(signature))
 	 *
 	 * */
	char *message;
	message = (char *) calloc(strlen(token[0]) + 1 + 
				  strlen(auth_result) + 1, sizeof(char));
	if (message == NULL) {
		D("Error: Unable to allocate memory for message");
		free(message);
                return (errno);
	}
	strncat(message, token[0], SIBYL_NONCE_LENGTH-1);
	strncat(message, ":", 1);
	strncat(message, auth_result, 1);

	D1("message: %s\n", message);

        retval = sign_msg_and_send(message, sign, *sock);

        free(message);
	return (retval);
}


int
translate_and_send(char *p1_data, char version, char *decr_namefile, char *dir,
		int  sock, RSA *sign)
{

        int retval = SIBYL_SUCCESS;
        
        char public_fname[_POSIX_PATH_MAX + 1];
        char encrypted_p1[SIBYL_CRYPTD_PWD_MAX];
        char b64_enc_p1[SIBYL_CRYPTD_PWD_MAX];
        FILE *public = NULL;
        RSA *pub_key = NULL;

        snprintf(public_fname, _POSIX_PATH_MAX, "%s%s%c.pub", dir,
			decr_namefile, version);

        public = fopen("../keys/decrypt1.pub", "r");
        if (public == NULL) {
                D1("Unable to open [%s]", public_fname);
                return (errno);
        }
        
        pub_key = RSA_new();
        if (pub_key == NULL) {
                D("Unable to initialise pub_key");
		fclose(public);
                return (SIBYL_KEYS_ERROR);
        }

        PEM_read_RSA_PUBKEY(public, &pub_key, NULL, NULL);
        if (pub_key == NULL) {
                D("Unable to initialise pub_key");
		RSA_free(pub_key);
		fclose(public);
                return (SIBYL_KEYS_ERROR);
        }

        /* DANGER: strlen(p1_data!!!) */
        retval = RSA_public_encrypt(strlen(p1_data), (unsigned char *)p1_data,
                                    (unsigned char *)encrypted_p1, pub_key,
                                    RSA_PKCS1_OAEP_PADDING);
        if (retval < 0) {
		return (retval);
        }
        
	b64_ntop((u_char *)encrypted_p1, RSA_size(pub_key), b64_enc_p1,
			RSA_size(pub_key) * 4);

        retval = sign_msg_and_send(b64_enc_p1, sign, sock);


	return (retval);        
}


int
send_public_keys(char *dir, char *decr_fn, char *sign_fn, int sock)
{
        char decr_path[_POSIX_PATH_MAX];
        char sign_path[_POSIX_PATH_MAX];
        FILE *d = NULL;
        FILE *s = NULL;

        int i,j;
        char buf[512];

        /* Only PUB keys! */
        snprintf(decr_path, _POSIX_PATH_MAX, "%s/%s.pub", dir, decr_fn);
        snprintf(sign_path, _POSIX_PATH_MAX, "%s/%s.pub", dir, sign_fn);
        printf("[%s],[%s]\n", decr_path, sign_path);


        d = fopen(decr_path, "r");
        s = fopen(sign_path, "r");
        if (d == NULL || s == NULL) {
                D("Error opening public keys");
                return (SIBYL_KEYS_ERROR);
	}

        FILE *f[2] = {d, s};
        char *n[2] = {decr_fn, sign_fn};
        for (j = 0; j < 2; j++) {
                send(sock, n[j], strlen(n[j]), 0);
                send(sock, "\n\n", 2, 0);
                while (!feof(f[j])) {
                        i = fread(buf, 1, 512, f[j]);
                        if (i<0) {
                                D("Error reading public files.");
                                return (errno);
                        }
                        if (send(sock, buf, i, 0) == -1) {
                                D("Error sending public files.");
                                return (errno);
                        }
                }
                fclose(f[j]);
        }

        
        return (SIBYL_SUCCESS);
}


int
sign_msg_and_send(char *msg, RSA *sign, int sock)
{
        char *sha1_m = NULL;
        char *signature = NULL;
        char *signature_b64 = NULL;
        char *response = NULL;

	/* computes the SHA-1 message digest (20 bytes) */
	sha1_m = (char *)calloc(20, sizeof(char));

	if (sha1_m == NULL) {
		D("Error: Unable to allocate memory");
                return (errno);
	}

        D1("msg: {%s}\n", msg);

	SHA1((u_char *)msg, strlen(msg), (u_char*)sha1_m); 

	u_int siglen;
	siglen = RSA_size(sign);
	signature = (char *)calloc(RSA_size(sign) + 1, 1);

	if (signature == NULL) {
		D("Error: Unable to allocate memory");
		free(sha1_m);
                return (errno);
	}

	if (RSA_sign(NID_sha1, (u_char *)sha1_m, 20, (u_char *)signature,
		     &siglen, sign) != 1) {
                D("Error signing");
		free(sha1_m);	
                return (errno);
	}
	
	/* encode the signature to base-64 */
	signature_b64 = (char *)calloc(RSA_size(sign) * 4 + 1,1);

	if (signature_b64 == NULL) {
		D("Error: Unable to allocate memory");
		free(sha1_m);
		free(signature);
                return (errno);
	}

	b64_ntop((u_char *)signature, siglen, signature_b64, RSA_size(sign) * 4);
	D1("signature_b64: %s\n", signature_b64);

	/* creates the response string */
	response = (char *) calloc(strlen(msg) + 1 +
			strlen(signature_b64)+5, sizeof(char));
	if (response == NULL) {
		D("Error: Unable to allocate memory for response");
		free(sha1_m);
		free(signature);
		free(signature_b64);
                return (errno);
	}

        /* all strings are safe here */
	strcat(response, msg);
	strcat(response, ";");
	strcat(response, signature_b64);
	strcat(response, "@");

	D1("response: %s\n", response);

	/* Send response */
	if (send(sock, response, strlen(response), 0) == -1) {
		D("Error: sending response");
		free(sha1_m);
		free(signature);
		free(signature_b64);
		free(response);	
                return (errno);
	}

        free(response);
        free(signature_b64);
        free(signature);
        free(sha1_m);

        return (SIBYL_SUCCESS);
}
