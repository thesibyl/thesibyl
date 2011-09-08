/*
 *
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

#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include "sibyl.h"

#include "bsd-base64.h"

#define DEBUG

void sigchld_handler(int s)
{
	while(waitpid(-1, NULL, WNOHANG) > 0);
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
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
int read_keys(RSA **decrypt,
	      RSA **sign){

	/* RSA private keys */
	char *decr_fname, *sign_fname;
	decr_fname = (char *)calloc(_POSIX_PATH_MAX, sizeof(char));
	sign_fname = (char *)calloc(_POSIX_PATH_MAX, sizeof(char));
	if(decr_fname == NULL || sign_fname == NULL){
		D("Error: decr_fname or sign_fname alloc");
		return(SIBYL_KEYS_ERROR);
	}

	if(strlen(SIBYL_DIR) >= _POSIX_PATH_MAX ||
	   FILE_LEN >= _POSIX_PATH_MAX ||
	   (strlen(SIBYL_DIR) + 1 + FILE_LEN) >= _POSIX_PATH_MAX){
		D("Error: dir length");
		return(SIBYL_KEYS_ERROR);
	}

        snprintf(decr_fname, _POSIX_PATH_MAX, "%s/%s", SIBYL_DIR, SIBYL_DECR_KEY);
        snprintf(sign_fname, _POSIX_PATH_MAX, "%s/%s", SIBYL_DIR, SIBYL_SIGN_KEY);

	/* Fetch the private keys */
	FILE *decr_f, *sign_f;
	if((decr_f = fopen(decr_fname, "r")) == NULL){
		D("Error: Unable to open file decr_f");
		return(SIBYL_KEYS_ERROR);
	}
	if((sign_f = fopen(sign_fname, "r")) == NULL){
		D("Error: Unable to open file sign_f");
		return(SIBYL_KEYS_ERROR);
	}

	/* RSA *decrypt *sign */
	if((*decrypt = RSA_new()) == NULL){
		D("Error: Unable to RSA_new() decrypt");
		return(SIBYL_KEYS_ERROR);
	}
	if((*sign = RSA_new()) == NULL){
		D("Error: Unable to RSA_new() sign");
		return(SIBYL_KEYS_ERROR);
	}

	/* Read the private keys */
	PEM_read_RSAPrivateKey(decr_f, decrypt, NULL, NULL);
	PEM_read_RSAPrivateKey(sign_f, sign, NULL, NULL);

	if((*decrypt)->n == NULL){
		D("Error reading the RSA decrypt key");
		fclose(decr_f);
		fclose(sign_f);
		return(SIBYL_KEYS_ERROR);
	}
	if((*sign)->n == NULL){
		D("Error reading the RSA sign key");
		fclose(decr_f);
		fclose(sign_f);
		return(SIBYL_KEYS_ERROR);
	}
	fclose(decr_f);
	fclose(sign_f);

	return(SIBYL_SUCCESS);
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
int start_server(int *sock){
	struct addrinfo hints, *srvinfo, *p;
	int status; 
	int yes = 1;
	struct sigaction sa;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if ((status = getaddrinfo(NULL, SIBYL_PORT, &hints, &srvinfo)) != 0) {
		D1("Error: getaddrinfo  %s\n", gai_strerror(status));
		return(SIBYL_LISTEN_ERROR);
	}

	// loop through all the results and bind to the first we can
	for(p = srvinfo; p != NULL; p = p->ai_next){
		if ((*sock = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			D("Error: server socket");
			continue;
		}

		if (setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, &yes,
				sizeof(int)) == -1){
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
		return(SIBYL_LISTEN_ERROR);
	}

	freeaddrinfo(srvinfo);

	/* Start listening */
	if (listen(*sock, SIBYL_BACKLOG) == -1) {
		D("Error: listening");
		return(SIBYL_LISTEN_ERROR);
	}

	sa.sa_handler = sigchld_handler; // reap all dead processes
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1){
		D("Error: sigaction");
		return(SIBYL_LISTEN_ERROR);
	}

	return (SIBYL_SUCCESS);
}

/* send_nonce
 *   Once the client's connection is accepted the server send a random nonce
 * 
 * INPUT:
 *   sock -> socket connected to the client
 *   *strnonce -> pointer to the string where the nonce will be stored
 *
 * OUTPUT:
 *   SIBYL_SUCCESS if the nonce is generated and sent with no errors
 *   SIBYL_NONCE_ERROR if any error ocurred
 *
 * COLLATERAL EFFECTS:
 *   The *strnonce is filled with the nonce
 *
 */
int send_nonce(int sock,
	       char **strnonce){
	u_char nonce[9];
	int count;

	// seed some bytes into the PRNG
	FILE *rand_f;
	int seed;
	struct timeval tv;
	if((rand_f = fopen("/dev/random", "r")) == NULL){
		gettimeofday(&tv,0);
		seed = tv.tv_sec + tv.tv_usec;
	} else {
		if(fread(&seed,sizeof(seed),1,rand_f) == 1) {
			fclose(rand_f);
		} else {
			gettimeofday(&tv,0);
			seed = tv.tv_sec + tv.tv_usec;
		}
	}
	RAND_seed((const void *)&seed, sizeof(seed));

	// generate a random nonce.
        // this may need to be larger than 8 bytes
	if (*strnonce == NULL){
		D("Error: strnonce calloc");
		return(SIBYL_NONCE_ERROR);
	}
	RAND_bytes(nonce, 8);
	for(count = 0; count < 8; count++)
		sprintf((*strnonce)+count*2, "%02X", nonce[count]);			

	// send the nonce
	if (send(sock, *strnonce, 17, 0) == -1){
		D("Error: sending strnonce");
		return(SIBYL_NONCE_ERROR);
	}

	// the nonce ends in '@'
	if (send(sock, "@", 1, 0) == -1){
		D("Error: sending '@'");
		return(SIBYL_NONCE_ERROR);
	}

	return(SIBYL_SUCCESS);
}

/* receive_msg
 *   
 *
 * INPUT:
 *   *msg -> message received
 *   sock -> socket connected to the client
 *   token[3] -> array where the 3 items parsed from the message will be stored,
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
int receive_msg(char **msg,
		int sock,
		char *token[3]){
	int count_bytes = 0;
	int bytes_rcvd = 0;

	/* Receive the client's message */
	while(count_bytes == 0 || 
	      !( (*((*msg)+(count_bytes-1)) == '\n') &&
		 (*((*msg)+(count_bytes-2)) == '@') &&
		 (*((*msg)+(count_bytes-3)) == '@') &&
		 (*((*msg)+(count_bytes-4)) == '\n'))){
		if((bytes_rcvd = recv(sock, *msg + count_bytes,
				      SIBYL_MAX_MSG - count_bytes, 0)) <= 0){
			perror("Connection error with the client.");
			return(SIBYL_RECV_ERROR);
		}
		if((count_bytes += bytes_rcvd) > SIBYL_MAX_MSG){
			perror("Sibyl's client is sending more bytes than"
			       "necessary");
                        // we exit here because the client is cheating
			return(SIBYL_NASTY_CLIENT);
		}
	}

	/* parse message, which is as follows: 
	 * m;p1;p2\n@@\n
 	 * where
 	 * m	nonce generated by the client, usually different from
 	 * 	the one generated by us (the sibyl).
 	 * p1	the entry in the 'shadow' file corresponding to
 	 * 	the user
 	 * p2	is the output of 
 	 * 	b64_encode(RSA_encrypt("nonce:crypt(passwd,salt)"))
 	 * 	where nonce is the nonce generated by the sibyl
 	 * the trailing \n@@\n is the end-of-message notification
 	 */

	/* remove the end-of-message notification */
	char *new_msg = (char *)calloc(count_bytes-4, sizeof(char));
        if(new_msg == NULL){
		D("Error: Unable to allocate memory for new_msg");
		return(errno);
        }
	strncpy(new_msg, *msg, count_bytes-4);

	/* token[0] = m */
	token[0] = strsep(&new_msg, ";");
	if(token[0] == NULL){
		D("Error: Malformed message received from the client");
		return(SIBYL_MALFORMED_MSG);
	}
	/* token[1] = p1 */
	token[1] = strsep(&new_msg, ";");
	if(token[1] == NULL){
		D("Error: Malformed message received from the client");
		return(SIBYL_MALFORMED_MSG);
	}
	/* token[2] = p2 */
	token[2] = strsep(&new_msg, ";");
	if(token[2] == NULL){
		D("Error: Malformed message received from the client");
		return(SIBYL_MALFORMED_MSG);
	}
	/* there should not be more tokens */
	if(strsep(&new_msg, ";") != NULL){
		D("Error: Malformed message received from the client");
		return(SIBYL_MALFORMED_MSG);
	}

	return(SIBYL_SUCCESS);
}

/* decrypt_token
 *   decrypt the token (p1 or p2) received and parsed from the client's message
 *
 * INPUT:
 *   *p_data -> pointer to store the decrypted token in
 *   *token -> string with the token (p1 or p2) 
 *   *decrypt -> private key for decryption
 *
 * OUTPUT:
 *   SIBYL_SUCCESS if the decryption is successful
 *   SIBYL_OPENSSL_ERROR if there is any error decrypting the token
 *
 * COLLATERAL EFFECTS:
 *   *p_data is filled with the decrypted token
 *
 */
int decrypt_token(char *p_data,
	          char *token,
	          RSA *decrypt){
	int rsa_d;
	char *p_rsa = (char *)calloc(RSA_size(decrypt) + 1, 1);
	if(p_rsa == NULL){
		D("Error: Unable to allocate memory for token_rsa");
		return(errno);
	}
	b64_pton(token,
		 (u_char *)p_rsa,
		 RSA_size(decrypt) + 1);
	rsa_d = RSA_private_decrypt(RSA_size(decrypt),
				    (u_char *)p_rsa,
				    (u_char *)p_data,
				    decrypt,
				    RSA_PKCS1_OAEP_PADDING);
	if (rsa_d == -1){
		ERR_print_errors_fp(stderr);
		exit(SIBYL_OPENSSL_ERROR);
	}

	return(SIBYL_SUCCESS);
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
 *   SIBYL_SUCCESS if there is no problems
 *   SIBYL_MALFORMED_MSG if the p2_data is malformed
 *
 * COLLATERAL EFFECTS:
 *   *auth_result is filled with the result of the password check
 *
 */
int is_pwd_ok(char *p1_data,
	      char *p2_data,
	      char **auth_result,
	      char *strnonce){

	/* Calculates v1, that is: p2_data = n:v1 */
	char *p2_token[2];
	/* p2_token[0] = nonce */
	p2_token[0] = strsep(&p2_data, ":");
	if(p2_token[0] == NULL){
		D("Error: Malformed p2_data");
		return(SIBYL_MALFORMED_MSG);
	}
	/* p2_token[1] = v1 */
	p2_token[1] = strsep(&p2_data, ":");
	if(p2_token[1] == NULL){
		D("Error: Malformed p2_data");
		return(SIBYL_MALFORMED_MSG);
	}

	D1("nonce: %s\n", p2_token[0]);
	D1("v1: %s\n", p2_token[1]);

	/* Is the password correct? */
	if((strcmp(p1_data, p2_token[1]) == 0) && 
	   (strcmp(strnonce, p2_token[0]) == 0)){
		*auth_result = "1";
		D("auth ok");
		printf("auth ok\n");
	} else {
		*auth_result = "0";
		D("auth NOok");
		printf("auth NOok\n");
	}

	return(SIBYL_SUCCESS);
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
int send_response(int *sock,
		  char *token[3],
		  char *auth_result,
		  RSA *sign){

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
				  strlen(auth_result), sizeof(char));
	if (message == NULL){
		D("Error: Unable to allocate memory for message");
		return(errno);
	}
	// TODO: use strncat instead of strcat with a NONCE_LENGHT const
	strcat(message, token[0]);
	strcat(message, ":");
	strcat(message, auth_result);

	printf("message: %s\n", message);

	/* computes the SHA-1 message digest (20 bytes) */
	char *sha1_m = (char *) calloc(20, sizeof(char));
	if (sha1_m == NULL){
		D("Error: Unable to allocate memory for sha1_m");
		return(errno);
	}
	SHA1((u_char *)message, strlen(message), (u_char*)sha1_m); 

	/* sign the message digest */
	char *signature = (char *) calloc(RSA_size(sign) + 1, 1);
	if (signature == NULL){
		D("Error: Unable to allocate memory for signature");
		return(errno);
	}
	u_int siglen;
	siglen = RSA_size(sign);
	if (RSA_sign(NID_sha1,
		     (u_char *)sha1_m,
		     20,
		     (u_char *)signature,
		     &siglen,
		     sign) != 1){
		ERR_print_errors_fp(stderr);
 		return(SIBYL_OPENSSL_ERROR);
	}
	
	/* encode the signature to base-64 */
	char *signature_b64 = (char *)calloc(RSA_size(sign) * 4,1);
	if(signature_b64 == NULL){
		D("Error: Unable to allocate memory for signature_b64");
		return(errno);
	}
	b64_ntop((u_char *)signature,
		 RSA_size(sign),
		 signature_b64,
		 RSA_size(sign) * 4);
	D1("signature_b64: %s\n", signature_b64);
	/* creates the response string */
	char *response;
	response = (char *) calloc(strlen(message) + 1 +
				   strlen(signature_b64), sizeof(char));
	if (response == NULL){
		D("Error: Unable to allocate memory for response");
		return(errno);
	}
	strcat(response, message);
	strcat(response, ";");
	strcat(response, signature_b64);
	strcat(response, "@");

	D1("response: %s\n", response);

	/* Send response */
	if (send(*sock, response, strlen(response), 0) == -1){
		D("Error: sending response");
		return(errno);
	}

	return(SIBYL_SUCCESS);
}

int main (int argc, char *argv[])
{
	int sock, newsock;
	struct sockaddr_storage client_addr;
	socklen_t sin_size;
	char s[INET6_ADDRSTRLEN];
	RSA *decrypt, *sign;
	int result;

	/* Read private keys */
	result = read_keys(&decrypt,
			   &sign);
	if(result != SIBYL_SUCCESS){
		D("Error reading keys");
		exit(SIBYL_KEYS_ERROR);
	}
        D("Private keys read");

	/* Start server */
	result = start_server(&sock);
	if(result != SIBYL_SUCCESS){
		D("Error starting server");
		exit(SIBYL_LISTEN_ERROR);
	}
        D("Server started\n");

	while(1){
		/* Accept connection */
		sin_size = sizeof client_addr;
		newsock = accept(sock, (struct sockaddr *)&client_addr, &sin_size);
		if (newsock == -1){
			perror("server: accept");
			continue;
		}

		inet_ntop(client_addr.ss_family,
			  get_in_addr((struct sockaddr *)&client_addr), s, sizeof(s));
		printf("server: got connection from %s\n", s);

		if (!fork()){ // child process
			close(sock); // child doesn't need the listener


			/* Send the nonce */
			char *strnonce;
			strnonce = (char *) calloc(17, sizeof(char));
			result = send_nonce(newsock, &strnonce);
			if (result != SIBYL_SUCCESS){
				D("Error sending the nonce");
				exit(result);
			}

			/* Receive the client's message and parse it */
			char *msg;
			char *token[3];
			msg = (char *) calloc(SIBYL_MAX_MSG, sizeof(char));
			if(msg == NULL){
				D("Unable to allocate memory for the client's message");
				exit(errno);
			}
			result = receive_msg(&msg,
					     newsock,
					     token);
			if (result != SIBYL_SUCCESS){
				D("Error receiving the client's message");
				exit(result);
			}

        		D1("Received: [%s]\n", msg);
			D1("m : %s\n", token[0]);
			D1("p1 : %s\n", token[1]);
			D1("p2 : %s\n", token[2]);

			/* Decrypt p1 (p1 = token[1]) */
			char *p1_data = (char *)calloc(RSA_size(decrypt) + 1, sizeof(u_char));
                        if(p1_data == NULL){
                                perror("Unable to allocate memory for p1_data");
                                exit(errno);
                        }
			result = decrypt_token(p1_data,
					       token[1],
					       decrypt);
			if (result != SIBYL_SUCCESS){
				D("Error decrypting p1");
				exit (result);
			}

			D1("p1_data: %s\n", p1_data);

			/* Decrypt p2 (p2 = token[2]) */
			char *p2_data = (char *)calloc(RSA_size(decrypt) + 1, sizeof(u_char));
                        if(p2_data == NULL){
                                perror("Unable to allocate memory for p2_data");
                                exit(errno);
                        }
			result = decrypt_token(p2_data,
					       token[2],
					       decrypt);
			if (result != SIBYL_SUCCESS){
				D("Error decrypting p2");
				exit(result);
			}

			D1("p2_data: %s\n", p2_data);

			/* Is the password correct */
			char *auth_result = calloc(1, sizeof(char));
			if(auth_result == NULL){
				D("Unable to allocate memory for auth_result");
				exit(errno);
			}
			result = is_pwd_ok(p1_data,
					   p2_data,
					   &auth_result,
					   strnonce);
			if (result != SIBYL_SUCCESS){
				D("Error checking is the password is OK");
				exit(result);
			}

			/* Send the response to the client */

			result = send_response(&newsock,
					       token,
					       auth_result,
					       sign);
			if (result != SIBYL_SUCCESS){
				D("Error sending the response");
				exit(result);
			}

			/* Close socket */
			close(newsock);
			exit(0);
		}
		close(newsock); // parent doesn't need this
	}

	return 0;
}
