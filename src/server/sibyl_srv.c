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

int read_keys(RSA **decrypt, RSA **sign){

	/* RSA private keys */
	char *decr_fname, *sign_fname;
	decr_fname = (char *)calloc(_POSIX_PATH_MAX, sizeof(char));
	sign_fname = (char *)calloc(_POSIX_PATH_MAX, sizeof(char));
	if(decr_fname == NULL || sign_fname == NULL){
		perror("decr_fname or sign_fname alloc");
		return(errno);
	}

	if(strlen(SIBYL_DIR) >= _POSIX_PATH_MAX ||
	   FILE_LEN >= _POSIX_PATH_MAX ||
	   (strlen(SIBYL_DIR) + 1 + FILE_LEN) >= _POSIX_PATH_MAX){
		perror("dir length");
		return(errno);
	}

        snprintf(decr_fname, _POSIX_PATH_MAX, "%s/%s", SIBYL_DIR, SIBYL_DECR_KEY);
        snprintf(sign_fname, _POSIX_PATH_MAX, "%s/%s", SIBYL_DIR, SIBYL_SIGN_KEY);

	/* Fetch the private keys */
	FILE *decr_f, *sign_f;
	if((decr_f = fopen(decr_fname, "r")) == NULL){
		perror("Unable to open file decr_f");
		return(errno);
	}
	if((sign_f = fopen(sign_fname, "r")) == NULL){
		perror("Unable to open file sign_f");
		return(errno);
	}

	/* RSA *decrypt *sign */
	if((*decrypt = RSA_new()) == NULL){
		perror("Unable to RSA_new() decrypt");
		return(errno);
	}
	if((*sign = RSA_new()) == NULL){
		perror("Unable to RSA_new() sign");
		return(errno);
	}

	/* Read the private keys */
	PEM_read_RSAPrivateKey(decr_f, decrypt, NULL, NULL);
	PEM_read_RSAPrivateKey(sign_f, sign, NULL, NULL);

	if((*decrypt)->n == NULL){
		perror("Error reading the RSA decrypt key");
		fclose(decr_f);
		fclose(sign_f);
		return(errno);
	}
	if((*sign)->n == NULL){
		perror("Error reading the RSA sign key");
		fclose(decr_f);
		fclose(sign_f);
		return(errno);
	}
	fclose(decr_f);
	fclose(sign_f);

	return(SIBYL_SUCCESS);

}

int main (int argc, char *argv[])
{
	int status, sock, newsock;
	struct addrinfo hints, *srvinfo, *p;
	struct sockaddr_storage client_addr;
	socklen_t sin_size;
	struct sigaction sa;
	int yes = 1;
	char s[INET6_ADDRSTRLEN];
	RSA *decrypt, *sign;
	int result;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	result = read_keys(&decrypt, &sign);
	if(result != SIBYL_SUCCESS){
		D("Error reading keys");
		exit(SIBYL_KEYS_ERROR);
	}
        D("Private keys read");

	/* Start listening */
	if ((status = getaddrinfo(NULL, SIBYL_PORT, &hints, &srvinfo)) != 0) {
		fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
                // return status?
		return 1;
	}

	// loop through all the results and bind to the first we can
	for(p = srvinfo; p != NULL; p = p->ai_next){
		if ((sock = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}

		if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes,
				sizeof(int)) == -1){
			perror("server: setsockopt");
			continue;
		}

  	if (bind(sock, p->ai_addr, p->ai_addrlen) == -1) {
			close(sock);
			perror("server: bind");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "server: failed to bind\n");
                //return 2? should be a macro, should it not?
		return 2;
	}

	freeaddrinfo(srvinfo);

	if (listen(sock, SIBYL_BACKLOG) == -1) {
		perror("listen");
		exit(errno);
	}

	sa.sa_handler = sigchld_handler; // reap all dead processes
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1){
		perror("sigaction");
		exit(errno);
	}

        D("Waiting for connections...\n");

	while(1){
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
			u_char nonce[9];
			int count;
			char *strnonce;
			strnonce = (char *) calloc(17, sizeof(char));
			if (strnonce == NULL){
				perror("strnonce calloc");
				exit(errno);
			}
			RAND_bytes(nonce, 8);
			for(count = 0; count < 8; count++)
				sprintf(strnonce+count*2, "%02X", nonce[count]);			
			// send the nonce
			if (send(newsock, strnonce, 17, 0) == -1){
				perror("send strnonce");
				exit(errno);
			}

			// the nonce ends in '@'
			if (send(newsock, "@", 1, 0) == -1){
				perror("send '@'");
				exit(errno);
			}

			/* receive the client's message */
			char *msg;
			msg = (char *) calloc(SIBYL_MAX_MSG, sizeof(char));
			if(msg == NULL){
				perror("Unable to allocate memory for the client's message");
				exit(errno);
			}

			int count_bytes = 0;
			int bytes_rcvd = 0;
			while(count_bytes == 0 || 
			      !( (*(msg+(count_bytes-1)) == '\n') &&
				 (*(msg+(count_bytes-2)) == '@') &&
				 (*(msg+(count_bytes-3)) == '@') &&
				 (*(msg+(count_bytes-4)) == '\n'))){
				if((bytes_rcvd = recv(newsock, msg + count_bytes,
						      SIBYL_MAX_MSG - count_bytes, 0)) <= 0){
					perror("Connection error with the client.");
					exit(SIBYL_RECV_ERROR);
				}
				if((count_bytes += bytes_rcvd) > SIBYL_MAX_MSG){
					perror("Sibyl's client is sending more bytes than"
					       "necessary");
                                        // we exit here because the client is cheating
					exit(SIBYL_NASTY_CLIENT);
				}
			}

                        D1("Received: [%s]\n", msg);

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
                                perror("Unable to allocate memory for new_msg");
                                exit(errno);
                        }
			strncpy(new_msg, msg, count_bytes-4);

			char *token[3];
			/* token[0] = m */
			token[0] = strsep(&new_msg, ";");
			if(token[0] == NULL){
				perror("Malformed message received from the client");
				exit(SIBYL_MALFORMED_MSG);
			}
			/* token[1] = p1 */
			token[1] = strsep(&new_msg, ";");
			if(token[1] == NULL){
				perror("Malformed message received from the client");
				exit(SIBYL_MALFORMED_MSG);
			}
			/* token[2] = p2 */
			token[2] = strsep(&new_msg, ";");
			if(token[2] == NULL){
				perror("Malformed message received from the client");
				exit(SIBYL_MALFORMED_MSG);
			}
			/* there should not be more tokens */
			if(strsep(&new_msg, ";") != NULL){
				perror("Malformed message received from the client");
				exit(SIBYL_MALFORMED_MSG);
			}

			D1("m : %s\n", token[0]);
			D1("p1 : %s\n", token[1]);
			D1("p2 : %s\n", token[2]);

			/* decrypt p1 (p1 = token[1]) */
			int rsa_d;
			char *p1_rsa = (char *)calloc(RSA_size(decrypt) + 1, 1);
                        if(p1_rsa == NULL){
                                perror("Unable to allocate memory for p1_rsa");
                                exit(errno);
                        }
			b64_pton(token[1],
				 (u_char *)p1_rsa,
				 RSA_size(decrypt) + 1);

			char *p1_data = (char *)calloc(RSA_size(decrypt) + 1, sizeof(u_char));
                        if(p1_data == NULL){
                                perror("Unable to allocate memory for p1_data");
                                exit(errno);
                        }

			rsa_d = RSA_private_decrypt(RSA_size(decrypt),
						    (u_char *)p1_rsa,
						    (u_char *)p1_data,
						    decrypt,
						    RSA_PKCS1_OAEP_PADDING);

			if (rsa_d == -1){
                                ERR_print_errors_fp(stderr);
				exit(SIBYL_OPENSSL_ERROR);
			}

			D1("p1_data: %s\n", p1_data);

			/* decrypt p2 (p2 = token[2]) */
			char *p2_rsa = (char *)calloc(RSA_size(decrypt) + 1, sizeof(u_char));
                        if(p2_rsa == NULL){
                                perror("Unable to allocate memory for p2_rsa");
                                exit(errno);
                        }
			b64_pton(token[2],
				 (u_char *)p2_rsa,
				 RSA_size(decrypt) + 1);

			char *p2_data = (char *)calloc(RSA_size(decrypt) + 1, sizeof(u_char));
                        if(p2_data == NULL){
                                perror("Unable to allocate memory for p2_data");
                                exit(errno);
                        }

			rsa_d = RSA_private_decrypt(RSA_size(decrypt),
						    (u_char *)p2_rsa,
						    (u_char *)p2_data,
						    decrypt,
						    RSA_PKCS1_OAEP_PADDING);

			if (rsa_d == -1){
                                ERR_print_errors_fp(stderr);
				exit(SIBYL_OPENSSL_ERROR);
			}

			D1("p2_data: %s\n", p2_data);

			/* Calculates v1, that is: p2_data = n:v1 */
			char *p2_token[2];
			/* p2_token[0] = nonce */
			p2_token[0] = strsep(&p2_data, ":");
			if(p2_token[0] == NULL){
				perror("Malformed p2_data");
				exit(SIBYL_MALFORMED_MSG);
			}
			/* p2_token[1] = v1 */
			p2_token[1] = strsep(&p2_data, ":");
			if(p2_token[1] == NULL){
				perror("Malformed p2_data");
				exit(SIBYL_MALFORMED_MSG);
			}

			D1("nonce: %s\n", p2_token[0]);
			D1("v1: %s\n", p2_token[1]);

			/* Is the password correct? */
			char *auth_result = calloc(1, sizeof(char));
                        if(auth_result == NULL){
                                perror("Unable to allocate memory for auth_result");
                                exit(errno);
                        }
			if((strcmp(p1_data, p2_token[1]) == 0) && 
			   (strcmp(strnonce, p2_token[0]) == 0)){
				auth_result = "1";
				printf("auth ok\n");
			} else {
				auth_result = "0";
				printf("auth NOok\n");
			}

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
				perror("Unable to allocate memory for message");
				exit(errno);
			}
			// TODO: use strncat instead of strcat with a NONCE_LENGHT const
			strcat(message, token[0]);
			strcat(message, ":");
			strcat(message, auth_result);

			printf("message: %s\n", message);

			/* computes the SHA-1 message digest (20 bytes) */
			char *sha1_m = (char *) calloc(20, sizeof(char));
			if (sha1_m == NULL){
				perror("Unable to allocate memory for sha1_m");
				exit(errno);
			}
			SHA1((u_char *)message, strlen(message), (u_char*)sha1_m); 

			/* sign the message digest */
			char *signature = (char *) calloc(RSA_size(sign) + 1, 1);
			if (signature == NULL){
				perror("Unable to allocate memory for signature");
				exit(errno);
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
                                exit(SIBYL_OPENSSL_ERROR);
			}

			/* encode the signature to base-64 */
			char *signature_b64 = (char *)calloc(RSA_size(sign) * 4,1);
                        if(signature_b64 == NULL){
                                perror("Unable to allocate memory for signature_b64");
                                exit(errno);
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
				perror("Unable to allocate memory for response");
				exit(errno);
			}
			strcat(response, message);
			strcat(response, ";");
			strcat(response, signature_b64);
                        strcat(response, "@");

			D1("response: %s\n", response);

			/* Send response */
			if (send(newsock, response, strlen(response), 0) == -1){
				perror("send response");
				exit(errno);
			}

			/* Close socket */
			close(newsock);
			exit(0);
		}
		close(newsock); // parent doesn't need this
	}

	return 0;
}
