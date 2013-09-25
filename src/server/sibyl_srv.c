/* 
 * Sibyl server
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <sys/time.h>
#include <syslog.h>

#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <openssl/rsa.h>

#include "sibyl.h"
#include "sibyl_srv_support.h"

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa){
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main (int argc, char *argv[]){
	int sock, newsock;
	struct sockaddr_storage client_addr;
	socklen_t sin_size;
	char s[INET6_ADDRSTRLEN];
	RSA *decrypt, *sign;
        decrypt = NULL;
        sign    = NULL;

	int retval = SIBYL_SUCCESS;

        char *dir  = NULL;
        char *ip   = NULL;
        char *port = NULL;
        char *decr_namefile = NULL;
        char *sign_namefile = NULL;

        dir  = (char *)calloc(_POSIX_PATH_MAX + 1, sizeof(char));
        ip   = (char *)calloc(_POSIX_PATH_MAX + 1, sizeof(char));
        port = (char *)calloc(10, sizeof(char));
        decr_namefile = (char *)calloc(FILE_LEN + 1, sizeof(char));
        sign_namefile = (char *)calloc(FILE_LEN + 1, sizeof(char));

        if(dir == NULL || ip == NULL || port == NULL ||
           decr_namefile == NULL || sign_namefile == NULL){
                D("Malloc");
                retval = SIBYL_OSERR;
                goto FREE;
        }

        strncpy(dir, SIBYL_DIR, _POSIX_PATH_MAX);
        strncpy(port, SIBYL_PORT, 9);
        strncpy(decr_namefile, SIBYL_DECR_KEY, FILE_LEN);
        strncpy(sign_namefile, SIBYL_SIGN_KEY, FILE_LEN);

	/* Read options */
	int c;
	while((c = getopt(argc, argv, SIBYL_SRV_OPTS)) != -1){
                if(optarg == NULL)
                        c = 'h';
		switch(c){
			case 'd':
                                strncpy(decr_namefile, 
                                        optarg,
                                        _POSIX_PATH_MAX);
				break;
			case 's':
                                strncpy(sign_namefile,
                                        optarg,
                                        _POSIX_PATH_MAX);
				break;
			case 'p':
                                strncpy(port,
                                        optarg,
                                        9);
				break;
			case 'i':
                                strncpy(ip,
                                        optarg,
                                        _POSIX_PATH_MAX);
				break;
			case 'D':
                                strncpy(dir,
                                        optarg,
                                        _POSIX_PATH_MAX);
				break;
			case 'h':
			default:
				printf("Usage: %s -d decrypt -s sign -i IP -p port -D dir\n"
				       "  -d decrypt: decrypt private key (default: decrypt)\n"
				       "  -s sign: sign private key (default: sign)\n"
				       "  -i IP: IP where the server will listen (default: localhost)\n"
				       "  -p port: port where the server will listen (default: 9999)\n"
				       "  -D dir: directory where the private keys are stored "
				       "(default: /etc/sibyl)\n"
				       "  -h: shows this help text\n", argv[0]);
				exit(1);
		}
	}

	/* Read private keys */
	retval = read_keys(&decrypt,
			   decr_namefile,
			   &sign,
			   sign_namefile,
			   dir);
	if(retval != SIBYL_SUCCESS)
                goto FREE;
        D("Private keys read");

	/* Start server */
	retval = start_server(&sock,
			      ip,
			      port);
	if(retval != SIBYL_SUCCESS){
                goto FREE;
	}
        D("Server started\n");

	while(1){
		/* Accept connection */
		sin_size = sizeof client_addr;
		newsock = accept(sock, 
                                 (struct sockaddr *)&client_addr, 
                                 &sin_size);
		if (newsock == -1){
			perror("server: accept");
			continue;
		}

		inet_ntop(client_addr.ss_family,
			  get_in_addr((struct sockaddr *)&client_addr), 
                          s, 
                          sizeof(s));
		D1("server: got connection from %s\n", s);

		if (!fork()){ // child process
			close(sock); // child doesn't need the listener
			char *strnonce = NULL;
			char *msg      = NULL;
                        char command   = 0;
			char *token[3] = {NULL,NULL,NULL};
			char *p1_data     = NULL;
                        char *p2_data     = NULL;
                        char *auth_result = NULL;

			/* Send the nonce */
			strnonce = (char *) calloc(32, sizeof(char));
                        if (strnonce == NULL){
                                D("Malloc");
                                retval = SIBYL_OSERR;
                                goto ENDCHILD;
                        }

			retval = send_nonce(newsock, strnonce);
			if (retval != SIBYL_SUCCESS){
                                goto ENDCHILD;
			}

			/* Receive the client's message and parse it */
			msg = (char *) calloc(SIBYL_MAX_MSG, sizeof(char));
			if(msg == NULL){
                                D("Malloc");
                                retval = SIBYL_OSERR;
                                goto ENDCHILD;
			}
			retval = receive_msg(msg,
					     newsock,
                                             &command,
					     token);
			if (retval != SIBYL_SUCCESS){
                                goto ENDCHILD;
			}

        		D1("Received: [%s]\n", msg);
                        D1("command: [%c]\n", command);
			D1("m : %s\n", token[0]);
			D1("p1 : %s\n", token[1]);
			D1("p2 : %s\n", token[2]);

                        /* 
                         * Now there are several actions depending on the command
                         * which is stored in command.
                         */

                        /* Just send the public keys */
                        if(command == '-'){
                                retval = send_public_keys(dir,
                                                          decr_namefile,
                                                          sign_namefile,
                                                          newsock);
                                goto ENDCHILD;
                        }
                        
                        /* Any other command requires decryption of p1 */
			/* Decrypt p1 (p1 = token[1]) */
                        /* p1_data always includes a trailing 0 */
                        p1_data = (char *)calloc(RSA_size(decrypt) + 1, 
                                                 sizeof(u_char));
                        if(p1_data == NULL){
                                D("Malloc strnonce");
                                retval = SIBYL_OSERR;
                                goto ENDCHILD;
                        }


                        D1("token[1]:{%s}\n", token[1]);
                        /* this is path */
                        char *resp = (char *)calloc(SIBYL_MAX_MSG,
                                                    sizeof(u_char));
                        memcpy(resp, token[1], strlen(token[1]));
			retval = decrypt_token(p1_data,
                                               command,
					       resp,
					       decrypt);
			if (retval != SIBYL_SUCCESS){
                                printf("Decryption error\n");
                                goto ENDCHILD;
			}

			D1("p1_data: %s\n", p1_data);

                        /* 
                         * If command != \000 then it is '0' <= command <='9'
                         * and translation is asked for.
                         */
                        D1("token[0]:{%s}\n", token[0]);
                        if(command != 0){
                                if(strncmp(strnonce, 
                                           token[0], 
                                           strlen(strnonce))){
                                        D("Wrong nonce");
                                        retval = SIBYL_NONCE_ERROR;
                                        goto ENDCHILD;
                                }
                                retval = translate_and_send(p1_data,
                                                            command,
                                                            decr_namefile,
                                                            dir,
                                                            newsock,
                                                            sign);
                                goto ENDCHILD;
                        }

			/* 
                         * Decrypt p2 (p2 = token[2]):
                         * only if command == verify
                         */
                        p2_data = (char *)calloc(RSA_size(decrypt) + 1, 
                                                 sizeof(u_char));
                        if(p2_data == NULL){
                                perror("Unable to allocate memory for p2_data");
                                retval = SIBYL_OSERR;
                                goto ENDCHILD;
                        }

			retval = decrypt_token(p2_data,
                                               command,
					       token[2],
					       decrypt);
			if (retval != SIBYL_SUCCESS){
                                goto ENDCHILD;
			}

			D1("p2_data: %s\n", p2_data);

			/* Is the password correct */
                        auth_result = calloc(1, sizeof(char));
			if(auth_result == NULL){
				D("Unable to allocate memory for auth_result");
                                retval = SIBYL_OSERR;
                                goto ENDCHILD;
			}
			retval = is_pwd_ok(p1_data,
					   p2_data,
					   auth_result,
					   strnonce);
			if (retval != SIBYL_SUCCESS){
                                goto ENDCHILD;
			}

			/* Send the response to the client */

			retval = send_response(&newsock,
					       token,
					       auth_result,
					       sign);
			if (retval != SIBYL_SUCCESS){
                                goto ENDCHILD;
			}

                ENDCHILD:
                        free(strnonce);
                        free(msg);
                        free(p1_data);
                        free(p2_data);
                        free(auth_result);

			/* Close socket */
			close(newsock);
                        retval = SIBYL_SUCCESS;
                        goto FREE;
		}
		close(newsock); // parent doesn't need this
	}

FREE:

        RSA_free(decrypt);
        RSA_free(sign);
        free(dir);
        free(ip);
        free(port);
        free(decr_namefile);
        free(sign_namefile);
	exit(retval);
}
