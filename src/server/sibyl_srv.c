/* Sibyl server
 * 
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
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main (int argc, char *argv[])
{
	int sock, newsock;
	struct sockaddr_storage client_addr;
	socklen_t sin_size;
	char s[INET6_ADDRSTRLEN];
	RSA *decrypt, *sign;
	int result;

	/* Default values */
	char *dir = SIBYL_DIR;
	char *decr_namefile = SIBYL_DECR_KEY;
	char *sign_namefile = SIBYL_SIGN_KEY;
	char *ip = NULL;
	char *port = SIBYL_PORT;

	/* Read options */
	int c;
	while((c = getopt(argc, argv, SIBYL_SRV_OPTS)) != -1){
		switch(c){
			case 'd':
				decr_namefile = optarg;
				break;
			case 's':
				sign_namefile = optarg;
				break;
			case 'p':
				port = optarg;
				break;
			case 'i':
				ip = optarg;
				break;
			case 'D':
				dir = optarg;
				break;
			case 'h':
			default:
				printf("Usage: %s -d decrypt -s sign -i IP -p port -D dir\n"
				       "  -d decrypt: decrypt private key (default: decrypt)\n"
				       "  -s sign: sign private key (default: sign)\n"
				       "  -i IP: IP where the server will listen (default: localhost)\n"
				       "  -p port: port where the server will listen (default: 9999)\n"
				       "  -D dir: directory where the private keys are stored "
				       "(default: /etc/sibyl)\n", argv[0]);
				exit(1);
		}
	}

	/* Read private keys */
	result = read_keys(&decrypt,
			   decr_namefile,
			   &sign,
			   sign_namefile,
			   dir);
	if(result != SIBYL_SUCCESS){
		D("Error reading keys");
		exit(SIBYL_KEYS_ERROR);
	}
        D("Private keys read");

	/* Start server */
	result = start_server(&sock,
			      ip,
			      port);
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
