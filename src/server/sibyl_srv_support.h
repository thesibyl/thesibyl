#ifndef __SIBYL_SRV_SUPPORT_H__
#define __SIBYL_SRV_SUPPORT_H__

/* Sibyl server options:
 * -d decrypt -> private key for decryption (default: decrypt)
 * -s sign    -> private key for signing (default: sign)
 * -i IP      -> IP where the server will listen (default: localhost)
 * -p port    -> port where the server will listen (default: 9999)
 * -D dir     -> directory where the private keys are stored
 */
#define SIBYL_SRV_OPTS "d:s:i:p:D:h"

#define PASSPHRASE_MAX_LENGTH 1024

int
read_keys(RSA **decrypt, char *decr_filename, RSA **sign, char *sign_filename,
		char *dir);

int
start_server(int *sock, char *ip, char *port);

int
send_nonce(int sock, char *strnonce);

int
receive_msg(char *msg, int sock, char *command, char *token[3]);

int
decrypt_token(char *p_data, char key, char *token, RSA *decrypt);

int
is_pwd_ok(char *p1_data, char *p2_data, char *auth_result, char *strnonce);

int
send_response(int *sock, char *token[3], char *auth_result, RSA *sign);

int
translate_and_send(char *p1_data, char version, char *decr_namefile,
		char *dir, int  sock, RSA *sign);

int
send_public_keys(char *dir, char *decrypt_fn, char *sign_fn, int sock);

int
sign_msg_and_send(char *msg, RSA *sign, int sock); 

#endif /* __SIBYL_SRV_SUPPORT_H__ */
