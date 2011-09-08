
int read_keys(RSA **decrypt,
	      RSA **sign);

int start_server(int *sock);

int send_nonce(int sock,
	       char **strnonce);

int receive_msg(char **msg,
		int sock,
		char *token[3]);

int decrypt_token(char *p_data,
		  char *token,
		  RSA *decrypt);

int is_pwd_ok(char *p1_data,
	      char *p2_data,
	      char **auth_result,
	      char *strnonce);

int send_response(int *sock,
		  char *token[3],
		  char *auth_result,
		  RSA *sign);
