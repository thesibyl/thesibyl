#include <unistd.h>
#include <stdlib.h>

int main (int argc, char *argv[]){

	if(argc != 2){
		printf("Usage: %s [password]\n", argv[0]);
	}
	
	printf("%s\n", crypt(argv[1], "$1$326428$"));
	exit(1);


}
