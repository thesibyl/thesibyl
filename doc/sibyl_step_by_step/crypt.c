#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <crypt.h>

int main(int argc, char *argv[])
{
	unsigned long seed[2];
	const char *const seedchars =
	"./0123456789ABCDEFGHIJKLMNOPQRST"
	"UVWXYZabcdefghijklmnopqrstuvwxyz";
	char *password;
	int i;

	if (argc == 2) {
		char salt[] = "$1$........";
		/* If no args are passed, we generate a (not very) random seed */
		seed[0] = time(NULL);
		seed[1] = getpid() ^ (seed[0] >> 14 & 0x30000);

		/* Turn it into printable characters from `seedchars'. */
		for (i = 0; i < 8; i++)
		salt[3+i] = seedchars[(seed[i/5] >> (i%5)*6) & 0x3f];

		/* Read in the user's password and encrypt it. */
		password = crypt(argv[1], salt);
     	} else if (argc == 3) {
		/* If the salt is passed */
		/* Read in the user's password and encrypt it. */
		password = crypt(argv[1], argv[2]);
	} else {
		printf ("Usage: %s password [salt]\n", argv[0]);
		return(1);
	}

  /* Print the results. */
  puts(password);
  return 0;
}

