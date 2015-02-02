#The Sibyl

Secure storage of the shadow file and, in general, of any database of
secret authentication tokens (think of passwords of users of a
Web-based service) is one of the main security concerns of a Systems
Administrator.

With the advent of rainbow tables and cheap fast hardware, this
problem has become especially relevant: today, dictionary attacks take
negligible time (and the fact is that users will end up using
passwords as simple as possible).

We present a different approach for storing shadow files: using a
separate server for checking the correctness of the password
introduced by the user, taking advantage of asymmetric key encryption.

In summary: instead of keeping the hash (as `crypt(3)` does, or `SHA1`) of
the password in the shadow file, store an OAEP RSA-cyphertext of the
password (using a public encryption key) and, each time the user tries
to log in, ask someone (the owner of the private key) if the
OAEP-encryption of the password issued by the logging user matches the
stored cyphertext. That is: use an oracle to ask if the user has
entered the correct password or not. This oracle is the Sibyl.

See the [website](http://thesibyl.net) for more up-to-date documentation. 


