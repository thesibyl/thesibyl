NUM_BITS = 2048

keys: sign sign.pub decrypt decrypt.pub

nopass: sign-nopass sign.pub decrypt-nopass decrypt.pub

sign:
	@echo generating key files: sign, sign.pub, decrypt, decrypt.pub
	@openssl genrsa -out sign.tmp -aes256 $(NUM_BITS) 
	@mv sign.tmp sign

sign-nopass:
	@echo generating key files: sign, sign.pub, decrypt, decrypt.pub
	@openssl genrsa -out sign.tmp $(NUM_BITS) 
	@mv sign.tmp sign

sign.pub: sign
	@openssl rsa -pubout -in sign > sign.pub.tmp
	@mv sign.pub.tmp sign.pub

decrypt:
	@openssl genrsa -out decrypt.tmp -aes256 $(NUM_BITS) 
	@mv decrypt.tmp decrypt

decrypt-nopass:
	@openssl genrsa -out decrypt.tmp $(NUM_BITS) 
	@mv decrypt.tmp decrypt

decrypt.pub:
	@openssl rsa -pubout -in decrypt > decrypt.pub.tmp
	@mv decrypt.pub.tmp decrypt.pub

clean:
	@rm sign sign.pub decrypt decrypt.pub {~} || true
