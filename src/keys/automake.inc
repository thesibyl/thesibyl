NUM_BITS = 2048

keys: sign sign.pub decrypt decrypt.pub

sign:
	@echo generating key file sign...
	@@OPENSSL@ genrsa -out sign $(NUM_BITS) 

sign.pub: sign
	@echo generating key file sign.pub...
	@@OPENSSL@ rsa -pubout -in sign > sign.pub

decrypt:
	@echo generating key file decrypt...
	@@OPENSSL@ genrsa -out decrypt $(NUM_BITS) 

decrypt.pub:
	@echo generating key file decrypt.pub...
	@@OPENSSL@ rsa -pubout -in decrypt > decrypt.pub

cleankeys:
	@rm sign sign.pub decrypt decrypt.pub {~} || true
