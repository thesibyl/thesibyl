NUM_BITS = 2048

keys: sign sign.pub decrypt decrypt.pub

sign:
	@echo generating key file sign...
	@openssl genrsa -out sign $(NUM_BITS) 

sign.pub: sign
	@echo generating key file sign.pub...
	@openssl rsa -pubout -in sign > sign.pub

decrypt:
	@echo generating key file decrypt...
	@openssl genrsa -out decrypt $(NUM_BITS) 

decrypt.pub:
	@echo generating key file decrypt.pub...
	@openssl rsa -pubout -in decrypt > decrypt.pub

clean:
	@rm sign sign.pub decrypt decrypt.pub {~} || true
