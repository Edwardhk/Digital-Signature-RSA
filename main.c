#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <stdbool.h>
#include <string.h>

bool
rsa_sign(RSA* rsa, const unsigned char* Msg, 
	      size_t MsgLen, unsigned char** EncMsg, 
	      size_t* MsgLenEnc){
	EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
	EVP_PKEY* priKey  = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(priKey, rsa);

	if (EVP_DigestSignInit(m_RSASignCtx,NULL, EVP_sha256(), NULL,priKey) <= 0)
  		return false;
	if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0)
		return false;
	if (EVP_DigestSignFinal(m_RSASignCtx, NULL, MsgLenEnc) <= 0)
		return false;

	*EncMsg = (unsigned char*)malloc(*MsgLenEnc);
	if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0)
		return false;
	EVP_MD_CTX_cleanup(m_RSASignCtx);

	return true;
}

void
base_64_encode(const unsigned char* b64_input, size_t length, 
                   char** b64_output){ 
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);
	BIO_write(bio, b64_input, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);
	*b64_output=(*bufferPtr).data;
}

char*
write_rsa_to_char(RSA* rsa){
	char* pem_key;
	int keylen;

	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);
	keylen = BIO_pending(bio);
	pem_key = calloc(keylen+1, 1); /* Null-terminate */
	BIO_read(bio, pem_key, keylen);

	return pem_key;
}


int
main(){
	const int kBits = 2048;
	unsigned long e = RSA_F4;
	char *pem_key, *pem_key_fake;
	
	// BIGNUM PART
	BIGNUM* bignum = BN_new();
	if(BN_set_word(bignum, e))
		printf("[Debug] BIGNUM allocated!\n");
	else
		printf("[Debug] BIGNUM NOT allocated!\n");
 	
	// RSA PART
	RSA *rsa = RSA_new();
	RSA* rsa_fake = RSA_new();
	if(RSA_generate_key_ex(rsa, 2048, bignum, NULL))
		printf("[Debug] RSA allocated!\n");
	else
		printf("[Debug] RSA NOT allocated!\n");

	if(RSA_generate_key_ex(rsa_fake, 2048, bignum, NULL))
		printf("[Debug] FAKE RSA allocated!\n");
	else
		printf("[Debug] FAKE RSA NOT allocated!\n");

	// Generate char* pem_key using RSA* rsa
	pem_key = write_rsa_to_char(rsa);
	pem_key_fake = write_rsa_to_char(rsa_fake);
	//printf("[Debug] Private key generated as: \n%s\n", pem_key);
	//printf("[Debug] FAKE Private key generated as: \n%s\n", pem_key_fake);
 	
 	// Create a plain text input before the 
 	unsigned char* plain_text_input = "Hello I am Edward";
 	unsigned char* b64_input, b64_input_fake;
 	size_t b64_input_len, b64_input_fake_len;
	char* b64_output, b64_output_fake;

	printf("[Debug] Message before sign: \n%s\n\n", plain_text_input);

	rsa_sign(rsa, plain_text_input, strlen(plain_text_input), &b64_input, &b64_input_len); // Sign the message with RSA generated and store in b64_input
	rsa_sign(rsa_fake, plain_text_input, strlen(plain_text_input), &b64_input_fake, &b64_input_fake_len);
	//printf("[Debug] Message after sign: \n%s\n\n", b64_input);
	//printf("[Debug] Message after FAKE KEY sign: \n%s\n\n", b64_input_fake);

	base_64_encode(b64_input, strlen(b64_input), &b64_output);	// Encode the b64_input produced by rsa_sign
	base_64_encode(b64_input_fake, strlen(b64_input_fake), &b64_output_fake);
	printf("[Debug] Message after sign (base_64 encoded): \n%s\n\n", b64_output);
	printf("[Debug] FAKE Message after FAKE KEY sign (base_64 encoded): \n%s\n\n", b64_output_fake);
 
	// FREE THE MEMORY
	RSA_free(rsa);
	BN_free(bignum);
	free(pem_key);
	return 0;
}
