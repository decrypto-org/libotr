/*/gcry_
 *  Off-the-Record Messaging library
 *  Copyright (C) 2015-2016  Dimitrios Kolotouros <dim.kolotouros@gmail.com>,
 *  						 Konstantinos Andrikopoulos <el11151@mail.ntua.gr>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of version 2.1 of the GNU Lesser General
 *  Public License as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <gcrypt.h>

#include "chat_enc.h"
#include "dh.h"
#include "stdlib.h"
#include "instag.h"

#define OTRL_ENC_KEY_SIZE 32


gcry_error_t chat_enc_initialize_cipher(OtrlChatEncInfo *enc_info)
{
    gcry_error_t err = gcry_error(GPG_ERR_NO_ERROR);
    unsigned char *key = NULL;

    fprintf(stderr, "libotr-mpOTR: chat_enc_initialize_cipher: start\n");
    /* NOT FOR PRODUCTION */
    /* This code is not for production as this is just a dummy way
     * to generate a secret key with no GKA protocol. */
    /* enc_info->key */
    key = gcry_random_bytes_secure(OTRL_ENC_KEY_SIZE, GCRY_STRONG_RANDOM);


    fprintf(stderr, "libotr-mpOTR: chat_enc_initialize_cipher: before memcpy\n");
    memcpy(enc_info->key, key, OTRL_ENC_KEY_SIZE);

    fprintf(stderr, "libotr-mpOTR: chat_enc_initialize_cipher: before memset\n");
    memset(enc_info->ctr, 0, 16);

    /* NOT FOR PRODUCTION */
    /* This code is not meant for production as it is very likely that
     * a (key,ctr) pair will be reused by different users */


    fprintf(stderr, "libotr-mpOTR: chat_enc_initialize_cipher: before cipher open\n");
    err = gcry_cipher_open( &(enc_info->cipher), GCRY_CIPHER_AES256,
			    GCRY_CIPHER_MODE_CTR, GCRY_CIPHER_SECURE);
    /**********************/
    if (err) goto err;


    fprintf(stderr, "libotr-mpOTR: chat_enc_initialize_cipher: before setkey\n");
    err = gcry_cipher_setkey(enc_info->cipher, enc_info->key, OTRL_ENC_KEY_SIZE);
    if (err) goto err;


    fprintf(stderr, "libotr-mpOTR: chat_enc_initialize_cipher: end no_err\n");
    return err;

err:

    fprintf(stderr, "libotr-mpOTR: chat_enc_initialize_cipher: end err\n");
    gcry_cipher_close(enc_info->cipher);
    return err;

}

gcry_error_t chat_enc_sync_key(OtrlChatEncInfo *enc_info,
			       const OtrlAuthGKAInfo *auth_info)
{
    gcry_error_t err = gcry_error(GPG_ERR_NO_ERROR);
    // TODO
    // allocate secure memory for key
    //enc_info->key = gcry_malloc_secure(32);

    fprintf(stderr, "libotr-mpOTR: chat_enc_sync_key: start\n");
    // copy the key to the enc_info
    memcpy(enc_info->key, auth_info->key, 32);


    fprintf(stderr, "libotr-mpOTR: chat_enc_sync_key: before memset\n");
    // copy the key to the enc_info
    // set the counter
    memset(enc_info->ctr, 0, 16);


    fprintf(stderr, "libotr-mpOTR: chat_enc_sync_key: before cipher_open\n");
    // copy the key to the enc_info
    // initialise the cipher
    err = gcry_cipher_open( &enc_info->cipher, GCRY_CIPHER_AES256,
    		GCRY_CIPHER_MODE_CTR, GCRY_CIPHER_SECURE);
    if(err) goto err;


    fprintf(stderr, "libotr-mpOTR: chat_enc_sync_key: before setkey\n");
    // copy the key to the enc_info
    //set the key we just copied
    err = gcry_cipher_setkey(enc_info->cipher, enc_info->key, OTRL_ENC_KEY_SIZE);
    if (err) goto err;


    fprintf(stderr, "libotr-mpOTR: chat_enc_sync_key: end no_err\n");
    // copy the key to the enc_info
    return err;

err:

    fprintf(stderr, "libotr-mpOTR: chat_enc_sync_key: end err\n");
    // copy the key to the enc_info
    gcry_cipher_close(enc_info->cipher);
    return err;
}

gcry_error_t chat_enc_encrypt_data(gcry_cipher_hd_t cipher, OtrlChatEncInfo *enc_info,
				   const char *in, size_t inlen,
				   unsigned char *out, size_t outlen)
{
    gcry_error_t err = gcry_error(GPG_ERR_NO_ERROR);


    fprintf(stderr, "libotr-mpOTR: chat_enc_encrypt_data: start\n");

    otrl_dh_incctr(enc_info->ctr);

    fprintf(stderr, "libotr-mpOTR: chat_enc_encrypt_data: before cipher reset\n");
    err = gcry_cipher_reset(cipher);
    if(err) goto err;


    fprintf(stderr, "libotr-mpOTR: chat_enc_encrypt_data: befor setctr\n");
    err = gcry_cipher_setctr(cipher, enc_info->ctr, 16);
    if(err) goto err;

    fprintf(stderr, "libotr-mpOTR: chat_enc_encrypt_data: before encrypt\n");
    err = gcry_cipher_encrypt(cipher, out, outlen, in, inlen);
    if(err) goto err;

    fprintf(stderr, "libotr-mpOTR: chat_enc_encrypt_data: end no_err\n");
    return err;
err:
    fprintf(stderr, "libotr-mpOTR: chat_enc_encrypt_data: end err\n");
    return err;
}

gcry_error_t chat_enc_decrypt_data(const gcry_cipher_hd_t cipher,
				   const unsigned char ctr[16],
				   char *out, size_t outlen,
				   const unsigned char *in, size_t inlen)
{
    gcry_error_t err = gcry_error(GPG_ERR_NO_ERROR);

    fprintf(stderr, "libotr-mpOTR: chat_enc_decrypt_data: start \n");

    err = gcry_cipher_reset(cipher);
    if (err) goto err;

    fprintf(stderr, "libotr-mpOTR: chat_enc_decrypt_data: before setctr \n");
    err = gcry_cipher_setctr(cipher, ctr, 16);
    if (err) goto err;


    fprintf(stderr, "libotr-mpOTR: chat_enc_decrypt_data: before gcry_cipher_decrypt\n");
    err = gcry_cipher_decrypt(cipher, out, outlen, in, inlen);
    if (err) goto err;


    fprintf(stderr, "libotr-mpOTR: chat_enc_decrypt_data: end \n");
err:
    return err;
}


gcry_error_t chat_enc_get_personal_cipher(const OtrlChatEncInfo *enc_info,
			      const otrl_instag_t sender_id, gcry_cipher_hd_t *cipher)
{
    unsigned char *hashdata;
    unsigned char *sdata;
    size_t sdata_len;
    size_t hash_len;
    size_t base = 0;
    gcry_error_t err;

    fprintf(stderr, "libotr-mpOTR: chat_enc_get_personal_key: start\n");

    sdata_len = sizeof(sender_id) + sizeof(enc_info->key);

    sdata = gcry_malloc_secure(sdata_len);
    if(!sdata) {
	fprintf(stderr, "libotr-mpOTR: chat_enc_get_personal_key: sdata malloc failed\n");
	return gcry_error(GPG_ERR_ENOMEM);
    }

    memmove(sdata, &sender_id, sizeof(sender_id));
    base += sizeof(sender_id);

    memmove(sdata + base, enc_info->key, sizeof(enc_info->key));
    base += sizeof(enc_info->key);

    hash_len = gcry_md_get_algo_dlen(GCRY_MD_SHA256);
    hashdata = gcry_malloc_secure(hash_len);
    if(!hashdata) {
	fprintf(stderr, "libotr-mpOTR: chat_enc_get_personal_key: hashdata malloc failed\n");
	gcry_free(sdata);
	return gcry_error(GPG_ERR_ENOMEM);
    }

    gcry_md_hash_buffer(GCRY_MD_SHA256, hashdata, sdata, sdata_len);
    //if (err) {
    //	fprintf(stderr, "libotr-mpOTR: chat_enc_get_personal_key: keygen failed\n");
    //	return err;
    //}

    err = gcry_cipher_open(cipher, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CTR,
			   GCRY_CIPHER_SECURE);
    if (err) {
	fprintf(stderr, "libotr-mpOTR: chat_enc_get_personal_key: cipher open failed\n");
	gcry_free(sdata);
	gcry_free(hashdata);
	return err;
    }

    err = gcry_cipher_setkey(*cipher, hashdata, hash_len);
    if (err) {
	fprintf(stderr, "libotr-mpOTR: chat_enc_get_personal_key: key set failed\n");

	gcry_free(sdata);
	gcry_free(hashdata);
	gcry_cipher_close(*cipher);
	return err;

    }

    fprintf(stderr, "sdata: ");
    for(size_t i = 0; i < sdata_len; i++)
	fprintf(stderr, "%02X", sdata[i]);
    fprintf(stderr, "\n");
    fprintf(stderr, "instag: %u \nhashdata: ", sender_id);
    for(size_t i =0; i<hash_len; i++)
	fprintf(stderr, "%02X", hashdata[i]);
    fprintf(stderr, "\n");

    fprintf(stderr, "libotr-mpOTR: chat_enc_get_personal_key: key exit no error\n");
    gcry_free(sdata);
    gcry_free(hashdata);
    return gcry_error(GPG_ERR_NO_ERROR);
}

char * chat_enc_decrypt(const OtrlChatContext *ctx, const unsigned char *ciphertext,
			size_t datalen, const unsigned char top_ctr[8],
			const otrl_instag_t sender_id) {
	char *plaintext;
	//size_t msglen;
	unsigned char ctr[16];
	gcry_cipher_hd_t dcipher;
	gcry_error_t err;
	fprintf(stderr, "libotr-mpOTR: chat_enc_decrypt: start\n");
	// TODO Dimitris: This function is meant to be a wrapper for enc_decrypt_data.
	// TODO Dimitris: I just return some dummy data for now.
	/*size_t test_size = 5;
	plaintext = (char *)malloc(5*sizeof(char));
	if(!plaintext)
		return NULL;
	memcpy(plaintext, "test\0", 5);
	*/

	fprintf(stderr, "libotr-mpOTR: chat_enc_decrypt: before malloc\n");
	plaintext = malloc(datalen*sizeof(char) + 1);
	plaintext[datalen] = '\0';

	if(!plaintext) {
	    fprintf(stderr, "libotr-mpOTR: chat_enc_decrypt: !plaintext\n");
	    return NULL;
	}


	fprintf(stderr, "libotr-mpOTR: chat_enc_decrypt: before memset\n");
	memset(ctr, 0, 16);

	fprintf(stderr, "libotr-mpOTR: chat_enc_decrypt: before memmove\n");
	memmove(ctr, top_ctr, 8);


	fprintf(stderr, "libotr-mpOTR: chat_enc_get_personal_key: before personal cipher\n");
	err = chat_enc_get_personal_cipher(&(ctx->enc_info), sender_id, &dcipher);
	if (err) {
	    fprintf(stderr, "libotr-mpOTR: chat_enc_decrypt: personal cipher failed\n");
	    free(plaintext);
	    return NULL;
	}

	fprintf(stderr, "libotr-mpOTR: chat_enc_decrypt: before decyrpt_data\n");
	err = chat_enc_decrypt_data(dcipher, ctr, plaintext, datalen,
				       ciphertext, datalen);

	if(err){

	fprintf(stderr, "libotr-mpOTR: chat_enc_decrypt: there was an error\n");
	    free(plaintext);
	    gcry_cipher_close(dcipher);
	    return NULL;
	}

	gcry_cipher_close(dcipher);

	fprintf(stderr, "libotr-mpOTR: chat_enc_decrypt %s: end\n", plaintext);
	return plaintext;
}


//TODO this function is not complete. must incorporate personal cipher
unsigned char * chat_enc_encrypt(OtrlChatContext *ctx, const char *plaintext) {
	//char *ciphertext;
	size_t msglen = 0;
	unsigned char *ciphertext = NULL;
	gcry_cipher_hd_t ecipher;
	gcry_error_t err = gcry_error(GPG_ERR_NO_ERROR);

	fprintf(stderr, "libotr-mpOTR: chat_enc_encrypt: start\n");
	// copy the key to the enc_info
	// TODO Dimitris: This function is meant to be a wrapper for enc_encrypt_data.
	// TODO Dimitris: I just return some dummy data for now.
	/*size_t test_size = 5;
	ciphertext = (char *)malloc(5*sizeof(char));
	if(!ciphertext)
		return NULL;
	memcpy(ciphertext, "test\0", 5);
*/

	fprintf(stderr, "libotr-mpOTR: chat_enc_encrypt: befor strlen\n");
	//TODO msglen should be passed as an argument, plaintext is not always text data
	msglen = strlen(plaintext);

	ciphertext = malloc(msglen*sizeof(char));

	if(!ciphertext) {

	    fprintf(stderr, "libotr-mpOTR: chat_enc_encrypt: !ciphertext\n");
	    return NULL;
	}


	fprintf(stderr, "libotr-mpOTR: chat_enc_encrypt: before personal cipher\n");
	err = chat_enc_get_personal_cipher(&(ctx->enc_info), ctx->our_instance, &ecipher);
	if (err) {
	    fprintf(stderr, "libotr-mpOTR: chat_enc_encrypt: personal cipher failed\n");
	    free(ciphertext);
	    return NULL;
	}

	fprintf(stderr, "libotr-mpOTR: chat_enc_encrypt: before encrypt_data\n");
	err = chat_enc_encrypt_data(ecipher, &(ctx->enc_info), plaintext, msglen, ciphertext, msglen);

	if(err) {
	    fprintf(stderr, "libotr-mpOTR: chat_enc_encrypt: error\n");
	    free(ciphertext);
	    gcry_cipher_close(ecipher);
	    return NULL;
	}

	gcry_cipher_close(ecipher);
	fprintf(stderr, "libotr-mpOTR: chat_enc_sync_key: end\n");
	return ciphertext;
}

