/*
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
#include "chat_participant.h"

#define OTRL_ENC_KEY_SIZE 32

void chat_enc_initialize_enc_info(OtrlChatEncInfo *enc_info) {

	memset(enc_info->ctr, 0, 16);
	enc_info->key = NULL;

}

void chat_enc_info_destroy(OtrlChatEncInfo *enc_info)
{
	gcry_free(enc_info->key);
}

unsigned char * mpi_serial_secure(gcry_mpi_t w, size_t *size)
{
	unsigned char *buf;
    size_t s;

    gcry_mpi_print(GCRYMPI_FMT_HEX,NULL,0,&s,w);
    buf = gcry_malloc_secure(s * sizeof(*buf));

    gcry_mpi_print(GCRYMPI_FMT_HEX,buf,s,NULL,w);

    *size = s;

    return buf;
}

gcry_error_t chat_enc_create_secret(OtrlChatEncInfo *enc_info ,gcry_mpi_t w, DH_keypair *key)
{
	gcry_md_hd_t md;
	gcry_error_t err;
	unsigned char *buf;
	size_t buf_size;
	gcry_mpi_t final_key = NULL;

	fprintf(stderr, "libotr-mpOTR: create_secret: start\n");

	final_key = gcry_mpi_snew(300);
	if(!final_key) {
		fprintf(stderr, "libotr-mpOTR: create_secret: no final_key\n");
		return 1;
	}

	otrl_dh_powm(final_key, w, key->priv);

	err = gcry_md_open(&md, GCRY_MD_SHA512, GCRY_MD_FLAG_SECURE);
	if(err)
		return err;
	fprintf(stderr, "libotr-mpOTR: create_secret: after md open\n");

	buf = mpi_serial_secure(final_key, &buf_size);

	gcry_mpi_release(final_key);

	fprintf(stderr,"libotr-mpOTR: create_secret buf is: %s\n", buf);
	if(!buf) {
		gcry_md_close(md);
		return gcry_error(GPG_ERR_ENOMEM);
	}
	fprintf(stderr, "libotr-mpOTR: create_secret: after buf secure malloc\n");

	gcry_md_write(md, buf, buf_size);
	gcry_md_final(md);
	fprintf(stderr, "libotr-mpOTR: create_secret: after buffer write\n");

	gcry_free(buf);

	if(enc_info->key)
		gcry_free(enc_info->key);

	enc_info->key = gcry_malloc_secure(CHAT_SECRET_LENGTH);
	if(!enc_info->key) {
		gcry_md_close(md);
		return gcry_error(GPG_ERR_ENOMEM);
	}
	fprintf(stderr, "libotr-mpOTR: create_secret: after secret secure malloc\n");

	buf = gcry_md_read(md, GCRY_MD_SHA512);

	memcpy(enc_info->key, buf, CHAT_SECRET_LENGTH);

	fprintf(stderr, "Secret is: ");
	for(size_t i = 0; i < CHAT_SECRET_LENGTH; i++)
		fprintf(stderr, "%02X", enc_info->key[i]);
	fprintf(stderr, "\n");

	fprintf(stderr, "libotr-mpOTR: create_secret: after read and memcopy\n");

	gcry_md_close(md);

	fprintf(stderr, "libotr-mpOTR: create_secret: end\n");

	return gcry_error(GPG_ERR_NO_ERROR);
}


/* TODO remove this
gcry_error_t chat_enc_initialize_cipher(OtrlChatEncInfo *enc_info)
{
    gcry_error_t err = gcry_error(GPG_ERR_NO_ERROR);
    //unsigned char *key = NULL;

    // NOT FOR PRODUCTION
    // This code is not for production as this is just a dummy way
    // to generate a secret key with no GKA protocol.
    // enc_info->key
    if(enc_info->key)
	gcry_free(enc_info->key);

    enc_info->key = gcry_random_bytes_secure(OTRL_ENC_KEY_SIZE, GCRY_STRONG_RANDOM);
    if(!enc_info->key)
	return gcry_error(GPG_ERR_ENOMEM);

    // TODO
    // allocate secure memory for key
    //enc_info->key = gcry_malloc_secure(32);


    //fprintf(stderr, "libotr-mpOTR: chat_enc_initialize_cipher: before memcpy\n");
    //memcpy(enc_info->key, key, OTRL_ENC_KEY_SIZE);

    memset(enc_info->ctr, 0, 16);

    return err;

err:
    fprintf(stderr, "libotr-mpOTR: chat_enc_initialize_cipher: end err\n");
    //gcry_cipher_close(enc_info->cipher);
    return err;

}
*/

/* TODO remove this
gcry_error_t chat_enc_sync_key(OtrlChatEncInfo *enc_info,
			       const OtrlAuthGKAInfo *auth_info)
{
    gcry_error_t err = gcry_error(GPG_ERR_NO_ERROR);
    // TODO
    // allocate secure memory for key

    if(enc_info->key)
	gcry_free(enc_info->key);

    enc_info->key = gcry_malloc_secure(32);
    if(!enc_info->key)
	return gcry_error(GPG_ERR_ENOMEM);

    // copy the key to the enc_info
    memcpy(enc_info->key, auth_info->key, OTRL_ENC_KEY_SIZE);

    // copy the key to the enc_info
    // set the counter
    memset(enc_info->ctr, 0, 16);

    // copy the key to the enc_info
    return err;

err:

    fprintf(stderr, "libotr-mpOTR: chat_enc_sync_key: end err\n");
    // copy the key to the enc_info
    //gcry_cipher_close(enc_info->cipher);
    return err;
}
*/
gcry_error_t chat_enc_encrypt_data(gcry_cipher_hd_t cipher, OtrlChatEncInfo *enc_info,
				   const char *in, size_t inlen,
				   unsigned char *out, size_t outlen)
{
    gcry_error_t err = gcry_error(GPG_ERR_NO_ERROR);
    otrl_dh_incctr(enc_info->ctr);
    err = gcry_cipher_reset(cipher);
    if(err) goto err;

    err = gcry_cipher_setctr(cipher, enc_info->ctr, 16);
    if(err) goto err;

    err = gcry_cipher_encrypt(cipher, out, outlen, in, inlen);
    if(err) goto err;

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

    err = gcry_cipher_reset(cipher);
    if (err) goto err;

    err = gcry_cipher_setctr(cipher, ctr, 16);
    if (err) goto err;

    err = gcry_cipher_decrypt(cipher, out, outlen, in, inlen);
    if (err) goto err;

err:
    return err;
}


gcry_error_t chat_enc_get_personal_cipher(const OtrlChatEncInfo *enc_info,
			      const unsigned int sender_id, gcry_cipher_hd_t *cipher)
{
    unsigned char *hashdata;
    unsigned char *sdata;
    size_t sdata_len;
    size_t hash_len;
    size_t base = 0;
    gcry_error_t err;

    sdata_len = sizeof(sender_id) + CHAT_SECRET_LENGTH;

    sdata = gcry_malloc_secure(sdata_len);
    if(!sdata) {
    	fprintf(stderr, "libotr-mpOTR: chat_enc_get_personal_cipher: sdata malloc failed\n");
    	return gcry_error(GPG_ERR_ENOMEM);
    }

    memmove(sdata, &sender_id, sizeof(sender_id));
    base += sizeof(sender_id);

    memmove(sdata + base, enc_info->key, CHAT_SECRET_LENGTH);
    base += CHAT_SECRET_LENGTH;

    hash_len = gcry_md_get_algo_dlen(GCRY_MD_SHA512);
    hashdata = gcry_malloc_secure(hash_len);
    if(!hashdata) {
    	fprintf(stderr, "libotr-mpOTR: chat_enc_get_personal_cipher: hashdata malloc failed\n");
    	gcry_free(sdata);
    	return gcry_error(GPG_ERR_ENOMEM);
    }

    gcry_md_hash_buffer(GCRY_MD_SHA512, hashdata, sdata, sdata_len);

    err = gcry_cipher_open(cipher, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CTR,
			   GCRY_CIPHER_SECURE);
    if (err) {
	fprintf(stderr, "libotr-mpOTR: chat_enc_get_personal_cipher: cipher open failed\n");
	gcry_free(sdata);
	gcry_free(hashdata);
	return err;
    }

    err = gcry_cipher_setkey(*cipher, hashdata, OTRL_ENC_KEY_SIZE);
    if (err) {
	fprintf(stderr, "libotr-mpOTR: chat_enc_get_personal_cipher: key set failed\n");

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


    gcry_free(sdata);
    gcry_free(hashdata);
    return gcry_error(GPG_ERR_NO_ERROR);
}

char * chat_enc_decrypt(const OtrlChatContext *ctx, const unsigned char *ciphertext,
			size_t datalen, const unsigned char top_ctr[8],
			const char *sender) {
	char *plaintext;
	//size_t msglen;
	unsigned char ctr[16];
	gcry_cipher_hd_t dcipher;
	gcry_error_t err;
	unsigned int participants_len, our_pos, their_pos;
	int sender_id;

	fprintf(stderr,"libotr-mpOTR: chat_enc_decrypt: before get_position\n");

	//TODO this is an ugly hack. In the future when we have a DSKE implemented we will
	//be able to infer our position based on our public signing keys.
	if(chat_participant_get_position(ctx->participants_list, ctx->accountname, &our_pos))
		return NULL;
	if(chat_participant_get_position(ctx->participants_list, sender, &their_pos))
		return NULL;

	participants_len = otrl_list_length(ctx->participants_list);

	fprintf(stderr, "our_pos: %u, their_pos: %u, our_gka_pos: %d, list len: %d\n", our_pos, their_pos, ctx->gka_info.position, participants_len);
	//TODO % operation is implementation defined. We want mod to only return positive
	//numbers
	sender_id = their_pos + ctx->gka_info.position - our_pos;
	if(sender_id >= (int) participants_len) {
		sender_id -= participants_len;
	}
	else if(sender_id < 0) {
		sender_id += participants_len;
	}

        //TODO this is probably wrong. If the plaintext is not purely text data
        //it is possible that one of its bytes may well be zero. So we should
        //somehow return the length of the plaintext explicitely and not rely
        //on it being null terminated.
	plaintext = malloc(datalen*sizeof(char) + 1);
	plaintext[datalen] = '\0';

	if(!plaintext) {
	    fprintf(stderr, "libotr-mpOTR: chat_enc_decrypt: !plaintext\n");
	    return NULL;
	}

	memset(ctr, 0, 16);
	memmove(ctr, top_ctr, 8);
	fprintf(stderr,"libotr-mpOTR: chat_enc_decrypt: before get_personal_cipher\n");
	err = chat_enc_get_personal_cipher(&(ctx->enc_info), sender_id, &dcipher);
	if (err) {
	    fprintf(stderr, "libotr-mpOTR: chat_enc_decrypt: personal cipher failed\n");
	    free(plaintext);
	    return NULL;
	}

	fprintf(stderr,"libotr-mpOTR: chat_enc_decrypt: before decrypt_data\n");
	err = chat_enc_decrypt_data(dcipher, ctr, plaintext, datalen,
				       ciphertext, datalen);

	if(err){
		fprintf(stderr, "libotr-mpOTR: chat_enc_decrypt: there was an error\n");
	    free(plaintext);
	    gcry_cipher_close(dcipher);
	    return NULL;
	}

	gcry_cipher_close(dcipher);

	fprintf(stderr,"libotr-mpOTR: chat_enc_decrypt: end\n");
	return plaintext;
}


unsigned char * chat_enc_encrypt(OtrlChatContext *ctx, const char *plaintext) {
	//char *ciphertext;
	size_t msglen = 0;
	unsigned char *ciphertext = NULL;
	gcry_cipher_hd_t ecipher;
	gcry_error_t err = gcry_error(GPG_ERR_NO_ERROR);

	//TODO msglen should be passed as an argument, plaintext is not always text data
	msglen = strlen(plaintext);

	ciphertext = malloc(msglen*sizeof(char));

	if(!ciphertext) {
	    fprintf(stderr, "libotr-mpOTR: chat_enc_encrypt: !ciphertext\n");
	    return NULL;
	}


	err = chat_enc_get_personal_cipher(&(ctx->enc_info), ctx->id, &ecipher);
	if (err) {
	    fprintf(stderr, "libotr-mpOTR: chat_enc_encrypt: personal cipher failed\n");
	    free(ciphertext);
	    return NULL;
	}

	err = chat_enc_encrypt_data(ecipher, &(ctx->enc_info), plaintext, msglen, ciphertext, msglen);

	if(err) {
	    fprintf(stderr, "libotr-mpOTR: chat_enc_encrypt: error\n");
	    free(ciphertext);
	    gcry_cipher_close(ecipher);
	    return NULL;
	}

	gcry_cipher_close(ecipher);
	return ciphertext;
}
