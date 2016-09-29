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

#include <stdlib.h>

#include "dh.h"
#include "instag.h"
#include "chat_context.h"
#include "chat_gka.h"
#include "chat_participant.h"

#define OTRL_ENC_KEY_SIZE 16

// TODO Dimitris: error handling

ChatEncInfo* chat_enc_info_new()
{
    ChatEncInfo *tmp;

    tmp = malloc(sizeof *tmp);
    if(!tmp) {
        return NULL;
    }

	memset(tmp->ctr, 0, 16);
	tmp->key = NULL;

    return tmp;

}

void chat_enc_info_free(ChatEncInfo *enc_info)
{
    if(enc_info) {
    	gcry_free(enc_info->key);
    }

    free(enc_info);
}

/**
 Print an mpi to a buffer allocated in secure memory. Caller must free the buffer.

 @param w The mpi to be written in the buffer
 @param size On success this variable will hold the size of the allocated buffer
 */
unsigned char * mpi_serial_secure(gcry_mpi_t w, size_t *size)
{
	unsigned char *buf = NULL;
    size_t s;

    /* Get the length of the mpi */
    gcry_mpi_print(GCRYMPI_FMT_HEX,NULL,0,&s,w);

    /* Allocate the buffer in secure memory */
    buf = gcry_malloc_secure(s * sizeof *buf);
    if(!buf) { goto error; }

    /* Print the mpi in the newly allocated buffer */
    gcry_mpi_print(GCRYMPI_FMT_HEX,buf,s,NULL,w);

    *size = s;

    return buf;

error:
    *size = 0;
    return NULL;
}

gcry_error_t chat_enc_create_secret(ChatEncInfo *enc_info ,gcry_mpi_t w, DH_keypair *key)
{
	gcry_md_hd_t md;
	gcry_error_t err;
	unsigned char *buf;
	size_t buf_size;
	gcry_mpi_t final_key = NULL;

	fprintf(stderr, "libotr-mpOTR: create_secret: start\n");

    /* Create a new mpi to hold the final key */
	final_key = gcry_mpi_snew(300);
	if(!final_key) {
		return 1;
	}

    /* Raise the intermediate key w to our priv exponent */
	otrl_dh_powm(final_key, w, key->priv);

    /* We will hash the final_key to produce the shared secret so open
     a digest now */
	err = gcry_md_open(&md, GCRY_MD_SHA512, GCRY_MD_FLAG_SECURE);
	if(err)
		return err;

    /* Print the final_key in the buffer so that we can hash it */
	buf = mpi_serial_secure(final_key, &buf_size);

    /* We don't need this mpi anymore */
	gcry_mpi_release(final_key);

	if(!buf) {
		gcry_md_close(md);
		return gcry_error(GPG_ERR_ENOMEM);
	}

    /* Write the buffer in the digest */
	gcry_md_write(md, buf, buf_size);
    /* And finalize the digest */
	gcry_md_final(md);

	gcry_free(buf);

	if(enc_info->key)
		gcry_free(enc_info->key);

    /* Generate secure memory to store the shared secret */
	enc_info->key = gcry_malloc_secure(CHAT_SECRET_LENGTH);
	if(!enc_info->key) {
		gcry_md_close(md);
		return gcry_error(GPG_ERR_ENOMEM);
	}

    /* Read the sha-512 hash */
	buf = gcry_md_read(md, GCRY_MD_SHA512);

    /* And copy it in enc_info */
	memcpy(enc_info->key, buf, CHAT_SECRET_LENGTH);

	gcry_md_close(md);

	fprintf(stderr, "libotr-mpOTR: create_secret: end\n");

	return gcry_error(GPG_ERR_NO_ERROR);
}

gcry_error_t chat_enc_encrypt_data(gcry_cipher_hd_t cipher, ChatEncInfo *enc_info,
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


gcry_error_t chat_enc_get_personal_cipher(const ChatEncInfo *enc_info,
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
    	return gcry_error(GPG_ERR_ENOMEM);
    }

    memmove(sdata, &sender_id, sizeof(sender_id));
    base += sizeof(sender_id);

    memmove(sdata + base, enc_info->key, CHAT_SECRET_LENGTH);
    base += CHAT_SECRET_LENGTH;

    hash_len = gcry_md_get_algo_dlen(GCRY_MD_SHA512);
    hashdata = gcry_malloc_secure(hash_len);
    if(!hashdata) {
    	gcry_free(sdata);
    	return gcry_error(GPG_ERR_ENOMEM);
    }

    gcry_md_hash_buffer(GCRY_MD_SHA512, hashdata, sdata, sdata_len);

    err = gcry_cipher_open(cipher, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CTR,
			   GCRY_CIPHER_SECURE);
    if (err) {
	    gcry_free(sdata);
	    gcry_free(hashdata);
	    return err;
    }

    err = gcry_cipher_setkey(*cipher, hashdata, OTRL_ENC_KEY_SIZE);
    if (err) {
	    gcry_free(sdata);
	    gcry_free(hashdata);
	    gcry_cipher_close(*cipher);
	    return err;
    }

    gcry_free(sdata);
    gcry_free(hashdata);
    return gcry_error(GPG_ERR_NO_ERROR);
}

char * chat_enc_decrypt(const ChatContextPtr ctx, const unsigned char *ciphertext,
			size_t datalen, const unsigned char top_ctr[8],
			const char *sender) {
	char *plaintext;
	//size_t msglen;
	unsigned char ctr[16];
	gcry_cipher_hd_t dcipher;
	gcry_error_t err;
	unsigned int sender_id;

	fprintf(stderr,"libotr-mpOTR: chat_enc_decrypt: start\n");

	if(chat_participant_get_position(chat_context_get_participants_list(ctx), sender, &sender_id))
		return NULL;

    //TODO this is probably wrong. If the plaintext is not purely text data
    //it is possible that one of its bytes may well be zero. So we should
    //somehow return the length of the plaintext explicitely and not rely
    //on it being null terminated.
	plaintext = malloc((datalen +1 ) * sizeof *plaintext);
	plaintext[datalen] = '\0';

	if(!plaintext) {
	    return NULL;
	}

	memset(ctr, 0, 16);
	memmove(ctr, top_ctr, 8);

	err = chat_enc_get_personal_cipher(chat_context_get_enc_info(ctx), sender_id, &dcipher);
	if (err) {
	    free(plaintext);
	    return NULL;
	}

	err = chat_enc_decrypt_data(dcipher, ctr, plaintext, datalen,
				       ciphertext, datalen);

	if(err){
	    free(plaintext);
	    gcry_cipher_close(dcipher);
	    return NULL;
	}

	gcry_cipher_close(dcipher);

	fprintf(stderr,"libotr-mpOTR: chat_enc_decrypt: end\n");
	return plaintext;
}


unsigned char * chat_enc_encrypt(ChatContextPtr ctx, const char *plaintext) {
	//char *ciphertext;
	size_t msglen = 0;
	unsigned char *ciphertext = NULL;
	gcry_cipher_hd_t ecipher;
	gcry_error_t err = gcry_error(GPG_ERR_NO_ERROR);

	//TODO msglen should be passed as an argument, plaintext is not always text data
	msglen = strlen(plaintext);

	ciphertext = malloc(msglen * sizeof *ciphertext);

	if(!ciphertext) {
	    fprintf(stderr, "libotr-mpOTR: chat_enc_encrypt: !ciphertext\n");
	    return NULL;
	}

	err = chat_enc_get_personal_cipher(chat_context_get_enc_info(ctx), chat_context_get_id(ctx), &ecipher);
	if (err) {
	    free(ciphertext);
	    return NULL;
	}

	err = chat_enc_encrypt_data(ecipher, chat_context_get_enc_info(ctx), plaintext, msglen, ciphertext, msglen);

	if(err) {
	    free(ciphertext);
	    gcry_cipher_close(ecipher);
	    return NULL;
	}

	gcry_cipher_close(ecipher);
	return ciphertext;
}
