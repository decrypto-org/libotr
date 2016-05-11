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

#ifndef CHAT_ENC_H
#define CHAT_ENC_H

#include <gcrypt.h>
//#include "chat_auth.h"
//#include "chat_context.h"
#include "chat_types.h"
//typedef struct ChatEncInfoStruct {
//	gcry_cipher_hd_t cipher;    /* Cipher used for sending and receiving group
//				       messages */
//	unsigned char ctr[16];    /* our counter */
//
//	unsigned char key[32];
//} OtrlChatEncInfo;


/* Initialise ChatEncInfo struct. this is not for production.
 * A "secret" key is also generated. this will change in production */
//gcry_error_t chat_enc_initialize_cipher(OtrlChatEncInfo *enc_info);

/* Synchonizes the cipher in enc_info with the data stored in auth_info */
//gcry_error_t chat_enc_sync_key(OtrlChatEncInfo *enc_info,
//		const OtrlAuthGKAInfo *auth_info);

/**
  Initializes an OtrlChatEncInfo struct

  @param enc_info a pointer to the struct to be initialized
 */
void chat_enc_initialize_enc_info(OtrlChatEncInfo *enc_info);

/**
  Destroys an OtrlChatEncInfo struct. It does not free the enc_info struct
  itself.

  @param enc_info a pointer to the struct to be destroyed
 */
void chat_enc_info_destroy(OtrlChatEncInfo *enc_info);

/**
  Generates the shared secret

  This function accepts a final intermediate key w, and our private keypair and creates
  a shared secret which is stored to the corresponding enc_info struct

  @param enc_info the corresponding enc_info struct
  @param w the final intermediate key
  @param key our private keypair
  @return GPG_ERR_NO_ERROR if everything was ok. GPG_ERR_ENOMEM if an allocation operation
   failed. Other gpg errors returned by gcry functions if there were other errors.
 */

gcry_error_t chat_enc_create_secret(OtrlChatEncInfo *enc_info ,gcry_mpi_t w, DH_keypair *key);

/* Encrypts data in plaintext using the cipher in ctx. For the time being
 * the plaintext is only textual data and no tlv's or other binaries.
 *
 * TODO add support for encryption of any data, no just text, this might need
 * an extra msglen argument? */
unsigned char * chat_enc_encrypt(OtrlChatContext *ctx,  const char *plaintext);

/* Decrypts the data in ciphertext using the cipher information in ctx and
 * top_ctr as the top half (8 bytes) of the AES counter */
char * chat_enc_decrypt(const OtrlChatContext *ctx, const unsigned char *ciphertext,
		size_t datalen, const unsigned char top_ctr[8], const char *sender);

/* Encrypts buffer in to buffer out. The buffers must be already allocated */
//gcry_error_t chat_enc_encrypt_data(OtrlChatEncInfo *enc_info, const char *in, size_t inlen,
//		unsigned char *out, size_t outlen);

//gcry_error_t chat_enc_decrypt_data(const OtrlChatEncInfo *enc_info, const unsigned char ctr[16],
//                               char *out, size_t outlen,
//                               const unsigned char *in, size_t inlen);

#endif /* CHAT_ENC_H */
