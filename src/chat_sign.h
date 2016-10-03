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

#ifndef CHAT_SIGN_H
#define CHAT_SIGN_H

#include <gcrypt.h>
#include <stdlib.h>

#define CHAT_SIGN_SIGNATURE_LENGTH 72

typedef struct {
	gcry_sexp_t priv_key;
	gcry_sexp_t pub_key;
} SignKey;

typedef struct {
	unsigned char *r;
	size_t rlen;
	unsigned char *s;
	size_t slen;
} Signature;

/**
 Prints the public part of a key in console. Used for debug.

 @param key The key to be printed
*/
void chat_sign_print_pubkey(SignKey *key);

/**
 Generates a signing keypair

 @return A new keypair to be used for signing messages. NULL if there was an
  error
*/
SignKey * chat_sign_genkey();

/**
 Copy the public part of a key

 @param key The key to be copied
 @return A new signing key with only the public part set.
*/
SignKey * chat_sign_copy_pub(SignKey *key);

/**
 Signs data

 @param key The key to be used for signing
 @param data The data to be signed
 @param datalen The length of the data to be signed
 @\return A signature for the data. NULL if there was an error.
*/
Signature * chat_sign_sign(SignKey *key, const unsigned char *data, size_t datalen);

/**
 Verifies data using a signature

 @param key The key to be used for verification
 @param data The data to be verified
 @param datalen The length of the data to be verified
 @param signature The signature claiming to authenticate the data
 @return Non-zero on success. Zero on failure to verify.
*/
int chat_sign_verify(SignKey *key, const unsigned char *data, size_t datalen, Signature *signature);

//TODO does this function even exist??
//const char* chat_sign_get_pubkey(SignKey *key);

/**
 Parses a serialized pubkey

 @param serialized The serialized pubkey to be parsed
 @param serlen The length of the serialized pubkey
 @return A SignKey struct containing the public key
*/
SignKey * chat_sign_parse_pubkey(const unsigned char *serialized, size_t serlen);

/**
 Serializes a public key

 @param key The keypair containing the public key to be serialized
 @param serialized If there was no error *serialized will contain the serialized data
 @param serlen If there was no error *serlen will contain the length of the serialized data
 @return Non-zero on success. Zero on error
*/
int chat_sign_serialize_pubkey(SignKey *key, unsigned char **serialized, size_t *serlen);

/**
 Serializes a private key

 @param key The keypair containing the private key to be serialized
 @param serialized If there was no error *serialized will contain the serialized data
 @param serlen If there was no error *serlen will contain the length of the serialized data
 @return Non-zero on success. Zero on error
*/
int chat_sign_serialize_privkey(SignKey *key, unsigned char **serialized, size_t *serlen);

/**
 Destroys a SignKey struct

 @param key The key to be destroyed
*/
void chat_sign_destroy_key(SignKey *key);

/**
 Destroys a Signature struct

 @param signature The signature to be destroyed
*/
void chat_sign_signature_free(Signature *sign);

/**
 Returns the length of a signature

 @param sig The signature whose length is returned
 @return The signature length
*/
unsigned int chat_sign_signature_get_length(Signature *sig);

/**
 Serializes a signature

 @param sig The signature to be serialized
 @param buf On success *buf will contain the serialized signature
 @param len On success *len will contain the serialized signature's length
 @return Non-zero on success. Zero on error
*/
int chat_sign_signature_serialize(Signature *sig, unsigned char **buf, size_t *len);

/**
 Parses a serialized signature

 @param buf A buffer containing a serialized signature
 @param sig On success *sig will point to a newly created Signature struct
  which will contain the signatures data
 @return Non-zero on success. Zero on error
*/
int chat_sign_signature_parse(const unsigned char *buf, Signature **sig);
#endif /* CHAT_SIGN_H */
