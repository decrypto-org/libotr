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

#ifndef CHAT_IDKEY_H
#define CHAT_IDKEY_H

#include <gcrypt.h>

#include "dh.h"
#include "list.h"

/* This struct abstracts the idea of an identity key. In other words
 it represents the users long term secret, used for identification. */
typedef struct {
	/* The private part of this diffie hellman keypair is the longterm
	 secret. It is the longterm key used in the triple diffie hellman
	 protocol */
	DH_keypair keyp;

	/* The accountname this identity key corresponds to */
	char* accountname;

	/* And the IM protocol this account uses */
	char* protocol;

} ChatIdKey;

/* This struct defines an idkey manager. It provides all the functions needed
 to handle a longterm identity key */
typedef struct {
	/**
	 Initializes a keypair

	 @param key The key to be initialized
	*/
	void (*init)(ChatIdKey* key);

	/**
	 Destroys a keypair

	 @param key The key to be destroyed
	*/
	void (*destroy_key)(ChatIdKey* key);

	/**
	 Parses a ChatIdKey from an sexpression

	 @param s The s expression containing the key data
	 @return A pointer to a newly allocated ChatIdKey in success.
	  NULL in error
	*/
	ChatIdKey * (*parse)(gcry_sexp_t s);

	/**
	 Generates a new keypair

	 @param key On success *key will point to a newly generated (and
	  allocated) ChatIdKey struct.
	 @return Zero on success. Non-zero on error
	*/
	int (*generate_key)(ChatIdKey** key);

	/**
	 Serializes a keypair in the form of an sexpression.

	 The s expression which serializes the data is of the following form:
	 (tdh-key (name <accountname>) (protocol <protocol name>) (group <diffie hellman group) (private-key <priv key>) (public-key <pub key>))

	 @param key The keypair to be serialized
	 @param s On success *s will be an s expression containing the serialized data
	 @return Zero on success. Non-zero on error
	*/
	gcry_error_t (*serialize)(ChatIdKey* key, gcry_sexp_t* s );


	ChatIdKey * (*find_key)(OtrlList *key_list, const char *accountname, const char *protocol);
} ChatIdKeyManager;

/* The exported operations on an idkey list */
struct OtrlListOpsStruct chat_idkey_listOps;

/* The exported idkey manager */
ChatIdKeyManager chat_id_key_manager;

void chat_idkey_print(ChatIdKey *key);

ChatIdKey * chat_idkey_find(OtrlList *key_list, const char *accountname, const char *protocol);
#endif /* CHAT_IDKEY_H */
