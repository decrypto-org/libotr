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

void chat_sign_print_pubkey(SignKey *key);

SignKey * chat_sign_genkey();

Signature * chat_sign_sign(SignKey *key, const unsigned char *data, size_t datalen);

int chat_sign_verify(SignKey *key, const unsigned char *data, size_t datalen, Signature *signature);

const char* chat_sign_get_pubkey(SignKey *key);

SignKey * chat_sign_parse_pubkey(const unsigned char *serialized, size_t serlen);

//TODO make the serialize functions return a possible error value
void chat_sign_serialize_pubkey(SignKey *key, unsigned char **serialized, size_t *serlen);

void chat_sign_serialize_privkey(SignKey *key, unsigned char **serialized, size_t *serlen);

void chat_sign_destroy_key(SignKey *key);

void chat_sign_destroy_signature(Signature *sign);

unsigned int chat_sign_signature_get_length(Signature *sig);

int chat_sign_signature_serialize(Signature *sig, unsigned char **buf, size_t *len);

int chat_sign_signature_parse(const unsigned char *buf, Signature **sig);
#endif /* CHAT_SIGN_H */
