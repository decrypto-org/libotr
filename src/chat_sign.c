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

#include "chat_sign.h"

#include <gcrypt.h>

#define SIGN_HASH_SIZE 64

void chat_sign_print_pubkey(SignKey *key)
{
	gcry_sexp_dump(key->pub_key);
}

SignKey * chat_sign_genkey()
{
    gcry_error_t err;
    gcry_sexp_t key, params;
    SignKey *sign_key;
    static const char *parmstr = "(genkey (ecc (curve Ed25519 (flags eddsa))))";

    err = gcry_sexp_new(&params, parmstr, strlen(parmstr), 0);
    if(err) {
        return NULL;
    }

    err = gcry_pk_genkey(&key, params);
    gcry_sexp_release(params);
    if(err) {
        return NULL;
    }


    sign_key = malloc(sizeof(*sign_key));
    if(!key) {
        gcry_sexp_release(key);
        return NULL;
    }

    sign_key->priv_key = gcry_sexp_find_token(key, "private-key", 0);
    sign_key->pub_key  = gcry_sexp_find_token(key, "public-key", 0);
    chat_sign_print_pubkey(sign_key);

    return sign_key;
}

int chat_sign_get_data_hash(const char *data, size_t datalen, char *hash)
{
    gcry_error_t err;
    gcry_md_hd_t md;

    err = gcry_md_open(&md, GCRY_MD_SHA512, 0);
    if(err){
        return 1;
    }

    gcry_md_write(md, data, datalen);

    memcpy(hash, gcry_md_read(md, GCRY_MD_SHA512), SIGN_HASH_SIZE);
    hash[SIGN_HASH_SIZE] = '\0';
    gcry_md_close(md);

    return 0;
}

Signature * chat_sign_sign(SignKey *key, const char *data, size_t datalen)
{
    char hash[SIGN_HASH_SIZE + 1];
    static char *datastr = "(data (flags eddsa) (hash-algo sha512) (value %s))";
    gcry_sexp_t datas, sigs, temp, r, s;
    const char *token = NULL;
    size_t tokenlen;
    Signature *signature = NULL;
    gcry_error_t err;

    signature = malloc(sizeof(*signature));
    if(!signature){
        return NULL;
    }

    if(chat_sign_get_data_hash(data, datalen, hash)) {
        free(signature);
        return NULL;
    }

    err = gcry_sexp_build(&datas, NULL, datastr, hash);
    if(err) {
        free(signature);
        return NULL;
    }

    err = gcry_pk_sign(&sigs, datas, key->priv_key);
    gcry_sexp_release(datas);
    if(err) {
        free(signature);
        return NULL;
    }

    temp = gcry_sexp_find_token(sigs, "sig-val", 0);
    r = gcry_sexp_find_token(temp, "r", 0);
    s = gcry_sexp_find_token(temp, "s", 0);
    gcry_sexp_release(temp);

    token = gcry_sexp_nth_data(r, 1, &tokenlen);
    gcry_sexp_release(r);
    if(!token) {
        gcry_sexp_release(s);
        free(signature);
        return NULL;
    }

    signature->r = malloc(tokenlen * sizeof(*signature->r));
    if(!signature->r){
        gcry_sexp_release(s);
        free(signature);
        return NULL;
    }

    memcpy(signature->r, token, tokenlen);
    signature->rlen = tokenlen;

    token = gcry_sexp_nth_data(s, 1, &tokenlen);
    gcry_sexp_release(s);
    if(!token) {
        free(signature->r);
        free(signature);
        return NULL;
    }

    signature->s = malloc(tokenlen * sizeof(*signature->s));
    if(!signature->s) {
        free(signature->r);
        free(signature);
        return NULL;
    }

    memcpy(signature->s, token, tokenlen);
    signature->slen = tokenlen;
    return signature;
}

int chat_sign_verify(SignKey *key, const char *data, size_t datalen, Signature *signature)
{

    char hash[SIGN_HASH_SIZE + 1];
	gcry_mpi_t datampi, rmpi, smpi;
	gcry_sexp_t sigs;
    gcry_sexp_t datas;
    gcry_error_t err;

    if(chat_sign_get_data_hash(data, datalen, hash)) {
        free(signature);
        return 1;
    }

    if (datalen) {
    	gcry_mpi_scan(&datampi, GCRYMPI_FMT_USG, data, SIGN_HASH_SIZE, NULL);
    } else {
    	datampi = gcry_mpi_set_ui(NULL, 0);
    }

    gcry_sexp_build(&datas, NULL, "(%m)", datampi);
    gcry_mpi_release(datampi);
    gcry_mpi_scan(&rmpi, GCRYMPI_FMT_USG, signature->r, signature->rlen, NULL);
    gcry_mpi_scan(&smpi, GCRYMPI_FMT_USG, signature->s, signature->slen, NULL);
    gcry_sexp_build(&sigs, NULL, "(sig-val (dsa (r %m)(s %m)))", rmpi, smpi);
    gcry_mpi_release(rmpi);
    gcry_mpi_release(smpi);

    err = gcry_pk_verify(sigs, datas, key->pub_key);
    gcry_sexp_release(datas);
    gcry_sexp_release(sigs);

    return err;
}

void chat_sign_serialize_pubkey(SignKey *key, unsigned char **serialized, size_t *serlen)
{
    gcry_sexp_t temps, pubvals;

    temps = gcry_sexp_find_token(key->pub_key, "ecc", 0);
    pubvals = gcry_sexp_find_token(temps, "q", 0);

    *serialized = (unsigned char*) gcry_sexp_nth_data(pubvals, 1, serlen);
}

SignKey * chat_sign_parse_pubkey(const unsigned char *serialized, size_t serlen) {
	static char *datastr = "(public-key (ecc (curve Ed25519) (flags eddsa) (q  %b)))";
	SignKey *key;

	key = malloc(sizeof(*key));
	if(!key) {
		return NULL;
	}

	gcry_sexp_build(&key->pub_key, NULL, datastr, serlen, serialized);
	key->priv_key = NULL;

	return key;
}

void chat_sign_destroy_key(SignKey *key)
{
	gcry_sexp_release(key->priv_key);
	gcry_sexp_release(key->pub_key);
	free(key);
}

void chat_sign_destroy_signature(Signature *sign)
{
	free(sign->r);
	free(sign->s);
	free(sign);
}


unsigned int chat_sign_signature_get_length(Signature *sig)
{
	if(!sig || !sig->s || !sig->r) {
		return 0;
	}
	return sizeof 4*sizeof(char) + sig->rlen*sizeof(*sig->r) + 4*sizeof(char) + sig->slen*sizeof(*sig->s);
}

int chat_sign_signature_serialize(Signature *sig, unsigned char **buf)
{
	size_t base = 0;
	if(!sig || !sig->s || !sig->r) {
		return 1;
	}

	*buf = malloc(chat_sign_signature_get_length(sig)*sizeof(**buf));
	if(!*buf) {
		return 1;
	}

	memcpy(buf + base, &sig->rlen, base + 4*sizeof(char));
	base += 4*sizeof(char);
	memcpy(buf + base, sig->r, base + sig->rlen);
	base += sig->rlen;
	memcpy(buf + base, &sig->slen, base + 4*sizeof(char));
	base += 4*sizeof(char);
	memcpy(buf + base, sig->s, sig->slen);

	return 0;
}

int chat_sign_signature_parse(unsigned char *buf, Signature **sig)
{
	size_t base;

	if(!buf) {
		return 1;
	}

	*sig = malloc(sizeof(**sig));
	if(!*sig) {
		return 1;
	}

	memcpy(&(*sig)->rlen, buf + base, base + 4*sizeof(char));
	(*sig)->r = malloc((*sig)->rlen*sizeof((*sig)->r));
	if(!(*sig)->r){
		free(*sig);
		return 1;
	}
	base += 4*sizeof(char);

	memcpy(&(*sig)->r, buf + base, base + (*sig)->rlen);
	base += (*sig)->rlen;

	memcpy(&(*sig)->slen, buf + base, base + 4*sizeof(char));
	(*sig)->s = malloc((*sig)->slen*sizeof((*sig)->s));
	if(!(*sig)->s){
		free((*sig)->r);
		free(*sig);
		return 1;
	}
	base += 4*sizeof(char);

	memcpy(&(*sig)->rlen, buf + base, base += 4*sizeof(char));

	return 0;
}
