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
#include "chat_serial.h"

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

    /* A parameter string to build an s-expression. This sexp will later be
     used to instruct gcrypt to create an EdDSA keypair. */
    static const char *parmstr = "(genkey (ecc (curve Ed25519 (flags eddsa))))";

    /* Create the sexp using the parameter string */
    err = gcry_sexp_new(&params, parmstr, strlen(parmstr), 0);
    if(err) { goto error; }

    /* Generate the keypair */
    err = gcry_pk_genkey(&key, params);
    gcry_sexp_release(params);
    if(err) { goto error; }

    /* Allocate a SignKey struct */
    sign_key = malloc(sizeof *sign_key);
    if(!sign_key) { goto error_with_key; }

    /* And store the generated key in sign_key */
    sign_key->priv_key = gcry_sexp_find_token(key, "private-key", 0);
    sign_key->pub_key  = gcry_sexp_find_token(key, "public-key", 0);

    gcry_sexp_release(key);

    return sign_key;

error_with_key:
    gcry_sexp_release(key);
error:
    return NULL;
}

SignKey* chat_sign_copy_pub(SignKey* key)
{
    SignKey *tmp = NULL;

    /* Allocate a new SignKey */
    tmp = malloc(sizeof *tmp);
    if(!tmp) { goto error; }

    /* Copy the public part */
    tmp->pub_key = gcry_sexp_find_token(key->pub_key, "public-key", 0);

    /* And put NULL in the private part */
    tmp->priv_key = NULL;

    return tmp;

error:
    return NULL;
}

int chat_sign_get_data_hash(const unsigned char *data, size_t datalen, unsigned char *hash)
{
    gcry_error_t err;
    gcry_md_hd_t md;

    fprintf(stderr,"libotr-mpOTR: chat_sign_get_data_hash: start\n");

    /* Open a digest */
    err = gcry_md_open(&md, GCRY_MD_SHA512, 0);
    if(err){
        return 1;
    }

    /* Write the data in it */
    gcry_md_write(md, data, datalen);

    /* Copy the hash read from the digest to the output buffer */
    memcpy(hash, gcry_md_read(md, GCRY_MD_SHA512), SIGN_HASH_SIZE);

    gcry_md_close(md);

    fprintf(stderr,"libotr-mpOTR: chat_sign_get_data_hash: end\n");
    return 0;
}

Signature * chat_sign_sign(SignKey *key, const unsigned char *data, size_t datalen)
{
    unsigned char hash[SIGN_HASH_SIZE];
    static char *datastr = "(data (flags eddsa) (hash-algo sha512) (value %m))";
    gcry_mpi_t datampi;
    gcry_sexp_t datas, sigs, temp, r, s;
    const char *token = NULL;
    size_t tokenlen;
    Signature *signature = NULL;
    gcry_error_t err;

    fprintf(stderr,"libotr-mpOTR: chat_sign_sign: start\n");

    /* Allocate a Signature struct */
    signature = malloc(sizeof *signature);
    if(!signature){
        return NULL;
    }

    /* Hash the data to be signed, Gcrypt requires the signed data to be
     * small, so we hash them and then sign the hash */
    if(chat_sign_get_data_hash(data, datalen, hash)) {
        free(signature);
        return NULL;
    }
    /* Store the hash in an mpi */
    gcry_mpi_scan(&datampi, GCRYMPI_FMT_USG, hash, SIGN_HASH_SIZE, NULL);

    /* Build an s-expression requesting to sign the hash stored in datampi */
    err = gcry_sexp_build(&datas, NULL, datastr, datampi);
    gcry_mpi_release(datampi);
    if(err) {
        free(signature);
        return NULL;
    }

    /* Sign the hash of the data */
    err = gcry_pk_sign(&sigs, datas, key->priv_key);
    gcry_sexp_release(datas);
    if(err) {
        free(signature);
        return NULL;
    }


    /* Get the sexpression containing the r and s sexpressions */
    temp = gcry_sexp_find_token(sigs, "sig-val", 0);
    gcry_sexp_release(sigs);

    /* And get the actual r and s sexpressions*/
    r = gcry_sexp_find_token(temp, "r", 0);
    s = gcry_sexp_find_token(temp, "s", 0);
    gcry_sexp_release(temp);


    /* Get the r value */
    token = gcry_sexp_nth_data(r, 1, &tokenlen);
    if(!token) {
        gcry_sexp_release(r);
        gcry_sexp_release(s);
        free(signature);
        return NULL;
    }

    /* Allocate memory for the r value in the signature struct */
    signature->r = malloc(tokenlen * sizeof *(signature->r));
    if(!signature->r){
        gcry_sexp_release(r);
        gcry_sexp_release(s);
        free(signature);
        return NULL;
    }

    /* And copy the r value in the signature */
    memcpy(signature->r, token, tokenlen);
    signature->rlen = tokenlen;

    gcry_sexp_release(r);

    /* Finaly we do the same for the s value */
    token = gcry_sexp_nth_data(s, 1, &tokenlen);
    if(!token) {
        gcry_sexp_release(s);
        free(signature->r);
        free(signature);
        return NULL;
    }


    signature->s = malloc(tokenlen * sizeof *(signature->s));
    if(!signature->s) {
        gcry_sexp_release(s);
        free(signature->r);
        free(signature);
        return NULL;
    }
    memcpy(signature->s, token, tokenlen);
    signature->slen = tokenlen;
    gcry_sexp_release(s);

    fprintf(stderr,"\nlibotr-mpOTR: chat_sign_sign: end\n");
    return signature;
}

int chat_sign_verify(SignKey *key, const unsigned char *data, size_t datalen, Signature *signature)
{

    unsigned char hash[SIGN_HASH_SIZE + 1];
	gcry_mpi_t datampi;
	gcry_sexp_t sigs;
    gcry_sexp_t datas;
    gcry_error_t err;
    static char *datastr = "(data (flags eddsa) (hash-algo sha512) (value %m))";

    fprintf(stderr,"libotr-mpOTR: chat_sign_verify: start\n");

    /* Check if there are data to be verified */
    if (datalen) {
        /* If there are, hash the data */
        if(chat_sign_get_data_hash(data, datalen, hash)) { goto error; }

        /* And store the hash in an mpi to build an s-expression later */
    	gcry_mpi_scan(&datampi, GCRYMPI_FMT_USG, hash, SIGN_HASH_SIZE, NULL);
    } else {
        /* If there are no data then store zero in the mpi */
    	datampi = gcry_mpi_set_ui(NULL, 0);
    }

    /* Build the data s-expression */
    gcry_sexp_build(&datas, NULL, datastr, datampi);
    gcry_mpi_release(datampi);

    /* And build the signature s-expression */
    gcry_sexp_build(&sigs, NULL, "(sig-val (eddsa (r %b)(s %b)))", signature->rlen, signature->r, signature->slen, signature->s);

    /* Verify the data sexp with the signature sexp */
    err = gcry_pk_verify(sigs, datas, key->pub_key);

    gcry_sexp_release(datas);
    gcry_sexp_release(sigs);

    fprintf(stderr, "libotr-mpOTR: chat_sign_verify: end\n");

    return err;

error:
    return 1;
}

int chat_sign_serialize_pubkey(SignKey *key, unsigned char **serialized, size_t *serlen)
{
    gcry_sexp_t temps, pubvals;
    unsigned char *temp;

    /* An auxiliary s-expression which holds the pubkey value */
    temps = gcry_sexp_find_token(key->pub_key, "ecc", 0);

    /* An s-expression which holds the public values of the key */
    pubvals = gcry_sexp_find_token(temps, "q", 0);

    /* An auxiliary variable to hold the actual q data */
    temp = (unsigned char*) gcry_sexp_nth_data(pubvals, 1, serlen);
    if(!temp) {
    	fprintf(stderr,"chat_sign_serialize_pubkey: temp not found\n");
    	goto error;
    }


    /* Allocate memory for the serialized pub key */
    *serialized = malloc(*serlen * sizeof **serialized);
    if(!*serialized) { goto error; }

    /* And copy the q data in the buffer */
    memcpy(*serialized, temp, *serlen);

    gcry_sexp_release(pubvals);
	gcry_sexp_release(temps);

    return 0;
error:
	gcry_sexp_release(pubvals);
	gcry_sexp_release(temps);
    *serialized = NULL;
    return 1;
}

//TODO serialize_privkey and serialize_pub key differ virtually in one line.
//restructure the code so that there is no duplication
int chat_sign_serialize_privkey(SignKey *key, unsigned char **serialized, size_t *serlen)
{
    gcry_sexp_t temps, privvals;
    unsigned char *temp;

    temps = gcry_sexp_find_token(key->priv_key, "ecc", 0);
    privvals = gcry_sexp_find_token(temps, "d", 0);

    temp = (unsigned char*) gcry_sexp_nth_data(privvals, 1, serlen);
    if(!temp) { goto error; }


    *serialized = malloc(*serlen * sizeof **serialized);
    if(!*serialized) { goto error; }

    memcpy(*serialized, temp, *serlen);

	gcry_sexp_release(privvals);
	gcry_sexp_release(temps);

    return 0;

error:
    *serialized = NULL;
	gcry_sexp_release(privvals);
	gcry_sexp_release(temps);

    return 1;
}

SignKey * chat_sign_parse_pubkey(const unsigned char *serialized, size_t serlen) {
	static char *datastr = "(public-key (ecc (curve Ed25519) (flags eddsa) (q  %b)))";
	SignKey *key;

    /* Allocate a SignKey struct */
	key = malloc(sizeof *key);
	if(!key) {
		return NULL;
	}

    /* Build an s-expression that contains the read priv_key */
	gcry_sexp_build(&key->pub_key, NULL, datastr, serlen, serialized);
	key->priv_key = NULL;

	return key;
}

void chat_sign_destroy_key(SignKey *key)
{
    if(!key) {
        return;
    }

    gcry_sexp_release(key->priv_key);
	gcry_sexp_release(key->pub_key);

    free(key);

    fprintf(stderr, "libotr-mpOTR: chat_sign_destroy_key: key destroyed\n");
}

void chat_sign_destroy_signature(Signature *sign)
{
    fprintf(stderr, "libotr-mpOTR: chat_sign_destroy_signature: start\n");

	free(sign->r);
	free(sign->s);

	free(sign);

    fprintf(stderr, "libotr-mpOTR: chat_sign_destroy_signature: end\n");
}


unsigned int chat_sign_signature_get_length(Signature *sig)
{
	if(!sig || !sig->s || !sig->r) {
		return 0;
	}
    /* The signature has length of:
    4 bytes for rlen + rlen bytes for r + 4 bytes for slen + slen bytes for s */
	return  4 + sig->rlen + 4 + sig->slen;
}

int chat_sign_signature_serialize(Signature *sig, unsigned char **buf, size_t *len)
{
	size_t base = 0;
    size_t temp = 0;
	fprintf(stderr, "libotr-mpOTR: chat_sign_signature_serialize: start\n");
	if(!sig || !sig->s || !sig->r) {
		return 1;
	}

    /* Read the length of the signature */
    temp = chat_sign_signature_get_length(sig);

    /* And allocate a buffer of the apropriate length */
	*buf = malloc(temp * sizeof **buf);
	if(!*buf) {
		return 1;
	}

    /* Serialize the rlen variable and place the output in buffer */
    chat_serial_int_to_string(sig->rlen, *buf + base);
    base += 4;

    /* Copy the r value in the buffer */
	memcpy(*buf + base, sig->r, sig->rlen);
	base += sig->rlen;

    /* And do the same for s */
    chat_serial_int_to_string(sig->slen, *buf + base);
	base += 4;
	memcpy(*buf + base, sig->s, sig->slen);

	fprintf(stderr, "libotr-mpOTR: chat_sign_signature_serialize: end\n");

    *len = temp;
	return 0;
}

int chat_sign_signature_parse(const unsigned char *buf, Signature **sig)
{
	size_t base = 0;

    fprintf(stderr, "libotr-mpOTR: chat_sign_signature_parse: start\n");

	if(!buf) {
		return 1;
	}


    /* Allocate a Signature struct */
	*sig = malloc(sizeof **sig);
	if(!*sig) {
		return 1;
	}

    /* Parse the rlen */
    (*sig)->rlen = chat_serial_string_to_int(buf + base);

    /*Allocate memory for rlen*/
	(*sig)->r = malloc((*sig)->rlen * sizeof *((*sig)->r));
	if(!(*sig)->r){
		free(*sig);
		return 1;
	}
	base += 4*sizeof(char);

    /* And copy the r data in (*sig)->r */
	memcpy((*sig)->r, buf + base, (*sig)->rlen * sizeof(*(*sig)->r));
	base += (*sig)->rlen;


    /* Do the same for s */
    (*sig)->slen = chat_serial_string_to_int(buf + base);
	(*sig)->s = malloc((*sig)->slen * sizeof *((*sig)->s));
	if(!(*sig)->s){
		free((*sig)->r);
		free(*sig);
		return 1;
	}
	base += 4*sizeof(char);

	memcpy((*sig)->s, buf + base, (*sig)->slen * sizeof(char));
	base += (*sig)->slen;

    fprintf(stderr, "libotr-mpOTR: chat_sign_signature_parse: end\n");
	return 0;
}
