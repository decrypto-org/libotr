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

#include "chat_dh_key.h"

#include <gcrypt.h>

#include "chat_id_key.h"
#include "dh.h"
#include "list.h"


struct ChatDHKey {
	DH_keypair keypair;
};

ChatDHKeyPtr chat_dh_key_new(unsigned int groupid, gcry_mpi_t priv, gcry_mpi_t pub)
{
	ChatDHKeyPtr key = NULL;

	key = malloc(sizeof *key);
	if(!key) { goto error; }

	key->keypair.groupid = groupid;
	key->keypair.priv = priv;
	key->keypair.pub = pub;

	return key;

error:
	return NULL;
}

DH_keypair chat_dh_key_get_keypair(ChatDHKeyPtr key)
{
	return key->keypair;
}

ChatDHKeyPtr chat_dh_key_generate()
{
	ChatDHKeyPtr key;
    gcry_error_t err;

    key = malloc(sizeof *key);
    if(!key) { goto error; }

    otrl_dh_keypair_init(&key->keypair);

    /* Generate a diffie hellman keypair */
    err = otrl_dh_gen_keypair(DH1536_GROUP_ID, &key->keypair);
    if(err) { goto error_with_key; }

    return key;

error_with_key:
	free(key);
error:
	return NULL;
}

int chat_dh_key_serialize(ChatDHKeyPtr key, gcry_sexp_t *key_sexp)
{
	gcry_error_t err;

	fprintf(stderr, "libotr-mpOTR: chat_dh_key_serialize: start\n");

    static char *key_paramstr = "(dh-key (group %u) (private-key %M) (public-key %M))";

    err = gcry_sexp_build(key_sexp, NULL, key_paramstr, key->keypair.groupid, key->keypair.priv, key->keypair.pub);
    if(err) { goto error; }

    fprintf(stderr, "libotr-mpOTR: chat_dh_key_serialize: end\n");

    return 0;

error:
	return 1;
}

ChatDHKeyPtr chat_dh_key_parse(gcry_sexp_t key_sexp)
{
	const char *token;
	size_t tokenlen;
	gcry_sexp_t group_sexp, priv_sexp, pub_sexp;
	char *group_str = NULL, *s = NULL;
	unsigned int groupid;
	gcry_mpi_t priv, pub;
	ChatDHKeyPtr key = NULL;

	fprintf(stderr,"libotr-mpOTR: chat_dh_key_parse: start\n");

	// Check if the first token is really "dh-key"
	token = gcry_sexp_nth_data(key_sexp, 0, &tokenlen);
	if (tokenlen != 6 || strncmp(token, "dh-key", 6)) { goto error; }

	/* Extract the group, private-key, and public-key S-exps */
	group_sexp = gcry_sexp_find_token(key_sexp, "group", 0);
	if(!group_sexp) { goto error; }
	priv_sexp = gcry_sexp_find_token(key_sexp, "private-key", 0);
	if(!priv_sexp) { goto error_with_group_sexp; }
	pub_sexp = gcry_sexp_find_token(key_sexp, "public-key", 0);
	if(!pub_sexp) { goto error_with_priv_sexp; }


	/* Extract the group */
	token = gcry_sexp_nth_data(group_sexp, 1, &tokenlen);
	if (!token) { goto error_with_pub_sexp; }

	/* Allocate memory for the group string. This auxiliary string is needed
	since the DH group is stored as a string and we must convert it to an
	integer later */
	group_str = malloc((tokenlen+1) * sizeof *group_str);
	if (!group_str) { goto error_with_pub_sexp; }

	/* Copy it and place a null character in the end */
	memmove(group_str, token, tokenlen);
	group_str[tokenlen] = '\0';

	/* Get the groupid from the string */
	groupid = strtol(group_str, &s, 10);
	if(s[0] != '\0'){ goto error_with_group_str; }


	/* Get the private key */
	priv = gcry_sexp_nth_mpi(priv_sexp, 1, GCRYMPI_FMT_USG);
	if(!priv) { goto error_with_group_str; }


	/* Get the public key */
	pub = gcry_sexp_nth_mpi(pub_sexp, 1, GCRYMPI_FMT_USG);
	if(!pub) { goto error_with_priv; }

	// Create and return the object
	key = chat_dh_key_new(groupid, priv, pub);
	if(!key) { goto error_with_pub; }

	free(group_str);
	gcry_sexp_release(pub_sexp);
	gcry_sexp_release(priv_sexp);
	gcry_sexp_release(group_sexp);

	fprintf(stderr,"libotr-mpOTR: chat_dh_key_parse: end\n");

	return key;

error_with_pub:
	fprintf(stderr,"libotr-mpOTR: chat_dh_key_parse: error_with_pub\n");
	gcry_mpi_release(pub);
error_with_priv:
	fprintf(stderr,"libotr-mpOTR: chat_dh_key_parse: error_with_priv\n");
	gcry_mpi_release(priv);
error_with_group_str:
	fprintf(stderr,"libotr-mpOTR: chat_dh_key_parse: error_with_group_str\n");
	free(group_str);
error_with_pub_sexp:
	fprintf(stderr,"libotr-mpOTR: chat_dh_key_parse: error_with_pub_sexp\n");
	gcry_sexp_release(pub_sexp);
error_with_priv_sexp:
	fprintf(stderr,"libotr-mpOTR: chat_dh_key_parse: error_with_priv_sexp\n");
	gcry_sexp_release(priv_sexp);
error_with_group_sexp:
	fprintf(stderr,"libotr-mpOTR: chat_dh_key_parse: error_with_group_sexp\n");
	gcry_sexp_release(group_sexp);
error:
	fprintf(stderr,"libotr-mpOTR: chat_dh_key_parse: error\n");
	return NULL;
}

unsigned char * chat_dh_key_pub_fingerprint_create(gcry_mpi_t pubkey)
{
	gcry_error_t err;
	gcry_md_hd_t md;
	unsigned char *buf, *hash;
	size_t buflen;

	/* Get the pubkey length*/
	gcry_mpi_print(GCRYMPI_FMT_HEX,NULL,0,&buflen, pubkey);

	/* Allocate memory for a temporary buffer to hold the pubkey data */
	buf = malloc(buflen * sizeof *buf);
	if(!buf) { goto error; }

	/* Print the pubkey in the buf */
	gcry_mpi_print(GCRYMPI_FMT_HEX,buf,buflen,NULL,pubkey);

	/* Open a digest */
	err = gcry_md_open(&md, GCRY_MD_SHA256, 0);
	if(err){ goto error_with_buf; }

	/* And write the data contained in buf to the digest */
	gcry_md_write(md, buf, buflen);

	/* Allocate memory for the hash result */
	hash = malloc(CHAT_ID_KEY_FINGERPRINT_SIZE * sizeof *hash);
	if(!hash) { goto error_with_buf; }

	/* And finally copy the result from the digest */
	memcpy(hash, gcry_md_read(md, GCRY_MD_SHA256), CHAT_ID_KEY_FINGERPRINT_SIZE);
	gcry_md_close(md);

	free(buf);

	return hash;

error_with_buf:
	free(buf);
error:
	return NULL;
}

unsigned char * chat_dh_key_fingerprint_create(ChatDHKeyPtr key)
{
	gcry_mpi_t pubkey;

	pubkey = chat_dh_key_get_keypair(key).pub;
	return chat_dh_key_pub_fingerprint_create(pubkey);

}

void chat_dh_key_free(ChatDHKeyPtr key)
{
	if(key) {
		otrl_dh_keypair_free(&key->keypair);
	}
    free(key);
}


ChatInternalKeyPtr chat_dh_key_generate_internalKeyOp()
{
	return chat_dh_key_generate();
}

int chat_dh_key_serialize_internalKeyOp(ChatInternalKeyPtr key, gcry_sexp_t *key_sexp)
{
	return chat_dh_key_serialize(key, key_sexp);
}

ChatInternalKeyPtr chat_dh_key_parse_internalKeyOp(gcry_sexp_t key_sexp)
{
	return chat_dh_key_parse(key_sexp);
}

unsigned char * chat_dh_key_fingerprint_create_internalKeyOp(ChatInternalKeyPtr key)
{
	return chat_dh_key_fingerprint_create(key);
}

void chat_dh_key_free_internalKeyOp(ChatInternalKeyPtr key)
{
	chat_dh_key_free(key);
}

struct ChatInternalKeyOps chat_dh_key_internalKeyOps = {
		chat_dh_key_generate_internalKeyOp,
		chat_dh_key_serialize_internalKeyOp,
		chat_dh_key_parse_internalKeyOp,
		chat_dh_key_fingerprint_create_internalKeyOp,
		chat_dh_key_free_internalKeyOp
};
