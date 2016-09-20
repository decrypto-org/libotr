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

#include <stdlib.h>
#include <gcrypt.h>

#include "dh.h"
#include "chat_idkey.h"
#include "list.h"

void print_mpi(gcry_mpi_t w)
{
	unsigned char *buf;
    size_t s;

    gcry_mpi_print(GCRYMPI_FMT_HEX,NULL,0,&s,w);
    buf = malloc((s+1) * sizeof *buf);
    if(!buf) {
    	return;
    }
    gcry_mpi_print(GCRYMPI_FMT_HEX,buf,s,NULL,w);
    buf[s]='\0';

    fprintf(stderr, "%s\n", buf);
    free(buf);
}

void chat_idkey_init_key(ChatIdKey *key){
	key->accountname = NULL;
	key->protocol = NULL;
	otrl_dh_keypair_init(&key->keyp);
}

void chat_idkey_free(ChatIdKey *key){

	if(!key) {
        return;
    }

    otrl_dh_keypair_free(&key->keyp);
    free(key->accountname);
    free(key->protocol);

    free(key);
}

void chat_idkey_print(ChatIdKey *key) {

	fprintf(stderr, "idkey:\n");
	fprintf(stderr, "|- accountname: %s\n", key->accountname );
	fprintf(stderr, "|- protocol: %s\n", key->protocol);
	fprintf(stderr, "|- group: %u\n", key->keyp.groupid);
	fprintf(stderr, "|- priv:");
	print_mpi(key->keyp.priv);
	fprintf(stderr, "|- pub:");
	print_mpi(key->keyp.pub);
}

int chat_idkey_generate_key(ChatIdKey **newkey)
{
	ChatIdKey *key;
    gcry_error_t err;

    fprintf(stderr,"libotr-mpOTR: chat_idkey_generate_key: start\n");

    /* Allocate memory for a ChatIdKey struct */
    key = malloc(sizeof *key);
    if(!key) { goto error; }

    /* Initialize the new key */
    chat_idkey_init_key(key);

    /* Generate a diffie hellman keypair */
    err = otrl_dh_gen_keypair(DH1536_GROUP_ID, &key->keyp);
    if(err) { goto error_with_key; }

    fprintf(stderr,"libotr-mpOTR: chat_idkey_generate_key: end\n");

    *newkey = key;
    return 0;

error_with_key:
	free(key);
error:
	return 1;
}

gcry_error_t chat_idkey_serialize_key(ChatIdKey *key, gcry_sexp_t *sexp)
{
    gcry_error_t err = gcry_error(GPG_ERR_NO_ERROR);
    static char *key_paramstr = "(tdh-key (name %s) (protocol %s) (group %u) (private-key %M) (public-key %M))";

    fprintf(stderr,"libotr-mpOTR: chat_idkey_serialize_key: start\n");

    /* Build the s expression according to the key_paramstr structure */
    err = gcry_sexp_build(sexp, NULL,
                          key_paramstr,
                          key->accountname, key->protocol, key->keyp.groupid,
                          key->keyp.priv, key->keyp.pub);

    fprintf(stderr,"libotr-mpOTR: chat_idkey_serialize_key: end\n");
    return err;
}

ChatIdKey * chat_idkey_parse_key(gcry_sexp_t accounts)
{
	const char *token;
	size_t tokenlen;
	gcry_sexp_t names, protos, groups, privs, pubs;
	ChatIdKey *key = NULL;
	char *group_str, *s;
	gcry_mpi_t w;

    fprintf(stderr,"libotr-mpOTR: chat_idkey_parse_key: start\n");

    token = gcry_sexp_nth_data(accounts, 0, &tokenlen);
    if (tokenlen != 7 || strncmp(token, "tdh-key", 7)) { goto error; }

	/* Extract the name, protocol, and privkey S-exps */
	names = gcry_sexp_find_token(accounts, "name", 0);
	protos = gcry_sexp_find_token(accounts, "protocol", 0);
	groups = gcry_sexp_find_token(accounts, "group", 0);
	privs = gcry_sexp_find_token(accounts, "private-key", 0);
	pubs = gcry_sexp_find_token(accounts, "public-key", 0);
	if (!names || !protos || !groups || !privs || !pubs ) { goto error_with_names; }

    /* Allocate memory for the key to be parsed */
	key = malloc(sizeof *key);
	if(!key) { goto error_with_names; }

    /* And initialize it */
	chat_idkey_init_key(key);


	/* Extract the name */
	token = gcry_sexp_nth_data(names, 1, &tokenlen);
	if (!token) { goto error_with_names;}

    /* Allocate memory for the accountname string inside the key struct */
	key->accountname = malloc((tokenlen+1) * sizeof *(key->accountname));
	if (!key->accountname) { goto error_with_names; }

    /* Copy the accountname and place a null character at the end */
	memmove(key->accountname, token, tokenlen);
	key->accountname[tokenlen] = '\0';

	gcry_sexp_release(names);

	/* Extract the protocol */
	token = gcry_sexp_nth_data(protos, 1, &tokenlen);
	if (!token) { goto error_with_protos; }

    /* Allocate memory for the protocol string inside the key struct */
	key->protocol = malloc((tokenlen+1) * sizeof *(key->protocol));
	if (!key->protocol) { goto error_with_protos; }

    /* Copy the protocol and place a null character at the end */
	memmove(key->protocol, token, tokenlen);
	key->protocol[tokenlen] = '\0';

	gcry_sexp_release(protos);

	/* Extract the group */
	token = gcry_sexp_nth_data(groups, 1, &tokenlen);
	if (!token) { goto error_with_groups; }

    /* Allocate memory for the group string. This auxiliary string is needed
    since the DH group is stored as a string and we must convert it to an
    integer later */
	group_str = malloc((tokenlen+1) * sizeof *group_str);
	if (!group_str) { goto error_with_groups; }

    /* Copy it and place a null character in the end */
	memmove(group_str, token, tokenlen);
	group_str[tokenlen] = '\0';

	gcry_sexp_release(groups);

	/* Get the groupid from the string */
	key->keyp.groupid = strtol(group_str, &s, 10);
	if(s[0] != '\0'){
	    free(group_str);
        goto error_with_privs;
    }
    free(group_str);

    /* Get the private key */
	w = gcry_sexp_nth_mpi(privs, 1, GCRYMPI_FMT_USG);
	if(!w) { goto error_with_privs; }

	key->keyp.priv = w;
	gcry_sexp_release(privs);

    /* Get the public key */
	w = gcry_sexp_nth_mpi(pubs, 1, GCRYMPI_FMT_USG);
	if(!w) { goto error_with_pubs; }

	key->keyp.pub = w;
	gcry_sexp_release(pubs);

    fprintf(stderr,"libotr-mpOTR: chat_idkey_parse_key: end\n");
	return key;

error_with_names:
	fprintf(stderr,"libotr-mpOTR: chat_idkey_parse_key: error_with_names\n");
	gcry_sexp_release(names);
error_with_protos:
	fprintf(stderr,"libotr-mpOTR: chat_idkey_parse_key: error_with_protos\n");
	gcry_sexp_release(protos);
error_with_groups:
	fprintf(stderr,"libotr-mpOTR: chat_idkey_parse_key: error_with_groups\n");
	gcry_sexp_release(groups);
error_with_privs:
	gcry_sexp_release(privs);
	fprintf(stderr,"libotr-mpOTR: chat_idkey_parse_key: error_with_privs\n");
error_with_pubs:
	fprintf(stderr,"libotr-mpOTR: chat_idkey_parse_key: error_with_names\n");
	gcry_sexp_release(pubs);
error:
	fprintf(stderr,"libotr-mpOTR: chat_idkey_parse_key: error\n");
    chat_idkey_free(key);
    return NULL;
}

int chat_idkey_compare(ChatIdKey *a_key, ChatIdKey *b_key)
{
    int username_eq = strcmp(a_key->accountname, b_key->accountname);
    fprintf(stderr,"chat_idkey_compar: comparing %s with %s\n", a_key->accountname, b_key->accountname);

    if(!username_eq) {
    	fprintf(stderr,"chat_idkey_compar: bingo! comparing protocol: %s with %s\n", a_key->protocol, b_key->protocol);
        return strcmp(a_key->protocol, b_key->protocol);
    }

   	return username_eq;
}

ChatIdKey * chat_idkey_find(OtrlList key_list, const char *accountname, const char *protocol)
{
    ChatIdKey target, *res;
    OtrlListNode found;

    fprintf(stderr,"libotr-mpOTR: chat_idkey_find: start\n");

    /* Duplicate the target accountname and protocol */
    target.accountname = strdup(accountname);
    if(!target.accountname) { goto error; }

    target.protocol = strdup(protocol);
    if(!target.protocol) { goto error_with_accountname; }

    /* And search the key in the key list */
    found = otrl_list_find(key_list, &target);
    if(!found){ goto error_with_protocol; }

    /* Free the target */
    free(target.protocol);
    free(target.accountname);

    fprintf(stderr,"libotr-mpOTR: chat_idkey_find: end\n");

    res = otrl_list_node_get_payload(found);
    return res;

error_with_protocol:
    free(target.protocol);
error_with_accountname:
    free(target.accountname);
error:
    return NULL;
}

int chat_idkey_compareOp(OtrlListPayload a, OtrlListPayload b)
{
    ChatIdKey *a_key = a;
    ChatIdKey *b_key = b;

   	return chat_idkey_compare(a_key, b_key);
}

void chat_idkey_printOp(OtrlListNode a) {
	ChatIdKey *key;

	key = otrl_list_node_get_payload(a);
	chat_idkey_print(key);
}

void chat_idkey_freeOp(OtrlListPayload a) {
	chat_idkey_free(a);
}

struct OtrlListOpsStruct chat_idkey_listOps = {
		chat_idkey_compareOp,
		chat_idkey_printOp,
		chat_idkey_freeOp
};

ChatIdKeyManager chat_id_key_manager = {
    chat_idkey_init_key,
    chat_idkey_free,
	chat_idkey_parse_key,
    chat_idkey_generate_key,
    chat_idkey_serialize_key,
	chat_idkey_find
};
