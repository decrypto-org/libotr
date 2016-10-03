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
    buf = malloc((s+1) * sizeof (*buf));
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

void chat_idkey_destroy_key(ChatIdKey *key){
    otrl_dh_keypair_free(&key->keyp);
    free(key->accountname);
    free(key->protocol);
    free(key);
}

void chat_idkey_destroy_keyOp(PayloadPtr a) {
	chat_idkey_destroy_key(a);
}

void chat_idkey_print_key(ChatIdKey *key) {

	fprintf(stderr, "idkey:\n");
	fprintf(stderr, "|- accountname: %s\n", key->accountname );
	fprintf(stderr, "|- protocol: %s\n", key->protocol);
	fprintf(stderr, "|- group: %u\n", key->keyp.groupid);
	fprintf(stderr, "|- priv:");
	print_mpi(key->keyp.priv);
	fprintf(stderr, "|- pub:");
	print_mpi(key->keyp.pub);
}

void chat_idkey_print_keyOp(OtrlListNode* a) {
	ChatIdKey *key = a->payload;

	chat_idkey_print_key(key);
}

gcry_error_t chat_idkey_generate_key(ChatIdKey **newkey)
{
    gcry_error_t err = gcry_error(GPG_ERR_NO_ERROR);

    fprintf(stderr,"libotr-mpOTR: chat_idkey_generate_key: start\n");

    *newkey = malloc(sizeof(**newkey));

    err = otrl_dh_gen_keypair(DH1536_GROUP_ID, &(*newkey)->keyp);
    if(err) {
    	fprintf(stderr,"libotr-mpOTR: chat_idkey_generate_key: error\n");
        free(newkey);
    }

    fprintf(stderr,"libotr-mpOTR: chat_idkey_generate_key: end\n");
    return err;
}

gcry_error_t chat_idkey_serialize_key(ChatIdKey *key, gcry_sexp_t *sexp)
{
    gcry_error_t err = gcry_error(GPG_ERR_NO_ERROR);

    fprintf(stderr,"libotr-mpOTR: chat_idkey_serialize_key: start\n");
    err = gcry_sexp_build(sexp, NULL,
                          "(tdh-key (name %s) (protocol %s) (group %u) (private-key %M) (public-key %M))",
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
    fprintf(stderr,"libotr-mpOTR: chat_idkey_parse_key: token is %d %.*s\n",(int)tokenlen, (int)tokenlen, token);
    if (tokenlen != 7 || strncmp(token, "tdh-key", 7)) {
    	return NULL;
    }

    fprintf(stderr,"libotr-mpOTR: chat_idkey_parse_key: before find_tokens\n");
	/* Extract the name, protocol, and privkey S-exps */
	names = gcry_sexp_find_token(accounts, "name", 0);
	protos = gcry_sexp_find_token(accounts, "protocol", 0);
	groups = gcry_sexp_find_token(accounts, "group", 0);
	privs = gcry_sexp_find_token(accounts, "private-key", 0);
	pubs = gcry_sexp_find_token(accounts, "public-key", 0);
	if (!names || !protos || !groups || !privs || !pubs ) {
	    gcry_sexp_release(names);
	    gcry_sexp_release(protos);
	    gcry_sexp_release(groups);
	    gcry_sexp_release(privs);
	    gcry_sexp_release(pubs);
	    return NULL;
	}

	key = malloc(sizeof(*key));
	chat_idkey_init_key(key);

	fprintf(stderr,"libotr-mpOTR: chat_idkey_parse_key: before name\n");
	/* Extract the name */
	token = gcry_sexp_nth_data(names, 1, &tokenlen);
	if (!token) {
	    gcry_sexp_release(names);
	    gcry_sexp_release(protos);
	    gcry_sexp_release(groups);
	    gcry_sexp_release(privs);
	    gcry_sexp_release(pubs);
	    return NULL;
	}

	fprintf(stderr,"libotr-mpOTR: chat_idkey_parse_key: before accountname alloc\n");
	key->accountname = malloc(tokenlen + 1);
	if (!key->accountname) {
	    gcry_sexp_release(names);
	    gcry_sexp_release(protos);
	    gcry_sexp_release(groups);
	    gcry_sexp_release(privs);
	    gcry_sexp_release(pubs);
	    chat_idkey_destroy_key(key);
	    return NULL;
	}
	memmove(key->accountname, token, tokenlen);
	key->accountname[tokenlen] = '\0';
	gcry_sexp_release(names);

	fprintf(stderr,"libotr-mpOTR: chat_idkey_parse_key: before protocol\n");
	/* Extract the protocol */
	token = gcry_sexp_nth_data(protos, 1, &tokenlen);
	if (!token) {
	    gcry_sexp_release(protos);
	    gcry_sexp_release(privs);
	    gcry_sexp_release(groups);
	    gcry_sexp_release(pubs);
	    chat_idkey_destroy_key(key);
	    return NULL;
	}
	fprintf(stderr,"libotr-mpOTR: chat_idkey_parse_key: before protocol alloc\n");
	key->protocol = malloc(tokenlen + 1);
	if (!key->protocol) {
	    gcry_sexp_release(protos);
	    gcry_sexp_release(privs);
	    gcry_sexp_release(groups);
	    gcry_sexp_release(pubs);
	    chat_idkey_destroy_key(key);
	    return NULL;
	}
	memmove(key->protocol, token, tokenlen);
	key->protocol[tokenlen] = '\0';
	gcry_sexp_release(protos);

	fprintf(stderr,"libotr-mpOTR: chat_idkey_parse_key: before group\n");
	/* Extract the group */
	token = gcry_sexp_nth_data(groups, 1, &tokenlen);
	if (!token) {
	    gcry_sexp_release(privs);
	    gcry_sexp_release(groups);
	    gcry_sexp_release(pubs);
	    chat_idkey_destroy_key(key);
	    return NULL;
	}
	fprintf(stderr,"libotr-mpOTR: chat_idkey_parse_key: before group alloc\n");
	group_str = malloc(tokenlen + 1);
	if (!group_str) {
	    gcry_sexp_release(privs);
	    gcry_sexp_release(groups);
	    gcry_sexp_release(pubs);
	    chat_idkey_destroy_key(key);
	    return NULL;
	}
	memmove(group_str, token, tokenlen);
	group_str[tokenlen] = '\0';
	gcry_sexp_release(groups);

	fprintf(stderr,"libotr-mpOTR: chat_idkey_parse_key: before groupid\n");
	/* Get the groupid from the string */
	key->keyp.groupid = strtol(group_str, &s, 10);
	if(s[0] != '\0'){
		free(group_str);
	    gcry_sexp_release(privs);
	    gcry_sexp_release(pubs);
	    chat_idkey_destroy_key(key);
	    return NULL;
	}
	free(group_str);

	fprintf(stderr,"libotr-mpOTR: chat_idkey_parse_key: before priv\n");
	w = gcry_sexp_nth_mpi(privs, 1, GCRYMPI_FMT_USG);
	if(!w) {
	    gcry_sexp_release(privs);
	    gcry_sexp_release(pubs);
	    chat_idkey_destroy_key(key);
	    return NULL;
	}
	key->keyp.priv = w;//gcry_mpi_copy(w);

	if(!key->keyp.priv) {
	    gcry_sexp_release(privs);
	    gcry_sexp_release(pubs);
	    chat_idkey_destroy_key(key);
		return NULL;
	}
	gcry_sexp_release(privs);

	fprintf(stderr,"libotr-mpOTR: chat_idkey_parse_key: before pub\n");
	w = gcry_sexp_nth_mpi(pubs, 1, GCRYMPI_FMT_USG);
	if(!w) {
	    gcry_sexp_release(pubs);
	    chat_idkey_destroy_key(key);
	    return NULL;
	}
	key->keyp.pub = w; //gcry_mpi_copy(w);
	if(!key->keyp.pub) {
	    gcry_sexp_release(pubs);
	    chat_idkey_destroy_key(key);
		return NULL;
	}
	gcry_sexp_release(pubs);

    fprintf(stderr,"libotr-mpOTR: chat_idkey_parse_key: end\n");
	return key;
}

int chat_idkey_compar(PayloadPtr a, PayloadPtr b)
{
    ChatIdKey *a_key = a;
    ChatIdKey *b_key = b;

    int username_eq = strcmp(a_key->accountname, b_key->accountname);
    fprintf(stderr,"chat_idkey_compar: comparing %s with %s\n", a_key->accountname, b_key->accountname);

    if(!username_eq) {
    	fprintf(stderr,"chat_idkey_compar: bingo! comparing protocol: %s with %s\n", a_key->protocol, b_key->protocol);
        return strcmp(a_key->protocol, b_key->protocol);
    }

   	return username_eq;
}

ChatIdKey * chat_idkey_find(OtrlList *key_list, const char *accountname, const char *protocol)
{
    ChatIdKey target;
    OtrlListNode *found;
    fprintf(stderr,"libotr-mpOTR: chat_idkey_find: start\n");
    target.accountname = strdup(accountname);
    fprintf(stderr,"libotr-mpOTR: chat_idkey_find: after accountname dup, it is: %s\n", accountname);
    target.protocol = strdup(protocol);
    fprintf(stderr,"libotr-mpOTR: chat_idkey_find: after protocol dup, it is: %s\n", protocol);

    found = otrl_list_find(key_list, &target);
    if(!found){
    	fprintf(stderr,"libotr-mpOTR: chat_idkey_find: a key was not found\n");
    }
    else {
    	fprintf(stderr,"libotr-mpOTR: chat_idkey_find: a key was found\n");
    }

    fprintf(stderr,"libotr-mpOTR: chat_idkey_find: after list find\n");
    free(target.accountname);
    fprintf(stderr,"libotr-mpOTR: chat_idkey_find: after accountname free\n");
    free(target.protocol);
    fprintf(stderr,"libotr-mpOTR: chat_idkey_find: after protocol free\n");

    return (ChatIdKey *)found->payload;
}

//ChatIdKey * chat_idkey_find_or_add(OtrlList *key_list, const char *accountname, const char *protocol)
//{
//	ChatIdKey *key;
//	gcry_error_t err;
//
//	key = chat_idkey_find(key_list, accountname, protocol);
//	if(!key){
//		err = chat_idkey_generate_key(&key);
//		if(err) {
//			return NULL;
//		}
//
//	}
//}

struct OtrlListOpsStruct chat_idkey_listOps = {
		chat_idkey_compar,
		chat_idkey_print_keyOp,
		chat_idkey_destroy_keyOp
};

ChatIdKeyManager chat_id_key_manager = {
    chat_idkey_init_key,
    chat_idkey_destroy_key,
	chat_idkey_parse_key,
    chat_idkey_generate_key,
    chat_idkey_serialize_key,
	chat_idkey_find
};
