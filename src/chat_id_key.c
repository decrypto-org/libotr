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

#include "chat_id_key.h"

#include <gcrypt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "chat_types.h" // to use OtrlIdKeyInfo, maybe find a better solution later
#include "list.h"

struct ChatIdKeyS {
	char *accountname;
	char *protocol;
	ChatInternalKeyPtr internal_key;
	ChatInternalKeyOpsPtr internal_key_ops;
};

size_t chat_id_key_size()
{
	return sizeof(struct ChatIdKeyS);
}

ChatIdKeyPtr chat_id_key_new(const char *accountname, const char *protocol, ChatInternalKeyPtr internal_key, ChatInternalKeyOpsPtr internal_key_ops)
{
	ChatIdKeyPtr key;

	key = malloc(sizeof *key);
	if(!key) { goto error;}

	key->accountname = strdup(accountname);
	if(!key->accountname) { goto error_with_key; }

	key->protocol = strdup(protocol);
	if(!key->protocol) { goto error_with_accountname; }

	key->internal_key = internal_key;
	key->internal_key_ops = internal_key_ops;

	return key;

error_with_accountname:
	free(key->accountname);
error_with_key:
	free(key);
error:
	return NULL;
}

void chat_id_key_free(ChatIdKeyPtr key)
{
	if(key) {
		free(key->accountname);
		free(key->protocol);

		if(key->internal_key_ops) {
			key->internal_key_ops->free(key->internal_key);
		}
	}
	free(key);
}

char * chat_id_key_get_accountname(ChatIdKeyPtr key)
{
	return key->accountname;
}

char * chat_id_key_get_protocol(ChatIdKeyPtr key)
{
	return key->protocol;
}

ChatInternalKeyPtr chat_id_key_get_internal_key(ChatIdKeyPtr key)
{
	return key->internal_key;
}

unsigned char * chat_id_key_fingerprint_create(ChatIdKeyPtr key)
{
	return key->internal_key_ops->fingerprint_create(key->internal_key);
}

ChatIdKeyPtr chat_id_key_generate(const char *accountname, const char *protocol, ChatInternalKeyOpsPtr internal_key_ops)
{
	ChatIdKeyPtr key;
	ChatInternalKeyPtr internal_key;

	internal_key = internal_key_ops->generate();
	if(!internal_key) { goto error; }

	key = chat_id_key_new(accountname, protocol, internal_key, internal_key_ops);
	if(!key) { goto error_with_internal_key; }

	return key;

error_with_internal_key:
	free(key);
error:
	return NULL;
}

int chat_id_key_serialize(ChatIdKeyPtr key, gcry_sexp_t *key_sexp)
{
	gcry_sexp_t sexp, intenral_key_sexp;
	gcry_error_t g_err;
	int err;
	static char *key_paramstr = "(id-key (accountname %s) (protocol %s) (internal-key %S))";

	err = key->internal_key_ops->serialize(key->internal_key, &intenral_key_sexp);
	if(err) { goto error; }

	/* Build the s expression according to the key_paramstr structure */
	g_err = gcry_sexp_build(&sexp, NULL, key_paramstr, chat_id_key_get_accountname(key), chat_id_key_get_protocol(key), intenral_key_sexp);
	if(g_err) { goto error_with_internal_key_sexp; }

	gcry_sexp_release(intenral_key_sexp);

	*key_sexp = sexp;
	return 0;

error_with_internal_key_sexp:
	gcry_sexp_release(intenral_key_sexp);
error:
	return 1;
}

ChatIdKeyPtr chat_id_key_parse(gcry_sexp_t key_sexp, ChatInternalKeyOpsPtr internal_key_ops)
{
	const char *token;
	size_t tokenlen;
	gcry_sexp_t accountname_sexp, protocol_sexp, internal_key_sexp, internal_key_value_sexp;
	char *accountname, *protocol;
	ChatInternalKeyPtr internal_key = NULL;
	ChatIdKeyPtr key = NULL;

	// Check if the first token is really "id-key"
	token = gcry_sexp_nth_data(key_sexp, 0, &tokenlen);
	if (tokenlen != 6 || strncmp(token, "id-key", 6)) { goto error; }

	/* Extract the accountname, protocol, and internal-key S-exps */
	accountname_sexp = gcry_sexp_find_token(key_sexp, "accountname", 0);
	if(!accountname_sexp) { goto error; }

	protocol_sexp = gcry_sexp_find_token(key_sexp, "protocol", 0);
	if(!protocol_sexp) { goto error_with_accountname_sexp; }

	internal_key_sexp = gcry_sexp_find_token(key_sexp, "internal-key", 0);
	if(!internal_key_sexp) { goto error_with_protocol_sexp; }


	/* Extract the accountname */
	token = gcry_sexp_nth_data(accountname_sexp, 1, &tokenlen);
	if (!token) { goto error_with_internal_key_sexp;}

	accountname = malloc((tokenlen+1) * sizeof *accountname);
	if (!accountname) { goto error_with_internal_key_sexp; }

	memmove(accountname, token, tokenlen);
	accountname[tokenlen] = '\0';


	/* Extract the protocol */
	token = gcry_sexp_nth_data(protocol_sexp, 1, &tokenlen);
	if (!token) { goto error_with_accountname; }

	protocol = malloc((tokenlen+1) * sizeof * protocol);
	if (!protocol) { goto error_with_accountname; }

	memmove(protocol, token, tokenlen);
	protocol[tokenlen] = '\0';

	/* Extract the internal key */
	internal_key_value_sexp = gcry_sexp_nth(internal_key_sexp, 1);
	if(!internal_key_value_sexp) { goto error_with_protocol; }

	internal_key = internal_key_ops->parse(internal_key_value_sexp);
	if(!internal_key) { goto error_with_internal_key_value_sexp; }

	key = chat_id_key_new(accountname, protocol, internal_key, internal_key_ops);
	if(!key) { goto error_with_internal_key; }

	gcry_sexp_release(internal_key_value_sexp);
	free(protocol);
	free(accountname);
	gcry_sexp_release(internal_key_sexp);
	gcry_sexp_release(protocol_sexp);
	gcry_sexp_release(accountname_sexp);

	return key;

error_with_internal_key:
	internal_key_ops->free(internal_key);
error_with_internal_key_value_sexp:
	gcry_sexp_release(internal_key_value_sexp);
error_with_protocol:
	free(protocol);
error_with_accountname:
	free(accountname);
error_with_internal_key_sexp:
	gcry_sexp_release(internal_key_sexp);
error_with_protocol_sexp:
	gcry_sexp_release(protocol_sexp);
error_with_accountname_sexp:
	gcry_sexp_release(accountname_sexp);
error:
	return NULL;
}

int chat_id_key_compare(ChatIdKeyPtr a, ChatIdKeyPtr b)
{
	int res;

	res = strcmp(a->accountname, a->accountname);
	if(0 == res) {
		res = strcmp(a->protocol, a->protocol);
	}

	return res;
}

void chat_id_key_print(ChatIdKeyPtr key)
{
	//char *fingerprint = NULL;

	//fingerprint = chat_id_key_fingerprint_create(key);

	fprintf(stderr, "ChatIdKey:\n");
	fprintf(stderr, "|- accountname: %s\n", key->accountname );
	fprintf(stderr, "|- protocol: %s\n", key->protocol);
	//fprintf(stderr, "|- fingerprint: %s\n", fingerprint);

	//free(fingerprint);
}

int chat_id_key_find(OtrlListPtr key_list, const char * accountname, const char *protocol, ChatIdKeyPtr *found)
{
	ChatIdKeyPtr key = NULL, res = NULL;
	OtrlListIteratorPtr iter;

	iter = otrl_list_iterator_new(key_list);
	if(!iter) { goto error; }
	while(NULL == res && otrl_list_iterator_has_next(iter)) {
		key = otrl_list_node_get_payload(otrl_list_iterator_next(iter));

		if( 0 == strcmp(accountname, chat_id_key_get_accountname(key)) && 0 == strcmp(protocol, chat_id_key_get_protocol(key)) ) {
			res = key;
		}
	}
	otrl_list_iterator_free(iter);

	*found = res;
	return 0;

error:
	return 1;
}

int chat_id_key_add(OtrlListPtr key_list, ChatIdKeyPtr key)
{
	OtrlListNodePtr found = NULL, node = NULL;

	found = otrl_list_find(key_list, key);
	if(found) {
		otrl_list_remove(key_list, found);
	}

	node = otrl_list_insert(key_list, key);
	// TODO Dimitrs: here we have lost the previous key, is that ok??
	if(!node) { goto error; }

	return 0;

error:
	return 1;
}

ChatIdKeyPtr chat_id_key_generate_and_add(OtrlListPtr key_list, const char *accountname, const char *protocol, ChatInternalKeyOpsPtr internal_key_ops)
{
	ChatIdKeyPtr key = NULL;
	int err = 0;

	key = chat_id_key_generate(accountname, protocol, internal_key_ops);
	if(!key) { goto error; }

	err = chat_id_key_add(key_list, key);
	if(err) { goto error_with_key; }

	return key;

error_with_key:
	chat_id_key_free(key);
error:
	return NULL;
}

int chat_id_key_forget(OtrlListPtr key_list, const char *accountname, const char *protocol)
{
	ChatIdKeyPtr key = NULL;
	OtrlListIteratorPtr iter = NULL;
	OtrlListNodePtr node = NULL;
	char *key_accountname = NULL, *key_protocol = NULL;

	iter = otrl_list_iterator_new(key_list);
	if(!iter) { goto error; }
	while(otrl_list_iterator_has_next(iter)) {
		node = otrl_list_iterator_next(iter);
		key = otrl_list_node_get_payload(node);

		key_accountname = chat_id_key_get_accountname(key);
		key_protocol = chat_id_key_get_protocol(key);

		if(0 == strcmp(accountname, key_accountname) && 0 == strcmp(protocol, key_protocol)) {
			otrl_list_remove_and_free(key_list, node);
		}
	}
	otrl_list_iterator_free(iter);

	return 0;


error:
	return 1;
}

int chat_id_key_generate_new(OtrlListPtr key_list, const char *accountname, const char *protocol, ChatInternalKeyOpsPtr internal_key_ops)
{
	int err;
	ChatIdKeyPtr key = NULL;

	fprintf(stderr, "libotr-mpOTR: chat_id_key_generate_new: start\n");

	err = chat_id_key_forget(key_list, accountname, protocol);
	if(err) { goto error; }

	key = chat_id_key_generate_and_add(key_list, accountname, protocol, internal_key_ops);
	if(!key) { goto error; }

	fprintf(stderr, "libotr-mpOTR: chat_id_key_generate_new: end\n");

	return 0;

error:
	return 1;

}

int chat_id_key_list_read_FILEp(OtrlListPtr key_list, ChatInternalKeyOpsPtr internal_key_ops, FILE *privf)
{
	int privfd, i, err;
	struct stat st;
	char *buf = NULL;
	const char *token;
	size_t tokenlen;
	gcry_sexp_t key_sexp,  allkeys;
	gcry_error_t g_err;
	ChatIdKeyPtr key;

	if (!privf) { goto error; }

	/* Release any old ideas we had about our keys */
	otrl_list_clear(key_list);

	/** Load the data into a buffer **/

	/* Get the file descriptor of the privkey file */
	privfd = fileno(privf);

	/* Use fstat to get the file size */
	if (fstat(privfd, &st)) { goto error; }

	/* Allocate memory for a buffer to hold the file contents */
	buf = malloc(st.st_size * sizeof *buf);
	if (!buf && st.st_size > 0) { goto error; }

	/* Read the file contents into the buffer */
	if (fread(buf, st.st_size, 1, privf) != 1) { goto error_with_buf; }

	/* Create an s-expression from the read buffer */
	g_err = gcry_sexp_new(&allkeys, buf, st.st_size, 0);
	if (g_err) { goto error_with_buf; }

	/* Validate that the s-expression is a "chat_privkeys" instance */
	token = gcry_sexp_nth_data(allkeys, 0, &tokenlen);
	if (tokenlen != 13 || strncmp(token, "chat_privkeys", 13)) { goto error_with_allkeys; }

	/* Iterate over each account in the list. The loop starts at 1 because
     the zeroth element of a list is the list name, not actual data. */
	for(i=1; i<gcry_sexp_length(allkeys); ++i) {

		/* Get the ith "account" S-exp */
		key_sexp = gcry_sexp_nth(allkeys, i);

		/* Parse the account sexpression */
		key = chat_id_key_parse(key_sexp, internal_key_ops);
		// TODO Dimitris: In this case should I clear the list???
		if(!key) { goto error_with_idkeylist; }

		/* Append the parsed key in the privkey list */
		// TODO Dimitris: Why not insert?
		err = chat_id_key_add(key_list, key);
		if(err) { goto error_with_key; }

		gcry_sexp_release(key_sexp);
	}

	gcry_sexp_release(allkeys);
	free(buf);

	return 0;

error_with_key:
	chat_id_key_free(key);
	error_with_idkeylist:
	otrl_list_clear(key_list);
error_with_allkeys:
	gcry_sexp_release(allkeys);
error_with_buf:
	free(buf);
error:
	return 1;
}

static int chat_id_key_sexp_write(FILE *privf, gcry_sexp_t sexp)
{
    size_t buflen;
    char *buf;

    buflen = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);

    buf = malloc(buflen * sizeof *buf);
    if (!buf) { goto error; }

    gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, buf, buflen);

    fprintf(privf, "%s", buf);
    free(buf);

    return 0;

error:
	return 1;
}

int chat_id_key_list_write_FILEp(OtrlListPtr key_list, FILE *privf)
{
	OtrlListIteratorPtr iter;
	OtrlListNodePtr node;
	ChatIdKeyPtr key;
	gcry_sexp_t key_sexp;
	int err;

	fprintf(stderr, "libotr-mpOTR: chat_id_key_list_write_FILEp: start\n");

	// Print the starting parenthesis of the s expression along with its name
	fprintf(privf, "(chat_privkeys\n");

	// We iterate over every key in the privkey list
	iter = otrl_list_iterator_new(key_list);
	if(!iter) { goto error; }
	while(otrl_list_iterator_has_next(iter)) {
		node = otrl_list_iterator_next(iter);
		key = otrl_list_node_get_payload(node);

		 /* Serialize the key to be written */
		err = chat_id_key_serialize(key, &key_sexp);
		if(err) { goto error_with_iter; }

		/* Write the sexpression in the file */
		err = chat_id_key_sexp_write(privf, key_sexp);
		if(err) { goto error_with_key_sexp; }

		gcry_sexp_release(key_sexp);
	}

	// Print the ending parenthesis of the s expression
	fprintf(privf, ")\n");

	otrl_list_iterator_free(iter);

	fprintf(stderr, "libotr-mpOTR: chat_id_key_list_write_FILEp: end\n");

	return 0;

error_with_key_sexp:
	gcry_sexp_release(key_sexp);
error_with_iter:
	otrl_list_iterator_free(iter);
error:
	return 1;
}

int chat_id_key_compareOp(OtrlListPayloadPtr a, OtrlListPayloadPtr b)
{
   	return chat_id_key_compare(a, b);
}

void chat_id_key_printOp(OtrlListNodePtr a) {
	ChatIdKeyPtr key;

	key = otrl_list_node_get_payload(a);
	chat_id_key_print(key);
}

void chat_id_key_freeOp(OtrlListPayloadPtr a) {
	chat_id_key_free(a);
}

struct OtrlListOpsStruct chat_id_key_listOps = {
		chat_id_key_compareOp,
		chat_id_key_printOp,
		chat_id_key_freeOp
};


/* IdKeyInfo */

OtrlChatIdKeyInfoPtr chat_id_key_info_new(const char *accountname, const char *protocol, const unsigned char *fingerprint_bytes)
{
	OtrlChatIdKeyInfoPtr key = NULL;

	key = malloc(sizeof *key);
	if(!key) { goto error; }

	key->accountname = strdup(accountname);
	if(!key->accountname) { goto error; }

	key->protocol = strdup(protocol);
	if(!key->protocol) { goto error_with_accountname; }

	key->fingerprint_hex = otrl_chat_fingerprint_bytes_to_hex(fingerprint_bytes);
	if(!key->fingerprint_hex) { goto error_with_protocol; }

	return key;

error_with_protocol:
	free(key->protocol);
error_with_accountname:
	free(key->accountname);
error:
	return NULL;
}

int chat_id_key_info_compare(OtrlChatIdKeyInfoPtr a, OtrlChatIdKeyInfoPtr b)
{
	int res;

	res = strcmp(a->accountname, a->accountname);
	if(0 == res) {
		res = strcmp(a->protocol, a->protocol);
	}

	return res;
}

void chat_id_key_info_print(OtrlChatIdKeyInfoPtr key)
{
	fprintf(stderr, "OtrlChatIdKeyInfo:\n");
	fprintf(stderr, "|- accountname: %s\n", key->accountname );
	fprintf(stderr, "|- protocol: %s\n", key->protocol);
	fprintf(stderr, "|- fingerprint: %s\n", key->fingerprint_hex);
}

void chat_id_key_info_free(OtrlChatIdKeyInfoPtr key)
{
	if(key) {
		free(key->accountname);
		free(key->protocol);
		free(key->fingerprint_hex);
	}
	free(key);
}

int chat_id_key_info_compareOp(OtrlListPayloadPtr a, OtrlListPayloadPtr b)
{
   	return chat_id_key_info_compare(a, b);
}

void chat_id_key_info_printOp(OtrlListNodePtr a) {
	OtrlChatIdKeyInfoPtr key;

	key = otrl_list_node_get_payload(a);
	chat_id_key_info_print(key);
}

void chat_id_key_info_freeOp(OtrlListPayloadPtr a) {
	chat_id_key_info_free(a);
}

struct OtrlListOpsStruct chat_id_key_info_listOps = {
		chat_id_key_info_compareOp,
		chat_id_key_info_printOp,
		chat_id_key_info_freeOp
};

OtrlListPtr chat_id_key_info_list_create(OtrlListPtr key_list)
{
	OtrlListPtr info_list = NULL;
	OtrlListIteratorPtr iter = NULL;
	OtrlListNodePtr node = NULL, node2 = NULL;
	ChatIdKeyPtr key = NULL;
	OtrlChatIdKeyInfoPtr info = NULL;
	unsigned char *fingerprint_bytes = NULL;

	info_list = otrl_list_new(&chat_id_key_info_listOps, sizeof(struct OtrlChatIdKeyInfo));
	if(!info_list) { goto error ;}

	iter = otrl_list_iterator_new(key_list);
	if(!iter) { goto error_with_info_list; }
	while(otrl_list_iterator_has_next(iter)) {
		node = otrl_list_iterator_next(iter);
		key = otrl_list_node_get_payload(node);

		fingerprint_bytes = chat_id_key_fingerprint_create(key);
		if(!fingerprint_bytes) { goto error_with_info_list; }

		info = chat_id_key_info_new(chat_id_key_get_accountname(key), chat_id_key_get_protocol(key), fingerprint_bytes);
		if(!info) { goto error_with_fingerprint_bytes; }

		node2 = otrl_list_insert(info_list, info);
		if(!node2) { goto error_with_fingerprint_bytes; }

		free(fingerprint_bytes);
	}
	otrl_list_iterator_free(iter);

	return info_list;

error_with_fingerprint_bytes:
	free(fingerprint_bytes);
error_with_info_list:
	otrl_list_free(info_list);
error:
	return NULL;
}
