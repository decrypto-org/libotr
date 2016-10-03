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

#include "chat_fingerprint.h"

#include <stdio.h>
#include <string.h>
#include <gcrypt.h>

#include "chat_privkeydh.h"
#include "list.h"
#include "userstate.h"
#include "list.h"

struct OtrlChatFingerprintStruct {
	char *accountname;  	/* the account name we have trusted with */
	char *protocol;			/* the protocol we have trusted the user with */
	char *username;     	/* the username that the fingerprint corresponds to */
	unsigned char *bytes; 	/* the actual bytes of the fingerprint */
	int trusted; 			/* boolean value showing if the user has verified the fingerprint */
};

char *otrl_chat_fingerprint_bytes_to_hex(const unsigned char *fingerprint)
{
	char *hex;
	unsigned int i;

	hex = malloc((2*CHAT_FINGERPRINT_SIZE + 1) * sizeof *hex);
	if(!hex) { goto error; }

	for(i=0; i<CHAT_FINGERPRINT_SIZE; i++) {
		sprintf(&hex[i*2], "%02X", fingerprint[i]);
	}

	return hex;

error:
	return NULL;
}

unsigned char *chat_fingerprint_hex_to_bytes(const char *fingerprint_hex)
{
	unsigned int i;
	unsigned int tmp;
	unsigned char *bytes;

	if(strlen(fingerprint_hex) != 2*CHAT_FINGERPRINT_SIZE) { goto error; }

	bytes = malloc(CHAT_FINGERPRINT_SIZE * sizeof *bytes);
	if(!bytes) { goto error; }

	for(i=0; i<CHAT_FINGERPRINT_SIZE; i++) {
		sscanf(&fingerprint_hex[i*2], "%02X", &tmp);
		bytes[i] = (unsigned char) tmp;
	}

	return bytes;

error:
	return NULL;
}

size_t chat_fingerprint_size()
{
	return sizeof(struct OtrlChatFingerprintStruct);
}

OtrlChatFingerprint chat_fingerprint_new(char *accountname, char *protocol, char *username, unsigned char *bytes, int isTrusted)
{
	OtrlChatFingerprint fnprnt;

	fnprnt = malloc(sizeof *fnprnt);
	if(!fnprnt) { goto error; }

	fnprnt->accountname = strdup(accountname);
	if(!fnprnt->accountname) { goto error_with_fnprnt; }

	fnprnt->protocol = strdup(protocol);
	if(!fnprnt->protocol) { goto error_with_accountname; }

	fnprnt->username = strdup(username);
	if(!fnprnt->username) { goto error_with_protocol; }

	fnprnt->bytes = malloc(CHAT_FINGERPRINT_SIZE * sizeof *fnprnt->bytes);
	if(!fnprnt->bytes) { goto error_with_username; }

	fnprnt->trusted = isTrusted;

	memcpy(fnprnt->bytes, bytes, CHAT_FINGERPRINT_SIZE);

	return fnprnt;

error_with_username:
	free(fnprnt->username);
error_with_protocol:
	free(fnprnt->protocol);
error_with_accountname:
	free(fnprnt->accountname);
error_with_fnprnt:
	free(fnprnt);
error:
	return NULL;
}

void chat_fingerprint_free(OtrlChatFingerprint fnprnt)
{
	if(fnprnt) {
		free(fnprnt->accountname);
		free(fnprnt->protocol);
		free(fnprnt->username);
		free(fnprnt->bytes);
	}
    free(fnprnt);
}

char * otrl_chat_fingerprint_get_accountname(OtrlChatFingerprint fnprnt)
{
	return fnprnt->accountname;
}

char * otrl_chat_fingerprint_get_protocol(OtrlChatFingerprint fnprnt)
{
	return fnprnt->protocol;
}

char * otrl_chat_fingerprint_get_username(OtrlChatFingerprint fnprnt)
{
	return fnprnt->username;
}

unsigned char * otrl_chat_fingerprint_get_bytes(OtrlChatFingerprint fnprnt)
{
	return fnprnt->bytes;
}

int otrl_chat_fingerprint_is_trusted(OtrlChatFingerprint fnprnt)
{
	return fnprnt->trusted;
}

OtrlChatFingerprint chat_fingerprint_find(OtrlList fingerlist, char *accountname , char *protocol, char *username, unsigned char *bytes)
{
	OtrlListIterator iter;
	OtrlListNode cur;
	OtrlChatFingerprint fnprnt, result;

	iter = otrl_list_iterator_new(fingerlist);
	if(!iter) { goto error; }

	result = NULL;
	while(!result && otrl_list_iterator_has_next(iter)) {
		cur = otrl_list_iterator_next(iter);
		fnprnt = otrl_list_node_get_payload(cur);

		if( 0 == strcmp(accountname, otrl_chat_fingerprint_get_accountname(fnprnt)) &&
				0 == strcmp(protocol, otrl_chat_fingerprint_get_protocol(fnprnt)) &&
				0 == strcmp(username, otrl_chat_fingerprint_get_username(fnprnt)) &&
				0 == memcmp(bytes, otrl_chat_fingerprint_get_bytes(fnprnt), CHAT_FINGERPRINT_SIZE)) {
			result = fnprnt;
		}
	}

	otrl_list_iterator_free(iter);

	return result;

error:
	return NULL;
}

int chat_fingerprint_add(OtrlList fingerlist, OtrlChatFingerprint fnprnt)
{
	OtrlListNode node;

	node = otrl_list_insert(fingerlist, fnprnt);
	if(!node) { goto error; }

	return 0;

error:
	return 1;
}

int chat_fingerprint_remove(OtrlList fingerlist, OtrlChatFingerprint fnprnt)
{
	OtrlListNode node;

	node = otrl_list_find(fingerlist, fnprnt);
	if(!node) { goto error; }

	otrl_list_remove_and_free(fingerlist, node);

	return 0;

error:
	return 1;
}

void chat_fingerprint_verify(OtrlChatFingerprint fnprnt)
{
	// TODO check already initialized contexts and inform the application
	fnprnt->trusted = 1;
}

void chat_fingerprint_forget(OtrlList fingerlist, OtrlChatFingerprint fnprnt)
{
	// TODO check already initialized contexts and inform the application
	chat_fingerprint_remove(fingerlist, fnprnt);
}

int chat_fingerprint_read_FILEp(OtrlList fingerlist, FILE *fingerfile)
{
	char buf[CHAT_FINGERPRINT_BUFSIZE];
	char *accountname, *protocol, *username, *bytes_hex, *trustedStr, *pch;
	unsigned char *bytes;
	int trusted;
	OtrlChatFingerprint fnprnt;
	OtrlListNode node;

	fprintf(stderr,"libotr-mpOTR: otrl_chat_fingerprint_read_FILEp: start\n");

	while(fgets(buf, CHAT_FINGERPRINT_BUFSIZE, fingerfile)) {
		//remove trailing newline
		strtok(buf, "\n");

		if(strlen(buf) == 0) { continue; }

		pch = strtok (buf, ",");
		if(pch == NULL) {
			continue;
		}
		accountname = strdup(pch);
		if(!accountname) { goto error; }

		pch = strtok (NULL, ",");
		if(pch == NULL) {
			free(accountname);
			continue;
		}
		protocol = strdup(pch);
		if(!protocol) { goto error_with_accountname; }

		pch = strtok (NULL, ",");
		if(pch == NULL) {
			free(accountname);
			free(protocol);
			continue;
		}
		username = strdup(pch);
		if(!username) { goto error_with_protocol; }

		pch = strtok (NULL, ",");
		if(pch == NULL) {
			free(accountname);
			free(protocol);
			free(username);
			continue;
		}
		bytes_hex = strdup(pch);
		if(!bytes_hex) { goto error_with_username; }

		pch = strtok (NULL, ",");
		if(pch == NULL) {
			free(accountname);
			free(protocol);
			free(username);
			free(bytes_hex);
			continue;
		}
		trustedStr = strdup(pch);
		if(!trustedStr) { goto error_with_fingerprint_hex; }

		if(strlen(trustedStr)!=1 || (trustedStr[0]!='0' && trustedStr[0]!='1')) {
			free(accountname);
			free(protocol);
			free(username);
			free(bytes_hex);
			free(trustedStr);
			continue;
		}
		trusted = (trustedStr[0] == '0') ? 0 : 1;

		bytes = chat_fingerprint_hex_to_bytes(bytes_hex);
		if(!bytes) { goto error_with_isTrusted; }

		fnprnt = chat_fingerprint_new(accountname, protocol, username, bytes, trusted);
		if(!fnprnt) { goto error_with_fingerprint; }

		node = otrl_list_insert(fingerlist, fnprnt);
		if(!node) { goto error_with_fnprnt; }

		free(bytes);
		free(bytes_hex);
		free(trustedStr);
	}

	fprintf(stderr,"libotr-mpOTR: otrl_chat_fingerprint_read_FILEp: dumping fingerprint list:\n");
	otrl_list_dump(fingerlist);

	fprintf(stderr,"libotr-mpOTR: otrl_chat_fingerprint_read_FILEp: end\n");

	return 0;

error_with_fnprnt:
	chat_fingerprint_free(fnprnt);
error_with_fingerprint:
	free(bytes);
error_with_isTrusted:
	free(trustedStr);
error_with_fingerprint_hex:
	free(bytes_hex);
error_with_username:
	free(username);
error_with_protocol:
	free(protocol);
error_with_accountname:
	free(accountname);
error:
	return 1;
}

int chat_fingerprint_write_FILEp(OtrlList fingerlist, FILE *fingerFile)
{
	OtrlListIterator iter;
	OtrlListNode cur;
	OtrlChatFingerprint fnprnt;
	char *accountname = NULL, *protocol = NULL, *username = NULL;
	unsigned char *bytes;
	char *bytes_hex = NULL;
	char trustedChar;

	iter = otrl_list_iterator_new(fingerlist);
	if(!iter) { goto error; }

	while(otrl_list_iterator_has_next(iter)) {
		cur = otrl_list_iterator_next(iter);
		fnprnt = otrl_list_node_get_payload(cur);

		accountname = otrl_chat_fingerprint_get_accountname(fnprnt);
		protocol = otrl_chat_fingerprint_get_protocol(fnprnt);
		username = otrl_chat_fingerprint_get_username(fnprnt);
		bytes = otrl_chat_fingerprint_get_bytes(fnprnt);

		bytes_hex = otrl_chat_fingerprint_bytes_to_hex(bytes);
		if(!bytes_hex) { goto error_with_iter; }

		trustedChar = (otrl_chat_fingerprint_is_trusted(fnprnt)) ? '1' : '0';

		fprintf(fingerFile, "%s,%s,%s,%s,%c\n", accountname, protocol, username, bytes_hex, trustedChar);

		free(bytes_hex);
	}

	otrl_list_iterator_free(iter);

	return 0;

error_with_iter:
	otrl_list_iterator_free(iter);
error:
	return 1;
}

void chat_fingerprint_print(OtrlChatFingerprint fnprnt)
{
	char *accountname = NULL, *protocol = NULL, *username = NULL, *bytes_hex = NULL;
	unsigned char *bytes;

	accountname = otrl_chat_fingerprint_get_accountname(fnprnt);
	protocol = otrl_chat_fingerprint_get_protocol(fnprnt);
	username = otrl_chat_fingerprint_get_username(fnprnt);
	bytes = otrl_chat_fingerprint_get_bytes(fnprnt);

	bytes_hex = otrl_chat_fingerprint_bytes_to_hex(bytes);

	fprintf(stderr, "fingerprint:\n");
	fprintf(stderr, "|- accountname: %s\n", accountname);
	fprintf(stderr, "|- protocol: %s\n", protocol);
	fprintf(stderr, "|- username: %s\n", username);
	fprintf(stderr, "|- fingerprint: %s\n", bytes_hex);
	fprintf(stderr, "|- verified: %d\n", otrl_chat_fingerprint_is_trusted(fnprnt));

	free(bytes_hex);
}

int chat_fingerprint_compare(OtrlChatFingerprint a, OtrlChatFingerprint b)
{
    int res;
    res = strcmp(otrl_chat_fingerprint_get_accountname(a), otrl_chat_fingerprint_get_accountname(b));
    if(res == 0) res = strcmp(otrl_chat_fingerprint_get_protocol(a), otrl_chat_fingerprint_get_protocol(b));
    if(res == 0) res = strcmp(otrl_chat_fingerprint_get_username(a), otrl_chat_fingerprint_get_username(b));
    if(res == 0) res = memcmp(otrl_chat_fingerprint_get_bytes(a), otrl_chat_fingerprint_get_bytes(b), CHAT_FINGERPRINT_SIZE);
    return res;
}

int chat_fingerprint_compareOp(OtrlListPayload a, OtrlListPayload b)
{
	OtrlChatFingerprint fa, fb;

	fa = a;
	fb = b;

	return chat_fingerprint_compare(fa, fb);
}

void chat_fingerprint_printOp(OtrlListNode a)
{
	OtrlChatFingerprint fnprnt;

	fnprnt = otrl_list_node_get_payload(a);
	chat_fingerprint_print(fnprnt);
}

void chat_fingerprint_freeOp(OtrlListPayload a)
{
	OtrlChatFingerprint fnprnt = a;

	chat_fingerprint_free(fnprnt);
}

struct OtrlListOpsStruct chat_fingerprint_listOps = {
		chat_fingerprint_compareOp,
		chat_fingerprint_printOp,
		chat_fingerprint_freeOp
};
