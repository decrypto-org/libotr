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

#include <stdio.h>
#include <string.h>

#include <gcrypt.h>

#include "chat_fingerprint.h"
#include "chat_privkeydh.h"
#include "list.h"
#include "userstate.h"

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

ChatFingerprint *chat_fingerprint_new(char *accountname, char *protocol, char *username, unsigned char *fingerprint, unsigned char isTrusted)
{
	ChatFingerprint *fnprnt;

	fnprnt = malloc(sizeof *fnprnt);
	if(!fnprnt) { goto error; }

	fnprnt->accountname = strdup(accountname);
	if(!fnprnt->accountname) { goto error_with_fnprnt; }

	fnprnt->protocol = strdup(protocol);
	if(!fnprnt->protocol) { goto error_with_accountname; }

	fnprnt->username = strdup(username);
	if(!fnprnt->username) { goto error_with_protocol; }

	fnprnt->fingerprint = malloc(CHAT_FINGERPRINT_SIZE * sizeof *fnprnt->fingerprint);
	if(!fnprnt->fingerprint) { goto error_with_username; }

	fnprnt->isTrusted = isTrusted;

	memcpy(fnprnt->fingerprint, fingerprint, CHAT_FINGERPRINT_SIZE);

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

void chat_fingerprint_destroy(ChatFingerprint *fingerprint)
{
    free(fingerprint->fingerprint);
    free(fingerprint->username);
    free(fingerprint->accountname);
    free(fingerprint->protocol);
    free(fingerprint);
}

ChatFingerprint *chat_fingerprint_find(OtrlUserState us, char *accountname , char *protocol, char *username, unsigned char *fingerprint)
{
	ChatFingerprint *fnprnt;
	OtrlListNode *cur;
	int found = 0;

	cur = us->chat_fingerprints->head;
	//TODO better find implementation
	while(cur != NULL && !found) {
		fnprnt = cur->payload;

		if(strcmp(accountname, fnprnt->accountname) == 0
				&& strcmp(protocol, fnprnt->protocol) == 0
				&& strcmp(username, fnprnt->username) == 0
				&& memcmp(fingerprint, fnprnt->fingerprint, CHAT_FINGERPRINT_SIZE) == 00) {
			found = 1;
		}

		cur=cur->next;
	}

	if(!found) fnprnt = NULL;

	return fnprnt;
}

int chat_fingerprint_add(OtrlUserState us, ChatFingerprint *finger)
{
	OtrlListNode *node;
	node = otrl_list_insert(us->chat_fingerprints, finger);
	if(!node) { goto error; }

	return 0;

error:
	return 1;
}

int chat_fingerprint_remove(OtrlUserState us, ChatFingerprint *finger)
{
	OtrlListNode *node;


	node = otrl_list_find(us->chat_fingerprints, finger);
	if(!node) { goto error; }

	otrl_list_remove_and_destroy(us->chat_fingerprints, node);

	return 0;

error:
	return 1;
}

int otrl_chat_fingerprint_verify(OtrlUserState us, const OtrlMessageAppOps *ops, ChatFingerprint *finger)
{
	fprintf(stderr,"libotr-mpOTR: otrl_chat_fingerprint_verify: start\n");

	finger->isTrusted = 1;
	ops->chat_fingerprints_write(NULL);

	fprintf(stderr,"libotr-mpOTR: otrl_chat_fingerprint_verify: end\n");
	return 0;
}

int otrl_chat_fingerprint_forget(OtrlUserState us, const OtrlMessageAppOps *ops, ChatFingerprint *finger)
{

	fprintf(stderr,"libotr-mpOTR: otrl_chat_fingerprint_forget: start\n");

	chat_fingerprint_remove(us, finger);
	ops->chat_fingerprints_write(NULL);

	fprintf(stderr,"libotr-mpOTR: otrl_chat_fingerprint_forget: end\n");
	return 0;
}

int otrl_chat_fingerprint_read_FILEp(OtrlUserState us, FILE *fingerfile)
{
	char buf[CHAT_FINGERPRINT_BUFSIZE];
	char *accountname, *protocol, *username, *fingerprint_hex, *isTrustedStr, *pch;
	unsigned char *fingerprint;
	unsigned char isTrusted;
	ChatFingerprint *fnprnt;
	OtrlListNode *node;

	fprintf(stderr,"libotr-mpOTR: otrl_chat_fingerprint_read_FILEp: start\n");

	while(fgets(buf, CHAT_FINGERPRINT_BUFSIZE, fingerfile)) {
		//remove trailing newline
		strtok(buf, "\n");

		if(strlen(buf) == 0) { continue; }

		fprintf(stderr,"libotr-mpOTR: otrl_chat_fingerprint_read_FILEp: parsing line: %s\n", buf);

		pch = strtok (buf, ",");
		if(pch == NULL) {
			continue;
		}
		accountname = strdup(pch);
		if(!accountname) { goto error; }

		fprintf(stderr,"libotr-mpOTR: otrl_chat_fingerprint_read_FILEp: accountname: %s\n", accountname);

		pch = strtok (NULL, ",");
		if(pch == NULL) {
			free(accountname);
			continue;
		}
		protocol = strdup(pch);
		if(!protocol) { goto error_with_accountname; }

		fprintf(stderr,"libotr-mpOTR: otrl_chat_fingerprint_read_FILEp: protocol: %s\n", protocol);

		pch = strtok (NULL, ",");
		if(pch == NULL) {
			free(accountname);
			free(protocol);
			continue;
		}
		username = strdup(pch);
		if(!username) { goto error_with_protocol; }

		fprintf(stderr,"libotr-mpOTR: otrl_chat_fingerprint_read_FILEp: username: %s\n", username);

		pch = strtok (NULL, ",");
		if(pch == NULL) {
			free(accountname);
			free(protocol);
			free(username);
			continue;
		}
		fingerprint_hex = strdup(pch);
		if(!fingerprint_hex) { goto error_with_username; }

		fprintf(stderr,"libotr-mpOTR: otrl_chat_fingerprint_read_FILEp: fingerprint_hex: %s\n", fingerprint_hex);

		pch = strtok (NULL, ",");
		if(pch == NULL) {
			free(accountname);
			free(protocol);
			free(username);
			free(fingerprint_hex);
			continue;
		}
		isTrustedStr = strdup(pch);
		if(!isTrustedStr) { goto error_with_fingerprint_hex; }

		if(strlen(isTrustedStr)!=1 || (isTrustedStr[0]!='0' && isTrustedStr[0]!='1')) {
			free(accountname);
			free(protocol);
			free(username);
			free(fingerprint_hex);
			free(isTrustedStr);
			continue;
		}
		isTrusted = (isTrustedStr[0] == '0') ? 0 : 1;

		fingerprint = chat_fingerprint_hex_to_bytes(fingerprint_hex);
		if(!fingerprint) { goto error_with_isTrusted; }

		fnprnt = chat_fingerprint_new(accountname, protocol, username, fingerprint, isTrusted);
		if(!fnprnt) { goto error_with_fingerprint; }

		node = otrl_list_insert(us->chat_fingerprints, fnprnt);
		if(!node) { goto error_with_fnprnt; }

		free(fingerprint);
		free(fingerprint_hex);
		free(isTrustedStr);
	}

	fprintf(stderr,"libotr-mpOTR: otrl_chat_fingerprint_read_FILEp: dumping fingerprint list:\n");
	otrl_list_dump(us->chat_fingerprints);


	fprintf(stderr,"libotr-mpOTR: otrl_chat_fingerprint_read_FILEp: end\n");

	return 0;

error_with_fnprnt:
	chat_fingerprint_destroy(fnprnt);
error_with_fingerprint:
	free(fingerprint);
error_with_isTrusted:
	free(isTrustedStr);
error_with_fingerprint_hex:
	free(fingerprint_hex);
error_with_username:
	free(username);
error_with_protocol:
	free(protocol);
error_with_accountname:
	free(accountname);
error:
	return 1;
}

int otrl_chat_fingerprint_write_FILEp(OtrlUserState us, FILE *fingerFile)
{
	OtrlListNode *cur;
	ChatFingerprint *fnprnt;
	char *hex_fingerprint;
	char isTrustedChar;

	for(cur=us->chat_fingerprints->head; cur!=NULL; cur=cur->next)
	{
		fnprnt = cur->payload;
		hex_fingerprint = otrl_chat_fingerprint_bytes_to_hex(fnprnt->fingerprint);
		// TODO better handle this case
		if(!hex_fingerprint) { goto error; }
		isTrustedChar = (fnprnt->isTrusted) ? '1' : '0';
		fprintf(fingerFile, "%s,%s,%s,%s,%c\n", fnprnt->accountname, fnprnt->protocol, fnprnt->username, hex_fingerprint, isTrustedChar);
	}

	return 0;

error:
	return 1;
}

void chat_fingerprint_destroyOp(PayloadPtr a)
{
	ChatFingerprint *fingerprint = a;
	chat_fingerprint_destroy(fingerprint);
}

void chat_fingerprint_print(ChatFingerprint *fingerprint)
{
	char *finhex = otrl_chat_fingerprint_bytes_to_hex(fingerprint->fingerprint);
	fprintf(stderr, "fingerprint:\n");
	fprintf(stderr, "|- fingerprint: %s\n", finhex);
	fprintf(stderr, "|- username: %s\n", fingerprint->username);
	fprintf(stderr, "|- accountname: %s\n", fingerprint->accountname);
	fprintf(stderr, "|- protocol: %s\n", fingerprint->protocol);
	fprintf(stderr, "|- verified: %d\n", fingerprint->isTrusted);

	free(finhex);
}

void chat_fingerprint_printOp(OtrlListNode* a)
{
	ChatFingerprint *fingerprint = a->payload;
	chat_fingerprint_print(fingerprint);
}

int chat_fingerprint_compare(ChatFingerprint *a, ChatFingerprint *b)
{
    int res;
    res = strcmp(a->accountname, b->accountname);
    if(res == 0) res = strcmp(a->protocol, b->protocol);
    if(res == 0) res = strcmp(a->username, b->username);
    if(res == 0) res = memcmp(a->fingerprint, b->fingerprint, CHAT_FINGERPRINT_SIZE);
    return res;
}

int chat_fingerprint_compareOp(PayloadPtr a, PayloadPtr b)
{
	ChatFingerprint *fa = a;
	ChatFingerprint *fb = b;

	return chat_fingerprint_compare(fa, fb);
}

struct OtrlListOpsStruct chat_fingerprint_listOps = {
		chat_fingerprint_compareOp,
		chat_fingerprint_printOp,
		chat_fingerprint_destroyOp
};
