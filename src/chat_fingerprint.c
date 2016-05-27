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

char *chat_fingerprint_bytes_to_hex(const unsigned char *fingerprint)
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

	fprintf(stderr, "libotr-mpOTR: chat_fingerprint_hex_to_bytes: start\n");

	if(strlen(fingerprint_hex) != 2*CHAT_FINGERPRINT_SIZE) { goto error; }


	fprintf(stderr, "libotr-mpOTR: chat_fingerprint_hex_to_bytes: before malloc\n");
	bytes = malloc(CHAT_FINGERPRINT_SIZE * sizeof *bytes);
	if(!bytes) { goto error; }

	fprintf(stderr, "libotr-mpOTR: chat_fingerprint_hex_to_bytes: before for\n");
	for(i=0; i<CHAT_FINGERPRINT_SIZE; i++) {
		sscanf(&fingerprint_hex[i*2], "%02X", &tmp);
		bytes[i] = (unsigned char) tmp;
	}

	fprintf(stderr, "libotr-mpOTR: chat_fingerprint_hex_to_bytes: end\n");
	return bytes;
error:
	return NULL;
}

ChatFingerprint *chat_fingerprint_new(char *accountname, char *protocol, char *username, unsigned char *fingerprint)
{
	ChatFingerprint *fnprnt;

	fnprnt = malloc(sizeof *fnprnt);
	if(!fnprnt) { goto error; }

	fnprnt->accountname = accountname;
	fnprnt->protocol = protocol;
	fnprnt->username = username;
	fnprnt->fingerprint = fingerprint;

	return fnprnt;

error:
	return NULL;
}

ChatFingerprint *chat_fingerprint_find(OtrlUserState us, char *accountname , char *protocol, char *username)
{
	ChatFingerprint *fnprnt;
	OtrlListNode *cur;
	int found = 0;

	cur = us->chat_trusted_fingerprints->head;
	//TODO better find implementation
	while(cur != NULL && !found) {
		fnprnt = cur->payload;

		if(strcmp(accountname, fnprnt->accountname) == 0 && strcmp(protocol, fnprnt->protocol) == 0 && strcmp(username, fnprnt->username) == 0) {
			found = 1;
		}

		cur=cur->next;
	}

	if(!found) fnprnt = NULL;

	return fnprnt;
}

int otrl_chat_fingerprint_read_FILEp(OtrlUserState us, FILE *fingerfile)
{
	char buf[CHAT_FINGERPRINT_BUFSIZE];
	char *accountname, *protocol, *username, *fingerprint_hex, *pch;
	unsigned char *fingerprint;
	ChatFingerprint *fnprnt;

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
		fprintf(stderr,"libotr-mpOTR: otrl_chat_fingerprint_read_FILEp: accountname: %s\n", accountname);

		pch = strtok (NULL, ",");
		if(pch == NULL) {
			free(accountname);
			continue;
		}
		protocol = strdup(pch);
		fprintf(stderr,"libotr-mpOTR: otrl_chat_fingerprint_read_FILEp: protocol: %s\n", protocol);

		pch = strtok (NULL, ",");
		if(pch == NULL) {
			free(accountname);
			free(protocol);
			continue;
		}
		username = strdup(pch);
		fprintf(stderr,"libotr-mpOTR: otrl_chat_fingerprint_read_FILEp: username: %s\n", username);

		pch = strtok (NULL, ",");
		if(pch == NULL) {
			free(accountname);
			free(protocol);
			free(username);
			continue;
		}
		fingerprint_hex = strdup(pch);
		fprintf(stderr,"libotr-mpOTR: otrl_chat_fingerprint_read_FILEp: fingerprint_hex: %s\n", fingerprint_hex);

		fingerprint = chat_fingerprint_hex_to_bytes(fingerprint_hex);
		if(!fingerprint) {
			free(accountname);
			free(protocol);
			free(username);
			free(fingerprint_hex);
			continue;
		}
		free(fingerprint_hex);

		fprintf(stderr,"libotr-mpOTR: otrl_chat_fingerprint_read_FILEp: before chat_fingerprint_new\n");
		fnprnt = chat_fingerprint_new(accountname, protocol, username, fingerprint);
		if(!fnprnt) {
			free(accountname);
			free(protocol);
			free(username);
			free(fingerprint);
			continue;
		}

		fprintf(stderr,"libotr-mpOTR: otrl_chat_fingerprint_read_FILEp: before otrl_list_insert\n");
		otrl_list_insert(us->chat_trusted_fingerprints, fnprnt);
	}

	fprintf(stderr,"libotr-mpOTR: otrl_chat_fingerprint_read_FILEp: dumping fingerprint list:\n");
	otrl_list_dump(us->chat_trusted_fingerprints);


	fprintf(stderr,"libotr-mpOTR: otrl_chat_fingerprint_read_FILEp: end\n");

	return 0;
}

int chat_fingerprint_write_FILEp(OtrlUserState us, FILE *fingerfile)
{
	OtrlListNode *cur;
	ChatFingerprint *fnprnt;
	char *hex_fingerprint;

	for(cur=us->chat_trusted_fingerprints->head; cur!=NULL; cur++)
	{
		fnprnt = cur->payload;
		hex_fingerprint = chat_fingerprint_bytes_to_hex(fnprnt->fingerprint);
		// TODO better handle this case
		if(!hex_fingerprint) { goto error; }
		fnprnt = cur->payload;
		fprintf(fingerfile, "%s,%s,%s,%s\n", fnprnt->accountname, fnprnt->protocol, fnprnt->username, hex_fingerprint);
	}

	return 0;

error:
	return 1;
}

void chat_fingerprint_destroy(ChatFingerprint *fingerprint){
    free(fingerprint->fingerprint);
    free(fingerprint->username);
    free(fingerprint->accountname);
    free(fingerprint->protocol);
}

void chat_fingerprint_destroyOp(PayloadPtr a) {
	ChatFingerprint *fingerprint = a;
	chat_fingerprint_destroy(fingerprint);
}

void chat_fingerprint_print(ChatFingerprint *fingerprint) {
	char *finhex = chat_fingerprint_bytes_to_hex(fingerprint->fingerprint);
	fprintf(stderr, "fingerprint:\n");
	fprintf(stderr, "|- fingerprint: %s\n", finhex);
	fprintf(stderr, "|- username: %s\n", fingerprint->username);
	fprintf(stderr, "|- accountname: %s\n", fingerprint->accountname);
	fprintf(stderr, "|- protocol: %s\n", fingerprint->protocol);

	free(finhex);
}

void chat_fingerprint_printOp(OtrlListNode* a) {
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
