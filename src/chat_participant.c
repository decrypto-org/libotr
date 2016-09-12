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

#include <gcrypt.h>
#include <stdio.h>

#include "chat_types.h"
#include "chat_message.h"
#include "chat_dake.h"
#include "chat_sign.h"
#include "chat_fingerprint.h"
#include "list.h"

int chat_participant_compare(ChatParticipant *a, ChatParticipant *b)
{
	return strcmp(a->username, b->username);
}

void chat_participant_free(ChatParticipant *participant)
{
    fprintf(stderr, "libotr-mpOTR: chat_participant_free: start\n");

    if(participant)  {
    	free(participant->username);
    	chat_sign_destroy_key(participant->sign_key);
    	chat_dake_destroy(participant->dake);
    	otrl_list_free(participant->fingerprints);
    	otrl_list_free(participant->messages);
    }

    free(participant);

    fprintf(stderr, "libotr-mpOTR: chat_participant_free: end\n");
}

ChatParticipant * chat_participant_create(const char *username, SignKey *pub_key)
{
    ChatParticipant *participant = NULL;

    participant = malloc(sizeof *participant);
    if(!participant) { goto error; }

    participant->username = strdup(username);
    if(!participant->username) { goto error_with_participant; }

    participant->sign_key = (pub_key) ? pub_key : NULL;

    participant->dake = NULL;

    participant->fingerprint = NULL;

    participant->fingerprints = otrl_list_create(&chat_fingerprint_listOps, sizeof(OtrlChatFingerprint));
    if(!participant->fingerprints) { goto error_with_username; }

    participant->shutdown = NULL;

    participant->messages = otrl_list_create(&chat_message_listOps, sizeof(char*));
    if(!participant->messages) { goto error_with_fingerprints; }

    return participant;

error_with_fingerprints:
	otrl_list_free(participant->fingerprints);
error_with_username:
	free(participant->username);
error_with_participant:
	free(participant);
error:
	return NULL;
}

ChatParticipant* chat_participant_find(OtrlChatContext *ctx, const char *username, unsigned int *position)
{
    unsigned int i;
    OtrlListNode *cur;
    ChatParticipant *res = NULL;

    fprintf(stderr,"chat_participant_find: start\n");

    if(!ctx) { goto error; }
    if(!ctx->participants_list) { goto error; }

	//TODO Dimitris: this is a workaround, should be removed as soon as we find how to get the participant's account identifier instead of chat name
	char *splitposition = strchr(username, '@');
	char *name;
	if(splitposition) {
		name = malloc( (splitposition - username + 1) * sizeof *name);
		if(!name) { goto error;	}
		memcpy(name, username, splitposition - username);
		name[splitposition - username] = '\0';
	} else {
		name = malloc( (strlen(username) + 1) * sizeof *name);
		if(!name) { goto error; }
		strcpy(name, username);
	}
    // TODO for loop should be stopped if we have gone too far in the ordered list
    for(cur=ctx->participants_list->head,i=0; cur!=NULL && strcmp(name,((ChatParticipant *)cur->payload)->username)!=0; cur=cur->next,i++);

    free(name);

    if(cur) {
    	*position = i;
    	res = cur->payload;
    }

    fprintf(stderr,"chat_participant_find: end\n");

    return res;

error:
    return NULL;
}

int chat_participant_add(OtrlList *list, const ChatParticipant *participant)
{
    OtrlListNode *node;

    node = otrl_list_insert(list, (PayloadPtr)participant);
    if(!node) { goto error; }

	return 0;

error:
	return 1;
}

int chat_participant_list_from_usernames(OtrlList *participants, char **usernames, unsigned int usernames_size)
{
	ChatParticipant *a_participant;
	int err;

	fprintf(stderr, "libotr-mpOTR: chat_participant_list_from_usernames: start\n");

	for(size_t i = 0; i < usernames_size; i++) {
		a_participant = chat_participant_create(usernames[i],NULL);
		if(!a_participant){ goto error_with_participants; }

		err = chat_participant_add(participants,a_participant);
		if(err) { goto error_with_participants; }
	}

	fprintf(stderr, "libotr-mpOTR: chat_participant_list_from_usernames: end\n");
	return 0;

error_with_participants:
	fprintf(stderr, "libotr-mpOTR: chat_participant_list_from_usernames: error_with_participants\n");
	otrl_list_clear(participants);
	return 1;
}

int chat_participant_get_position(const OtrlList *participants, const char *accountname, unsigned int *position)
{
	char *splitposition, *name = NULL;
	unsigned int i;
	OtrlListNode *cur;

	//TODO Dimitris: this is a workaround, should be removed as soon as we find how to get the participant's account identifier instead of chat name
	splitposition = strchr(accountname, '@');
	if(splitposition) {
		name = malloc( (splitposition - accountname + 1) * sizeof *name);
		if(!name) { goto error;	}
		memcpy(name, accountname, splitposition - accountname);
		name[splitposition - accountname] = '\0';
	} else {
		name = malloc( (strlen(accountname) + 1) * sizeof *name);
		if(!name) { goto error; }
		strcpy(name, accountname);
	}

	if(!participants) { goto error_with_name; }

	// TODO for loop should be stopped if we have gone too far in the ordered list
	for(cur = participants->head, i = 0; cur != NULL && strcmp(name, ((ChatParticipant *)cur->payload)->username) != 0;  cur = cur->next, i++);
	if(!cur) { goto error_with_name; }
	*position = i;

	free(name);

	return 0;

error_with_name:
	free(name);
error:
	return 1;
}

int chat_participant_get_me_next_position(const char *accountname, const OtrlList *participants, unsigned int *me_next)
{
	int err;
	unsigned int me;

	fprintf(stderr, "libotr-mpOTR: chat_participant_get_me_next_position: start\n");

	err = chat_participant_get_position(participants, accountname, &me);
	if(err) { goto error; }

	me_next[0] = me;
	me_next[1] = (me < participants->size-1) ? me+1 : 0;

	fprintf(stderr, "libotr-mpOTR: chat_participant_get_me_next_position: end\n");

	return 0;

error:
	return 1;
}

/* TODO improve docstring
   This function hashes all the messages from a participant. The messages are
   stored in lexicographic ordering. */
int chat_participant_get_messages_hash(ChatParticipant *participant, unsigned char* result)
{
    gcry_md_hd_t md;
    gcry_error_t err;
    OtrlListNode *cur;
    char *msg;
    size_t len;
    unsigned char *hash_result = NULL;

    fprintf(stderr,"libotr-mpOTR: chat_participant_get_messages_hash: start\n");

    err = gcry_md_open(&md, GCRY_MD_SHA512, 0);
    if(err) { goto error; }

    for(cur = participant->messages->head; cur != NULL; cur = cur->next)
    {
        msg = cur->payload;
        len = strlen(msg);
        gcry_md_write(md, msg, len);
    }

    gcry_md_final(md);
    hash_result = gcry_md_read(md, GCRY_MD_SHA512);
    if(!hash_result) { goto error_with_md; }

    memcpy(result, hash_result, gcry_md_get_algo_dlen(GCRY_MD_SHA512));

    gcry_md_close(md);

    fprintf(stderr,"libotr-mpOTR: chat_participant_get_messages_hash: end\n");

    return 0;

error_with_md:
	gcry_md_close(md);
error:
	return 1;
}

void chat_participant_print(ChatParticipant *participant)
{
    //unsigned char *buf;
    //size_t s;

    //gcry_mpi_print(GCRYMPI_FMT_HEX, NULL, 0, &s, participant->signing_pub_key);
    //buf = malloc((s+1)*sizeof(*buf));
    //gcry_mpi_print(GCRYMPI_FMT_HEX, buf, s, NULL, participant->signing_pub_key);
    fprintf(stderr, "OtrlChatParticipant:\n");
    fprintf(stderr, "|-username\t:%s\n",participant->username);
    //fprintf(stderr, "|-pub_key\t:%s\n", buf);

    //free(buf);
}

int chat_participant_compareOp(PayloadPtr a, PayloadPtr b)
{
    ChatParticipant *a1 = a;
    ChatParticipant *b1 = b;

    return chat_participant_compare(a1, b1);
}

void chat_participant_printOp(OtrlListNode *node)
{
	ChatParticipant *participant = node->payload;
	chat_participant_print(participant);
}

void chat_participant_freeOp(PayloadPtr a)
{
	ChatParticipant *participant = a;
    chat_participant_free(participant);
}

struct OtrlListOpsStruct chat_participant_listOps = {
	chat_participant_compareOp,
	chat_participant_printOp,
    chat_participant_freeOp
};
