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
#include "list.h"

int chat_participant_compare(ChatParticipant *a, ChatParticipant *b)
{
	return strcmp(a->username, b->username);
}

void chat_participant_destroy(ChatParticipant *a)
{
    ChatParticipant *a1 = a;

    fprintf(stderr, "libotr-mpOTR: chat_participant_free: start\n");

    free(a1->username);

    //gcry_mpi_release(a1->signing_pub_key);
    //fprintf(stderr, "libotr-mpOTR: chat_participant_free: before chat_sign_destroy_key\n");
    chat_sign_destroy_key(a1->sign_key);

    chat_dake_destroy(a->dake);

    otrl_list_destroy(a->trusted_fingerprints);

    fprintf(stderr, "libotr-mpOTR: chat_participant_free: end\n");

    free(a1);
}

ChatParticipant * chat_participant_create(const char *username, SignKey *pub_key)
{
    ChatParticipant *participant;

    participant = malloc(sizeof(ChatParticipant));
    if(!participant)
	return NULL;

    participant->username = strdup(username);
    if(pub_key)
	    participant->sign_key = pub_key;
    else
	    participant->sign_key = NULL;

    participant->dake = NULL;

    participant->fingerprint = NULL;

    participant->trusted_fingerprints = otrl_list_create(&chat_fingerprint_listOps, sizeof(ChatFingerprint));

    participant->shutdown = NULL;
    return participant;
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
    OtrlListNode *aNode;

    aNode = otrl_list_insert(list, (PayloadPtr)participant);

    if(!aNode)
	return 1;
    else
	return 0;
}

int chat_participant_list_from_usernames(OtrlList *participants, char **usernames, unsigned int usernames_size)
{
		char error = 0;
		ChatParticipant *a_participant;
	    //OtrlChatMessage msg;

		fprintf(stderr, "libotr-mpOTR: otrl_chat_participant_list_from_users: start\n");


	    error = 0;

	    //fprintf(stderr, "libotr-mpOTR: otrl_chat_participant_list_from_users: size: %d\n", usernames_size);
	    for(size_t i = 0; i < usernames_size; i++) {
	    	//fprintf(stderr, "libotr-mpOTR: otrl_chat_participant_list_from_users: adding %s\n", usernames[i]);
	    	a_participant = chat_participant_create(usernames[i],NULL);
	    	if(!a_participant){
	    		//fprintf(stderr, "libotr-mpOTR: otrl_chat_participant_list_from_users: username was not allocated\n");
	    		error = 1;
	    		break;
	    	}
	    	if(chat_participant_add(participants,a_participant)) {
	    		//fprintf(stderr, "libotr-mpOTR: otrl_chat_participant_list_from_users: participant not added\n");
	    		error = 1;
	    		break;
	    	}
	    }
	    if(error) {
	    	otrl_list_clear(participants);
	    	return 1;
	    }

	    fprintf(stderr, "libotr-mpOTR: otrl_chat_participant_list_from_users: end\n");
	    return 0;
}

int chat_participant_get_position(const OtrlList *participants, const char *accountname, unsigned int *position)
{
	char *splitposition, *name = NULL;
	unsigned int i;
	OtrlListNode *cur;

	//fprintf(stderr, "libotr-mpOTR: chat_participant_get_position: start\n");

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

	//fprintf(stderr, "libotr-mpOTR: chat_participant_get_position: before if(!participants)\n");
	if(!participants) { goto error; }

	//fprintf(stderr, "libotr-mpOTR: chat_participant_get_position: before for\n");
	// TODO for loop should be stopped if we have gone too far in the ordered list
	for(cur = participants->head, i = 0; cur != NULL && strcmp(name, ((ChatParticipant *)cur->payload)->username) != 0;  cur = cur->next, i++);
	//fprintf(stderr, "libotr-mpOTR: chat_participant_get_position: after for\n");
	if(!cur) { goto error; }
	*position = i;

	free(name);

	//fprintf(stderr, "libotr-mpOTR: chat_participant_get_position: end\n");

	return 0;

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

void chat_participant_destroyOp(PayloadPtr a)
{
	ChatParticipant *participant = a;
    chat_participant_destroy(participant);
}

struct OtrlListOpsStruct chat_participant_listOps = {
	chat_participant_compareOp,
	chat_participant_printOp,
    chat_participant_destroyOp
};
