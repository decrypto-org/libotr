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
#include "chat_dake.h"
#include "chat_sign.h"
#include "list.h"


int chat_participant_compare(PayloadPtr a, PayloadPtr b)
{
    OtrlChatParticipant *a1 = a;
    OtrlChatParticipant *b1 = b;

    return strcmp(a1->username, b1->username);
}

void chat_participant_free(OtrlChatParticipant *a)
{
    OtrlChatParticipant *a1 = a;

    free(a1->username);

    free(a1->pending_message);

    //gcry_mpi_release(a1->signing_pub_key);
    chat_sign_destroy_key(a1->sign_key);

    free(a1);
}

void chat_participant_free_payload(PayloadPtr a)
{
    chat_participant_free(a);
}

void chat_participant_free_foreach(OtrlListNode *a)
{
    chat_participant_free(a->payload);
}

OtrlChatParticipant * chat_participant_create(const char *username, SignKey *pub_key)
{
    OtrlChatParticipant *participant;

    participant = malloc(sizeof(OtrlChatParticipant));
    if(!participant)
	return NULL;

    participant->username = strdup(username);
    if(pub_key)
	    participant->sign_key = pub_key;
    else
	    participant->sign_key = NULL;

    participant->pending_message = NULL;

    return participant;
}

OtrlChatParticipant* chat_participant_find(OtrlChatContext *ctx, const char *username, unsigned int *position)
{
    unsigned int i;
    OtrlListNode *cur;

    if(!ctx) { goto error; }
    if(!ctx->participants_list) { goto error; }

    // TODO for loop should be stopped if we have gone too far in the ordered list
    for(cur=ctx->participants_list->head,i=0; cur!=NULL && strcmp(username,((OtrlChatParticipant *)cur->payload)->username)!=0; cur=cur->next,i++);

    if(cur) {
    	*position = i;
    }

    return cur->payload;

error:
    return NULL;
}

int chat_participant_add(OtrlList *list, const OtrlChatParticipant *participant)
{
    OtrlListNode *aNode;

    aNode = otrl_list_insert(list, (PayloadPtr)participant);

    if(!aNode)
	return 1;
    else
	return 0;
}

void chat_participant_list_destroy(OtrlList *list)
{
	otrl_list_foreach(list,chat_participant_free_foreach);
}

int chat_participant_list_from_usernames(OtrlList *participants, char **usernames, unsigned int usernames_size)
{
		char error = 0;
		OtrlChatParticipant *a_participant;
	    //OtrlChatMessage msg;

		fprintf(stderr, "libotr-mpOTR: otrl_chat_participant_list_from_users: start\n");


	    error = 0;

	    fprintf(stderr, "libotr-mpOTR: otrl_chat_participant_list_from_users: size: %d\n", usernames_size);
	    for(size_t i = 0; i < usernames_size; i++) {
	    	fprintf(stderr, "libotr-mpOTR: otrl_chat_participant_list_from_users: adding %s\n", usernames[i]);
	    	a_participant = chat_participant_create(usernames[i],NULL);
	    	if(!a_participant){
	    		fprintf(stderr, "libotr-mpOTR: otrl_chat_participant_list_from_users: username was not allocated\n");
	    		error = 1;
	    		break;
	    	}
	    	if(chat_participant_add(participants,a_participant)) {
	    		fprintf(stderr, "libotr-mpOTR: otrl_chat_participant_list_from_users: participant not added\n");
	    		error = 1;
	    		break;
	    	}
	    }
	    if(error) {
	    	chat_participant_list_destroy(participants);
	    	return 1;
	    }

	    fprintf(stderr, "libotr-mpOTR: otrl_chat_participant_list_from_users: end\n");
	    return 0;
}

int chat_participant_get_position(const OtrlList *participants, const char *accountname, unsigned int *position)
{
	char *splitposition, *name;
	unsigned int i;
	OtrlListNode *cur;

	name = NULL;

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

	if(participants) {
		// TODO for loop should be stopped if we have gone too far in the ordered list
		for(cur = participants->head, i = 0; cur != NULL && strcmp(name, ((OtrlChatParticipant *)cur->payload)->username) != 0;  cur = cur->next, i++);
		if(!cur) { goto error; }
		*position = i;
	}

	free(name);

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

void chat_participant_toString(OtrlListNode *node)
{
    OtrlChatParticipant *participant = node->payload;
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

struct OtrlListOpsStruct chat_participant_listOps = {
    chat_participant_compare,
    chat_participant_toString,
    chat_participant_free_payload
};
