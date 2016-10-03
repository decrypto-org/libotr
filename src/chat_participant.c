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

#include "chat_participant.h"

#include <gcrypt.h>
#include <stdio.h>

#include "chat_types.h"
#include "chat_message.h"
#include "chat_dake.h"
#include "chat_sign.h"
#include "chat_fingerprint.h"
#include "list.h"

struct ChatParticipantStruct {
	char *username; 			// This users username
	SignKey *sign_key; 			//This users signing key
	OtrlChatFingerprint fingerprint;
	OtrlList fingerprints;
	DAKE *dake;
	//TODO move these in Shutdown struct and release them
	ChatParticipantShutdown *shutdown;
	OtrlList messages;
	unsigned char messages_hash[CHAT_PARTICIPANTS_HASH_LENGTH];
	int consensus; //TODO check if there is consensus or not
};

size_t chat_participant_size()
{
	return sizeof(struct ChatParticipantStruct);
}

ChatParticipant chat_participant_new(const char *username, SignKey *pub_key)
{
    ChatParticipant participant;

    participant = malloc(sizeof *participant);
    if(!participant) { goto error; }

    participant->username = strdup(username);
    if(!participant->username) { goto error_with_participant; }

    participant->sign_key = (pub_key) ? pub_key : NULL;

    participant->dake = NULL;

    participant->fingerprint = NULL;

    participant->fingerprints = otrl_list_new(&chat_fingerprint_listOps, chat_fingerprint_size());
    if(!participant->fingerprints) { goto error_with_username; }

    participant->shutdown = NULL;

    participant->messages = otrl_list_new(&chat_message_listOps, sizeof(char*));
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

char * chat_participant_get_username(ChatParticipant participant)
{
	return participant->username;
}

SignKey * chat_participant_get_sign_key(ChatParticipant participant)
{
	return participant->sign_key;
}

void chat_participant_set_sign_key(ChatParticipant participant, SignKey *sign_key)
{
	participant->sign_key = sign_key;
}

OtrlChatFingerprint chat_participant_get_fingerprint(ChatParticipant participant)
{
	return participant->fingerprint;
}

void chat_participant_set_fingerprint(ChatParticipant participant, OtrlChatFingerprint fingerprint)
{
	participant->fingerprint = fingerprint;
}

OtrlList chat_participant_get_fingerprints(ChatParticipant participant)
{
	return participant->fingerprints;
}

DAKE * chat_participant_get_dake(ChatParticipant participant)
{
	return participant->dake;
}

void chat_participant_set_dake(ChatParticipant participant, DAKE *dake)
{
	participant->dake = dake;
}

OtrlList chat_participant_get_messages(ChatParticipant participant)
{
	return participant->messages;
}

unsigned char * chat_participant_get_messages_hash(ChatParticipant participant)
{
	return participant->messages_hash;
}

int chat_participant_get_consensus(ChatParticipant participant)
{
	return participant->consensus;
}

void chat_participant_set_consensus(ChatParticipant participant, int consesnus)
{
	participant->consensus = consesnus;
}

void chat_participant_free(ChatParticipant participant)
{
    if(participant)  {
    	free(participant->username);
    	chat_sign_destroy_key(participant->sign_key);
    	chat_dake_destroy(participant->dake);
    	otrl_list_free(participant->fingerprints);
    	otrl_list_free(participant->messages);
    }

    free(participant);
}

int chat_participant_compare(ChatParticipant a, ChatParticipant b)
{
	return strcmp(chat_participant_get_username(a), chat_participant_get_username(b));
}

// TODO Dimitris: support NULL for position pointer if the caller doesn't need the position
ChatParticipant chat_participant_find(OtrlList participants_list, const char *username, unsigned int *position)
{
    unsigned int i;
    OtrlListIterator iter;
    OtrlListNode cur;
    ChatParticipant part;
    ChatParticipant res;

    if(!participants_list) { goto error; }

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
    i = 0;
    res = NULL;
    iter = otrl_list_iterator_new(participants_list);
    if(!iter) { goto error_with_name; }
    while(!res && otrl_list_iterator_has_next(iter)) {
    	cur = otrl_list_iterator_next(iter);
    	part = otrl_list_node_get_payload(cur);
    	if(0 == strcmp(name, part->username)) {
    		res = part;
    	} else {
    		i++;
    	}
    }

    otrl_list_iterator_free(iter);
    free(name);

    if(res) {
    	*position = i;
    }

    return res;

error_with_name:
	free(name);
error:
    return NULL;
}

int chat_participant_add(OtrlList participants_list, const ChatParticipant participant)
{
    OtrlListNode node;

    node = otrl_list_insert(participants_list, participant);
    if(!node) { goto error; }

	return 0;

error:
	return 1;
}

int chat_participant_list_from_usernames(OtrlList participants_list, char **usernames, unsigned int usernames_size)
{
	ChatParticipant participant;
	int err;

	otrl_list_clear(participants_list);

	for(size_t i = 0; i < usernames_size; i++) {
		participant = chat_participant_new(usernames[i],NULL);
		if(!participant){ goto error_with_participants; }

		err = chat_participant_add(participants_list, participant);
		if(err) { goto error_with_participants; }
	}

	return 0;

error_with_participants:
	fprintf(stderr, "libotr-mpOTR: chat_participant_list_from_usernames: error_with_participants\n");
	otrl_list_clear(participants_list);
	return 1;
}

int chat_participant_get_position(OtrlList participants_list, const char *accountname, unsigned int *position)
{
	char *splitposition, *name = NULL;
	unsigned int i, flag;
	OtrlListIterator iter;
	OtrlListNode cur;
	ChatParticipant part;

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

	if(!participants_list) { goto error_with_name; }

	// TODO for loop should be stopped if we have gone too far in the ordered list
	i = 0; flag =0;
	iter = otrl_list_iterator_new(participants_list);
	if(!iter) { goto error_with_name; }
	while(!flag && otrl_list_iterator_has_next(iter)) {
		cur = otrl_list_iterator_next(iter);
		part = otrl_list_node_get_payload(cur);
		if(0 == strcmp(name, part->username)) {
			flag = 1;
		} else {
			i++;
		}
	}

	if(!flag) { goto error_with_iter; }

	otrl_list_iterator_free(iter);
	free(name);

	*position = i;
	return 0;

error_with_iter:
	otrl_list_iterator_free(iter);
error_with_name:
	free(name);
error:
	return 1;
}

int chat_participant_get_me_next_position(const char *accountname, OtrlList participants_list, unsigned int *me_next)
{
	int err;
	unsigned int me;

	err = chat_participant_get_position(participants_list, accountname, &me);
	if(err) { goto error; }

	me_next[0] = me;
	me_next[1] = (me < otrl_list_size(participants_list)-1) ? me+1 : 0;

	return 0;

error:
	return 1;
}

/* TODO improve docstring
   This function hashes all the messages from a participant. The messages are
   stored in lexicographic ordering. */
int chat_participant_calculate_messages_hash(ChatParticipant participant, unsigned char* result)
{
    gcry_md_hd_t md;
    gcry_error_t err;
    OtrlListIterator iter;
    OtrlListNode cur;
    char *msg;
    size_t len;
    unsigned char *hash_result = NULL;

    err = gcry_md_open(&md, GCRY_MD_SHA512, 0);
    if(err) { goto error; }

    iter = otrl_list_iterator_new(chat_participant_get_messages(participant));
    if(!iter) { goto error_with_md; }

    while(otrl_list_iterator_has_next(iter)) {
    	cur = otrl_list_iterator_next(iter);
        msg = otrl_list_node_get_payload(cur);
        len = strlen(msg);
        gcry_md_write(md, msg, len);
    }

    gcry_md_final(md);
    hash_result = gcry_md_read(md, GCRY_MD_SHA512);
    if(!hash_result) { goto error_with_iter; }

    memcpy(result, hash_result, gcry_md_get_algo_dlen(GCRY_MD_SHA512));

    otrl_list_iterator_free(iter);
    gcry_md_close(md);

    return 0;

error_with_iter:
	otrl_list_iterator_free(iter);
error_with_md:
	gcry_md_close(md);
error:
	return 1;
}

void chat_participant_print(ChatParticipant participant)
{
    //unsigned char *buf;
    //size_t s;

    //gcry_mpi_print(GCRYMPI_FMT_HEX, NULL, 0, &s, participant->signing_pub_key);
    //buf = malloc((s+1)*sizeof(*buf));
    //gcry_mpi_print(GCRYMPI_FMT_HEX, buf, s, NULL, participant->signing_pub_key);
    fprintf(stderr, "OtrlChatParticipant:\n");
    fprintf(stderr, "|-username\t:%s\n", chat_participant_get_username(participant));
    //fprintf(stderr, "|-pub_key\t:%s\n", buf);

    //free(buf);
}

int chat_participant_compareOp(OtrlListPayload a, OtrlListPayload b)
{
    ChatParticipant part1 = a;
    ChatParticipant part2 = b;

    return chat_participant_compare(part1, part2);
}

void chat_participant_printOp(OtrlListNode node)
{
	ChatParticipant participant;

	participant = otrl_list_node_get_payload(node);
	chat_participant_print(participant);
}

void chat_participant_freeOp(OtrlListPayload a)
{
	ChatParticipant participant = a;
    chat_participant_free(participant);
}

struct OtrlListOpsStruct chat_participant_listOps = {
	chat_participant_compareOp,
	chat_participant_printOp,
    chat_participant_freeOp
};
