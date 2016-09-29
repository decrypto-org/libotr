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

#include "chat_gka.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "chat_context.h"
#include "chat_enc.h"
#include "chat_message.h"
#include "chat_participant.h"
#include "chat_types.h"
#include "dh.h"
#include "list.h"

struct ChatGKAInfo {
        ChatGKAState state;  /* the gka state */
        unsigned int position;      /* Our position in the participants order starting from the gka initiator */
        DH_keypair *keypair;		/* The keypair used for the gka */
        unsigned char participants_hash[CHAT_PARTICIPANTS_HASH_LENGTH];
};

ChatGKAInfoPtr chat_gka_info_new()
{
    ChatGKAInfoPtr gka_info;

    gka_info = malloc(sizeof *gka_info);
    if(!gka_info) {
        return NULL;
    }

    gka_info->keypair = NULL;
    gka_info->state = CHAT_GKASTATE_NONE;

    return gka_info;
}

unsigned int chat_gka_info_get_position(ChatGKAInfoPtr gka_info)
{
	return gka_info->position;
}

ChatGKAState chat_gka_info_get_state(ChatGKAInfoPtr gka_info)
{
	return gka_info->state;
}

/**
  Destroy the data stored in a OtrlAuthGKAInfo

  This function releases, deallocates, and free's any memory allocated
  dynamically inside a OtrlAuthGKAInfo. The struct itself is not free'd

  @param gka_info the OtrlAuthGKAInfo to be destroyed
 */
void chat_gka_info_free(ChatGKAInfoPtr gka_info)
{
    if(!gka_info){
        return;
    }

	if(gka_info->keypair)
		otrl_dh_keypair_free(gka_info->keypair);

	free(gka_info->keypair);
    free(gka_info);
}

/**
  Compares two MPIs stored in a otr list

  @param a the first MPI to compare
  @param b the second MPI to compare
  @return 0 if a = b, a positive value if a > b and a negative value if a < b
 */
int chat_gka_keys_compareOp(OtrlListPayloadPtr a, OtrlListPayloadPtr b)
{
	return gcry_mpi_cmp(a, b);
}

/**
  Releases and free's an MPI stored in an otr list

  @param a the MPI to be free'd and released
 */
void chat_gka_key_freeOp(OtrlListPayloadPtr a)
{
	gcry_mpi_t *w = a;

	gcry_mpi_release(*w);

	free(a);
}

/**
  Prints an MPI stored in an otr list

  @param node the list node containing the MPI to be printed
 */
void chat_gka_key_printOp(OtrlListNodePtr node)
{
	gcry_mpi_t *w = otrl_list_node_get_payload(node);
	unsigned char *buf;
    size_t s;

    gcry_mpi_print(GCRYMPI_FMT_HEX,NULL,0,&s,*w);
    buf = malloc((s+1) * sizeof *buf);
    gcry_mpi_print(GCRYMPI_FMT_HEX,buf,s,NULL,*w);
    buf[s]='\0';

    fprintf(stderr, "Intermediate key:\n");
    fprintf(stderr, "|- value\t: %s\n", buf);
    free(buf);
}


/**
  Prints an MPI

  @param w the MPI to be printed
 */
void chat_gka_mpi_print(gcry_mpi_t w)
{
	unsigned char *buf;
    size_t s;

    gcry_mpi_print(GCRYMPI_FMT_HEX,NULL,0,&s,w);
    buf = malloc((s+1) * sizeof *buf);
    gcry_mpi_print(GCRYMPI_FMT_HEX,buf,s,NULL,w);
    buf[s]='\0';

    fprintf(stderr, "%s\n", buf);
    free(buf);
}

struct OtrlListOpsStruct interKeyOps = {
		chat_gka_keys_compareOp,
		chat_gka_key_printOp,
		chat_gka_key_freeOp
};

/**
  This function returns a list containing only the generator of the DH group

  This function allocates memory to hold a copy of the groups generator. It also
  allocates and initializes a OtrlList in which the newly allocated generator
  copy is appened. If the function returns with no error the OtrlList returned
  needs to be destroyed >by the caller<.

  @return an OtrlList containing only the generator.
   The caller must deallocate this
 */
//TODO maybe refactor to get an allready initialized list as argument
//instead of allocating in the function and returning it.
OtrlListPtr chat_gka_initial_intermediate_key_list()
{
	OtrlListPtr key_list;
	gcry_mpi_t *generator;
	OtrlListNodePtr node;

	generator = malloc(sizeof *generator);
	if(!generator) {
		return NULL;
	}

	/* Get the generator of the group */
	*generator = gcry_mpi_copy(otrl_dh_get_generator());

	/* Initialize a new list and check if it was actually initialized */
	key_list = otrl_list_new(&interKeyOps, sizeof(gcry_mpi_t));
	if(!key_list) { goto error; }

	/* Append the generator in the list and check if it was inserted correctly */
	node = otrl_list_append(key_list, generator);
	if(!node) { goto error_with_list; }

	return key_list;

error_with_list:
	otrl_list_free(key_list);
error:
	gcry_mpi_release(*generator);
	free(generator);
	return NULL;

}

//TODO fix phrasing in this docstring
/**
  This function creates a new list from an old one, with each element of the
  old raised to the private key.

  @param new_key_list a pointer to an OtrlList which will hold the new values
  @param old_key_list a pointer to an OtrlList which contains the keys which
   holds the old values
  @key a pointer to our DH keypair used in this GKA run
 */
int chat_gka_append_with_key(OtrlListPtr new_key_list, OtrlListPtr old_key_list, DH_keypair *key)
{
	OtrlListIteratorPtr iter;
	OtrlListNodePtr cur, node;
	gcry_mpi_t *w, *tmp;
	int err;

	/* For every key in the key_list raise it to the key->priv
	 * and append it to the new_list */
	iter = otrl_list_iterator_new(old_key_list);
	if(!iter) { goto error; }
	while(otrl_list_iterator_has_next(iter)) {
		cur = otrl_list_iterator_next(iter);
		tmp = otrl_list_node_get_payload(cur);

		err = otrl_dh_is_inrange(*tmp);
		if(err) { goto error_with_iter; }

		/* Allocate a new gcry_mpi_t to be held in the list */
		w = malloc(sizeof *w);
		if(!w) { goto error_with_iter; }
		*w = gcry_mpi_new(256);

		/* raise it to the key->priv (mod the modulo) */
		otrl_dh_powm(*w, *tmp , key->priv);

		/* Append it to the new_list and check if it was added correctly */
		node = otrl_list_append(new_key_list,w);
		if(!node){ goto error_with_w; };
	}

	otrl_list_iterator_free(iter);

	return 0;

error_with_w:
	gcry_mpi_release(*w);
	free(w);
error_with_iter:
	otrl_list_iterator_free(iter);
error:
	return 1;
}

/**
  This function returns the key list to be sent to the next hop

  This function will allocate and initialize a new OtrlList which holds the
  intermediate keys to be sent. The new list must be destroyed >by the caller<

  @param key_list a pointer to an OtrlList containing the keys received from
   the previous hop in this GKA run
  @param key a pointer to our diffie hellman keypair for this GKA run
  @return a list containing the keys to be sent to the next hop. This list
   must be deallocated by the caller
 */
OtrlListPtr chat_gka_intermediate_key_list_to_send(OtrlListPtr key_list, DH_keypair *key)
{
	OtrlListPtr new_list;
	OtrlListNodePtr node;
	gcry_mpi_t *w, *last, *first;
	int err;

    /* If the intermediate key_list we received is from the first upflow message
     * we should check that the sender is using the correct generator */
	node = otrl_list_get_head(key_list);
	if(!node) { goto error; }

    first = otrl_list_node_get_payload(node);
    if(!first) { goto error; }

    if(2 == otrl_list_size(key_list) && gcry_mpi_cmp(otrl_dh_get_generator(),*first)){
    	goto error;
     }

    /* Append the last key in the key_list to the new list, as
	 * specified by the algorithm */
    node = otrl_list_get_tail(key_list);
    if(!node) { goto error; }

	last = otrl_list_node_get_payload(node);
	if(!last) { goto error; }

	/* Initialize the list to be returned */
	new_list = otrl_list_new(&interKeyOps, sizeof(gcry_mpi_t));
	if(!new_list) { goto error; }

	w = malloc(sizeof *w);
	if(!w) { goto error_with_new_list; }

	*w = gcry_mpi_copy(*last);

	node = otrl_list_append(new_list, w);
	if(!node) { goto error_with_w; }

	/* If there was an error destroy the new_list and return NULL */
	err = chat_gka_append_with_key(new_list, key_list, key);
	if(err) { goto error_with_new_list; }

	otrl_list_dump(new_list);

	return new_list;

error_with_w:
	gcry_mpi_release(*w);
	free(w);
error_with_new_list:
	otrl_list_free(new_list);
error:
	return NULL;
}

/**
  This function returns the final key list to be sent to every participant
  except the last.

  This function will allocate and initialize a new OtrlList which holds the
  intermediate keys for the final downflow message. The new list must be
  destroyed >by the caller<

  @param key_list a pointer to an OtrlList containing the keys received from
   the previous hop in this GKA run
  @param key a pointer to our diffie hellman keypair for this GKA run
  @return a list containing the keys to be sent to everyone else. This list
   must be deallocated by the caller
 */
OtrlListPtr chat_gka_final_key_list_to_send(OtrlListPtr key_list, DH_keypair *key)
{
	OtrlListPtr new_list;
	int err;

    /* Create a new list */
	new_list = otrl_list_new(&interKeyOps, sizeof(gcry_mpi_t));
	if(!new_list) { goto error; }

    /* And add each intermediate key, raising it to our private key */
	err = chat_gka_append_with_key(new_list, key_list, key);
	if(err) { goto error_with_new_list; }

	return new_list;

error_with_new_list:
	otrl_list_free(new_list);
error:
	return NULL;
}

/**
  This function concatenates and hashes the usernames of each participant.

  This function will iterate over an OtrlList containing the participats
  and hash their usernames. Then it will store the produced hash in an
  >alread< allocated buffer passed as an argument.

  @param participants an OtrlList containing each participant
  @param hash a buffer to hold the produced hash. It must be already
   allocated by the caller
 */
gcry_error_t chat_gka_get_participants_hash(OtrlListPtr participants, unsigned char* hash)
{
	gcry_md_hd_t md;
	gcry_error_t err;
	OtrlListIteratorPtr iter;
	OtrlListNodePtr cur;
	ChatParticipantPtr participant;
	size_t len;
	unsigned char *hash_result;

    /* Open a new md */
	err = gcry_md_open(&md, GCRY_MD_SHA512, 0);
	if(err) { goto error; }

	/* Iterate over the list and write each username in the message digest */
	iter = otrl_list_iterator_new(participants);
	if(!iter) { goto error; }
	while(otrl_list_iterator_has_next(iter)) {
		cur = otrl_list_iterator_next(iter);
		participant = otrl_list_node_get_payload(cur);
		len = strlen(chat_participant_get_username(participant));
		gcry_md_write(md, chat_participant_get_username(participant), len);
	}

	gcry_md_final(md);
	hash_result = gcry_md_read(md, GCRY_MD_SHA512);

	memcpy(hash, hash_result, CHAT_PARTICIPANTS_HASH_LENGTH);

	gcry_md_close(md);
	otrl_list_iterator_free(iter);

	return gcry_error(GPG_ERR_NO_ERROR);

error:
	return 1;
}

int chat_gka_info_init(ChatGKAInfoPtr gka_info)
{
	gcry_error_t err;

    /* Allocate the DH keypair */
    if(gka_info->keypair)
    	free(gka_info->keypair);

    gka_info->keypair = malloc(sizeof *(gka_info->keypair));
    if(!gka_info->keypair) { goto error; }

    /* Initialize it */
    otrl_dh_keypair_init(gka_info->keypair);

    /* Generate a key */
    //TODO Dimitris: Error handling should fallback to previous state
    err = otrl_dh_gen_keypair(DH1536_GROUP_ID, gka_info->keypair);
    if(err) { goto error; }

	return 0;

error:
	return 1;
}

int chat_gka_init(ChatContextPtr ctx, ChatMessage **msgToSend)
{
	ChatGKAInfoPtr gka_info;
	ChatMessage *newmsg = NULL;
    unsigned int me_next[2];
    gcry_error_t g_err;
    int err;
    OtrlListPtr inter_key_list;
    OtrlListPtr initial_key_list;

    fprintf(stderr, "libotr-mpOTR: chat_gka_init: start\n");

    gka_info = chat_gka_info_new();
    if(!gka_info) { goto error; }

    /* Initialize the gka info */
    g_err = chat_gka_info_init(gka_info);
    if(g_err) { goto error_with_gka_info; }

    /* Get our position in the upflow stream */
    err = chat_participant_get_me_next_position(chat_context_get_accountname(ctx), chat_context_get_participants_list(ctx), me_next);
    if(err) { goto error_with_gka_info; }

    if(0 != me_next[0]){
        gka_info->state = CHAT_GKASTATE_AWAITING_UPFLOW;
        newmsg = NULL;

    } else {
		/* Get a intermediate key list with only the generator inside */
		initial_key_list = chat_gka_initial_intermediate_key_list();
		if(!initial_key_list) { goto error_with_gka_info; }

		/* Create the intermediate key list to send */
		inter_key_list = chat_gka_intermediate_key_list_to_send(initial_key_list, gka_info->keypair);
		if(!inter_key_list) { goto error_with_initial_key_list; }

		/* Generate the message that will be sent */
		newmsg = chat_message_gka_upflow_new(ctx, inter_key_list, me_next[1]);
		if(!newmsg) { goto error_with_inter_list; }

		/* Set the gka_info state to await downflow message */
		gka_info->state = CHAT_GKASTATE_AWAITING_DOWNFLOW;
		gka_info->position = 0;

		otrl_list_free(initial_key_list);
    }

    chat_context_set_gka_info(ctx, gka_info);

    *msgToSend = newmsg;
    fprintf(stderr, "libotr-mpOTR: chat_gka_init: end\n");

    return 0;

error_with_inter_list:
    otrl_list_free(inter_key_list);
error_with_initial_key_list:
	otrl_list_free(initial_key_list);
error_with_gka_info:
	chat_gka_info_free(gka_info);
error:
    return 1;
}


int chat_gka_handle_upflow_message(ChatContextPtr ctx, ChatMessage *msg, ChatMessage **msgToSend, int *free_msg)
{
	ChatGKAInfoPtr gka_info;
	ChatEncInfo *enc_info;
	ChatMessage *newmsg = NULL;
	OtrlListPtr inter_key_list;
	OtrlListNodePtr last;
	gcry_mpi_t *last_key;
	ChatMessagePayloadGKAUpflow *upflowMsg;
	unsigned int me_next[2];
	unsigned int inter_key_list_length, participants_list_length;
	gcry_error_t err;

	fprintf(stderr, "libotr-mpOTR: handle_upflow_message: start\n");

	upflowMsg = msg->payload;

	gka_info = chat_context_get_gka_info(ctx);
	if(!gka_info) { goto error; }

	if(CHAT_GKASTATE_AWAITING_DOWNFLOW == chat_gka_info_get_state(gka_info)) { goto error; }
    if(CHAT_GKASTATE_NONE == chat_gka_info_get_state(gka_info)) { goto error ; }

    /* Do any initializations needed */
    err = chat_gka_info_init(gka_info);
    if(err) { goto error; }

	/* Get our position in the participants list */
    err = chat_participant_get_me_next_position(chat_context_get_accountname(ctx), chat_context_get_participants_list(ctx), me_next);
    if(err){ goto error_with_gka_init; }

    /* Check if the message is intended for the same users */
    if(upflowMsg->recipient != me_next[0]) { goto error_with_gka_init; }

    /* Get the length of the intermediate keys */
    inter_key_list_length = otrl_list_size(upflowMsg->interKeys);

    //TODO Infering our position in the upflow stream may be dangerous
	//because an attacker (maybe a dishonest participant?) can manipulate
	//this to something he wants. I cant think of a possible attack now
	//but you never know. Check it!
    gka_info->position = inter_key_list_length - 1;//me_next[0];

    participants_list_length = otrl_list_size(chat_context_get_participants_list(ctx));

    if(inter_key_list_length < participants_list_length ) {
    	fprintf(stderr, "libotr-mpOTR: handle_upflow_message: in upflow generation\n");

    	/* Generate the intermediate key list that we will send */
    	inter_key_list = chat_gka_intermediate_key_list_to_send(upflowMsg->interKeys, gka_info->keypair);
    	if(!inter_key_list) { goto error_with_gka_init; }

    	newmsg = chat_message_gka_upflow_new(ctx, inter_key_list, me_next[1]);
    	if(!newmsg) { goto error_with_inter_key_list; }

    	/* Set the gka_info state to await downflow message */
    	gka_info->state = CHAT_GKASTATE_AWAITING_DOWNFLOW;
    }
    else {
    	/* Get last intermediate key */
    	last = otrl_list_get_tail(upflowMsg->interKeys);
    	last_key = otrl_list_node_get_payload(last);

    	/* Initialize enc_info struct */
    	enc_info = chat_enc_info_new();
        if(!enc_info) { goto error_with_gka_init; }

    	/* Generate the master secret */
    	err = chat_enc_create_secret(enc_info, *last_key, gka_info->keypair);
    	if(err) { goto error_with_gka_init; }

    	chat_context_set_enc_info(ctx, enc_info);

    	/* Drop the last element */
    	otrl_list_remove_and_free(upflowMsg->interKeys, last);

    	/* Get the final intermediate key list to send in the downflow message */
    	inter_key_list = chat_gka_final_key_list_to_send(upflowMsg->interKeys, gka_info->keypair);
    	if(!inter_key_list) { goto error_with_gka_init; }

    	fprintf(stderr, "libotr-mpOTR: handle_upflow_message: dumping inter_key_list:\n");
    	otrl_list_dump(inter_key_list);

    	/* Generate the downflow message */
    	newmsg = chat_message_gka_downflow_new(ctx, inter_key_list);
    	if(!newmsg) { goto error_with_inter_key_list; }

    	/* Set the gka_info state to finished */
    	gka_info->state = CHAT_GKASTATE_FINISHED;
    	chat_context_set_id(ctx, gka_info->position);
    }

	fprintf(stderr, "libotr-mpOTR: handle_upflow_messaget: end\n");

	*msgToSend = newmsg;
	return 0;

error_with_inter_key_list:
	otrl_list_free(inter_key_list);
error_with_gka_init:
	otrl_dh_keypair_free(gka_info->keypair);
error:
	return 1;
}

int chat_gka_handle_downflow_message(ChatContextPtr ctx, ChatMessage *msg, ChatMessage **msgToSend, int *free_msg)
{
	ChatGKAInfoPtr gka_info;
	ChatEncInfo *enc_info;
	ChatMessagePayloadGKADownflow *downflowMsg;
	OtrlListNodePtr cur;
	gcry_mpi_t *w;
	unsigned int i;
	unsigned int key_list_length;
	gcry_error_t err;

	fprintf(stderr, "libotr-mpOTR: handle_downflow_message: start\n");

	gka_info = chat_context_get_gka_info(ctx);
	if(!gka_info) { goto error;}

	downflowMsg = msg->payload;

    /* Get the intermediate key list length */
    key_list_length = otrl_list_size(downflowMsg->interKeys);

    /* The key list is reversed so we need the i-th element from the end
       of the list. This item is at position key_list_length - gka_info->position */
    i = key_list_length - 1 - gka_info->position;

    /* Get the appropriate intermediate key */
    cur = otrl_list_get(downflowMsg->interKeys, i);
    if(!cur) { goto error; }

    w = otrl_list_node_get_payload(cur);

    /* Initialize enc_info struct */
    enc_info = chat_enc_info_new();
    if(!enc_info) { goto error; }

    /* Calculate the shared secret */
    err = chat_enc_create_secret(enc_info, *w, gka_info->keypair);
    if(err) { goto error_with_enc_info; }

    // Set enc_info struct to context
    chat_context_set_enc_info(ctx, enc_info);

    gka_info->state = CHAT_GKASTATE_FINISHED;
    chat_context_set_id(ctx, gka_info->position);

    *msgToSend = NULL;

    fprintf(stderr, "libotr-mpOTR: handle_downflow_message: end\n");

    return 0;

error_with_enc_info:
	chat_enc_info_free(enc_info);
error:
	return 1;
}

int chat_gka_is_my_message(const ChatMessage *msg)
{
	ChatMessageType msg_type = msg->msgType;

	switch(msg_type) {
		case CHAT_MSGTYPE_GKA_UPFLOW:
		case CHAT_MSGTYPE_GKA_DOWNFLOW:
			return 1;
		default:
			return 0;
	}
}

int chat_gka_handle_message(ChatContextPtr ctx, ChatMessage *msg,
                             ChatMessage **msgToSend) {
	ChatMessageType msgType = msg->msgType;
	int free_msg;

	switch(msgType) {
		case CHAT_MSGTYPE_GKA_UPFLOW:
			return chat_gka_handle_upflow_message(ctx, msg, msgToSend, &free_msg);
		case CHAT_MSGTYPE_GKA_DOWNFLOW:
			return chat_gka_handle_downflow_message(ctx, msg, msgToSend, &free_msg);
		default:
			return 1;
	}
}
