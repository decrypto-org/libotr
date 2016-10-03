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

#include "chat_message.h"
#include "chat_enc.h"
#include "instag.h"
#include "dh.h"
#include "chat_types.h"

#include "chat_participant.h"

#include <stdio.h>


int keys_compare(PayloadPtr a, PayloadPtr b)
{
	return gcry_mpi_cmp(a, b);
}

void key_free(PayloadPtr a)
{
	gcry_mpi_t *w = a;

	gcry_mpi_release(*w);

	free(a);
}

void key_toString(OtrlListNode *node)
{
	gcry_mpi_t *w = node->payload;
	unsigned char *buf;
    size_t s;

    gcry_mpi_print(GCRYMPI_FMT_HEX,NULL,0,&s,*w);
    buf = malloc(s+1);
    gcry_mpi_print(GCRYMPI_FMT_HEX,buf,s,NULL,*w);
    buf[s]='\0';

    fprintf(stderr, "Intermediate key:\n");
    fprintf(stderr, "|- value\t: %s\n", buf);
    free(buf);
}

void mpi_toString(gcry_mpi_t w)
{
	unsigned char *buf;
    size_t s;

    gcry_mpi_print(GCRYMPI_FMT_HEX,NULL,0,&s,w);
    buf = malloc(s+1);
    gcry_mpi_print(GCRYMPI_FMT_HEX,buf,s,NULL,w);
    buf[s]='\0';

    fprintf(stderr, "%s\n", buf);
    free(buf);
}

struct OtrlListOpsStruct interKeyOps = {
		keys_compare,
		key_toString,
		key_free
};

OtrlList * initial_intermediate_key_list()
{
	OtrlList *key_list;
	gcry_mpi_t *generator;
	OtrlListNode *node;

	fprintf(stderr, "libotr-mpOTR: inital_intermediate_key_list: start\n");

	generator = malloc(sizeof(gcry_mpi_t));
	if(!generator) {
		return NULL;
	}

	/* Get the generator of the group */
	*generator = gcry_mpi_copy(otrl_dh_get_generator());

	/* Initialize a new list and check if it was actually initialized */
	key_list = otrl_list_init(&interKeyOps, sizeof(gcry_mpi_t));
	if(!key_list) { goto error; }
/*		gcry_mpi_release(*generator);
		free(generator);
		return NULL;
	}
*/

	/* Append the generator in the list and check if it was inserted correctly */
	node = otrl_list_append(key_list, generator);
	if(!node) { goto error_with_list; }
/*		otrl_list_destroy(key_list);
		return NULL;
	}
*/
	fprintf(stderr, "libotr-mpOTR: inital_intermediate_key_list: end\n");
	return key_list;

error_with_list:
	otrl_list_destroy(key_list);
error:
	gcry_mpi_release(*generator);
	free(generator);
	fprintf(stderr, "libotr-mpOTR: inital_intermediate_key_list: end error\n");
	return NULL;

}


int append_with_key(OtrlList *new_key_list, OtrlList *old_key_list, DH_keypair *key)
{
	OtrlListNode *cur, *node;
	gcry_mpi_t *w, *tmp;
	char error = 0;

	fprintf(stderr, "libotr-mpOTR: append_with_key: start\n");

	/* For every key in the key_list raise it to the key->priv
	 * and append it to the new_list */
	for(cur = old_key_list->head; cur!=NULL; cur = cur->next) {

		tmp = cur->payload;
		if(otrl_dh_is_inrange(*tmp)) {
			error = 1;
			break;
		}

		/* Allocate a new gcry_mpi_t to be held in the list */
		w = malloc( sizeof(*w) );
		if(!w) {
			error = 1;
			break;
		}
		*w = gcry_mpi_new(256);

		/* raise it to the key->prive (mod the modulo) */
		otrl_dh_powm(*w, *tmp , key->priv);

		/* Append it to the new_list and check if it was added correctly */
		node = otrl_list_append(new_key_list,w);
		if(!node){
			error = 1;
			break;
		}
	}

	if(error){
		fprintf(stderr, "libotr-mpOTR: append_with_key: end error\n");
		return 1;
	}

	fprintf(stderr, "libotr-mpOTR: append_with_key: end\n");
	return 0;
}

OtrlList * intermediate_key_list_to_send(OtrlList *key_list, DH_keypair *key)
{
	OtrlList *new_list;
	gcry_mpi_t *w, *last;

	fprintf(stderr, "libotr-mpOTR: intermediate_key_list_to_send: start\n");

	/* Initialize the list to be returned */
	new_list = otrl_list_init(&interKeyOps, sizeof(gcry_mpi_t));

	/* Append the last key in the key_list to the new list, as
	 * specified by the algorithm */
	last = otrl_list_get_last(key_list)->payload;

	w = malloc( sizeof(*w));
	*w = gcry_mpi_copy(*last);

	if(!otrl_list_append(new_list, w)) {
		gcry_mpi_release(*w);
		free(w);
		fprintf(stderr, "libotr-mpOTR: intermediate_key_list_to_send: end error\n");
		return NULL;
	}

	/* If there was an error destroy the new_list and return NULL */
	if(append_with_key(new_list, key_list, key)){
		otrl_list_destroy(new_list);
		fprintf(stderr, "libotr-mpOTR: intermediate_key_list_to_send: end error\n");
		return NULL;
	}


	otrl_list_dump(new_list);

	fprintf(stderr, "libotr-mpOTR: intermediate_key_list_to_send: end\n");

	return new_list;
}

OtrlList * final_key_list_to_send(OtrlList *key_list, DH_keypair *key)
{
	OtrlList *new_list;

	fprintf(stderr, "libotr-mpOTR: final_key_list_to_send: start\n");

	/* Initialize the list to be returned */
	new_list = otrl_list_init(&interKeyOps, sizeof(gcry_mpi_t));
	fprintf(stderr, "libotr-mpOTR: final_key_list_to_send: after list init\n");

	/* If there was an error destroy the new_list and return NULL */
	if(append_with_key(new_list, key_list, key)){
		fprintf(stderr, "libotr-mpOTR: final_key_list_to_send: append_with_key error\n");
		otrl_list_destroy(new_list);
		return NULL;
	}

	fprintf(stderr, "libotr-mpOTR: final_key_list_to_send: end\n");

	return new_list;
}

int usernames_check_or_free(char **usernames, unsigned int usernames_size){
    unsigned char error = 0;

    fprintf(stderr, "libotr-mpOTR: usernames_check_or_free: start\n");

    if(!usernames)
    	return 1;
    fprintf(stderr, "libotr-mpOTR: usernames_check_or_free: after usernames array check\n");

    /* Check if every username is allocated */
    for(size_t i = 0; i < usernames_size; i++)
    	if(!usernames[i]) {
    		error = 1;
    		break;
    	}
    fprintf(stderr, "libotr-mpOTR: usernames_check_or_free: after each username check\n");
    /* If a username was not allocated then we must deallocate every username
       and the usernames array itself */
    if(error){
    	fprintf(stderr, "libotr-mpOTR: usernames_check_or_free: in error handling\n");
    	for(size_t i = 0; i < usernames_size; i++)
    		free(usernames[i]);
    	free(usernames);
    	return 1;
    }
    fprintf(stderr, "libotr-mpOTR: usernames_check_or_free: after error handling\n");

    return 0;
}

gcry_error_t get_participants_hash(OtrlList *participants, unsigned char* hash)
{
	gcry_md_hd_t md;
	gcry_error_t err;
	OtrlListNode *cur;
	OtrlChatParticipant *participant;
	size_t len;
	unsigned char *hash_result;

	fprintf(stderr, "libotr-mpOTR: get_participants_hash: start\n");

	err = gcry_md_open(&md, GCRY_MD_SHA512, 0);
	if(err)
		return err;
	fprintf(stderr, "libotr-mpOTR: get_participants_hash: after md open\n");

	for(cur = participants->head; cur!=NULL; cur = cur->next) {
		participant = cur->payload;
		len = strlen(participant->username);
		gcry_md_write(md, participant->username, len);
	}
	fprintf(stderr, "libotr-mpOTR: get_participants_hash: after writting each username\n");

	gcry_md_final(md);
	hash_result = gcry_md_read(md, GCRY_MD_SHA512);

	fprintf(stderr, "libotr-mpOTR: get_participants_hash: after result\n");

	memcpy(hash, hash_result, CHAT_PARTICIPANTS_HASH_LENGTH);
	fprintf(stderr, "libotr-mpOTR: get_participants_hash: after memcopy\n");

	gcry_md_close(md);
	fprintf(stderr, "libotr-mpOTR: get_participants_hash: end\n");

	return gcry_error(GPG_ERR_NO_ERROR);
}

gcry_error_t get_participants_list(const OtrlMessageAppOps *ops, OtrlChatContext *ctx)
{
    char **usernames;
    unsigned int usernames_size;

    fprintf(stderr, "libotr-mpOTR: get_participants_list: start\n");

    /* Get the usernames of the participants from the application */
    usernames = ops->chat_get_participants(NULL, ctx->accountname, ctx->protocol, ctx->the_chat_token, &usernames_size);
    fprintf(stderr, "libotr-mpOTR: get_participants_list: after callback\n");

    //fprintf(stderr, "libotr-mpOTR: otrl_chat_auth_init: after get_participants, size: %d\n", usernames_size);

    /* Check if the usernames array is allocated, and every username in it is also allocate */
    if(usernames_check_or_free(usernames,usernames_size))
    	return gcry_error(GPG_ERR_ENODATA);
    fprintf(stderr, "libotr-mpOTR: get_participants_list: after check_or_free\n");

    /* Create the participants list from the usernames array */
    if(chat_participant_list_from_usernames(ctx->participants_list, usernames, usernames_size))
    	return gcry_error(GPG_ERR_INTERNAL);
    fprintf(stderr, "libotr-mpOTR: get_participants_list: after list_from_usernames\n");

    /* Free the usernames array as it is not needed anymor */
    free(usernames);
    fprintf(stderr, "libotr-mpOTR: get_participants_list: end\n");

    return gcry_error(GPG_ERR_NO_ERROR);

}

gcry_error_t initialize_gka_info(const OtrlMessageAppOps *ops, OtrlChatContext *ctx)
{
	gcry_error_t err;

	fprintf(stderr, "libotr-mpOTR: initialize_gka_info: start\n");

    /* Get the participants list from the application */
    err =  get_participants_list(ops, ctx);
    fprintf(stderr, "libotr-mpOTR: initialize_gka_info: after get_participants_list\n");
    if(err) {
    	fprintf(stderr, "libotr-mpOTR: initialize_gka_info: get_list error\n");
    	return err;
    }

    /* Hash the participants so that the others can check that we intend to speak
       to the same group of users */
    err = get_participants_hash(ctx->participants_list, ctx->gka_info.participants_hash);
    fprintf(stderr, "libotr-mpOTR: initialize_gka_info: after get_hash\n");
    if(err) {
    	fprintf(stderr, "libotr-mpOTR: initialize_gka_info: error get_hash\n");
    	otrl_list_clear(ctx->participants_list);
    	return err;
    }

    /* Allocate the DH keypair */
    if(ctx->gka_info.keypair)
    	free(ctx->gka_info.keypair);
    ctx->gka_info.keypair = malloc(sizeof(DH_keypair));
    if(!ctx->gka_info.keypair) {
    	return gcry_error(GPG_ERR_ENOMEM);
    }
    fprintf(stderr, "libotr-mpOTR: initialize_gka_info: after keypair allocation\n");

    /* Initialize it */
    otrl_dh_keypair_init(ctx->gka_info.keypair);
    fprintf(stderr, "libotr-mpOTR: initialize_gka_info: after keypair init\n");

    /* Generate a key */
    err = otrl_dh_gen_keypair(DH1536_GROUP_ID, ctx->gka_info.keypair);
    fprintf(stderr, "libotr-mpOTR: initialize_gka_info: after keypair gen\n");
    if(err) {
    	fprintf(stderr, "libotr-mpOTR: initialize_gka_info: keypair gen error\n");
    	otrl_list_clear(ctx->participants_list);
    	return err;
    }

	return gcry_error(GPG_ERR_NO_ERROR);
}

int chat_auth_init(const OtrlMessageAppOps *ops, OtrlChatContext *ctx, OtrlChatMessage **msgToSend)
{
    unsigned int me_next[2];
    gcry_error_t err;
    OtrlList *inter_key_list;
    OtrlList *initial_key_list;

    fprintf(stderr, "libotr-mpOTR: otrl_chat_auth_init: start\n");

    /* Do any initializations needed */
    err = initialize_gka_info(ops, ctx);
    if(err) {
    	return 1;
    }

    fprintf(stderr, "libotr-mpOTR: otrl_chat_auth_init: after initialization\n");
    /* Print the list for debugging purposes TODO remove this in release */
    otrl_list_dump(ctx->participants_list);

    /* Get our position in the upflow stream */
    //TODO handle possible errors
    chat_participant_get_me_next_position(ctx->accountname, ctx->participants_list, me_next);
    fprintf(stderr, "libotr-mpOTR: otrl_chat_auth_init: after get pos\n");

    /* Get a intermediate key list with only the generator inside */
    initial_key_list = initial_intermediate_key_list();
    fprintf(stderr, "libotr-mpOTR: otrl_chat_auth_init: after initial_intermediate_key_list\n");
    if(!initial_key_list) {
    	fprintf(stderr, "libotr-mpOTR: otrl_chat_auth_init: initial list error\n");
    	otrl_list_clear(ctx->participants_list);
    	otrl_dh_keypair_free(ctx->gka_info.keypair);
    	return 1;
    }

    otrl_list_dump(initial_key_list);
    fprintf(stderr, "libotr-mpOTR: chat_auth_init: after ini list dump\n");

    /* Create the intermediate key list to send */
    inter_key_list = intermediate_key_list_to_send(initial_key_list, ctx->gka_info.keypair);
    fprintf(stderr, "libotr-mpOTR: otrl_chat_auth_init: after list to send\n");

    /* We don't need the initial list anymore */
    otrl_list_destroy(initial_key_list);
    fprintf(stderr, "libotr-mpOTR: otrl_chat_auth_init: after init list destroy\n");

    if(!inter_key_list) {
    	fprintf(stderr, "libotr-mpOTR: otrl_chat_auth_init: inter list error\n");
    	otrl_list_clear(ctx->participants_list);
    	otrl_dh_keypair_free(ctx->gka_info.keypair);
    	return 1;
    }

    /* Generate the message that will be sent */
    *msgToSend = chat_message_gka_upflow_create(ctx, ctx->gka_info.participants_hash, inter_key_list, me_next[1]);
    fprintf(stderr, "libotr-mpOTR: otrl_chat_auth_init: start\n");
    if(!*msgToSend) {
    	fprintf(stderr, "libotr-mpOTR: otrl_chat_auth_init: msgToSend error\n");
    	otrl_list_clear(ctx->participants_list);
    	otrl_list_destroy(inter_key_list);
    	otrl_dh_keypair_free(ctx->gka_info.keypair);
    	return 1;
    }

    /* Set the gka_info state to await downflow message */
    ctx->gka_info.state = OTRL_CHAT_GKASTATE_AWAITING_DOWNFLOW;
    ctx->gka_info.position = 0; //me_next[0];

    fprintf(stderr, "libotr-mpOTR: otrl_chat_auth_init: end\n");

    return 0;
}


gcry_error_t handle_upflow_message(const OtrlMessageAppOps *ops, OtrlChatContext *ctx, const OtrlChatMessage *msg, OtrlChatMessage **msgToSend)
{
	gcry_error_t err;
	//int hashOk = 1;
	OtrlList *inter_key_list;
	OtrlListNode *last;
	gcry_mpi_t *last_key;
	OtrlChatMessagePayloadGkaUpflow *upflowMsg = msg->payload;
	unsigned int me_next[2];
	unsigned int inter_key_list_length, participants_list_length;

	fprintf(stderr, "libotr-mpOTR: handle_upflow_message: start\n");

	if(ctx->gka_info.state == OTRL_CHAT_GKASTATE_AWAITING_DOWNFLOW) {
		return gcry_error(GPG_ERR_INV_PACKET);
	}

    /* Do any initializations needed */
    err = initialize_gka_info(ops, ctx);
    if(err) goto err;
	fprintf(stderr, "libotr-mpOTR: handle_upflow_message: after gka_info init\n");

	/* Get our position in the participants list */
	chat_participant_get_me_next_position(ctx->accountname, ctx->participants_list, me_next);
	fprintf(stderr, "libotr-mpOTR: handle_upflow_message: after get position\n");

    /* Check if the message is intended for the same users */
    if(memcmp(ctx->gka_info.participants_hash, upflowMsg->partlistHash, CHAT_PARTICIPANTS_HASH_LENGTH)
       || upflowMsg->recipient != me_next[0]) {
    	err = gcry_error(GPG_ERR_BAD_DATA);
    	goto err_with_gka_init;
    }
	fprintf(stderr, "libotr-mpOTR: handle_upflow_message: after hash check\n");

    /* Get the length of the intermediate keys */
    inter_key_list_length = otrl_list_length(upflowMsg->interKeys);
	fprintf(stderr, "libotr-mpOTR: handle_upflow_message: keys length: %u \n", inter_key_list_length);


    //TODO Infering our position in the upflow stream may be dangerous
	//because an attacker (maybe a dishonest participant?) can manipulate
	//this to something he wants. I cant think of a possible attack now
	//but you never know. Check it!
	ctx->gka_info.position = inter_key_list_length - 1;//me_next[0];

    /* Get the participants list length */
    participants_list_length = otrl_list_length(ctx->participants_list);
	fprintf(stderr, "libotr-mpOTR: handle_upflow_message: participants length: %u \n", participants_list_length);


	fprintf(stderr, "libotr-mpOTR: handle_upflow_message: dumping participants\n");
	otrl_list_dump(ctx->participants_list);

    if(inter_key_list_length < participants_list_length ) {
    	fprintf(stderr, "libotr-mpOTR: handle_upflow_message: in upflow generation\n");

    	/* Generate the intermediate key list that we will send */
    	inter_key_list = intermediate_key_list_to_send(upflowMsg->interKeys, ctx->gka_info.keypair);
    	if(!inter_key_list) {
    		fprintf(stderr, "libotr-mpOTR: handle_upflow_message: inter_key_list error\n");
        	err = gcry_error(GPG_ERR_INTERNAL);
        	goto err_with_gka_init;
    	}
    	fprintf(stderr, "libotr-mpOTR: handle_upflow_message: after list to send\n");

    	*msgToSend = chat_message_gka_upflow_create(ctx, ctx->gka_info.participants_hash, inter_key_list, me_next[1]);
    	if(!*msgToSend) {
    		fprintf(stderr, "libotr-mpOTR: handle_upflow_message: msgToSend error\n");
        	err = gcry_error(GPG_ERR_INTERNAL);
        	goto err_with_inter_keys;
    	}
    	fprintf(stderr, "libotr-mpOTR: handle_upflow_message: after upflow_create\n");
    	/* Set the gka_info state to await downflow message */
    	ctx->gka_info.state = OTRL_CHAT_GKASTATE_AWAITING_DOWNFLOW;
    }
    else {
    	fprintf(stderr, "libotr-mpOTR: handle_upflow_message: in downflow generation\n");

    	otrl_list_dump(upflowMsg->interKeys);
    	/* Get last intermediate key */
    	last = otrl_list_get_last(upflowMsg->interKeys);
    	last_key = last->payload;

    	/* Initialize enc_info struct */
    	chat_enc_initialize_enc_info(&ctx->enc_info);

    	/* Generate the master secret */
    	err = chat_enc_create_secret(&ctx->enc_info, *last_key, ctx->gka_info.keypair);
    	if(err) {
    		goto err_with_gka_init;
    	}
    	fprintf(stderr, "libotr-mpOTR: handle_upflow_message: after create secret\n");

    	/* Drop the last element */
    	otrl_list_remove_and_destroy(upflowMsg->interKeys, last);
    	fprintf(stderr, "libotr-mpOTR: handle_upflow_message: after drop last elem\n");

    	/* Get the final intermediate key list to send in the downflow message */
    	inter_key_list = final_key_list_to_send(upflowMsg->interKeys, ctx->gka_info.keypair);
    	if(!inter_key_list) {
    		fprintf(stderr, "libotr-mpOTR: handle_upflow_message: inter_key_list error\n");
        	err = gcry_error(GPG_ERR_INTERNAL);
        	goto err_with_gka_init;
    	}
    	fprintf(stderr, "libotr-mpOTR: handle_upflow_message: after  list to send\n");
    	fprintf(stderr, "libotr-mpOTR: handle_upflow_message: dumping inter_key_list:\n");
    	     otrl_list_dump(inter_key_list);
    	/* Generate the downflow message */
    	*msgToSend = chat_message_gka_downflow_create(ctx, ctx->gka_info.participants_hash, inter_key_list);
    	if(!*msgToSend) {
    		fprintf(stderr, "libotr-mpOTR: handle_upflow_message: msgToSend error\n");
        	err = gcry_error(GPG_ERR_INTERNAL);
        	goto err_with_inter_keys;
    	}
    	fprintf(stderr, "libotr-mpOTR: handle_upflow_message: after downflow create\n");

    	/* Set the gka_info state to finished */
    	ctx->gka_info.state = OTRL_CHAT_GKASTATE_FINISHED;
    	ctx->msg_state = OTRL_MSGSTATE_ENCRYPTED;
    	ctx->id = ctx->gka_info.position;
    }


	fprintf(stderr, "libotr-mpOTR: handle_upflow_messaget: end\n");

	return gcry_error(GPG_ERR_NO_ERROR);


err_with_inter_keys:
	otrl_list_destroy(inter_key_list);
err_with_gka_init:
	otrl_dh_keypair_free(ctx->gka_info.keypair);
	otrl_list_clear(ctx->participants_list);
err:
	return err;
}

gcry_error_t handle_downflow_message(const OtrlMessageAppOps *ops, OtrlChatContext *ctx, const OtrlChatMessage *msg, OtrlChatMessage **msgToSend)
{
	gcry_error_t err;
	OtrlChatMessagePayloadGkaDownflow *downflowMsg = msg->payload;
	OtrlListNode *cur;
	gcry_mpi_t *w;
	unsigned int i;
	unsigned int key_list_length;

	fprintf(stderr, "libotr-mpOTR: handle_downflow_message: start\n");


    /* Check if the message is intended for the same users */
    if(memcmp(ctx->gka_info.participants_hash, downflowMsg->partlistHash, CHAT_PARTICIPANTS_HASH_LENGTH)) {
    	fprintf(stderr,"libotr-mpOTR: handle_downflow_message: hashes are not equal");
    	fprintf(stderr,"libotr-mpOTR: handle_downflow_message: stored hash is: ");
    	for(size_t i = 0; i < CHAT_PARTICIPANTS_HASH_LENGTH; i++)
    		fprintf(stderr,"%02X", ctx->gka_info.participants_hash[i]);
    	fprintf(stderr,"\n");

    	fprintf(stderr,"ligotr-mpOTR: handle_downflow_message: received hash is: ");
    	for(size_t i = 0; i < CHAT_PARTICIPANTS_HASH_LENGTH; i++)
    		fprintf(stderr,"%02X", downflowMsg->partlistHash[i]);
    	fprintf(stderr,"\n");

    	return gcry_error(GPG_ERR_BAD_DATA);
    }
    fprintf(stderr, "libotr-mpOTR: handle_downflow_message: after hash check\n");

    key_list_length = otrl_list_length(downflowMsg->interKeys);

    /* The key list is reversed so we need the i-th element from the end
       of the list. This items is at position key_list_length - ctx->gka_info.position */
    i = key_list_length -1 - ctx->gka_info.position;

    /* Get the appropriate intermediate key */
    cur = otrl_list_get(downflowMsg->interKeys, i);
    if(!cur) {
    	fprintf(stderr, "libotr-mpOTR: handle_downflow_message: error getting our intermediate key at pos %u\n", i);
    	return gcry_error(GPG_ERR_NOTHING_FOUND);
    }
    //for(cur = downflowMsg->interKeys->tail, i = 0; i < ctx->gka_info.position; i++, cur = cur->prev); TODO remove this
    fprintf(stderr, "libotr-mpOTR: handle_downflow_message: after getting our intermediate key\n");

    w = cur->payload;

    /* Initialize enc_info struct */
    chat_enc_initialize_enc_info(&ctx->enc_info);

    err = chat_enc_create_secret(&ctx->enc_info, *w, ctx->gka_info.keypair);
    if(err) {
    	return err;
    }
    fprintf(stderr, "libotr-mpOTR: handle_downflow_message: after create secret\n");

    *msgToSend = NULL;

    ctx->gka_info.state = OTRL_CHAT_GKASTATE_FINISHED;
    ctx->msg_state = OTRL_MSGSTATE_ENCRYPTED;
    ctx->id = ctx->gka_info.position;

    fprintf(stderr, "libotr-mpOTR: handle_downflow_message: end\n");

    return gcry_error(GPG_ERR_NO_ERROR);
}

int chat_auth_is_auth_message(const OtrlChatMessage *msg)
{
	OtrlChatMessageType msg_type = msg->msgType;

	fprintf(stderr, "libotr-mpOTR: chat_auth_is_auth_message: start\n");

	switch(msg_type) {
		case OTRL_MSGTYPE_CHAT_UPFLOW:
		case OTRL_MSGTYPE_CHAT_DOWNFLOW:
			fprintf(stderr, "libotr-mpOTR: chat_auth_is_auth_message: it is\n");
			return 1;
		default:
			fprintf(stderr, "libotr-mpOTR: chat_auth_is_auth_message: it is not\n");
			return 0;
	}
	fprintf(stderr, "libotr-mpOTR: chat_auth_is_auth_message: end\n");
}

int chat_auth_handle_message(const OtrlMessageAppOps *ops, OtrlChatContext *ctx, OtrlChatMessage *msg, OtrlChatMessage **msgToSend) {
	OtrlChatMessageType msgType = msg->msgType;

	fprintf(stderr, "libotr-mpOTR: chat_auth_handle_message: start\n");

	switch(msgType) {
		case OTRL_MSGTYPE_CHAT_UPFLOW:
			fprintf(stderr, "libotr-mpOTR: chat_auth_handle_message: upflow\n");
			return handle_upflow_message(ops, ctx, msg, msgToSend);
		case OTRL_MSGTYPE_CHAT_DOWNFLOW:
			fprintf(stderr, "libotr-mpOTR: chat_auth_handle_message: downflow\n");
			return handle_downflow_message(ops, ctx, msg, msgToSend);
		default:
			return 1;
	}
	fprintf(stderr, "libotr-mpOTR: chat_auth_handle_message: end\n");
}
