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

/**
  Compares two MPIs stored in a otr list

  @param a the first MPI to compare
  @param b the second MPI to compare
  @return 0 if a = b, a positive value if a > b and a negative value if a < b
 */
int keys_compare(PayloadPtr a, PayloadPtr b)
{
	return gcry_mpi_cmp(a, b);
}

/**
  Releases and free's an MPI stored in an otr list

  @param a the MPI to be free'd and released
 */
void key_free(PayloadPtr a)
{
	gcry_mpi_t *w = a;

	gcry_mpi_release(*w);

	free(a);
}

/**
  Prints an MPI stored in an otr list

  @param node the list node containing the MPI to be printed
 */
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


/**
  Prints an MPI

  @param w the MPI to be printed
 */
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

/**
  Destroy the data stored in a OtrlAuthGKAInfo

  This function releases, deallocates, and free's any memory allocated
  dynamically inside a OtrlAuthGKAInfo. The struct itself is not free'd

  @param gka_info the OtrlAuthGKAInfo to be destroyed
 */
void chat_auth_gka_info_destroy(OtrlAuthGKAInfo *gka_info)
{
	if(gka_info->keypair)
		otrl_dh_keypair_free(gka_info->keypair);

	free(gka_info->keypair);
}

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
	key_list = otrl_list_create(&interKeyOps, sizeof(gcry_mpi_t));
	if(!key_list) { goto error; }

	/* Append the generator in the list and check if it was inserted correctly */
	node = otrl_list_append(key_list, generator);
	if(!node) { goto error_with_list; }

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

//TODO fix phrasing in this docstring
/**
  This function creates a new list from an old one, with each element of the
  old raised to the private key.

  @param new_key_list a pointer to an OtrlList which will hold the new values
  @param old_key_list a pointer to an OtrlList which contains the keys which
   holds the old values
  @key a pointer to our DH keypair used in this GKA run
 */
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
OtrlList * intermediate_key_list_to_send(OtrlList *key_list, DH_keypair *key)
{
	OtrlList *new_list;
	gcry_mpi_t *w, *last;

	fprintf(stderr, "libotr-mpOTR: intermediate_key_list_to_send: start\n");

	/* Initialize the list to be returned */
	new_list = otrl_list_create(&interKeyOps, sizeof(gcry_mpi_t));

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
OtrlList * final_key_list_to_send(OtrlList *key_list, DH_keypair *key)
{
	OtrlList *new_list;

	fprintf(stderr, "libotr-mpOTR: final_key_list_to_send: start\n");

	/* Initialize the list to be returned */
	new_list = otrl_list_create(&interKeyOps, sizeof(gcry_mpi_t));
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

/**
  This function concatenates and hashes the usernames of each participant.

  This function will iterate over an OtrlList containing the participats
  and hash their usernames. Then it will store the produced hash in an
  >alread< allocated buffer passed as an argument.

  @param participants an OtrlList containing each participant
  @param hash a buffer to hold the produced hash. It must be already
   allocated by the caller
 */
gcry_error_t get_participants_hash(OtrlList *participants, unsigned char* hash)
{
	gcry_md_hd_t md;
	gcry_error_t err;
	OtrlListNode *cur;
	ChatParticipant *participant;
	size_t len;
	unsigned char *hash_result;

	fprintf(stderr, "libotr-mpOTR: get_participants_hash: start\n");

	err = gcry_md_open(&md, GCRY_MD_SHA512, 0);
	if(err)
		return err;
	fprintf(stderr, "libotr-mpOTR: get_participants_hash: after md open\n");

	/* Iterate over the list and write each username in the message digest */
	for(cur = participants->head; cur!=NULL; cur = cur->next) {
		participant = cur->payload;
		len = strlen(participant->username);
		gcry_md_write(md, participant->username, len);
	}
	fprintf(stderr, "libotr-mpOTR: get_participants_hash: after writting each username\n");

	gcry_md_final(md);
	hash_result = gcry_md_read(md, GCRY_MD_SHA512);

	fprintf(stderr, "libotr-mpOTR: get_participants_hash: after result\n");

	//TODO Dimitris: we should free hash_result
	memcpy(hash, hash_result, CHAT_PARTICIPANTS_HASH_LENGTH);
	fprintf(stderr, "libotr-mpOTR: get_participants_hash: after memcopy\n");

	gcry_md_close(md);
	fprintf(stderr, "libotr-mpOTR: get_participants_hash: end\n");

	return gcry_error(GPG_ERR_NO_ERROR);
}

//TODO This function does two things. First it gets the participants
//list and calculates its hash. Then it generates a diffie hellman keypair.
//Break this function into two seperate ones.
gcry_error_t initialize_gka_info(OtrlAuthGKAInfo *gka_info) //OtrlChatContext *ctx)
{
	gcry_error_t err;

	fprintf(stderr, "libotr-mpOTR: initialize_gka_info: start\n");

    /* Allocate the DH keypair */
    if(gka_info->keypair)
    	free(gka_info->keypair);
    gka_info->keypair = malloc(sizeof(DH_keypair));
    if(!gka_info->keypair) {
    	return gcry_error(GPG_ERR_ENOMEM);
    }

    /* Initialize it */
    otrl_dh_keypair_init(gka_info->keypair);

    /* Generate a key */
    err = otrl_dh_gen_keypair(DH1536_GROUP_ID, gka_info->keypair);
    if(err) {
    	fprintf(stderr, "libotr-mpOTR: initialize_gka_info: keypair gen error\n");
    	//otrl_list_clear(ctx->participants_list);
    	return err;
    }
    //mpi_toString(gka_info->keypair->priv);

	return gcry_error(GPG_ERR_NO_ERROR);
}

int chat_auth_init(OtrlChatContext *ctx, ChatMessage **msgToSend)
{
    unsigned int me_next[2];
    gcry_error_t err;
    OtrlList *inter_key_list;
    OtrlList *initial_key_list;

    fprintf(stderr, "libotr-mpOTR: otrl_chat_auth_init: start\n");

    /* Do any initializations needed */
    err = initialize_gka_info(&ctx->gka_info);
    if(err) {
    	return 1;
    }

    fprintf(stderr, "libotr-mpOTR: otrl_chat_auth_init: after initialization\n");
    /* Print the list for debugging purposes TODO remove this in release */
    //otrl_list_dump(ctx->participants_list);

    /* Get our position in the upflow stream */
    //TODO handle possible errors
    chat_participant_get_me_next_position(ctx->accountname, ctx->participants_list, me_next);
    fprintf(stderr, "libotr-mpOTR: otrl_chat_auth_init: after get pos\n");

    /* Get a intermediate key list with only the generator inside */
    initial_key_list = initial_intermediate_key_list();
    fprintf(stderr, "libotr-mpOTR: otrl_chat_auth_init: after initial_intermediate_key_list\n");
    if(!initial_key_list) {
    	fprintf(stderr, "libotr-mpOTR: otrl_chat_auth_init: initial list error\n");
    	otrl_dh_keypair_free(ctx->gka_info.keypair);
    	return 1;
    }

    //otrl_list_dump(initial_key_list);
    fprintf(stderr, "libotr-mpOTR: chat_auth_init: after ini list dump\n");

    /* Create the intermediate key list to send */
    inter_key_list = intermediate_key_list_to_send(initial_key_list, ctx->gka_info.keypair);
    //otrl_list_dump(inter_key_list);
    fprintf(stderr, "libotr-mpOTR: otrl_chat_auth_init: after list to send\n");

    /* We don't need the initial list anymore */
    otrl_list_destroy(initial_key_list);
    fprintf(stderr, "libotr-mpOTR: otrl_chat_auth_init: after init list destroy\n");

    if(!inter_key_list) {
    	fprintf(stderr, "libotr-mpOTR: otrl_chat_auth_init: inter list error\n");
    	otrl_dh_keypair_free(ctx->gka_info.keypair);
    	return 1;
    }

    /* Generate the message that will be sent */
    *msgToSend = chat_message_gka_upflow_create(ctx, inter_key_list, me_next[1]);
    fprintf(stderr, "libotr-mpOTR: otrl_chat_auth_init: start\n");
    if(!*msgToSend) {
    	fprintf(stderr, "libotr-mpOTR: otrl_chat_auth_init: msgToSend error\n");
    	otrl_list_destroy(inter_key_list);
    	otrl_dh_keypair_free(ctx->gka_info.keypair);
    	return 1;
    }

    /* Set the gka_info state to await downflow message */
    ctx->gka_info.state = CHAT_GKASTATE_AWAITING_DOWNFLOW;
    ctx->gka_info.position = 0;

    fprintf(stderr, "libotr-mpOTR: otrl_chat_auth_init: end\n");

    return 0;
}


gcry_error_t handle_upflow_message(OtrlChatContext *ctx,
                                   ChatMessage *msg,
                                   ChatMessage **msgToSend,
                                   int *free_msg)
{
	gcry_error_t err;
	//int hashOk = 1;
	OtrlList *inter_key_list;
	OtrlListNode *last;
	gcry_mpi_t *last_key;
	ChatMessagePayloadGKAUpflow *upflowMsg = msg->payload;
	unsigned int me_next[2];
	unsigned int inter_key_list_length, participants_list_length;

	//fprintf(stderr, "libotr-mpOTR: handle_upflow_message: start\n");

	if(ctx->gka_info.state == CHAT_GKASTATE_AWAITING_DOWNFLOW) {
		return gcry_error(GPG_ERR_INV_PACKET);
	}

    if(ctx->gka_info.state == CHAT_GKASTATE_NONE) {
    	//fprintf(stderr, "libotr-mpOTR: handle_upflow_message: storing\n");
        return 1;
    }

    /* Do any initializations needed */
    err = initialize_gka_info(&ctx->gka_info);
    if(err) goto err;
	//fprintf(stderr, "libotr-mpOTR: handle_upflow_message: after gka_info init\n");

	/* Get our position in the participants list */
    //TODO shouldn't i return if there was an error?
	if(chat_participant_get_me_next_position(ctx->accountname, ctx->participants_list, me_next))
        fprintf(stderr, "libotr-mpOTR: handle_upflow_message: get position error\n");
	//fprintf(stderr, "libotr-mpOTR: handle_upflow_message: after get position\n");

    /* Check if the message is intended for the same users */
    if(memcmp(ctx->sid, msg->sid, CHAT_OFFER_SID_LENGTH)
       || upflowMsg->recipient != me_next[0]) {
    	err = gcry_error(GPG_ERR_BAD_DATA);
    	goto err_with_gka_init;
    }
	//fprintf(stderr, "libotr-mpOTR: handle_upflow_message: after hash check\n");

    /* Get the length of the intermediate keys */
    inter_key_list_length = otrl_list_length(upflowMsg->interKeys);
	//fprintf(stderr, "libotr-mpOTR: handle_upflow_message: keys length: %u \n", inter_key_list_length);


    //TODO Infering our position in the upflow stream may be dangerous
	//because an attacker (maybe a dishonest participant?) can manipulate
	//this to something he wants. I cant think of a possible attack now
	//but you never know. Check it!
	ctx->gka_info.position = inter_key_list_length - 1;//me_next[0];

    /* Get the participants list length */
    participants_list_length = otrl_list_length(ctx->participants_list);
	//fprintf(stderr, "libotr-mpOTR: handle_upflow_message: participants length: %u \n", participants_list_length);


	//fprintf(stderr, "libotr-mpOTR: handle_upflow_message: dumping participants\n");
	//otrl_list_dump(ctx->participants_list);

    if(inter_key_list_length < participants_list_length ) {
    	fprintf(stderr, "libotr-mpOTR: handle_upflow_message: in upflow generation\n");

    	/* Generate the intermediate key list that we will send */
    	inter_key_list = intermediate_key_list_to_send(upflowMsg->interKeys, ctx->gka_info.keypair);
    	if(!inter_key_list) {
    		//fprintf(stderr, "libotr-mpOTR: handle_upflow_message: inter_key_list error\n");
        	err = gcry_error(GPG_ERR_INTERNAL);
        	goto err_with_gka_init;
    	}
    	//fprintf(stderr, "libotr-mpOTR: handle_upflow_message: after list to send\n");

    	*msgToSend = chat_message_gka_upflow_create(ctx, inter_key_list, me_next[1]);
    	if(!*msgToSend) {
    		//fprintf(stderr, "libotr-mpOTR: handle_upflow_message: msgToSend error\n");
        	err = gcry_error(GPG_ERR_INTERNAL);
        	goto err_with_inter_keys;
    	}
    	//fprintf(stderr, "libotr-mpOTR: handle_upflow_message: after upflow_create\n");
    	/* Set the gka_info state to await downflow message */
    	ctx->gka_info.state = CHAT_GKASTATE_AWAITING_DOWNFLOW;
    }
    else {
    	//fprintf(stderr, "libotr-mpOTR: handle_upflow_message: in downflow generation\n");

    	//otrl_list_dump(upflowMsg->interKeys);
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
    	//fprintf(stderr, "libotr-mpOTR: handle_upflow_message: after create secret\n");

    	/* Drop the last element */
    	otrl_list_remove_and_destroy(upflowMsg->interKeys, last);
    	//fprintf(stderr, "libotr-mpOTR: handle_upflow_message: after drop last elem\n");

    	/* Get the final intermediate key list to send in the downflow message */
    	inter_key_list = final_key_list_to_send(upflowMsg->interKeys, ctx->gka_info.keypair);
    	if(!inter_key_list) {
    		//fprintf(stderr, "libotr-mpOTR: handle_upflow_message: inter_key_list error\n");
        	err = gcry_error(GPG_ERR_INTERNAL);
        	goto err_with_gka_init;
    	}
    	//fprintf(stderr, "libotr-mpOTR: handle_upflow_message: after  list to send\n");
    	//fprintf(stderr, "libotr-mpOTR: handle_upflow_message: dumping inter_key_list:\n");
    	     otrl_list_dump(inter_key_list);
    	/* Generate the downflow message */
    	*msgToSend = chat_message_gka_downflow_create(ctx, inter_key_list);
    	if(!*msgToSend) {
    		//fprintf(stderr, "libotr-mpOTR: handle_upflow_message: msgToSend error\n");
        	err = gcry_error(GPG_ERR_INTERNAL);
        	goto err_with_inter_keys;
    	}
    	//fprintf(stderr, "libotr-mpOTR: handle_upflow_message: after downflow create\n");

    	/* Set the gka_info state to finished */
    	ctx->gka_info.state = CHAT_GKASTATE_FINISHED;
    	//ctx->msg_state = OTRL_MSGSTATE_ENCRYPTED;
    	ctx->id = ctx->gka_info.position;
    }


	fprintf(stderr, "libotr-mpOTR: handle_upflow_messaget: end\n");

	return gcry_error(GPG_ERR_NO_ERROR);


err_with_inter_keys:
	otrl_list_destroy(inter_key_list);
err_with_gka_init:
	otrl_dh_keypair_free(ctx->gka_info.keypair);
err:
	return err;
}

gcry_error_t handle_downflow_message(OtrlChatContext *ctx,
                                     ChatMessage *msg,
                                     ChatMessage **msgToSend,
                                     int *free_msg)
{
	gcry_error_t err;
	ChatMessagePayloadGKADownflow *downflowMsg = msg->payload;
	OtrlListNode *cur;
	gcry_mpi_t *w;
	unsigned int i;
	unsigned int key_list_length;

	fprintf(stderr, "libotr-mpOTR: handle_downflow_message: start\n");

    //TODO check if we are in the correct state before processing downflow
    /* Check if the message is intended for the same users */
    if(memcmp(ctx->sid, msg->sid, CHAT_PARTICIPANTS_HASH_LENGTH)) {
    	fprintf(stderr,"libotr-mpOTR: handle_downflow_message: hashes are not equal");
    	fprintf(stderr,"libotr-mpOTR: handle_downflow_message: stored hash is: ");
    	for(size_t i = 0; i < CHAT_OFFER_SID_LENGTH; i++)
    		fprintf(stderr,"%02X", ctx->sid[i]);
    	fprintf(stderr,"\n");

    	fprintf(stderr,"ligotr-mpOTR: handle_downflow_message: received hash is: ");
    	for(size_t i = 0; i < CHAT_OFFER_SID_LENGTH; i++)
    		fprintf(stderr,"%02X", msg->sid[i]);
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

    ctx->gka_info.state = CHAT_GKASTATE_FINISHED;
    //ctx->msg_state = OTRL_MSGSTATE_ENCRYPTED;
    ctx->id = ctx->gka_info.position;

    fprintf(stderr, "libotr-mpOTR: handle_downflow_message: end\n");

    return gcry_error(GPG_ERR_NO_ERROR);
}

int chat_auth_is_my_message(ChatMessage *msg)
{
	ChatMessageType msg_type = msg->msgType;

	fprintf(stderr, "libotr-mpOTR: chat_auth_is_auth_message: start\n");

	switch(msg_type) {
		case CHAT_MSGTYPE_GKA_UPFLOW:
		case CHAT_MSGTYPE_GKA_DOWNFLOW:
			//fprintf(stderr, "libotr-mpOTR: chat_auth_is_auth_message: it is\n");
			return 1;
		default:
			//fprintf(stderr, "libotr-mpOTR: chat_auth_is_auth_message: it is not\n");
			return 0;
	}
	fprintf(stderr, "libotr-mpOTR: chat_auth_is_auth_message: end\n");
}

int chat_auth_handle_message(OtrlChatContext *ctx, ChatMessage *msg,
                             ChatMessage **msgToSend) {
	ChatMessageType msgType = msg->msgType;
	int free_msg;
	fprintf(stderr, "libotr-mpOTR: chat_auth_handle_message: start\n");

	switch(msgType) {
		case CHAT_MSGTYPE_GKA_UPFLOW:
			fprintf(stderr, "libotr-mpOTR: chat_auth_handle_message: upflow\n");
			return handle_upflow_message(ctx, msg, msgToSend, &free_msg);
		case CHAT_MSGTYPE_GKA_DOWNFLOW:
			fprintf(stderr, "libotr-mpOTR: chat_auth_handle_message: downflow\n");
			return handle_downflow_message(ctx, msg, msgToSend, &free_msg);
		default:
			return 1;
	}
	fprintf(stderr, "libotr-mpOTR: chat_auth_handle_message: end\n");
}
