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

#include <stdlib.h>

#include "chat_types.h"
#include "chat_dake.h"
#include "chat_dske.h"
#include "chat_message.h"
#include "chat_participant.h"
#include "chat_sign.h"
#include "chat_privkeydh.h"
#include "chat_fingerprint.h"


enum {
	DSKE_NO_ERROR,
	DSKE_ERROR,
	DSKE_KEY_UNVERIFIED
};

void chat_dske_info_free(OtrlAuthDSKEInfo *dske_info)
{
	if(dske_info) {
		chat_dake_destroy_info(&dske_info->dake_info);
	}
    free(dske_info);
}

int chat_dske_init(OtrlChatContext *ctx, ChatMessage **msgToSend)
{
    unsigned int my_pos;
    ChatParticipant *me;
    OtrlListNode *cur;
    ChatParticipant *participant;
    DAKE_handshake_message_data *dataToSend;
    char error;

    fprintf(stderr,"chat_dske_init: start\n");

    ctx->dske_info = malloc(sizeof(*ctx->dske_info));
    if(!ctx->dske_info) {
        return DSKE_ERROR;
    }

    chat_idkey_print(ctx->identity_key);

    me = chat_participant_find(ctx, ctx->accountname, &my_pos);
    if(!me) {
        return DSKE_ERROR;
    }

    //chat_idkey_print_key(ctx->identity_key);
    fprintf(stderr,"chat_dske_init: before genkey\n");
    //TODO make sure to destroy the key in the event of an error
    ctx->signing_key = chat_sign_genkey();

    //chat_idkey_print_key(ctx->identity_key);
    fprintf(stderr,"chat_dske_init: after my keygen\n");
    //TODO encapsulate this in a chat_sign function
    me->sign_key = malloc(sizeof *(me->sign_key));
    if(!me->sign_key) {
        chat_sign_destroy_key(ctx->signing_key);
            return DSKE_ERROR;
    }

    //chat_idkey_print_key(ctx->identity_key);
    //fprintf(stderr,"chat_dske_init: after my key alloc\n");
    me->sign_key->pub_key = gcry_sexp_find_token(ctx->signing_key->pub_key, "public-key", 0);
    me->sign_key->priv_key = NULL;

    //gcry_sexp_dump(ctx->signing_key->pub_key);
    //gcry_sexp_dump(me->sign_key->pub_key);

    //fprintf(stderr,"chat_dske_init: after genkey\n");

    /* Get what values we should broadcast to every other user */
    //chat_idkey_print_key(ctx->identity_key);
    error = chat_dake_init_keys(&ctx->dske_info->dake_info, ctx->identity_key, ctx->accountname,
                        ctx->protocol, &dataToSend);
    if(error) {
        chat_sign_destroy_key(ctx->signing_key);
        return DSKE_ERROR;
    }
    //fprintf(stderr,"chat_dske_init: after init_keys\n");

    /* Initiate a dake for each participant */
    for(cur = ctx->participants_list->head; cur != NULL; cur = cur->next)
    {
        participant = cur->payload;
        participant->dake = malloc(sizeof *(participant->dake));
        if(!participant->dake){
            error = DSKE_ERROR;
            break;
        }

        chat_dake_init(participant->dake,&ctx->dske_info->dake_info);//, participant->fingerprint);
    }
    if(error) {
    	//TODO de-initialize every participant that was init'ed before the error
        chat_sign_destroy_key(ctx->signing_key);
        return DSKE_ERROR;
    }

    //fprintf(stderr,"chat_dske_init: after handhsake_init\n");
    /* Create the message we should send */
    *msgToSend = chat_message_dake_handshake_create(ctx, dataToSend);

    //fprintf(stderr,"chat_dske_init: destroying data\n");
    //chat_dake_destroy_handshake_data(dataToSend);
    //free(dataToSend);
    //fprintf(stderr,"chat_dske_init: after destroying data\n");
    if(!msgToSend) {
        chat_sign_destroy_key(ctx->signing_key);
    	chat_dake_destroy_handshake_data(dataToSend);
        free(dataToSend);
        return DSKE_ERROR;
    }

    //fprintf(stderr,"chat_dske_init: after handshake_create\n");
    /* Change the protocol state */
    ctx->dske_info->remaining = otrl_list_length(ctx->participants_list) - 1;
    ctx->dske_info->state = CHAT_DSKESTATE_AWAITING_KEYS;


    fprintf(stderr,"chat_dske_init: end\n");
    return DSKE_NO_ERROR;
}

int chat_dske_handle_handshake_message(OtrlChatContext *ctx, ChatMessage *msg,
                                       ChatMessage **msgToSend, int *free_msg)
{
    ChatMessagePayloadDAKEHandshake *handshake_msg = msg->payload;
    ChatParticipant *sender;
    DAKE_confirm_message_data *dataToSend;
    unsigned int pos;
    unsigned char *fingerprint;
    OtrlChatFingerprint *cur_finger;
    OtrlListNode *cur = NULL;
    OtrlListNode *node = NULL;
    int error = DSKE_NO_ERROR;

    fprintf(stderr,"chat_dske_handle_handshake_message: start\n");
    /* Check if we shouldn't have received this message */
    //if(ctx->dske_info == OTRL_CHAT_DSKESTATE_NONE)
    //    return 1;

    sender = chat_participant_find(ctx, msg->senderName, &pos);
    if(!sender) {
        return DSKE_ERROR;
    }

    /* If this message arrived before it should have, store it
     * and return */
    if(ctx->dske_info->state == CHAT_DSKESTATE_NONE){
    	fprintf(stderr, "libotr-mpOTR: chat_dske_handle_handshake_message: dske state is none\n");
        return DSKE_ERROR;
    }

    /* If we were not expecting a handshake from this user return error */
    if(sender->dake->state != DAKE_STATE_WAITING_HANDSHAKE) {
        return DSKE_ERROR;
    }

    /* Load the keys they sent us and determine what data we should send them */
    error = chat_dake_load_their_part(sender->dake,
    								  handshake_msg->handshake_data,
									  &dataToSend,
									  &fingerprint);
    if(error == DAKE_ERROR) {
        return DSKE_ERROR;
    }
    //else if(error == DAKE_UNVERIFIED) {
    //	fprintf(stderr,"chat_dske_handle_handshake_message: a longetrm public key was not verified\n");
    //	error = DSKE_ERROR;
    //}

    /* Check if the fingerprint calculated during the dake exists in the list of
     * this users trusted fingerprints */
    fprintf(stderr,"chat_dske_handle_handshake_message: looking for:\n");
    for(int i=0; i< CHAT_FINGERPRINT_SIZE; i++)
    	fprintf(stderr,"%02X", fingerprint[i]);
    fprintf(stderr,"\n");

    for(cur = sender->fingerprints->head; cur != NULL; cur = cur->next){
    	cur_finger = cur->payload;

        fprintf(stderr,"chat_dske_handle_handshake_message: currently at:\n");
        for(int i=0; i< CHAT_FINGERPRINT_SIZE; i++)
        	fprintf(stderr,"%02X", cur_finger->fingerprint[i]);
        fprintf(stderr,"\n");
    	if(!memcmp(fingerprint, cur_finger->fingerprint, CHAT_FINGERPRINT_SIZE))
    		break;
    }
    fprintf(stderr,"chat_dske_handle_handshake_message: after for\n");
    if(!cur){
    	/* If not found, generate a temporary fingerprint object so that we can inform
    	 * the user that a public key needs to be verified. */
    	sender->fingerprint = chat_fingerprint_new(ctx->accountname, ctx->protocol,
                                                   sender->username, fingerprint, 0);
        if(!sender->fingerprint){
            fprintf(stderr,"chat_dske_handle_handshake_message: fingerpint was not created\n");
            return DSKE_ERROR;
        }
        node = otrl_list_insert(sender->fingerprints, sender->fingerprint);
        if(!node) {
            free(fingerprint);
            chat_dake_destroy_confirm_data(dataToSend);
            free(dataToSend);
            fprintf(stderr,"chat_dske_handle_handshake_message: fingerprint not found\n");
            return DSKE_ERROR;
        }
    }
    else {
        fprintf(stderr,"chat_dske_handle_handshake_message: after !cur\n");
        sender->fingerprint = cur->payload;
        fprintf(stderr,"chat_dske_handle_handshake_message: after fingerprint = cur->payload\n");
        fprintf(stderr,"chat_dske_handle_handshake_message: after free\n");
    }
    free(fingerprint);

    /* Create the message we should send */
    *msgToSend = chat_message_dake_confirm_create(ctx, pos, dataToSend);
    //fprintf(stderr,"chat_dske_handle_handshake_message: destroying data\n");
    //chat_dake_destroy_confirm_data(dataToSend);
    //free(dataToSend);
    //fprintf(stderr,"chat_dske_handle_handshake_message: after destroying data\n");
    if(!*msgToSend) {
    	chat_dake_destroy_confirm_data(dataToSend);
    	free(dataToSend);
        return DSKE_ERROR;
    }

    fprintf(stderr,"chat_dske_handle_handshake_message: end\n");
    return error;
}

int chat_dske_handle_confirm_message(OtrlChatContext *ctx, ChatMessage *msg,
                                     ChatMessage **msgToSend, int *free_msg)
{
    ChatMessagePayloadDAKEConfirm *confirm_msg = msg->payload;
    DAKE_key_message_data *dataToSend;
    unsigned char *key_bytes;
    size_t key_len;
    ChatParticipant *sender;
    unsigned int their_pos;
    unsigned int our_pos;
    int error;

    fprintf(stderr,"libotr-mpOTR: chat_dske_handle_confirm_message: start\n");

//    pos = chat_participant_get_position(ctx->participants_list, ctx->accountname);
//    if(pos < 0) {
//    	return 1;
//    }


    sender = chat_participant_find(ctx, msg->senderName, &their_pos);
    if(!sender) {
        return DSKE_ERROR;
    }

    //fprintf(stderr,"libotr-mpOTR: chat_dske_handle_confirm_message: after find recipient: %u, their_pos: %u\n", confirm_msg->recipient, their_pos);

    if(chat_participant_get_position(ctx->participants_list, ctx->accountname, &our_pos)) {
    	return DSKE_ERROR;
    }

    if(confirm_msg->recipient != our_pos) {
    	return DSKE_NO_ERROR;
    }

    //fprintf(stderr,"libotr-mpOTR: chat_dske_handle_confirm_message: after position check\n");

    /* Check if we shouldnt have received this message */
    if(ctx->dske_info->state != CHAT_DSKESTATE_AWAITING_KEYS)
        return DSKE_ERROR;

    //fprintf(stderr,"libotr-mpOTR: chat_dske_handle_confirm_message: after state check\n");

    if(sender->dake->state != DAKE_STATE_WAITING_CONFIRM){
        return DSKE_ERROR;
    }

    //fprintf(stderr,"libotr-mpOTR: chat_dske_handle_confirm_message: after after dake state check\n");

    /* Verify that we have computed the same shared secret */
    error = chat_dake_verify_confirm(sender->dake, confirm_msg->data->mac);
    if(error) {
        return DSKE_ERROR;
    }

    //fprintf(stderr,"libotr-mpOTR: chat_dske_handle_confirm_message: after verify\n");

    /* Get the serialized pubkey */
    error = chat_sign_serialize_pubkey(ctx->signing_key, &key_bytes, &key_len);
    if(error) {
        return DSKE_ERROR;
    }

    fprintf(stderr,"libotr-mpOTR: chat_dske_handle_confirm_message: after serialize keylen: %lu\n", key_len);

    /* Encrypt and authenticate our pubkey to send the to the other party */
    //
    error = chat_dake_send_key(sender->dake, key_bytes, key_len, &dataToSend);
    free(key_bytes);
    if(error) {
        return DSKE_ERROR;
    }

    //fprintf(stderr,"libotr-mpOTR: chat_dske_handle_confirm_message: after send_key\n");

    /* Create the message to send */
    *msgToSend = chat_message_dake_key_create(ctx, their_pos, dataToSend);
    if(!*msgToSend) {
        return DSKE_ERROR;
    }

    //fprintf(stderr,"libotr-mpOTR: chat_dske_handle_confirm_message: after message create\n");

    fprintf(stderr,"chat_dske_handle_confirm_message: end\n");
    return DSKE_NO_ERROR;
}

int chat_dske_handle_key_message(OtrlChatContext *ctx, ChatMessage *msg,
                                 ChatMessage **msgToSend, int *free_msg)
{
    ChatMessagePayloadDAKEKey *key_msg = msg->payload;
    unsigned char *plain_key;
    size_t keylen;
    unsigned int their_pos;
    unsigned int our_pos;
    ChatParticipant *sender;
    int error;

    fprintf(stderr,"chat_dske_handle_key_message: start\n");

    sender = chat_participant_find(ctx, msg->senderName, &their_pos);
    if(!sender) {
        return DSKE_ERROR;
    }

    //fprintf(stderr,"chat_dske_handle_key_message: after find\n");

    if(chat_participant_get_position(ctx->participants_list,ctx->accountname, &our_pos)) {
    	return DSKE_ERROR;
    }

    //fprintf(stderr,"chat_dske_handle_key_message: after get_position\n");

    if(key_msg->recipient !=  our_pos) {
    	return DSKE_NO_ERROR;
    }

    //fprintf(stderr,"chat_dske_handle_key_message: after our_pos check\n");

    if(ctx->dske_info->state != CHAT_DSKESTATE_AWAITING_KEYS) {
        return DSKE_ERROR;
    }

    //fprintf(stderr,"chat_dske_handle_key_message: after dske state check\n");

    if(sender->dake->state != DAKE_STATE_WAITING_KEY) {
        return DSKE_ERROR;
    }

    //fprintf(stderr,"chat_dske_handle_key_message: after dake state check\n");

    //error = chat_dake_auth_decrypt(sender->dake, key_msg->data.key, key_msg->data.keylen, plain_key,
    //                               key_msg->data.mac);
    error = chat_dake_receive_key(sender->dake, key_msg->data, &plain_key, &keylen);
    if(error) {
        return DSKE_ERROR;
    }

    //fprintf(stderr,"chat_dske_handle_key_message: after dake_key_receive\n");

    sender->sign_key = chat_sign_parse_pubkey(plain_key, keylen);
    free(plain_key);
    if(!sender->sign_key) {
    	return DSKE_ERROR;
    }
    //fprintf(stderr,"chat_dske_handle_key_message: after key parse\n");
    //chat_sign_print_pubkey(sender->sign_key);

    sender->dake->state = DAKE_STATE_DONE;
    ctx->dske_info->remaining -= 1;
    if(ctx->dske_info->remaining == 0) {
    	fprintf(stderr,"chat_dske_handle_key_message: dske finished\n");
    	ctx->dske_info->state = CHAT_DSKESTATE_FINISHED;
    }

    fprintf(stderr,"chat_dske_handle_key_message: end\n");
    return DSKE_NO_ERROR;

}

int chat_dske_is_my_message(const ChatMessage *msg)
{
	ChatMessageType msg_type = msg->msgType;

	fprintf(stderr, "libotr-mpOTR: chat_auth_is_dske_message: start\n");

	switch(msg_type) {
	case CHAT_MSGTYPE_DAKE_HANDSHAKE:
	case CHAT_MSGTYPE_DAKE_CONFIRM:
	case CHAT_MSGTYPE_DAKE_KEY:
			//fprintf(stderr, "libotr-mpOTR: chat_dske_is_auth_message: it is\n");
			return 1;
		default:
			//fprintf(stderr, "libotr-mpOTR: chat_dske_is_auth_message: it is not\n");
			return 0;
	}
	fprintf(stderr, "libotr-mpOTR: chat_auth_is_dske_message: end\n");
}

int chat_dske_handle_message(OtrlChatContext *ctx, ChatMessage *msg,
                             ChatMessage **msgToSend) {
	ChatMessageType msgType = msg->msgType;
	int free_msg;

	fprintf(stderr, "libotr-mpOTR: chat_dske_handle_message: start\n");

	switch(msgType) {
		case CHAT_MSGTYPE_DAKE_HANDSHAKE:
			fprintf(stderr, "libotr-mpOTR: chat_dske_handle_message: handshake\n");
			return chat_dske_handle_handshake_message(ctx, msg, msgToSend, &free_msg);
		case CHAT_MSGTYPE_DAKE_CONFIRM:
			fprintf(stderr, "libotr-mpOTR: chat_dske_handle_message: confirm\n");
			return chat_dske_handle_confirm_message(ctx, msg, msgToSend, &free_msg);
		case CHAT_MSGTYPE_DAKE_KEY:
			fprintf(stderr, "libotr-mpOTR: chat_dske_handle_message: key\n");
			return chat_dske_handle_key_message(ctx, msg, msgToSend, &free_msg);
		default:
			return 1;
	}
	fprintf(stderr, "libotr-mpOTR: chat_dske_handle_message: end\n");
}
