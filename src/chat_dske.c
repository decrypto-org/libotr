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

#include "chat_dske.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "chat_context.h"
#include "chat_dake.h"
#include "chat_fingerprint.h"
//#include "chat_idkey.h"
#include "chat_message.h"
#include "chat_participant.h"
//#include "chat_privkeydh.h"
#include "chat_sign.h"
#include "chat_types.h"
#include "list.h"

struct ChatDSKEInfo {
	ChatDSKEState state;
	DAKEInfo dake_info;
	unsigned int remaining;
};

void chat_dske_info_free(ChatDSKEInfoPtr dske_info)
{
	if(dske_info) {
		chat_dake_destroy_info(&dske_info->dake_info);
	}
    free(dske_info);
}

ChatDSKEState chat_dske_info_get_state(ChatDSKEInfoPtr dske_info)
{
	return dske_info->state;
}

int chat_dske_init(ChatContextPtr ctx, ChatMessage **msgToSend)
{
	ChatDSKEInfoPtr dske_info;
    unsigned int my_pos;
    ChatParticipantPtr me, participant;
    SignKey *sign_key, *sign_key_pub_copy;
    DAKE *dake;
    OtrlListIteratorPtr iter, iter2;
    OtrlListNodePtr cur;
    DAKE_handshake_message_data *dataToSend;
    ChatMessage *msg = NULL;
    int err;

    fprintf(stderr,"chat_dske_init: start\n");

    /* Allocate memory for the info struct */
    dske_info = malloc(sizeof *dske_info);
    if(!dske_info) { goto error; }

    //chat_idkey_print(chat_context_get_identity_key(ctx));

    /* Find us in the participant list */
    me = chat_participant_find(chat_context_get_participants_list(ctx), chat_context_get_accountname(ctx), &my_pos);
    if(!me) { goto error_with_dske_info; }

    /* Get what values we should broadcast to every other user. dataToSend will
     * contain the data that will be sent in the handshake message. */
    err = chat_dake_init_keys(&dske_info->dake_info, chat_context_get_identity_key(ctx), chat_context_get_accountname(ctx),
                        chat_context_get_protocol(ctx), &dataToSend);
    if(err) { goto error_with_dske_info; }

    /* Initiate a dake for each participant. The dake struct holds information
     * regarding each individual DAKE with each participant. */
    iter = otrl_list_iterator_new(chat_context_get_participants_list(ctx));

    // TODO Dimitris error handling iterator
    while(otrl_list_iterator_has_next(iter)) {
    	cur = otrl_list_iterator_next(iter);
        participant = otrl_list_node_get_payload(cur);

        dake = malloc(sizeof *dake);
        if(!dake) { goto error_with_participants; }

        chat_participant_set_dake(participant, dake);

        err = chat_dake_init(chat_participant_get_dake(participant), &dske_info->dake_info);
        if(err) { goto error_with_participants; }
    }

    /* Create the message we should send */
    msg = chat_message_dake_handshake_new(ctx, dataToSend);
    if(!msg) { goto error_with_participants; }

    /* Change the protocol state */
    dske_info->remaining = otrl_list_size(chat_context_get_participants_list(ctx)) - 1;
    dske_info->state = CHAT_DSKESTATE_AWAITING_KEYS;

    fprintf(stderr,"chat_dske_init: before genkey\n");

    /* Generate an ephemeral signing key for this session */
    sign_key = chat_sign_genkey();
    if(!sign_key) { goto error_with_msg; }

    /* Copy the public part of the signing key in me */
    sign_key_pub_copy = chat_sign_copy_pub(sign_key);
    if(!sign_key) { goto error_with_sign_key; }

    //TODO    Is singing_key in context needed??
    //        Maybe generate it in a local variable instead of a context field
    //        KOSTIS
    chat_context_set_signing_key(ctx, sign_key);
    chat_participant_set_sign_key(me, sign_key_pub_copy);

    chat_context_set_dske_info(ctx, dske_info);

    *msgToSend = msg;

    fprintf(stderr,"chat_dske_init: end\n");
    return 0;

error_with_sign_key:
	chat_sign_destroy_key(sign_key);
error_with_msg:
	chat_message_free(msg);
error_with_participants:
	iter2 = otrl_list_iterator_new(chat_context_get_participants_list(ctx));
	if(iter2) {
		while(otrl_list_iterator_has_next(iter2)) {
			cur = otrl_list_iterator_next(iter2);
			participant = otrl_list_node_get_payload(cur);
			if(NULL != chat_participant_get_dake(participant)){
				chat_dake_destroy(chat_participant_get_dake(participant));
				free(chat_participant_get_dake(participant));
				chat_participant_set_dake(participant, NULL);
			}
		}
	}
	otrl_list_iterator_free(iter2);
	chat_dake_destroy_handshake_data(dataToSend);
	free(dataToSend);
error_with_dske_info:
	free(dske_info);
error:
	return 1;
}

int chat_dske_handle_handshake_message(ChatContextPtr ctx, ChatMessage *msg, OtrlListPtr fnprnt_list , ChatMessage **msgToSend, int *free_msg)
{
	ChatDSKEInfoPtr dske_info;
    ChatMessagePayloadDAKEHandshake *handshake_msg = msg->payload;
    ChatParticipantPtr sender;
    DAKE *sender_dake;
    DAKE_confirm_message_data *dataToSend;
    unsigned int pos;
    unsigned char *fingerprint;
    OtrlChatFingerprintPtr fnprnt;
    int err;

    fprintf(stderr,"chat_dske_handle_handshake_message: start\n");

    dske_info = chat_context_get_dske_info(ctx);

    sender = chat_participant_find(chat_context_get_participants_list(ctx), msg->senderName, &pos);
    if(!sender) { goto error; }

    if(NULL == dske_info || CHAT_DSKESTATE_NONE == dske_info->state){ goto error; }

    sender_dake = chat_participant_get_dake(sender);

    /* If we were not expecting a handshake from this user return err */
    if(!sender_dake || DAKE_STATE_WAITING_HANDSHAKE != sender_dake->state) { goto error; }

    /* Load the keys they sent us and determine what data we should send them */
    err = chat_dake_load_their_part(sender_dake, handshake_msg->handshake_data, &dataToSend, &fingerprint);
    if(err) { goto error; }

    /* Check if the fingerprint calculated during the dake exists in the list of known fingerprints
     * if not, add a new fingerprint in the list */
    fnprnt = chat_fingerprint_find(fnprnt_list, chat_context_get_accountname(ctx), chat_context_get_protocol(ctx) , chat_participant_get_username(sender), fingerprint);

    if (NULL == fnprnt) {
    	fnprnt = chat_fingerprint_new(chat_context_get_accountname(ctx), chat_context_get_protocol(ctx), chat_participant_get_username(sender), fingerprint, 0);
    	if(!fnprnt) { goto error_with_fingerprint; }

    	err = chat_fingerprint_add(fnprnt_list, fnprnt);
    	if(err) { goto error_with_fnprnt; }
    }

    /* Set a reference to the user's fingerprint */
    chat_participant_set_fingerprint(sender, fnprnt);

    /* Create the message we should send */
    *msgToSend = chat_message_dake_confirm_new(ctx, pos, dataToSend);
    if(!*msgToSend) { goto error_with_fingerprint; }

    free(fingerprint);

    fprintf(stderr,"chat_dske_handle_handshake_message: end\n");
    return 0;

error_with_fnprnt:
	chat_fingerprint_free(fnprnt);
error_with_fingerprint:
	free(fingerprint);
	chat_dake_destroy_confirm_data(dataToSend);
	free(dataToSend);
error:
	return 1;
}

int chat_dske_handle_confirm_message(ChatContextPtr ctx, ChatMessage *msg, ChatMessage **msgToSend, int *free_msg)
{
	ChatDSKEInfoPtr dske_info;
    ChatMessagePayloadDAKEConfirm *confirm_msg = msg->payload;
    DAKE_key_message_data *dataToSend;
    unsigned char *key_bytes = NULL;
    size_t key_len;
    ChatParticipantPtr sender;
    unsigned int their_pos;
    unsigned int our_pos;
    int err;

    fprintf(stderr,"libotr-mpOTR: chat_dske_handle_confirm_message: start\n");

    dske_info = chat_context_get_dske_info(ctx);

    sender = chat_participant_find(chat_context_get_participants_list(ctx), msg->senderName, &their_pos);
    if(!sender) { goto error; }

    err = chat_participant_get_position(chat_context_get_participants_list(ctx), chat_context_get_accountname(ctx), &our_pos);
    if(err) { goto error; }

    if(confirm_msg->recipient != our_pos) { goto error; }

    /* Check if we shouldn't have received this message */
    if(CHAT_DSKESTATE_AWAITING_KEYS != dske_info->state) { goto error; }

    if(DAKE_STATE_WAITING_CONFIRM != chat_participant_get_dake(sender)->state){ goto error; }

    /* Verify that we have computed the same shared secret */
    err = chat_dake_verify_confirm(chat_participant_get_dake(sender), confirm_msg->data->mac);
    if(err) { goto error; }

    /* Get the serialized pubkey */
    err = chat_sign_serialize_pubkey(chat_context_get_signing_key(ctx), &key_bytes, &key_len);
    if(err) { goto error; }

    /* Encrypt and authenticate our pubkey to send the to the other party */
    err = chat_dake_send_key(chat_participant_get_dake(sender), key_bytes, key_len, &dataToSend);
    if(err) { goto error_with_key_bytes; }

    /* Create the message to send */
    *msgToSend = chat_message_dake_key_new(ctx, their_pos, dataToSend);
    if(!*msgToSend) { goto error_with_key_bytes; }

    free(key_bytes);

    fprintf(stderr,"chat_dske_handle_confirm_message: end\n");

    return 0;

error_with_key_bytes:
	free(key_bytes);
error:
	return 1;
}

int chat_dske_handle_key_message(ChatContextPtr ctx, ChatMessage *msg,
                                 ChatMessage **msgToSend, int *free_msg)
{
	ChatDSKEInfoPtr dske_info;
    ChatMessagePayloadDAKEKey *key_msg = msg->payload;
    ChatParticipantPtr sender;
    SignKey *sign_key;
    unsigned char *plain_key;
    size_t keylen;
    unsigned int our_pos, their_pos;
    int err;

    fprintf(stderr,"chat_dske_handle_key_message: start\n");

    dske_info = chat_context_get_dske_info(ctx);

    sender = chat_participant_find(chat_context_get_participants_list(ctx), msg->senderName, &their_pos);
    if(!sender) { goto error; }

    err = chat_participant_get_position(chat_context_get_participants_list(ctx), chat_context_get_accountname(ctx), &our_pos);
    if(err) { goto error; }

    if(key_msg->recipient !=  our_pos) { goto error; }

    if(CHAT_DSKESTATE_AWAITING_KEYS != dske_info->state) { goto error; }

    if(DAKE_STATE_WAITING_KEY != chat_participant_get_dake(sender)->state) { goto error; }

    //error = chat_dake_auth_decrypt(sender->dake, key_msg->data.key, key_msg->data.keylen, plain_key,
    //                               key_msg->data.mac);
    err = chat_dake_receive_key(chat_participant_get_dake(sender), key_msg->data, &plain_key, &keylen);
    if(err) { goto error; }

    sign_key = chat_sign_parse_pubkey(plain_key, keylen);
    free(plain_key);
    if(!sign_key) { goto error; }

    chat_participant_set_sign_key(sender, sign_key);

    chat_participant_get_dake(sender)->state = DAKE_STATE_DONE;
    dske_info->remaining -= 1;
    if(dske_info->remaining == 0) {
    	dske_info->state = CHAT_DSKESTATE_FINISHED;
    }

    fprintf(stderr,"chat_dske_handle_key_message: end\n");
    return 0;

error:
	return 1;

}

int chat_dske_handle_message(ChatContextPtr ctx, ChatMessage *msg, OtrlListPtr fnprnt_list,
                             ChatMessage **msgToSend) {
	ChatMessageType msgType = msg->msgType;
	int free_msg;

	switch(msgType) {
		case CHAT_MSGTYPE_DAKE_HANDSHAKE:
			return chat_dske_handle_handshake_message(ctx, msg, fnprnt_list, msgToSend, &free_msg);
		case CHAT_MSGTYPE_DAKE_CONFIRM:
			return chat_dske_handle_confirm_message(ctx, msg, msgToSend, &free_msg);
		case CHAT_MSGTYPE_DAKE_KEY:
			return chat_dske_handle_key_message(ctx, msg, msgToSend, &free_msg);
		default:
			return 1;
	}
}

int chat_dske_is_my_message(const ChatMessage *msg)
{
	ChatMessageType msg_type = msg->msgType;

	switch(msg_type) {
	case CHAT_MSGTYPE_DAKE_HANDSHAKE:
	case CHAT_MSGTYPE_DAKE_CONFIRM:
	case CHAT_MSGTYPE_DAKE_KEY:
			return 1;
		default:
			return 0;
	}
}
