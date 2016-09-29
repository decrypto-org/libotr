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

#include "chat_shutdown.h"

#include "chat_context.h"
#include "chat_message.h"
#include "chat_participant.h"
#include "chat_sign.h"
#include "chat_types.h"
#include "list.h"

#define CONSENSUS_HASH_LEN 64

struct ChatShutdownInfo{
	int shutdowns_remaining;
	int digests_remaining;
	int ends_remaining;
	unsigned char *has_send_end;
	unsigned char *consensus_hash;
	ChatShutdownState state;
};

int get_consensus_hash(OtrlListPtr participants_list, unsigned char *result)
{
    gcry_md_hd_t md;
    gcry_error_t err;
    OtrlListIteratorPtr iter;
    OtrlListNodePtr cur;
    ChatParticipantPtr participant;
    size_t len;
    unsigned char *hash_result = NULL;

    /* Open a digest */
    err = gcry_md_open(&md, GCRY_MD_SHA512, 0);
    if(err) { goto error; }

    /* Iterate over each participant in partipants_list */
    iter = otrl_list_iterator_new(participants_list);
    if(!iter) { goto error_with_md; }
    while(otrl_list_iterator_has_next(iter)) {
    	cur = otrl_list_iterator_next(iter);
        participant = otrl_list_node_get_payload(cur);
        len = MESSAGES_HASH_LEN;
        /* Write the participant's messages_hash to the digest */
        gcry_md_write(md, chat_participant_get_messages_hash(participant), len);
    }

    /* Finalize the digest */
    gcry_md_final(md);
    /* And read the calculated hash */
    hash_result = gcry_md_read(md, GCRY_MD_SHA512);
    if(!hash_result) { goto error_with_iter; }

    /* Copy the result in the output buffer */
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

ChatShutdownState chat_shutdown_info_get_state(ChatShutdownInfoPtr shutdown_info)
{
	return shutdown_info->state;
}

void chat_shutdown_info_free(ChatShutdownInfoPtr shutdown_info)
{
	if(shutdown_info) {
		free(shutdown_info->has_send_end);
		free(shutdown_info->consensus_hash);
	}
	free(shutdown_info);
}

int chat_shutdown_init(ChatContextPtr ctx)
{
	ChatShutdownInfoPtr shutdown_info;

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_init: start\n");

    shutdown_info = malloc(sizeof *shutdown_info);
    if(!shutdown_info) { goto error; }

    /* Initiliaze the state of each participant */
    shutdown_info->has_send_end = calloc(otrl_list_size(chat_context_get_participants_list(ctx)), sizeof *shutdown_info->has_send_end);
    if(!shutdown_info->has_send_end){ goto error_with_info; }

    /* We expect a shutdown/digest/end message from all the participants */
    shutdown_info->shutdowns_remaining = otrl_list_size(chat_context_get_participants_list(ctx));
    shutdown_info->digests_remaining = shutdown_info->shutdowns_remaining;
    shutdown_info->ends_remaining = shutdown_info->shutdowns_remaining;

    /* The initial state of the protocol is to wait for shutdown messages */
    shutdown_info->state = CHAT_SHUTDOWNSTATE_AWAITING_SHUTDOWNS;

    chat_context_set_shutdown_info(ctx, shutdown_info);

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_init: end\n");

    return 0;
error_with_info:
	free(shutdown_info);
error:
	return 1;
}
int chat_shutdown_send_shutdown(ChatContextPtr ctx, ChatMessage **msgToSend)
{
	ChatShutdownInfoPtr shutdown_info;
    ChatParticipantPtr me;
    unsigned int my_pos;
    int err;

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_send_shutdown: start\n");

    shutdown_info = chat_context_get_shutdown_info(ctx);
    if(!shutdown_info) { goto error; }

    /* Find us in the participants list */
    me = chat_participant_find(chat_context_get_participants_list(ctx), chat_context_get_accountname(ctx), &my_pos);
    if(!me) { goto error; }

    /* If we have already sent a shutdown return error */
    if(1 <= shutdown_info->has_send_end[my_pos]) { goto error; }

    /* Calculate our messages hash, and store it for later */
    // TODO Dimitris: here getter plays the role of a setter, maybe refactor this and free in error handling
    err = chat_participant_calculate_messages_hash(me, chat_participant_get_messages_hash(me));
    if(err) { goto error; }

    /* Create a shutdown message */
    *msgToSend = chat_message_shutdown_shutdown_new(ctx, chat_participant_get_messages_hash(me));
    if(!*msgToSend) { goto error; }

    /* We have sent a shutdown message so update our state */
    shutdown_info->has_send_end[my_pos] = 1;

    /* We wait for one less shutdown message since we just sent one */
    shutdown_info->shutdowns_remaining -= 1;

    /* If everybode has sent us a shutdown message then we must proceed to the next phase */
    if(0 == shutdown_info->shutdowns_remaining) {
        /* Allocate memory for the consensus hash */
        shutdown_info->consensus_hash = malloc(CONSENSUS_HASH_LEN * sizeof *shutdown_info->consensus_hash);
        if(!shutdown_info->consensus_hash) { goto error; }

        /* And calculate the hash itself */
        err =  get_consensus_hash(chat_context_get_participants_list(ctx), shutdown_info->consensus_hash);
        if(err) { goto error_with_consensus_hash; }

        /* Set the state to wait for digest messages */
        shutdown_info->state = CHAT_SHUTDOWNSTATE_AWAITING_DIGESTS;
    }

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_send_shutdown: end\n");
    return 0;

error_with_consensus_hash:
	free(shutdown_info->consensus_hash);
error:
	return 1;
}

int chat_shutdown_handle_shutdown_message(ChatContextPtr ctx, ChatMessage *msg,
                                 ChatMessage **msgToSend)
{
	ChatShutdownInfoPtr shutdown_info;
    ChatParticipantPtr sender;
    unsigned int their_pos;
    int err;

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_handle_shutdown: start\n");

    shutdown_info = chat_context_get_shutdown_info(ctx);
    if(!shutdown_info) { goto error; }

    /* Get the sender from the participants list. If not found return error */
    sender = chat_participant_find(chat_context_get_participants_list(ctx), msg->senderName, &their_pos);
    if(!sender) { goto error; }

    /* Verify that we expected this message */
    if(CHAT_SHUTDOWNSTATE_AWAITING_SHUTDOWNS != shutdown_info->state) { goto error; }

    /* If we have already received the shutdown message from this user return
       success */
    if(1 <= shutdown_info->has_send_end[their_pos]) { goto error; }

    /* Remember that this user has sent us a shutdown */
    shutdown_info->has_send_end[their_pos] = 1; // True
    shutdown_info->shutdowns_remaining -= 1;

    /* Hash the participants messages and store them in sender */
    //TODO Dimitris: here getter plays the role of a setter, maybe refactor this and free in error handling
    err = chat_participant_calculate_messages_hash(sender, chat_participant_get_messages_hash(sender));
    if(err) { goto error; }

    /* Check if we have received shutdown messages from everybody.
       If yes then send a digest */
    if(0 == shutdown_info->shutdowns_remaining) {
        /* Allocate memory for the consensus hash */
        shutdown_info->consensus_hash = malloc(CONSENSUS_HASH_LEN * sizeof *shutdown_info->consensus_hash);
        if(!shutdown_info->consensus_hash) { goto error; }

        /* And calculate it */
        err = get_consensus_hash(chat_context_get_participants_list(ctx), shutdown_info->consensus_hash);
        if(err) { goto error; }

        /* Set the state so that we wait for digest messages */
        shutdown_info->state = CHAT_SHUTDOWNSTATE_AWAITING_DIGESTS;

    /* If not then we maybe have to send a shutdown message */
    } else {
        err = chat_shutdown_send_shutdown(ctx, msgToSend);
        if(err) { goto error; }
    }

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_handle_shutdown: end\n");
    return 0;

error:
	return 1;
}

int chat_shutdown_send_digest(ChatContextPtr ctx, ChatMessage **msgToSend)
{
	ChatShutdownInfoPtr shutdown_info;
    ChatParticipantPtr me;
    unsigned int my_pos;

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_send_digest: start\n");

    shutdown_info = chat_context_get_shutdown_info(ctx);
    if(!shutdown_info) { goto error; }

    /* Find us in the participants list */
    me = chat_participant_find(chat_context_get_participants_list(ctx), chat_context_get_accountname(ctx), &my_pos);
    if(!me) { goto error; }

    /* If we already sent a digest message return error */
    if(2 <= shutdown_info->has_send_end[my_pos]) { goto error; }

    /* Create a digest message to send */
    *msgToSend = chat_message_shutdown_digest_new(ctx, shutdown_info->consensus_hash);
    if(!*msgToSend) { goto error; }

    /* Remember that we sent a digest */
    shutdown_info->has_send_end[my_pos] = 2;

    /* And we now wait for one less shutdown */
    shutdown_info->digests_remaining -= 1;

    /* If there are no more digest messages pending then update the state */
    if(0 == shutdown_info->digests_remaining) {
        /* We now wait for end messages */
        shutdown_info->state = CHAT_SHUTDOWNSTATE_AWAITING_ENDS;
    }

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_send_digest: end\n");
    return 0;

error:
	return 1;
}

int chat_shutdown_handle_digest_message(ChatContextPtr ctx, ChatMessage *msg, ChatMessage **msgToSend)
{
	ChatShutdownInfoPtr shutdown_info;
    ChatMessagePayloadShutdownDigest *digest_msg = msg->payload;
    ChatParticipantPtr sender;
    int consensus;
    unsigned int their_pos;

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_handle_digest_message: start\n");

    shutdown_info = chat_context_get_shutdown_info(ctx);
    if(!shutdown_info) { goto error; }

    /* Get the sender from the participants list. If not found return error */
    sender = chat_participant_find(chat_context_get_participants_list(ctx), msg->senderName, &their_pos);
    if(!sender) { goto error; }

    /* Verify that we expected this message */
    if(CHAT_SHUTDOWNSTATE_AWAITING_DIGESTS != shutdown_info->state) { goto error; }

    /* If we have already received the shutdown message from this user return
       success */
    if(2 <= shutdown_info->has_send_end[their_pos]) { goto error; }

    /* Remember that this user has sent us a digest */
    shutdown_info->has_send_end[their_pos] = 2; // True

    /* We need to wait for one less digest message now */
    shutdown_info->digests_remaining -= 1;

    /* Determine consensus with this user */
    consensus = memcmp(digest_msg->digest, shutdown_info->consensus_hash, CONSENSUS_HASH_LEN) ? 0 : 1;
    chat_participant_set_consensus(sender, consensus);

    fprintf(stderr, "libotr-mpOTR: local digest: ");
    for(int i = 0; i < CONSENSUS_HASH_LEN; i++)
        fprintf(stderr, "%0X", shutdown_info->consensus_hash[i]);
    fprintf(stderr, "\nlibotr-mpOTR: received digest: ");
    for(int i = 0; i < CONSENSUS_HASH_LEN; i++)
        fprintf(stderr, "%0X", digest_msg->digest[i]);
    fprintf(stderr, "\n");


    /* If there are no more pending digest messages update the state */
    if(0 == shutdown_info->digests_remaining) {
        /* We now wait for end messages */
        shutdown_info->state = CHAT_SHUTDOWNSTATE_AWAITING_ENDS;
    }

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_handle_digest_message: end\n");
    return 0;

error:
	return 1;
}

int chat_shutdown_send_end(ChatContextPtr ctx, ChatMessage **msgToSend)
{
	ChatShutdownInfoPtr shutdown_info;
    ChatParticipantPtr me;
    unsigned int my_pos;

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_send_end: start\n");

    shutdown_info = chat_context_get_shutdown_info(ctx);
    if(!shutdown_info) { goto error; }

    /* Find us in the participant list */
    me = chat_participant_find(chat_context_get_participants_list(ctx), chat_context_get_accountname(ctx), &my_pos);
    if(!me) { goto error; }

    /* If we already sent an end message return error */
    if(3 <= shutdown_info->has_send_end[my_pos]) { goto error; }

    /* Create an end message to send */
    *msgToSend = chat_message_shutdown_end_new(ctx);
    if(!*msgToSend) { goto error; }

    /* Remember that we sent an end message */
    shutdown_info->has_send_end[my_pos] = 3;

    /* Decrement the pending end messages */
    shutdown_info->ends_remaining -= 1;

    /* If there are no more pending messages then update the state */
    if(0 == shutdown_info->ends_remaining){
        /* We have finished the shutdown subprotocol */
    	shutdown_info->state = CHAT_SHUTDOWNSTATE_FINISHED;
    }

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_send_end: start\n");
    return 0;

error:
	return 1;
}

int chat_shutdown_handle_end_message(ChatContextPtr ctx, ChatMessage *msg, ChatMessage **msgToSend)
{
	ChatShutdownInfoPtr shutdown_info;
    ChatParticipantPtr sender;
    unsigned int their_pos;

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_handle_end_message: start\n");

    shutdown_info = chat_context_get_shutdown_info(ctx);
    if(!shutdown_info) { goto error; }

    /* Get the sender from the participants list. If not found return error */
    sender = chat_participant_find(chat_context_get_participants_list(ctx), msg->senderName, &their_pos);
    if(!sender) { goto error; }

    /* Verify that we expected this message */
    if(CHAT_SHUTDOWNSTATE_AWAITING_ENDS != shutdown_info->state) { goto error; }

    /* If we have already received the shutdown message from this user return
       success */
    if(3 <= shutdown_info->has_send_end[their_pos]) { goto error; }

    /* Hash the participants messages and store them in sender */
    //TODO Dimtiris: here getter plays the role of a setter, maybe refactor this and free in error handling
    if(chat_participant_calculate_messages_hash(sender, chat_participant_get_messages_hash(sender))) { goto error;  }

    /* Remember that this user has sent us a digest */
    shutdown_info->has_send_end[their_pos] = 3; // True
    shutdown_info->ends_remaining -= 1;

    /* If there are no more pending messages update the state */
    if(0 == shutdown_info->ends_remaining){
        /* We have finished the shutdown protocol */
    	shutdown_info->state = CHAT_SHUTDOWNSTATE_FINISHED;
    }

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_handle_end_message: start\n");
    return 0;

error:
	return 1;
}

int chat_shutdown_release_secrets(ChatContextPtr ctx, ChatMessage **msgToSend)
{
    unsigned char *key_bytes = NULL;
    size_t keylen;
    int error = 0;

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_release_secrets: start\n");

    /* Serialize the private part of the signing key */
    error = chat_sign_serialize_privkey(chat_context_get_signing_key(ctx), &key_bytes, &keylen);
    if(error) { goto error; }

    /* Create a key release message */
	*msgToSend = chat_message_shutdown_keyrelease_new(ctx, key_bytes, keylen);
	if(!*msgToSend) { goto error_with_key_bytes; }

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_release_secrets: end\n");

	return 0;

error_with_key_bytes:
	free(key_bytes);
error:
	return 1;
}

int chat_shutdown_is_my_message(const ChatMessage *msg)
{
	ChatMessageType msg_type = msg->msgType;

    switch(msg_type) {
        case CHAT_MSGTYPE_SHUTDOWN_SHUTDOWN:
        case CHAT_MSGTYPE_SHUTDOWN_DIGEST:
        case CHAT_MSGTYPE_SHUTDOWN_END:
            return 1;
        default:
            return 0;
    }
}

int chat_shutdown_handle_message(ChatContextPtr ctx, ChatMessage *msg,
                                 ChatMessage **msgToSend)
{
	ChatMessageType msgType = msg->msgType;
    switch(msgType) {
        case CHAT_MSGTYPE_SHUTDOWN_SHUTDOWN:
            return chat_shutdown_handle_shutdown_message(ctx, msg, msgToSend);
        case CHAT_MSGTYPE_SHUTDOWN_DIGEST:
            return chat_shutdown_handle_digest_message(ctx, msg, msgToSend);
        case CHAT_MSGTYPE_SHUTDOWN_END:
            return chat_shutdown_handle_end_message(ctx, msg, msgToSend);
        default:
            return 0;
    }
}
