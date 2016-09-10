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

#include "chat_types.h"
#include "chat_message.h"
#include "chat_sign.h"
#include "chat_participant.h"

#define CONSENSUS_HASH_LEN 64

int get_consensus_hash(const OtrlList *participants_list, unsigned char *result)
{
    gcry_md_hd_t md;
    gcry_error_t err;
    OtrlListNode *cur = NULL;
    ChatParticipant *participant = NULL;
    size_t len;
    unsigned char *hash_result = NULL;

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_get_hashes_hash: start\n");

    err = gcry_md_open(&md, GCRY_MD_SHA512, 0);
    if(err) {
        return err;
    }

    for(cur = participants_list->head; cur != NULL; cur = cur->next)
    {
        participant = cur->payload;
        len = MESSAGES_HASH_LEN;

        gcry_md_write(md, participant->messages_hash, len);
    }

    gcry_md_final(md);
    hash_result = gcry_md_read(md, GCRY_MD_SHA512);
    if(!hash_result) {
        gcry_md_close(md);
        return 1;
    }

    memcpy(result, hash_result, gcry_md_get_algo_dlen(GCRY_MD_SHA512));

    gcry_md_close(md);

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_get_hashes_hash: end\n");

    return 0;
}

void chat_shutdown_info_destroy(ShutdownInfo *shutdown_info)
{
	free(shutdown_info->has_send_end);
    free(shutdown_info->consensus_hash);
}

int chat_shutdown_init(OtrlChatContext *ctx)
{
    //OtrlListNode *cur;
    //OtrlChatParticipant *participant;
    //int error = 0;

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_init: start\n");

    ctx->shutdown_info.has_send_end = calloc(otrl_list_length(ctx->participants_list),
                                             sizeof(*ctx->shutdown_info.has_send_end));
    if(!ctx->shutdown_info.has_send_end){
        return 1;
    }

    ctx->shutdown_info.shutdowns_remaining = otrl_list_length(ctx->participants_list);
    ctx->shutdown_info.digests_remaining = ctx->shutdown_info.shutdowns_remaining;
    ctx->shutdown_info.ends_remaining = ctx->shutdown_info.shutdowns_remaining;
    ctx->shutdown_info.state = CHAT_SHUTDOWNSTATE_AWAITING_SHUTDOWNS;

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_init: end\n");

    return 0;
}

int chat_shutdown_send_shutdown(OtrlChatContext *ctx, ChatMessage **msgToSend)
{
    ChatParticipant *me;
    unsigned int my_pos;
    unsigned char my_hash[MESSAGES_HASH_LEN];

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_send_shutdown: start\n");

    me = chat_participant_find(ctx, ctx->accountname, &my_pos);
    if(!me) {
        return 1;
    }

    if(1 <= ctx->shutdown_info.has_send_end[my_pos]) {
        return 1;
    }

    if(chat_participant_get_messages_hash(me, my_hash)) {
        return 1;
    }

    *msgToSend = chat_message_shutdown_shutdown_create(ctx, my_hash);
    if(!*msgToSend) {
    	return 1;
    }

    ctx->shutdown_info.has_send_end[my_pos] = 1; // True
    ctx->shutdown_info.shutdowns_remaining -= 1;
    if(0 ==ctx->shutdown_info.shutdowns_remaining) {
        ctx->shutdown_info.consensus_hash = malloc(CONSENSUS_HASH_LEN * sizeof(*ctx->shutdown_info.consensus_hash));
        if(!ctx->shutdown_info.consensus_hash) {
            return 1;
        }

        if(get_consensus_hash(ctx->participants_list, ctx->shutdown_info.consensus_hash)) {
           return 1;
        }

        ctx->shutdown_info.state = CHAT_SHUTDOWNSTATE_AWAITING_DIGESTS;
    }

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_send_shutdown: end\n");
    return 0;
}

int chat_shutdown_handle_shutdown_message(OtrlChatContext *ctx, ChatMessage *msg,
                                 ChatMessage **msgToSend)
{
    ChatParticipant *sender;
    unsigned int their_pos;
    int error = 0;
    fprintf(stderr, "libotr-mpOTR: chat_shutdown_handle_shutdown: start\n");

    /* Get the sender from the participants list. If not found return error */
    sender = chat_participant_find(ctx, msg->senderName, &their_pos);
    if(!sender) {
        return 1;
    }

    /* Verify that we expected this message */
    if(ctx->shutdown_info.state != CHAT_SHUTDOWNSTATE_AWAITING_SHUTDOWNS) {
        return 1;
    }

    /* If we have already received the shutdown message from this user return
       success */
    if(1 <= ctx->shutdown_info.has_send_end[their_pos]) {
        return 1;
    }

    /* Remember that this user has sent us a shutdown */
    ctx->shutdown_info.has_send_end[their_pos] = 1; // True
    ctx->shutdown_info.shutdowns_remaining -= 1;

    /* Hash the participants messages and store them in sender */
    if(chat_participant_get_messages_hash(sender, sender->messages_hash)) {
        return 1;
    }

    /* Check if we have received shutdown messages from everybody.
       If yes then send a digest */
    if(0 == ctx->shutdown_info.shutdowns_remaining) {
        ctx->shutdown_info.consensus_hash = malloc(CONSENSUS_HASH_LEN * sizeof(*ctx->shutdown_info.consensus_hash));
        if(!ctx->shutdown_info.consensus_hash) {
            return 1;
        }

        if(get_consensus_hash(ctx->participants_list, ctx->shutdown_info.consensus_hash)) {
           return 1;
        }

        //*msgToSend = chat_message_shutdown_digest_create(ctx,
                                                         //ctx->shutdown_info.consensus_hash);
        //if(!*msgToSend) {
        //    return 1;
        //}

        ctx->shutdown_info.state = CHAT_SHUTDOWNSTATE_AWAITING_DIGESTS;
    }
    /* If not then we maybe have to send a shutdown message */
    else {
        fprintf(stderr, "libotr-mpOTR: chat_shutdown_handle_shutdown: send shutdown");
        error = chat_shutdown_send_shutdown(ctx, msgToSend);
        if(error) {
            return 1;
        }
    }

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_handle_shutdown: end\n");
    return 0;
}

int chat_shutdown_send_digest(OtrlChatContext *ctx, ChatMessage **msgToSend)
{
    ChatParticipant *me;
    unsigned int my_pos;

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_send_digest: start\n");

    me = chat_participant_find(ctx, ctx->accountname, &my_pos);
    if(!me) {
    fprintf(stderr, "libotr-mpOTR: chat_shutdown_send_digest: me not found\n");
        return 1;
    }

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_send_digest: after find\n");

    if(2 <= ctx->shutdown_info.has_send_end[my_pos]) {
        return 1;
    }

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_send_digest: after has_send check\n");

    *msgToSend = chat_message_shutdown_digest_create(ctx, ctx->shutdown_info.consensus_hash);
    if(!*msgToSend) {
    	return 1;
    }

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_send_digest: after create\n");

    ctx->shutdown_info.has_send_end[my_pos] = 2;
    ctx->shutdown_info.digests_remaining -= 1;
    if(0 ==ctx->shutdown_info.digests_remaining) {
    fprintf(stderr, "libotr-mpOTR: chat_shutdown_send_digest: waiting ends\n");
        ctx->shutdown_info.state = CHAT_SHUTDOWNSTATE_AWAITING_ENDS;
    }

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_send_digest: end\n");
    return 0;
}

int chat_shutdown_handle_digest_message(OtrlChatContext *ctx, ChatMessage *msg, ChatMessage **msgToSend)
{
    ChatMessagePayloadShutdownDigest *digest_msg = msg->payload;
    ChatParticipant *sender;
    unsigned int their_pos;


    fprintf(stderr, "libotr-mpOTR: chat_shutdown_handle_digest_message: start\n");

    /* Get the sender from the participants list. If not found return error */
    sender = chat_participant_find(ctx, msg->senderName, &their_pos);
    if(!sender) {
        return 1;
    }

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_handle_digest_message: after sender find\n");
    /* Verify that we expected this message */
    if(ctx->shutdown_info.state != CHAT_SHUTDOWNSTATE_AWAITING_DIGESTS) {
        return 1;
    }

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_handle_digest_message: after state check\n");
    /* If we have already received the shutdown message from this user return
       success */
    if(2 <= ctx->shutdown_info.has_send_end[their_pos]) {
        return 1;
    }

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_handle_digest_message: after has_send check\n");
    /* Remember that this user has sent us a digest */
    ctx->shutdown_info.has_send_end[their_pos] = 2; // True
    ctx->shutdown_info.digests_remaining -= 1;

    //if(!memcmp(digest_msg->digest, ctx->shutdown_info.consensus_hash, CONSENSUS_HASH_LEN)) {
    //   sender->consensus = 1;
    //}
    //else {
    //    sender->consensus = 0;
    //}

    /* Determine consensus with this user */
    sender->consensus = memcmp(digest_msg->digest, ctx->shutdown_info.consensus_hash, CONSENSUS_HASH_LEN) ? 0 : 1;

    if(0 == ctx->shutdown_info.digests_remaining) {
        fprintf(stderr, "libotr-mpOTR: chat_shutdown_handle_digest_message: waiting ends\n");
        ctx->shutdown_info.state = CHAT_SHUTDOWNSTATE_AWAITING_ENDS;
        //*msgToSend = chat_message_shutdown_end_create(ctx);
        //if(!*msgToSend) {
        //   return 1;
        //}
    }

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_handle_digest_message: end\n");
    return 0;

}

int chat_shutdown_send_end(OtrlChatContext *ctx, ChatMessage **msgToSend)
{
    ChatParticipant *me = NULL;
    unsigned int my_pos;

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_send_end: start\n");

    me = chat_participant_find(ctx, ctx->accountname, &my_pos);
    if(!me) {
        return 1;
    }

    if(3 <= ctx->shutdown_info.has_send_end[my_pos]) {
        return 0;
    }

    *msgToSend = chat_message_shutdown_end_create(ctx);
    if(!*msgToSend) {
        return 1;
    }

    ctx->shutdown_info.has_send_end[my_pos] = 3; // True
    ctx->shutdown_info.ends_remaining -= 1;

    if(0 == ctx->shutdown_info.ends_remaining){
        ctx->shutdown_info.state = CHAT_SHUTDOWNSTATE_FINISHED;
    }

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_send_end: start\n");
    return 0;
}

int chat_shutdown_handle_end_message(OtrlChatContext *ctx, ChatMessage *msg, ChatMessage **msgToSend)
{
    ChatParticipant *sender;
    unsigned int their_pos;


    fprintf(stderr, "libotr-mpOTR: chat_shutdown_handle_end_message: start\n");

    /* Get the sender from the participants list. If not found return error */
    sender = chat_participant_find(ctx, msg->senderName, &their_pos);
    if(!sender) {
        return 1;
    }

    /* Verify that we expected this message */
    if(ctx->shutdown_info.state != CHAT_SHUTDOWNSTATE_AWAITING_ENDS) {
        return 1;
    }

    /* If we have already received the shutdown message from this user return
       success */
    if(3 <= ctx->shutdown_info.has_send_end[their_pos]) {
        return 1;
    }

    /* Hash the participants messages and store them in sender */
    if(chat_participant_get_messages_hash(sender, sender->messages_hash)) {
        return 1;
    }
    /* Remember that this user has sent us a digest */
    ctx->shutdown_info.has_send_end[their_pos] = 3; // True
    ctx->shutdown_info.ends_remaining -= 1;

    if(0 == ctx->shutdown_info.ends_remaining){
        ctx->shutdown_info.state = CHAT_SHUTDOWNSTATE_FINISHED;
    }

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_handle_end_message: start\n");
    return 0;
}

int chat_shutdown_release_secrets(OtrlChatContext *ctx, ChatMessage **msgToSend)
{
    unsigned char *key_bytes;
    size_t keylen;
    int error = 0;

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_release_secrets: start\n");

    error = chat_sign_serialize_privkey(ctx->signing_key, &key_bytes, &keylen);
    if(error) {
        return 1;
    }

	*msgToSend = chat_message_shutdown_keyrelease_create(ctx, key_bytes, keylen);
	if(!*msgToSend) {
		return 1;
	}

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_release_secrets: end\n");

	return 0;
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

int chat_shutdown_handle_message(OtrlChatContext *ctx, ChatMessage *msg,
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
