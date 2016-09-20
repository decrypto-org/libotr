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

#include "chat_attest.h"

#include <gcrypt.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "chat_context.h"
#include "chat_message.h"
#include "chat_participant.h"
#include "chat_protocol.h"
#include "chat_sign.h"
#include "chat_types.h"
#include "context.h"
#include "list.h"

struct ChatAttestInfoStruct {
	size_t size;
	size_t checked_count;
	unsigned short int *checked;
	ChatAttestState state;
};

ChatAttestInfo chat_attest_info_new(size_t size)
{
	ChatAttestInfo attest_info;

	attest_info = malloc(sizeof *attest_info);
	if(!attest_info) { goto error; }

	attest_info->size = size;
	attest_info->checked_count = 0;

	attest_info->checked = calloc(attest_info->size, sizeof *(attest_info->checked));
	if(!attest_info->checked) { goto error_with_attest_info; }

	attest_info->state = CHAT_ATTESTSTATE_AWAITING;

	return attest_info;

error_with_attest_info:
	free(attest_info);
error:
	return NULL;
}

ChatAttestState chat_attest_info_get_state(ChatAttestInfo attest_info)
{
	return attest_info->state;
}

void chat_attest_info_free(ChatAttestInfo attest_info)
{
	if(attest_info) {
		free(attest_info->checked);
	}
	free(attest_info);
}

int chat_attest_assoctable_hash(OtrlList participants_list, unsigned char **hash)
{
	OtrlListIterator iter;
	OtrlListNode cur;
	ChatParticipant participant;
	unsigned char *buf = NULL, *key = NULL;
	gcry_md_hd_t md;
	gcry_error_t g_err;
    int err;
	size_t len;

	g_err = gcry_md_open(&md, GCRY_MD_SHA512, 0);
	if(g_err) { goto error; }

	iter = otrl_list_iterator_new(participants_list);
	if(!iter) { goto error_with_md; }

	while(otrl_list_iterator_has_next(iter)) {
		cur = otrl_list_iterator_next(iter);
		participant = otrl_list_node_get_payload(cur);

		if(NULL == chat_participant_get_sign_key(participant)) { goto error_with_iter; }

		err = chat_sign_serialize_pubkey(chat_participant_get_sign_key(participant), &key, &len);
        if(err) { goto error_with_iter; }

		gcry_md_write(md, key, len);
		free(key);
	}

	buf = malloc(CHAT_ATTEST_ASSOCTABLE_HASH_LENGTH * sizeof *buf);
	if(!buf) { goto error_with_iter; }

	memcpy(buf, gcry_md_read(md, GCRY_MD_SHA512), CHAT_ATTEST_ASSOCTABLE_HASH_LENGTH);

	otrl_list_iterator_free(iter);
	gcry_md_close(md);

	*hash = buf;
	return 0;

error_with_iter:
	otrl_list_iterator_free(iter);
error_with_md:
	gcry_md_close(md);
error:
	return 1;
}

int chat_attest_verify_sid(ChatContext ctx, unsigned char *sid)
{
	int res, eq;

	eq = memcmp(chat_context_get_sid(ctx), sid, CHAT_OFFER_SID_LENGTH);
	res = (eq==0) ? 1 : 0;

	return res;
}

int chat_attest_verify_assoctable_hash(OtrlList participants_list, unsigned char *hash, int *result)
{
	int err, res, eq;
	unsigned char *ourhash;

	err = chat_attest_assoctable_hash(participants_list, &ourhash);
	if(err) { goto error; }

	eq = memcmp(ourhash, hash, CHAT_ATTEST_ASSOCTABLE_HASH_LENGTH);

	res = (eq==0) ? 1 : 0;

	free(ourhash);

	*result = res;
	return 0;

error:
	return 1;
}

int chat_attest_is_ready(ChatAttestInfo attest_info)
{
	return (attest_info->checked_count == attest_info->size) ? 1 : 0;
}

int chat_attest_verify(ChatContext ctx, unsigned char *sid, unsigned char *assoctable_hash, unsigned int part_pos, int *result)
{
	ChatAttestInfo attest_info;
	int err, res;

	attest_info = chat_context_get_attest_info(ctx);
	if(!attest_info) { goto error; }

	if(part_pos >= attest_info->size) { goto error; }

	if(attest_info->checked[part_pos]) {
		attest_info->checked[part_pos] = 0;
		attest_info->checked_count--;
	}

	res = chat_attest_verify_sid(ctx, sid);
	if(res) {
		err = chat_attest_verify_assoctable_hash(chat_context_get_participants_list(ctx), assoctable_hash, &res);
		if(err) { goto error; }
	}

	if(res) {
		attest_info->checked[part_pos] = 1;
		attest_info->checked_count++;
	}

	*result = res;
	return 0;

error:
	return 1;

}

int chat_attest_info_init(ChatContext ctx)
{
	size_t size;
	ChatAttestInfo attest_info;

	size = otrl_list_size(chat_context_get_participants_list(ctx));

	attest_info = chat_attest_info_new(size);
	if(!attest_info) { goto error; }

	chat_attest_info_free(chat_context_get_attest_info(ctx));

	chat_context_set_attest_info(ctx, attest_info);

	return 0;

error:
	return 1;
}

int chat_attest_create_our_message(ChatContext ctx, unsigned int our_pos , ChatMessage **msgToSend)
{
	int err;
	unsigned char *assoctable_hash;
	ChatMessage *msg;

	err = chat_attest_assoctable_hash(chat_context_get_participants_list(ctx), &assoctable_hash);
	if(err) { goto error; }

	msg = chat_message_attest_new(ctx, chat_context_get_sid(ctx), assoctable_hash);
	if(!msg) { goto error_with_assoctable_hash; }

	free(assoctable_hash);

	*msgToSend = msg;
	return 0;

error_with_assoctable_hash:
	free(assoctable_hash);
error:
	return 1;
}

int chat_attest_init(ChatContext ctx, ChatMessage **msgToSend)
{
	ChatAttestInfo attest_info;
	int err;
	unsigned int our_pos;
	ChatMessage *ourMsg = NULL;

	attest_info = chat_context_get_attest_info(ctx);
	if(NULL == attest_info) {
		err = chat_attest_info_init(ctx);
		if(err) { goto error; }
		attest_info = chat_context_get_attest_info(ctx);
	}

	err = chat_participant_get_position(chat_context_get_participants_list(ctx), chat_context_get_accountname(ctx), &our_pos);
	if(err) { goto error; }

	if(!attest_info->checked[our_pos]) {
		err = chat_attest_create_our_message(ctx, our_pos, &ourMsg);
		if(err) { goto error; }
		attest_info->checked[our_pos] = 1;
		attest_info->checked_count++;
	}

	attest_info->state = CHAT_ATTESTSTATE_AWAITING;

	*msgToSend = ourMsg;
	return 0;

error:
	return 1;

}

int chat_attest_handle_message(ChatContext ctx, const ChatMessage *msg, ChatMessage **msgToSend)
{
	ChatAttestInfo attest_info;
	OtrlList participants_list;
	char *accountname;
	unsigned int our_pos, their_pos;
	int res, err;
	ChatMessagePayloadAttest *payload;
	ChatMessage *ourMsg = NULL;

	fprintf(stderr, "libotr-mpOTR: chat_attest_handle_message: start\n");

	attest_info = chat_context_get_attest_info(ctx);

	if(!attest_info) {
		err = chat_attest_info_init(ctx);
		if(err) { goto error; }
		attest_info = chat_context_get_attest_info(ctx);
	}

	participants_list = chat_context_get_participants_list(ctx);
	accountname = chat_context_get_accountname(ctx);

	if(msg->msgType != CHAT_MSGTYPE_ATTEST) { goto error; }
	if(attest_info->state != CHAT_ATTESTSTATE_AWAITING) { goto error; }

	payload = msg->payload;

	err = chat_participant_get_position(participants_list, msg->senderName, &their_pos);
	if(err) { goto error; }

	err = chat_attest_verify(ctx, payload->sid, payload->assoctable_hash, their_pos, &res);
	if(err) { goto error; }

	if(res == 0) {
		fprintf(stderr, "libotr-mpOTR: chat_attest_handle_message: attest verification failed for participant #: %u\n", their_pos);
		chat_protocol_reset(ctx);
		goto error;
	} else {

		// Create our attest message if we haven't already sent one
		err = chat_participant_get_position(participants_list, accountname, &our_pos);
		if(err) { goto error; }

		if(!attest_info->checked[our_pos]) {
			err = chat_attest_create_our_message(ctx, our_pos, &ourMsg);
			if(err) { goto error; }

			attest_info->checked[our_pos] = 1;
			attest_info->checked_count++;
		}

		if(chat_attest_is_ready(attest_info)) {
			attest_info->state = CHAT_ATTESTSTATE_FINISHED;
			chat_context_set_msg_state(ctx, OTRL_MSGSTATE_ENCRYPTED);
		}
	}

	fprintf(stderr, "libotr-mpOTR: chat_attest_handle_message: end\n");

	*msgToSend = ourMsg;
	return 0;

error:
	return 1;
}


int chat_attest_is_my_message(ChatMessage *msg)
{
	ChatMessageType msg_type = msg->msgType;

	switch(msg_type) {
		case CHAT_MSGTYPE_ATTEST:
			return 1;
		default:
			return 0;
	}
}
