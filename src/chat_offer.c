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
#include <string.h>
#include <gcrypt.h>
#include "chat_offer.h"
#include "chat_types.h"
#include "chat_message.h"
#include "chat_participant.h"

unsigned char * chat_offer_compute_sid(unsigned char **sid_contributions, size_t size)
{
	unsigned int i;
	unsigned char *sid;
	gcry_md_hd_t md;
	gcry_error_t err;

	fprintf(stderr, "libotr-mpOTR: chat_offer_compute_sid: start\n");

	err = gcry_md_open(&md, GCRY_MD_SHA512, 0);
	if(err) { goto error; }

	for(i=0; i<size; i++) {
		if(sid_contributions[i] == NULL) { goto error; }
		gcry_md_write(md, sid_contributions[i], CHAT_OFFER_SID_CONTRIBUTION_LENGTH);
	}

	sid = malloc(CHAT_OFFER_SID_LENGTH * sizeof *sid);
	if(sid == NULL) { goto error_with_md; }

	memcpy(sid, gcry_md_read(md, GCRY_MD_SHA512), CHAT_OFFER_SID_LENGTH);
	gcry_md_close(md);

	fprintf(stderr, "libotr-mpOTR: chat_offer_compute_sid: computed sid: ");
	for(size_t i = 0; i < CHAT_OFFER_SID_LENGTH; i++) fprintf(stderr,"%02X", sid[i]);
	fprintf(stderr,"\n");

	fprintf(stderr, "libotr-mpOTR: chat_offer_compute_sid: emd\n");

	return sid;

error_with_md:
	gcry_md_close(md);
error:
	return NULL;
}

unsigned char * chat_offer_create_sid_contribution()
{
	unsigned char *rand_bytes, *sid_contribution = NULL;

	sid_contribution = malloc(CHAT_OFFER_SID_CONTRIBUTION_LENGTH * sizeof *sid_contribution);
	if(!sid_contribution) { goto error; }
	rand_bytes = gcry_random_bytes(CHAT_OFFER_SID_CONTRIBUTION_LENGTH, GCRY_STRONG_RANDOM);
	memcpy(sid_contribution, rand_bytes, CHAT_OFFER_SID_CONTRIBUTION_LENGTH);
	gcry_free(rand_bytes);

	return sid_contribution;

error:
	return NULL;
}

void chat_offer_info_free(ChatOfferInfo *info) {
	unsigned int i;

	if(info) {
		for(i=0; i<info->size; i++) {
			free(info->sid_contributions[i]);
		}
	}
	free(info);
}

int chat_offer_info_init(OtrlChatContext *ctx, size_t size) {
	ChatOfferInfo *offer_info;

	offer_info = malloc(sizeof *offer_info);
	if(!offer_info) { goto error; }

	offer_info->size = size;
	offer_info->added = 0;
	offer_info->sid_contributions = calloc(size, sizeof *offer_info->sid_contributions);
	if(!offer_info->sid_contributions) { goto err_with_offer_info; }

	offer_info->state = CHAT_OFFERSTATE_NONE;

	ctx->offer_info = offer_info;

	return 0;

err_with_offer_info:
	free(offer_info);
error:
	return 1;
}

int chat_offer_add_sid_contribution(OtrlChatContext *ctx, const unsigned char *sid_contribution, unsigned int position)
{
	ChatOfferInfo *offer_info = ctx->offer_info;
	unsigned char *contribution;

	if(position >= offer_info->size) { goto error; }
	if(offer_info->sid_contributions[position] != NULL) { goto error; }

	contribution = malloc(CHAT_OFFER_SID_CONTRIBUTION_LENGTH * sizeof *contribution);
	if(!contribution) { goto error; }
	memcpy(contribution, sid_contribution, CHAT_OFFER_SID_CONTRIBUTION_LENGTH);

	offer_info->sid_contributions[position] = contribution;
	offer_info->added++;

	return 0;

error:
	return 1;
}

int chat_offer_sid_contribution_exists(OtrlChatContext *ctx, unsigned int position)
{
	ChatOfferInfo *offer_info = ctx->offer_info;

	//TODO maybe check if position >= offer_info->size???
	if(offer_info->sid_contributions[position] == NULL) {
		return 0;
	} else {
		return 1;
	}



}

int chat_offer_is_ready(OtrlChatContext *ctx)
{
	ChatOfferInfo *offer_info = ctx->offer_info;

	if(offer_info->added < offer_info->size) {
		return 0;
	} else {
		return 1;
	}
}

int chat_offer_handle_message(OtrlChatContext *ctx, const ChatMessage *msg, ChatMessage **msgToSend)
{
	int err;
	unsigned int their_pos, our_pos;
	unsigned char *our_contribution, *sid;
	ChatMessage *newmsg = NULL;
	ChatMessagePayloadOffer *payload = msg->payload;

	*msgToSend = NULL;

	fprintf(stderr, "libotr-mpOTR: chat_offer_handle_message: start\n");

	if(!ctx->offer_info) { goto error; }

	err = chat_participant_get_position(ctx->participants_list, msg->senderName, &their_pos);
	if(err) { goto error; }
	if(their_pos != payload->position || their_pos >= ctx->offer_info->size) {
		goto error;
	}

	if( chat_offer_sid_contribution_exists(ctx, their_pos)) {
		goto error;
	}

	err = chat_offer_add_sid_contribution(ctx, payload->sid_contribution, their_pos);
	if(err) { goto error; }

	err = chat_participant_get_position(ctx->participants_list, ctx->accountname, &our_pos);
	if(err) { goto error; }

	if(!chat_offer_sid_contribution_exists(ctx, our_pos)) {
		our_contribution = chat_offer_create_sid_contribution();
		if(!our_contribution) { goto error; }

		err = chat_offer_add_sid_contribution(ctx, our_contribution, our_pos);
		if(err) { free(our_contribution); goto error; }

		newmsg = chat_message_offer_create(ctx, our_contribution, our_pos);

		if(!newmsg) { goto error; }

		free(our_contribution);
	}

	if(chat_offer_is_ready(ctx)) {
		sid = chat_offer_compute_sid(ctx->offer_info->sid_contributions, ctx->offer_info->size);
		if(!sid) { goto error; }
		memcpy(ctx->sid, sid, CHAT_OFFER_SID_LENGTH);
		free(sid);
		ctx->offer_info->state = CHAT_OFFERSTATE_FINISHED;
	}

	*msgToSend = newmsg;

	fprintf(stderr, "libotr-mpOTR: chat_offer_handle_message: end\n");

	return 0;

error:
	return 1;
}

int chat_offer_start(OtrlChatContext *ctx, ChatMessage **msgToSend)
{
	int err;
	unsigned int our_pos;
	unsigned char *our_contribution, *sid;
	ChatMessage *newmsg = NULL;

	fprintf(stderr, "libotr-mpOTR: chat_offer_start: start\n");

	*msgToSend = NULL;

	chat_offer_info_free(ctx->offer_info);

	err = chat_offer_info_init(ctx, otrl_list_length(ctx->participants_list));
	if(err) { goto error; }

	err = chat_participant_get_position(ctx->participants_list, ctx->accountname, &our_pos);
	if(err) { goto error; }

	our_contribution = chat_offer_create_sid_contribution();
	if(!our_contribution) { goto error; }

	newmsg = chat_message_offer_create(ctx, our_contribution, our_pos);
	if(!newmsg) { goto error_with_our_contribution; }

	err = chat_offer_add_sid_contribution(ctx, our_contribution, our_pos);
	if(err) { goto erro_with_newmsg; }

	// TODO handle better this case
	if(chat_offer_is_ready(ctx)) {
		sid = chat_offer_compute_sid(ctx->offer_info->sid_contributions, ctx->offer_info->size);
		if(!sid) { goto error; }
		memcpy(ctx->sid, sid, CHAT_OFFER_SID_LENGTH);
		ctx->offer_info->state = CHAT_OFFERSTATE_FINISHED;
	}

	*msgToSend = newmsg;

	free(our_contribution);

	fprintf(stderr, "libotr-mpOTR: chat_offer_start: end\n");

	return 0;

erro_with_newmsg:
	chat_message_free(newmsg);
error_with_our_contribution:
	free(our_contribution);
error:
	return 1;
}

int chat_offer_is_my_message(const ChatMessage *msg)
{
	ChatMessageType msg_type = msg->msgType;

	switch(msg_type) {
		case CHAT_MSGTYPE_OFFER:
			return 1;
		default:
			return 0;
	}
}
