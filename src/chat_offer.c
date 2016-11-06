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

#include "chat_offer.h"

#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>

#include "chat_context.h"
#include "chat_message.h"
#include "chat_participant.h"
#include "chat_types.h"

struct ChatOfferInfo {
		size_t size;
		size_t added;
		unsigned char **sid_contributions;
		ChatOfferState state;
};

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

ChatOfferInfoPtr chat_offer_info_new(size_t size)
{
	ChatOfferInfoPtr offer_info;

	offer_info = malloc(sizeof *offer_info);
	if(!offer_info) { goto error; }

	offer_info->size = size;
	offer_info->added = 0;
	offer_info->sid_contributions = calloc(size, sizeof *offer_info->sid_contributions);
	if(!offer_info->sid_contributions) { goto err_with_offer_info; }

	offer_info->state = CHAT_OFFERSTATE_NONE;

	return offer_info;

err_with_offer_info:
	free(offer_info);
error:
	return NULL;
}

void chat_offer_info_free(ChatOfferInfoPtr info) {
	unsigned int i;

	if(info) {
		for(i=0; i<info->size; i++) {
			free(info->sid_contributions[i]);
		}
	}
	free(info);
}

ChatOfferState chat_offer_info_get_state(ChatOfferInfoPtr offer_info)
{
	return offer_info->state;
}

int chat_offer_info_init(ChatContextPtr ctx, size_t size) {
	ChatOfferInfoPtr offer_info;

	offer_info = chat_offer_info_new(size);
	if(!offer_info) { goto error; }

	chat_context_set_offer_info(ctx, offer_info);

	return 0;

error:
	return 1;
}

int chat_offer_add_sid_contribution(ChatOfferInfoPtr offer_info, const unsigned char *sid_contribution, unsigned int position)
{
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

int chat_offer_sid_contribution_exists(ChatOfferInfoPtr offer_info, unsigned int position)
{
	//TODO maybe check if position >= offer_info->size???
	if(offer_info->sid_contributions[position] == NULL) {
		return 0;
	} else {
		return 1;
	}
}

int chat_offer_is_ready(ChatOfferInfoPtr offer_info)
{
	if(offer_info->added < offer_info->size) {
		return 0;
	} else {
		return 1;
	}
}

int chat_offer_handle_message(ChatContextPtr ctx, const ChatMessage *msg, ChatMessage **msgToSend)
{
	int err;
	unsigned int their_pos, our_pos;
	unsigned char *our_contribution, *sid;
	ChatOfferInfoPtr offer_info;
	ChatMessage *newmsg = NULL;
	ChatMessagePayloadOffer *payload = msg->payload;

	*msgToSend = NULL;

	fprintf(stderr, "libotr-mpOTR: chat_offer_handle_message: start\n");

	offer_info = chat_context_get_offer_info(ctx);
	if(!offer_info) { goto error; }

	err = chat_participant_get_position(chat_context_get_participants_list(ctx), msg->senderName, &their_pos);
	if(err) { goto error; }
	if(their_pos != payload->position || their_pos >= offer_info->size) {
		goto error;
	}

	if( chat_offer_sid_contribution_exists(offer_info, their_pos)) {
		goto error;
	}

	err = chat_offer_add_sid_contribution(offer_info, payload->sid_contribution, their_pos);
	if(err) { goto error; }

	err = chat_participant_get_position(chat_context_get_participants_list(ctx), chat_context_get_accountname(ctx), &our_pos);
	if(err) { goto error; }

	if(!chat_offer_sid_contribution_exists(offer_info, our_pos)) {
		our_contribution = chat_offer_create_sid_contribution();
		if(!our_contribution) { goto error; }

		err = chat_offer_add_sid_contribution(offer_info, our_contribution, our_pos);
		if(err) { free(our_contribution); goto error; }

		newmsg = chat_message_offer_new(ctx, our_contribution, our_pos);

		if(!newmsg) { goto error; }

		free(our_contribution);
	}

	if(chat_offer_is_ready(offer_info)) {
		sid = chat_offer_compute_sid(offer_info->sid_contributions, offer_info->size);
		if(!sid) { goto error; }
		//TODO Dimitris: Here the getter plays the role of a setter
		memcpy(chat_context_get_sid(ctx), sid, CHAT_OFFER_SID_LENGTH);
		free(sid);
		offer_info->state = CHAT_OFFERSTATE_FINISHED;
	}

	*msgToSend = newmsg;

	fprintf(stderr, "libotr-mpOTR: chat_offer_handle_message: end\n");

	return 0;

error:
	return 1;
}

int chat_offer_start(ChatContextPtr ctx, ChatMessage **msgToSend)
{
	ChatOfferInfoPtr offer_info;
	unsigned int our_pos;
	unsigned char *our_contribution, *sid;
	ChatMessage *newmsg = NULL;
	int err;

	fprintf(stderr, "libotr-mpOTR: chat_offer_start: start\n");

	offer_info = chat_context_get_offer_info(ctx);
	if(!offer_info) { goto error; }

	*msgToSend = NULL;

	err = chat_participant_get_position(chat_context_get_participants_list(ctx), chat_context_get_accountname(ctx), &our_pos);
	if(err) { goto error; }

	our_contribution = chat_offer_create_sid_contribution();
	if(!our_contribution) { goto error; }

	newmsg = chat_message_offer_new(ctx, our_contribution, our_pos);
	if(!newmsg) { goto error_with_our_contribution; }

	err = chat_offer_add_sid_contribution(offer_info, our_contribution, our_pos);
	if(err) { goto erro_with_newmsg; }

	// TODO handle better this case
	if(chat_offer_is_ready(offer_info)) {
		sid = chat_offer_compute_sid(offer_info->sid_contributions, offer_info->size);
		if(!sid) { goto error; }

		//TODO Dimitris: the getter plays the role of a setter
		memcpy(chat_context_get_sid(ctx), sid, CHAT_OFFER_SID_LENGTH);
		offer_info->state = CHAT_OFFERSTATE_FINISHED;
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
