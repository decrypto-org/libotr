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

#include <gcrypt.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "b64.h"
#include "chat_attest.h"
#include "chat_communication.h"
#include "chat_context.h"
#include "chat_dh_key.h"
#include "chat_dske.h"
#include "chat_event.h"
#include "chat_fingerprint.h"
#include "chat_gka.h"
#include "chat_id_key.h"
#include "chat_info.h"
#include "chat_message.h"
#include "chat_offer.h"
#include "chat_participant.h"
#include "chat_pending.h"
#include "chat_shutdown.h"
#include "chat_sign.h"
#include "chat_types.h"
#include "context.h"
#include "list.h"
#include "message.h"
#include "proto.h"
#include "tlv.h"
#include "userstate.h"

//TODO Check every list find function to be optimized based on the sort

otrl_instag_t chat_protocol_get_instag(OtrlUserState us, const OtrlMessageAppOps *ops, const char *accountname, const char *protocol)
{
	OtrlInsTag *ourInstanceTag;
	otrl_instag_t instag;

	ourInstanceTag = otrl_instag_find(us, accountname, protocol);
    if ((!ourInstanceTag) && ops->create_instag) {
    	ops->create_instag(NULL, accountname, protocol);
    	ourInstanceTag = otrl_instag_find(us, accountname, protocol);
    }

    if (ourInstanceTag && ourInstanceTag->instag >= OTRL_MIN_VALID_INSTAG) {
    	instag = ourInstanceTag->instag;
    } else {
    	instag = otrl_instag_get_new();
    }

    return instag;
}

int chat_protocol_app_info_refresh(const OtrlMessageAppOps *ops, ChatContextPtr ctx)
{
	OtrlChatInfoPtr info;

	info = chat_info_new_with_level(ctx);
	if(!info) { goto error; }

	ops->chat_info_refresh(NULL, info);

	chat_info_free(info);

	return 0;

error:
	return 1;
}

int chat_protocol_app_info_refresh_all(OtrlUserState us, const OtrlMessageAppOps *ops)
{
	OtrlListIteratorPtr iter;
	OtrlListNodePtr node;
	ChatContextPtr ctx;
	int err, ret = 0;

	iter = otrl_list_iterator_new(us->chat_context_list);
	if(!iter) { goto error; }
	while(otrl_list_iterator_has_next(iter)) {
		node = otrl_list_iterator_next(iter);
		ctx = otrl_list_node_get_payload(node);
		err = chat_protocol_app_info_refresh(ops, ctx);
		if(err) { ret = 1; }
	}

	return ret;

error:
	return 1;
}

int chat_protocol_is_in_use(OtrlUserState us, const char *accountname, const char *protocol, int *result)
{
	OtrlListIteratorPtr iter = NULL;
	OtrlListNodePtr node = NULL;
	ChatContextPtr ctx = NULL;
	ChatIdKeyPtr key = NULL;
	int res = 0;

	iter = otrl_list_iterator_new(us->chat_context_list);
	if(!iter) { goto error; }
	while(0 == res && otrl_list_iterator_has_next(iter)) {
		node = otrl_list_iterator_next(iter);
		ctx = otrl_list_node_get_payload(node);
		key = chat_context_get_identity_key(ctx);

		if(NULL != key) {
			if(0 == strcmp(accountname, chat_id_key_get_accountname(key)) && 0 == strcmp(protocol, chat_id_key_get_protocol(key))) {
				res = 1;
			}
		}
	}
	otrl_list_iterator_free(iter);

	*result = res;
	return 0;

error:
	return 1;
}

int otrl_chat_protocol_id_key_read_file(OtrlUserState us, FILE *privf)
{
	OtrlListPtr key_list = NULL;

	key_list = us->chat_privkey_list;
	return chat_id_key_list_read_FILEp(key_list, &chat_dh_key_internalKeyOps, privf);
}

int otrl_chat_protocol_id_keys_write_file(OtrlUserState us, FILE *privf)
{
	OtrlListPtr key_list;

	key_list = us->chat_privkey_list;
	return chat_id_key_list_write_FILEp(key_list, privf);
}

int otrl_chat_protocol_id_key_generate_new(OtrlUserState us, const OtrlMessageAppOps *ops, const char *accountname, const char *protocol)
{
	int err = 0, in_use;

	fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_id_key_generate_new: start\n");

	err = chat_protocol_is_in_use(us, accountname, protocol, &in_use);
	if(err) { goto error; }

	if(!in_use) {
		err = chat_id_key_generate_new(us->chat_privkey_list, accountname, protocol, &chat_dh_key_internalKeyOps);
		if(err) { goto error; }
		ops->chat_privkeys_write(NULL);
	}

	fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_id_key_generate_new: end\n");

	return 0;

error:
	return 1;
}

OtrlListPtr otrl_chat_protocol_id_key_list_create(OtrlUserState us)
{
	OtrlListPtr list = NULL;

	list = chat_id_key_info_list_create(us->chat_privkey_list);
	if(!list) { goto error; }

	return list;

error:
	return NULL;
}

int chat_protocol_fingerprint_is_in_use(OtrlUserState us, OtrlChatFingerprintPtr fnprnt, int *result)
{
	OtrlListIteratorPtr iter1 = NULL, iter2 = NULL;
	ChatContextPtr ctx = NULL;
	ChatParticipantPtr part = NULL;
	OtrlChatFingerprintPtr cur_fnprnt = NULL;
	int res = 0;

	iter1 = otrl_list_iterator_new(us->chat_context_list);
	if(!iter1) { goto error; }
	while(0 == res && otrl_list_iterator_has_next(iter1))
	{
		ctx = otrl_list_node_get_payload(otrl_list_iterator_next(iter1));

		iter2 = otrl_list_iterator_new(chat_context_get_participants_list(ctx));
		if(!iter2) { goto error_with_iter1; }
		while(0 == res && otrl_list_iterator_has_next(iter2)) {
			part = otrl_list_node_get_payload(otrl_list_iterator_next(iter2));
			cur_fnprnt = chat_participant_get_fingerprint(part);
			if(cur_fnprnt == fnprnt) {
				res = 1;
			}
		}
		otrl_list_iterator_free(iter2);

	}
	otrl_list_iterator_free(iter1);

	*result = res;
	return 0;

error_with_iter1:
	otrl_list_iterator_free(iter1);
error:
	return 1;
}

int otrl_chat_protocol_fingerprints_read_file(OtrlUserState us, FILE *fingerfile)
{
	OtrlListPtr fingerlist;

	fingerlist = us->chat_fingerprints;
	return chat_fingerprint_read_FILEp(fingerlist, fingerfile);
}

int otrl_chat_protocol_fingerprints_write_file(OtrlUserState us, FILE *fingerfile)
{
	OtrlListPtr fingerlist;

	fingerlist = us->chat_fingerprints;
	return chat_fingerprint_write_FILEp(fingerlist, fingerfile);
}

void otrl_chat_protocol_fingerprint_verify(OtrlUserState us, const OtrlMessageAppOps *ops, OtrlChatFingerprintPtr fnprnt)
{
	chat_fingerprint_verify(fnprnt);
	ops->chat_fingerprints_write(NULL);

	chat_protocol_app_info_refresh_all(us, ops);
}

void otrl_chat_protocol_fingerprint_forget(OtrlUserState us, const OtrlMessageAppOps *ops, OtrlChatFingerprintPtr fnprnt)
{
	OtrlListPtr fingerlist;
	int err, inUse;

	err = chat_protocol_fingerprint_is_in_use(us, fnprnt, &inUse);
	if(err) { goto error; }

	if(0 == inUse) {
		fingerlist = us->chat_fingerprints;
		chat_fingerprint_forget(fingerlist, fnprnt);
		ops->chat_fingerprints_write(NULL);
	}

	chat_protocol_app_info_refresh_all(us, ops);

error:
	return;
}

int chat_protocol_participants_list_load_fingerprints(OtrlUserState us, ChatContextPtr ctx)
{
	OtrlListNodePtr node1, node2, node3;
	OtrlListIteratorPtr iter1, iter2;
	ChatParticipantPtr participant;
	OtrlChatFingerprintPtr fnprnt, newfinger;
	char *accountname = NULL, *protocol = NULL, *username = NULL;
	unsigned char *bytes = NULL;
	int trusted;

	iter1 = otrl_list_iterator_new(chat_context_get_participants_list(ctx));
	if(!iter1) { goto error; }

	while(otrl_list_iterator_has_next(iter1)) {
		node1 = otrl_list_iterator_next(iter1);
		participant = otrl_list_node_get_payload(node1);

		iter2 = otrl_list_iterator_new(us->chat_fingerprints);
		if(!iter2) { goto error_with_iter1; }

		while(otrl_list_iterator_has_next(iter2)) {
			node2 = otrl_list_iterator_next(iter2);
			fnprnt = otrl_list_node_get_payload(node2);

			accountname = otrl_chat_fingerprint_get_accountname(fnprnt);
			protocol = otrl_chat_fingerprint_get_protocol(fnprnt);
			username = otrl_chat_fingerprint_get_username(fnprnt);
			bytes = otrl_chat_fingerprint_get_bytes(fnprnt);
			trusted = otrl_chat_fingerprint_is_trusted(fnprnt);

			if(0 == strcmp(username, chat_participant_get_username(participant)) &&
					0 == strcmp(accountname, chat_context_get_accountname(ctx)) &&
					0 == strcmp(protocol, chat_context_get_protocol(ctx))) {

				newfinger = chat_fingerprint_new(accountname, protocol, username, bytes, trusted);
				if(!newfinger) { goto error_with_iter2; }

				node3 = otrl_list_insert(chat_participant_get_fingerprints(participant), newfinger);
				if(!node3) { goto error_with_newfinger; }
			}
		}
		otrl_list_iterator_free(iter2);

	}
	otrl_list_iterator_free(iter1);

	return 0;

error_with_newfinger:
	chat_fingerprint_free(newfinger);
error_with_iter2:
	otrl_list_iterator_free(iter2);
error_with_iter1:
	otrl_list_iterator_free(iter1);
error:
	return 1;
}

int chat_protocol_participants_list_init(OtrlUserState us, const OtrlMessageAppOps *ops, ChatContextPtr ctx)
{
	int err;
	char **usernames;
	unsigned int usernames_size;
	OtrlChatInfoPtr info;

	info = chat_info_new(ctx);
	if(!info) { goto error; }

	usernames = ops->chat_get_participants(NULL, info, &usernames_size);
	if(!usernames) { goto error_with_info; }

	err = chat_participant_list_from_usernames(chat_context_get_participants_list(ctx), usernames, usernames_size);
	if(err) { goto error_with_usernames; }

	err = chat_protocol_participants_list_load_fingerprints(us, ctx);
	if(err) { goto error_with_participants_list; }


	for(unsigned int i = 0; i < usernames_size; i++) { free(usernames[i]); }
	free(usernames);
	chat_info_free(info);

    return 0;

error_with_participants_list:
	otrl_list_clear(chat_context_get_participants_list(ctx));
error_with_usernames:
	for(unsigned int i = 0; i < usernames_size; i++) { free(usernames[i]); }
    free(usernames);
error_with_info:
	chat_info_free(info);
error:
	return 1;
}

void chat_protocol_reset(ChatContextPtr ctx)
{
	chat_context_reset(ctx);
}

int chat_protocol_add_sign(ChatContextPtr ctx, unsigned char **msg, size_t *msglen)
{
	Signature *aSign;
	unsigned char *sig = NULL, *buf;
	size_t siglen;
	int err;

	aSign = chat_sign_sign(chat_context_get_signing_key(ctx), *msg, *msglen);
	if(!aSign) { goto error; }

	err = chat_sign_signature_serialize(aSign, &sig, &siglen);
	if(err) { goto error_with_aSign; }

	buf = malloc((*msglen+siglen) * sizeof *buf);
	if(!buf) { goto error_with_sig; }

	memcpy(buf, *msg, *msglen);
	memcpy(&buf[*msglen], sig, siglen);

	free(*msg);
	free(sig);
	chat_sign_signature_free(aSign);

	*msg = buf;
	*msglen = *msglen+siglen;
	return 0;

error_with_sig:
	free(sig);
error_with_aSign:
	chat_sign_signature_free(aSign);
error:
	return 1;
}

int chat_protocol_send_message(const OtrlMessageAppOps *ops, ChatContextPtr ctx, ChatMessage *msg)
{
	OtrlChatInfoPtr info;
	char *message = NULL;
	unsigned char *buf = NULL;
	size_t buflen;
	int err;

	fprintf(stderr, "libotr-mpOTR: chat_protocol_send_message: start\n");

	buf = chat_message_serialize(msg, &buflen);
	if(!buf) { goto error; }

	if(chat_message_type_should_be_signed(msg->msgType) && CHAT_SIGNSTATE_SIGNED == chat_context_get_sign_state(ctx)) {
		err = chat_protocol_add_sign(ctx, &buf, &buflen);
		if(err) { goto error_with_buf; }
	}

	message = otrl_base64_otr_encode(buf, buflen);
	if(!message) { goto error_with_buf; }

	info = chat_info_new(ctx);
	if(!info) { goto error_with_message; }

	err = ops->chat_inject_message(NULL, info, message);
	if(err) { goto error_with_info; }

	chat_info_free(info);
	free(message);
	free(buf);

	fprintf(stderr, "libotr-mpOTR: chat_protocol_send_message: end\n");

	return 0;

error_with_info:
	chat_info_free(info);
error_with_message:
	free(message);
error_with_buf:
	free(buf);
error:
	return 1;

}

int chat_protocol_verify_sign(ChatContextPtr ctx, const char *sender, const unsigned char *msg, const size_t msglen) {
	Signature *sign;
	ChatParticipantPtr theSender;
	unsigned int their_pos;
	int err;

	err = chat_sign_signature_parse(&msg[msglen-CHAT_SIGN_SIGNATURE_LENGTH], &sign);
	if(err) { goto error; }

	theSender = chat_participant_find(chat_context_get_participants_list(ctx), sender, &their_pos);
	if(!theSender) { goto error_with_sign; }

	err = chat_sign_verify(chat_participant_get_sign_key(theSender), msg, msglen - CHAT_SIGN_SIGNATURE_LENGTH, sign);
	if(err) { goto error_with_sign; }

	chat_sign_signature_free(sign);

	return 0;

error_with_sign:
	chat_sign_signature_free(sign);
error:
	return 1;
}

int chat_protocol_pending_queue_add(ChatContextPtr ctx, const char *sender, unsigned char *msg, size_t msglen)
{
	ChatPendingPtr pending;
	OtrlListNodePtr node;

	pending = chat_pending_new(sender, msg, msglen);
	if(!pending) { goto error; }

	node = otrl_list_append(chat_context_get_pending_list(ctx), pending);
	if(!node) { goto error_with_pending; }

	return 0;

error_with_pending:
	chat_pending_free(pending);
error:
	return 1;
}

int chat_protocol_emit_event(const OtrlMessageAppOps *ops, const ChatContextPtr ctx, OtrlChatEventPtr event)
{
	OtrlChatInfoPtr info;

	info = chat_info_new(ctx);
	if(!info) { goto error; }

	ops->chat_handle_event(NULL, info, event);

	chat_info_free(info);

	return 0;

error:
	return 1;
}

int chat_protocol_emit_consensus_events(const OtrlMessageAppOps *ops, const ChatContextPtr ctx)
{
	OtrlChatEventPtr event;
	OtrlListIteratorPtr iter;
	OtrlListNodePtr cur;
	ChatParticipantPtr me, part;
	unsigned int pos;
	int err;

	me = chat_participant_find(chat_context_get_participants_list(ctx), chat_context_get_accountname(ctx), &pos);
	if(!me) { goto error; }

	iter = otrl_list_iterator_new(chat_context_get_participants_list(ctx));
	if(!iter) { goto error; }

	while(otrl_list_iterator_has_next(iter)) {
		cur = otrl_list_iterator_next(iter);
		part = otrl_list_node_get_payload(cur);

		if(part != me && 0 == chat_participant_get_consensus(part)) {
			event = chat_event_consensus_broken_new(chat_participant_get_username(part));
			if(!event) { goto error_with_iter; }

			err = chat_protocol_emit_event(ops, ctx, event);
			if(err) { goto error_with_event; }

			chat_event_free(event);
		}
	}

	otrl_list_iterator_free(iter);

	return 0;

error_with_event:
	chat_event_free(event);
error_with_iter:
	otrl_list_iterator_free(iter);
error:
	return 1;
}

int chat_protocol_emit_offer_received_event(const OtrlMessageAppOps *ops, const ChatContextPtr ctx, const char *username)
{
	OtrlChatEventPtr event;
	int err;

	event = chat_event_offer_received_new(username);
	if(!event) { goto error; }

	err = chat_protocol_emit_event(ops, ctx, event);
	if(err) { goto error_with_event; }

	chat_event_free(event);

	return 0;

error_with_event:
	chat_event_free(event);
error:
	return 1;
}

int chat_protocol_emit_starting_event(const OtrlMessageAppOps *ops, const ChatContextPtr ctx)
{
	OtrlChatEventPtr event;
	int err;

	event = chat_event_starting_new();
	if(!event) { goto error; }

	err = chat_protocol_emit_event(ops, ctx, event);
	if(err) { goto error_with_event; }

	chat_event_free(event);

	return 0;

error_with_event:
	chat_event_free(event);
error:
	return 1;
}

int chat_protocol_emit_started_event(const OtrlMessageAppOps *ops, const ChatContextPtr ctx)
{
	OtrlChatEventPtr event;
	int err;

	event = chat_event_started_new();
	if(!event) { goto error; }

	err = chat_protocol_emit_event(ops, ctx, event);
	if(err) { goto error_with_event; }

	chat_event_free(event);

	return 0;

error_with_event:
	chat_event_free(event);
error:
	return 1;
}

int chat_protocol_emit_unverified_participant_events(const OtrlMessageAppOps *ops, const ChatContextPtr ctx)
{
	OtrlChatEventPtr event;
	OtrlListIteratorPtr iter;
	OtrlListNodePtr cur;
	ChatParticipantPtr me, part;
	OtrlChatFingerprintPtr fnprnt;
	unsigned int pos;
	int err;

	me = chat_participant_find(chat_context_get_participants_list(ctx), chat_context_get_accountname(ctx), &pos);
	if(!me) { goto error; }

	iter = otrl_list_iterator_new(chat_context_get_participants_list(ctx));
	if(!iter) { goto error; }

	while(otrl_list_iterator_has_next(iter)) {
		cur = otrl_list_iterator_next(iter);
		part = otrl_list_node_get_payload(cur);

		if(part != me) {
			fnprnt = chat_participant_get_fingerprint(part);
			if(!fnprnt) { goto error_with_iter; }

			if(0 == otrl_chat_fingerprint_is_trusted(fnprnt)) {
				event = chat_event_unverified_participant_new(chat_participant_get_username(part));
				if(!event) { goto error_with_iter; }

				err = chat_protocol_emit_event(ops, ctx, event);
				if(err) { goto error_with_event; }

				chat_event_free(event);
			}
		}
	}

	otrl_list_iterator_free(iter);

	return 0;

error_with_event:
	chat_event_free(event);
error_with_iter:
	otrl_list_iterator_free(iter);
error:
	return 1;
}

int chat_protocol_emit_plaintext_received_event(const OtrlMessageAppOps *ops, const ChatContextPtr ctx, const char *sender, const char *message)
{
	OtrlChatEventPtr event;
	int err;

	event = chat_event_plaintext_received_new(sender, message);
	if(!event) { goto error; }

	err = chat_protocol_emit_event(ops, ctx, event);
	if(err) { goto error_with_event; }

	chat_event_free(event);

	return 0;

error_with_event:
	chat_event_free(event);
error:
	return 1;
}

int chat_protocol_emit_private_received_event(const OtrlMessageAppOps *ops, const ChatContextPtr ctx, const char *sender)
{
	OtrlChatEventPtr event;
	int err;

	event = chat_event_private_received_new(sender);
	if(!event) { goto error; }

	err = chat_protocol_emit_event(ops, ctx, event);
	if(err) { goto error_with_event; }

	chat_event_free(event);

	return 0;

error_with_event:
	chat_event_free(event);
error:
	return 1;
}

int chat_protocol_emit_finished_event(const OtrlMessageAppOps *ops, const ChatContextPtr ctx)
{
	OtrlChatEventPtr event;
	int err;

	event = chat_event_finished_new();
	if(!event) { goto error; }

	err = chat_protocol_emit_event(ops, ctx, event);
	if(err) { goto error_with_event; }

	chat_event_free(event);

	return 0;

error_with_event:
	chat_event_free(event);
error:
	return 1;
}

int chat_protocol_handle_message(OtrlUserState us, const OtrlMessageAppOps *ops, ChatContextPtr ctx, const char *sender, const unsigned char *message, size_t messagelen, char **newmessagep, int *ignore, int *pending)
{
	int err, ignore_message = 0, ispending = 0, isrejected = 0;
	ChatMessageType type;
	ChatMessage *msg = NULL, *msgToSend = NULL;

	fprintf(stderr, "libotr-mpOTR: chat_protocol_handle_message: start\n");

	err = chat_message_parse_type(message, messagelen, &type);
	if(err) { goto error; }

	//TODO Dimitris: a new participant in an already initialized private session maybe should be handled better
	// Checking Session ID:
	// If the message contains a sid, we should check if it matches the sid of our context, otherwise reject it.
	// If we don't have obtained a sid for the session we add the message to the pending list.
	if(chat_message_type_contains_sid(type)) {
		ChatOfferInfoPtr offer_info = chat_context_get_offer_info(ctx);

		if(NULL == offer_info || CHAT_OFFERSTATE_FINISHED != chat_offer_info_get_state(offer_info)) {
			ispending = 1;
		} else {
			unsigned char *sid;
			err = chat_message_parse_sid(message, messagelen, &sid);
			if(err) { goto error; }

			if(memcmp(sid, chat_context_get_sid(ctx), CHAT_OFFER_SID_LENGTH)) {
				isrejected = 1;
			}

			free(sid);
		}
	}

	// Checking signature
	// If the singature verification fails, we reject the message
	// If we haven't entered the SINGED state yet, we add the message to the pending list
	if(!ispending && !isrejected ) {
		if(chat_message_type_should_be_signed(type)){
			if(CHAT_SIGNSTATE_SIGNED != chat_context_get_sign_state(ctx)) {
				ispending = 1;
			} else {
				err = chat_protocol_verify_sign(ctx, sender, message, messagelen);
				if(err) { goto error; }
				messagelen -= CHAT_SIGN_SIGNATURE_LENGTH;
			}
		}
	}

	// If sid and signature were verified, we try to handle the message based on its type
	if(!ispending && !isrejected) {
		msg = chat_message_parse(message, messagelen, sender);
		if(!msg) { goto error; }

		// CASE: Offer Message
		if(chat_offer_is_my_message(msg)) {

			// TODO Dimtiris: Check if we have this already and free it
			// If we haven't done that yet, initialize the participant list and the offer info
			if(NULL == chat_context_get_offer_info(ctx)) {

				// Library-Application Communication
				chat_protocol_emit_offer_received_event(ops, ctx, sender);

				err = chat_protocol_participants_list_init(us, ops, ctx);
				if(err) { goto error_with_msg; }

				err = chat_offer_info_init(ctx, otrl_list_size(chat_context_get_participants_list(ctx)));
				if(err) { goto error_with_msg; }
			}

			ChatOfferInfoPtr offer_info = chat_context_get_offer_info(ctx);

			if(CHAT_OFFERSTATE_FINISHED == chat_offer_info_get_state(offer_info)) {
				//reject
			} else {

				err = chat_offer_handle_message(ctx, msg, &msgToSend);
				if(err) { goto error_with_msg; }
				if(msgToSend) {
					err = chat_protocol_send_message(ops, ctx, msgToSend);
					if(err) { goto error_with_msgToSend; }
					chat_message_free(msgToSend);
					msgToSend = NULL;
				}

				if(NULL != offer_info && CHAT_OFFERSTATE_FINISHED == chat_offer_info_get_state(offer_info)) {
					// Load or generate our private key
					ChatIdKeyPtr id_key = NULL;
					err = chat_id_key_find(us->chat_privkey_list, chat_context_get_accountname(ctx), chat_context_get_protocol(ctx), &id_key);
					if(err) { goto error_with_msg; }

					if(!id_key) {
						ops->chat_privkey_create(NULL, chat_context_get_accountname(ctx), chat_context_get_protocol(ctx));
						err = chat_id_key_find(us->chat_privkey_list, chat_context_get_accountname(ctx), chat_context_get_protocol(ctx), &id_key);
						if(err || NULL == id_key) { goto error_with_msg; }
					}
					chat_context_set_identity_key(ctx, id_key);

					// Initiate dske
					err = chat_dske_init(ctx, &msgToSend);
					if(err) { goto error_with_msg; }
					err = chat_protocol_send_message(ops, ctx, msgToSend);
					if(err) { goto error_with_msgToSend; }
					chat_message_free(msgToSend);
					msgToSend = NULL;
				}
			}
			ignore_message = 1;

		// CASE: DSKE Message
		} else if(chat_dske_is_my_message(msg)) {
			ChatOfferInfoPtr offer_info = chat_context_get_offer_info(ctx);
			ChatDSKEInfoPtr dske_info = chat_context_get_dske_info(ctx);
			ChatGKAInfoPtr gka_info = chat_context_get_gka_info(ctx);

			if(NULL == dske_info || NULL == offer_info || chat_offer_info_get_state(offer_info) != CHAT_OFFERSTATE_FINISHED) {
				ispending = 1;
			} else if(CHAT_DSKESTATE_FINISHED == chat_dske_info_get_state(dske_info)) {
				// reject
			} else {
				err = chat_dske_handle_message(ctx, msg, us->chat_fingerprints, &msgToSend);
				if(err) { goto error_with_msg; }

				if(msgToSend) {
					err = chat_protocol_send_message(ops, ctx, msgToSend);
					if(err) { goto error_with_msgToSend; }
					chat_message_free(msgToSend);
					msgToSend = NULL;
				}

				// TODO maybe reject messages intended to other recipients before handling them :)
				if(NULL != dske_info && CHAT_DSKESTATE_FINISHED == chat_dske_info_get_state(dske_info) &&
						(NULL == gka_info || CHAT_GKASTATE_NONE == chat_gka_info_get_state(gka_info))) {

					chat_context_set_sign_state(ctx, CHAT_SIGNSTATE_SIGNED);

					err = chat_gka_init(ctx, &msgToSend);
					if(err) { goto error_with_msg; }

					if(msgToSend) {
						err = chat_protocol_send_message(ops, ctx, msgToSend);
						if(err) { goto error_with_msgToSend; }
						chat_message_free(msgToSend);
						msgToSend = NULL;
					}
				}
			}
			ignore_message = 1;

		// CASE: GKA Message
		} else if(chat_gka_is_my_message(msg)) {
			ChatDSKEInfoPtr dske_info = chat_context_get_dske_info(ctx);
			ChatGKAInfoPtr gka_info = chat_context_get_gka_info(ctx);

			if(NULL == dske_info || CHAT_DSKESTATE_FINISHED != chat_dske_info_get_state(dske_info)) {
				ispending = 1;
			} else if(CHAT_GKASTATE_FINISHED == chat_gka_info_get_state(gka_info)) {
				// reject
			} else {
				err = chat_gka_handle_message(ctx, msg, &msgToSend);
				if(err) { goto error_with_msg; }

				if(msgToSend) {
					err = chat_protocol_send_message(ops, ctx, msgToSend);
					if(err) { goto error_with_msgToSend; }
					chat_message_free(msgToSend);
					msgToSend = NULL;
				}

				if(CHAT_GKASTATE_FINISHED == chat_gka_info_get_state(gka_info)) {
					err = chat_attest_init(ctx, &msgToSend);
					if(err) { goto error_with_msg; }
					if(msgToSend) {
						err = chat_protocol_send_message(ops, ctx, msgToSend);
						if(err) { goto error_with_msgToSend; }
						chat_message_free(msgToSend);
						msgToSend = NULL;
					}
				}
			}

			ignore_message = 1;

		// CASE: Attest Message
		} else if(chat_attest_is_my_message(msg)) {

			ChatGKAInfoPtr gka_info = chat_context_get_gka_info(ctx);
			ChatAttestInfoPtr attest_info = chat_context_get_attest_info(ctx);

			if(NULL == attest_info || CHAT_GKASTATE_FINISHED != chat_gka_info_get_state(gka_info)) {
				ispending = 1;
			} else if(CHAT_ATTESTSTATE_FINISHED == chat_attest_info_get_state(attest_info)) {
				// reject
			} else {
				err = chat_attest_handle_message(ctx, msg, &msgToSend);
				if(err) { goto error_with_msg; }

				if(msgToSend) {
					err = chat_protocol_send_message(ops, ctx, msgToSend);
					if(err) { goto error_with_msgToSend; }
					chat_message_free(msgToSend);
					msgToSend = NULL;
				}

				if(NULL != attest_info && CHAT_ATTESTSTATE_FINISHED == chat_attest_info_get_state(attest_info)) {
					err = chat_shutdown_init(ctx);
					if(err) { goto error_with_msg; }

					// Library-Application Communication
					chat_protocol_emit_started_event(ops, ctx);
					chat_protocol_emit_unverified_participant_events(ops, ctx);
					chat_protocol_app_info_refresh(ops, ctx);
				}
			}
			ignore_message = 1;

		// CASE: Communication Message
		} else if(chat_communication_is_my_message(msg)) {

			ChatAttestInfoPtr attest_info = chat_context_get_attest_info(ctx);

			//pending case
			if(NULL != attest_info && CHAT_ATTESTSTATE_AWAITING == chat_attest_info_get_state(attest_info)) {
				ispending = 1;

			// rejecting
			} else if(OTRL_MSGSTATE_PLAINTEXT == chat_context_get_msg_state(ctx) || OTRL_MSGSTATE_FINISHED == chat_context_get_msg_state(ctx)) {
				chat_protocol_emit_private_received_event(ops, ctx, sender);

			// hnadling
			} else {
				char *plaintext;
				err = chat_communication_handle_msg(ctx, msg, NULL, &plaintext);
				// TODO Dimitris: add proper event in case of an error
				if(err) { goto error_with_msg; }
				*newmessagep = plaintext;
			}

		// CASE: Shutdown Message
		} else if (chat_shutdown_is_my_message(msg)) {

			ChatAttestInfoPtr attest_info = chat_context_get_attest_info(ctx);

			if(NULL == attest_info || CHAT_ATTESTSTATE_FINISHED != chat_attest_info_get_state(attest_info)) {
				// reject
			} else {
				ChatShutdownInfoPtr shutdown_info = chat_context_get_shutdown_info(ctx);
				ChatShutdownState prevState = chat_shutdown_info_get_state(shutdown_info);

				err = chat_shutdown_handle_message(ctx, msg, &msgToSend);
				if(err) { goto error_with_msg; }

				if(msgToSend) {
					err = chat_protocol_send_message(ops, ctx, msgToSend);
					if(err) { goto error_with_msgToSend; }
					chat_message_free(msgToSend);
					msgToSend = NULL;
				}

				if(CHAT_SHUTDOWNSTATE_AWAITING_DIGESTS == chat_shutdown_info_get_state(shutdown_info) && CHAT_SHUTDOWNSTATE_AWAITING_SHUTDOWNS == prevState) {
					err = chat_shutdown_send_digest(ctx, &msgToSend);
					if(err) { goto error_with_msgToSend;}

					err = chat_protocol_send_message(ops, ctx, msgToSend);
					if(err) { goto error_with_msgToSend; }

					chat_message_free(msgToSend);
					msgToSend = NULL;
				}

				if(CHAT_SHUTDOWNSTATE_AWAITING_ENDS == chat_shutdown_info_get_state(shutdown_info) && CHAT_SHUTDOWNSTATE_AWAITING_DIGESTS == prevState) {
					err = chat_shutdown_send_end(ctx, &msgToSend);
					if(err) { goto error_with_msgToSend;}

					err = chat_protocol_send_message(ops, ctx, msgToSend);
					if(err) { goto error_with_msgToSend; }

					chat_message_free(msgToSend);
					msgToSend = NULL;
				}

				if(CHAT_SHUTDOWNSTATE_FINISHED == chat_shutdown_info_get_state(shutdown_info)) {
					chat_context_set_msg_state(ctx, OTRL_MSGSTATE_FINISHED);

					err = chat_shutdown_release_secrets(ctx, &msgToSend);
					if(err) { goto error_with_msgToSend;}

					err = chat_protocol_send_message(ops, ctx, msgToSend);
					if(err) { goto error_with_msgToSend; }
					chat_message_free(msgToSend);
					msgToSend = NULL;

					// Library-Application Communication
					chat_protocol_emit_finished_event(ops, ctx);
					chat_protocol_emit_consensus_events(ops, ctx);
					chat_protocol_app_info_refresh(ops, ctx);

					chat_protocol_reset(ctx);
				}
			}

			ignore_message = 1;
		}
	}

	*pending = ispending;
	*ignore = ignore_message;

	fprintf(stderr, "libotr-mpOTR: chat_protocol_handle_message: end\n");
	return 0;

error_with_msgToSend:
	chat_message_free(msg);
error_with_msg:
	chat_message_free(msg);
error:
	return 1;
}

int chat_protocol_handle_pending(OtrlUserState us, const OtrlMessageAppOps *ops, ChatContextPtr ctx) {
	OtrlListIteratorPtr iter;
	OtrlListNodePtr cur;
	ChatPendingPtr pending;
	unsigned short int flag = 1;
	int err, ispending, ignore;

	fprintf(stderr, "libotr-mpOTR: chat_protocol_handle_pending: start\n");

	if(otrl_list_size(chat_context_get_pending_list(ctx)) > 0) {
		fprintf(stderr, "=========================================================\n");
		fprintf(stderr, "libotr-mpOTR: chat_protocol_handle_pending: PENDING LIST:\n");
		otrl_list_dump(chat_context_get_pending_list(ctx));
		fprintf(stderr, "=========================================================\n");
	}

	while(flag) {
		flag = 0;

		iter = otrl_list_iterator_new(chat_context_get_pending_list(ctx));
		if(!iter) { goto error; }

		while(otrl_list_iterator_has_next(iter)) {
			cur = otrl_list_iterator_next(iter);
			pending = otrl_list_node_get_payload(cur);

			// TODO newmessagep NULL????????
			err = chat_protocol_handle_message(us, ops, ctx, chat_pending_get_sender(pending), chat_pending_get_msg(pending), chat_pending_get_msglen(pending), NULL, &ignore, &ispending);
			if(err) { goto error_with_iter; }

			if(!ispending) {
				otrl_list_remove_and_free(chat_context_get_pending_list(ctx), cur);
				flag = 1;
			}
		}

		otrl_list_iterator_free(iter);
	}

	fprintf(stderr, "libotr-mpOTR: chat_protocol_handle_pending: end\n");

	return 0;

error_with_iter:
	otrl_list_iterator_free(iter);
error:
	return 1;
}

int otrl_chat_protocol_receiving(OtrlUserState us, const OtrlMessageAppOps *ops,
	void *opdata, const char *accountname, const char *protocol,
	const char *sender, otrl_chat_token_t chat_token, const char *message,
	char **newmessagep,	OtrlTLV **tlvsp)
{
	ChatContextPtr ctx;
	otrl_instag_t instag;
	int ignore_message = 0; // flag to determine if the message should be ignored
	int ispending, err;
	unsigned char *buf;
	size_t buflen;

	fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_receiving: start\n");

	if( !accountname || !protocol || !sender || !message || !newmessagep) { goto error; }

	instag = chat_protocol_get_instag(us, ops, accountname, protocol);

	ctx = chat_context_find_or_add(us->chat_context_list, accountname, protocol, chat_token, instag);
	if(!ctx) { goto error; }

	if(!chat_message_is_otr(message)) {

		if (OTRL_MSGSTATE_PLAINTEXT != chat_context_get_msg_state(ctx)) {
			chat_protocol_emit_plaintext_received_event(ops, ctx, sender, message);
			ignore_message = 1;
		}

	} else {

		err = otrl_base64_otr_decode(message, &buf, &buflen);
		if(err) { goto error; }

		err = chat_protocol_handle_message(us, ops, ctx, sender, buf, buflen, newmessagep, &ignore_message, &ispending);
		if(err) { goto error_with_buf; }

		if(ispending) {
			err = chat_protocol_pending_queue_add(ctx, sender, buf, buflen);
			if(err) { goto error_with_buf; }
		} else {
			// Dimitris: this is fixed!!!
			//The ctx may be destroyed by handle message in case of handling a proper shutdown message
			/*ctx = chat_context_find_or_add(us, ops, accountname, protocol, chat_token);
			if(!ctx) { goto error_with_buf; }*/
			err = chat_protocol_handle_pending(us, ops, ctx);
			if(err) { goto error_with_buf; }
		}

		free(buf);
	}

	fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_receiving: end\n");
	return ignore_message;

error_with_buf:
	free(buf);
error:
	return 1;
}

int otrl_chat_protocol_sending(OtrlUserState us,
	const OtrlMessageAppOps *ops,
	void *opdata, const char *accountname, const char *protocol,
	const char *message, otrl_chat_token_t chat_token, OtrlTLV *tlvs,
	char **messagep, OtrlFragmentPolicy fragPolicy)
{
	ChatContextPtr ctx;
	otrl_instag_t instag;
	unsigned char *buf;
	ChatMessage *msg;
	size_t buflen;
	int err;

	fprintf(stderr, "libotr-mpOTR: otrl_chat_message_sending: start\n");

	if( !accountname || !protocol || !message) { goto error; }

	instag = chat_protocol_get_instag(us, ops, accountname, protocol);

	ctx = chat_context_find_or_add(us->chat_context_list, accountname, protocol, chat_token, instag);
	if(!ctx) { goto error; }

	switch(chat_context_get_msg_state(ctx)) {
		case OTRL_MSGSTATE_PLAINTEXT:
			fprintf(stderr, "libotr-mpOTR: otrl_chat_message_sending: case OTRL_MSGSTATE_PLAINTEXT\n");
			break;
		case OTRL_MSGSTATE_ENCRYPTED:
			fprintf(stderr, "libotr-mpOTR: otrl_chat_message_sending: case OTRL_MSGSTATE_ENCRYPTED\n");

			err = chat_communication_broadcast(ctx, message, &msg);
			if(err) { goto error; }

			buf = chat_message_serialize(msg, &buflen);
			if(!buf) { goto error_with_msg; }

			if(chat_message_type_should_be_signed(msg->msgType) && CHAT_SIGNSTATE_SIGNED == chat_context_get_sign_state(ctx) ) {
				err = chat_protocol_add_sign(ctx, &buf, &buflen);
				if(err) { goto error_with_buf; }
			}

			*messagep = otrl_base64_otr_encode(buf, buflen);
			if(!*messagep) { goto error_with_buf; }

			free(buf);

			chat_message_free(msg);

			break;
		case OTRL_MSGSTATE_FINISHED:
			fprintf(stderr, "libotr-mpOTR: otrl_chat_message_sending: case OTRL_MSGSTATE_FINISHED\n");
			break;
	}

	fprintf(stderr, "libotr-mpOTR: otrl_chat_message_sending: end\n");
	return 0;

error_with_buf:
	free(buf);
error_with_msg:
	chat_message_free(msg);
error:
	return 1;
}

int otrl_chat_protocol_send_query(OtrlUserState us,
		const OtrlMessageAppOps *ops,
		const char *accountname, const char *protocol,
		otrl_chat_token_t chat_token, OtrlFragmentPolicy fragPolicy)
{
	ChatMessage *msgToSend;
	ChatContextPtr ctx;
	otrl_instag_t instag;
	int err;

	fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_send_query: start\n");

	// TODO Dimtiris: What happens if we have already a context????
	instag = chat_protocol_get_instag(us, ops, accountname, protocol);

	ctx = chat_context_find_or_add(us->chat_context_list, accountname, protocol, chat_token, instag);
	if(!ctx) { goto error; }

	err = chat_protocol_participants_list_init(us, ops, ctx);
	if(err) { goto error; }

	err = chat_offer_info_init(ctx, otrl_list_size(chat_context_get_participants_list(ctx)));
	if(err) { goto error_with_msg; }

	err = chat_offer_start(ctx, &msgToSend);
	if(err) { goto error; }

	chat_protocol_emit_starting_event(ops, ctx);

	err = chat_protocol_send_message(ops, ctx, msgToSend);
	if(err) { goto error_with_msg; }

	chat_message_free(msgToSend);

	fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_send_query: end\n");

	return 0;

error_with_msg:
	chat_message_free(msgToSend);
error:
	return 1;
}

int otrl_chat_protocol_shutdown(OtrlUserState us, const OtrlMessageAppOps *ops,
		const char *accountname, const char *protocol, otrl_chat_token_t chat_token)
{
	ChatMessage *msgToSend;
	ChatContextPtr ctx;
	ChatShutdownInfoPtr shutdown_info;
	OtrlListPtr context_list;
	otrl_instag_t instag;
	int err;

	fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_shutdown: start\n");

	instag = chat_protocol_get_instag(us, ops, accountname, protocol);
	context_list = us->chat_context_list;

	ctx = chat_context_find(context_list, accountname, protocol, chat_token, instag);
	if(!ctx) { goto error; }

	shutdown_info = chat_context_get_shutdown_info(ctx);

	if(NULL == shutdown_info || CHAT_SHUTDOWNSTATE_AWAITING_SHUTDOWNS != chat_shutdown_info_get_state(shutdown_info)) { goto error; }

	err = chat_shutdown_send_shutdown(ctx, &msgToSend);
	if(err) { goto error; }

	err = chat_protocol_send_message(ops, ctx, msgToSend);
	if(err) { goto error_with_msg; }

	chat_message_free(msgToSend);

	fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_showtdown: end\n");
	return 0;

error_with_msg:
	chat_message_free(msgToSend);
error:
	return 1;
}
