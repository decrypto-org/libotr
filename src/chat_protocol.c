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
#include "chat_dske.h"
#include "chat_event.h"
#include "chat_fingerprint.h"
#include "chat_gka.h"
#include "chat_idkey.h"
#include "chat_info.h"
#include "chat_message.h"
#include "chat_offer.h"
#include "chat_participant.h"
#include "chat_pending.h"
#include "chat_privkeydh.h"
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

int otrl_chat_protocol_fingerprints_read_file(OtrlUserState us, FILE *fingerfile)
{
	OtrlList fingerlist;

	fingerlist = us->chat_fingerprints;
	return chat_fingerprint_read_FILEp(fingerlist, fingerfile);
}

int otrl_chat_protocol_fingerprints_write_file(OtrlUserState us, FILE *fingerfile)
{
	OtrlList fingerlist;

	fingerlist = us->chat_fingerprints;
	return chat_fingerprint_write_FILEp(fingerlist, fingerfile);
}

void otrl_chat_protocol_fingerprint_verify(OtrlUserState us, const OtrlMessageAppOps *ops, OtrlChatFingerprint fnprnt)
{
	chat_fingerprint_verify(fnprnt);
	ops->chat_fingerprints_write(NULL);
}

void otrl_chat_protocol_fingerprint_forget(OtrlUserState us, const OtrlMessageAppOps *ops, OtrlChatFingerprint fnprnt)
{
	OtrlList fingerlist;

	fingerlist = us->chat_fingerprints;
	chat_fingerprint_forget(fingerlist, fnprnt);
	ops->chat_fingerprints_write(NULL);
}

int chat_protocol_app_info_refresh(const OtrlMessageAppOps *ops, ChatContext ctx)
{
	OtrlChatInfo info;

	fprintf(stderr, "libotr-mpOTR: chat_protocol_app_info_refresh: start\n");

	info = chat_info_new_with_level(ctx);
	if(!info) { goto error; }

	ops->chat_info_refresh(NULL, info);

	chat_info_free(info);

	fprintf(stderr, "libotr-mpOTR: chat_protocol_app_info_refresh: end\n");

	return 0;

error:
	return 1;
}

int chat_protocol_participants_list_load_fingerprints(OtrlUserState us, ChatContext ctx)
{
	OtrlListNode node1, node2, node3;
	OtrlListIterator iter1, iter2;
	ChatParticipant participant;
	OtrlChatFingerprint fnprnt, newfinger;
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
	fprintf(stderr, "libotr-mpOTR: chat_protocol_participants_list_load_fingerprints: error_with_newfinger\n");
	chat_fingerprint_free(newfinger);
error_with_iter2:
	fprintf(stderr, "libotr-mpOTR: chat_protocol_participants_list_load_fingerprints: error_with_iter2\n");
	otrl_list_iterator_free(iter2);
error_with_iter1:
	fprintf(stderr, "libotr-mpOTR: chat_protocol_participants_list_load_fingerprints: error_with_iter1\n");
	otrl_list_iterator_free(iter1);
error:
	fprintf(stderr, "libotr-mpOTR: chat_protocol_participants_list_load_fingerprints: error\n");
	return 1;
}

int chat_protocol_participants_list_init(OtrlUserState us, const OtrlMessageAppOps *ops, ChatContext ctx)
{
	int err;
	char **usernames;
	unsigned int usernames_size;
	OtrlChatInfo info;

	fprintf(stderr, "libotr-mpOTR: chat_protocol_participants_list_init: start\n");

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

	fprintf(stderr, "libotr-mpOTR: chat_protocol_participants_list_init: end\n");

    return 0;

error_with_participants_list:
	fprintf(stderr, "libotr-mpOTR: chat_protocol_participants_list_init: error_with_participants_list\n");
	otrl_list_clear(chat_context_get_participants_list(ctx));
error_with_usernames:
	fprintf(stderr, "libotr-mpOTR: chat_protocol_participants_list_init: error_with_usernames\n");
	for(unsigned int i = 0; i < usernames_size; i++) { free(usernames[i]); }
    free(usernames);
error_with_info:
	fprintf(stderr, "libotr-mpOTR: chat_protocol_participants_list_init: error_with_info\n");
	chat_info_free(info);
error:
	fprintf(stderr, "libotr-mpOTR: chat_protocol_participants_list_init: error\n");
	return 1;
}

void chat_protocol_reset(ChatContext ctx)
{
	chat_context_reset(ctx);
}

int chat_protocol_add_sign(ChatContext ctx, unsigned char **msg, size_t *msglen)
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

int chat_protocol_send_message(const OtrlMessageAppOps *ops, ChatContext ctx, ChatMessage *msg)
{
	OtrlChatInfo info;
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
	fprintf(stderr, "libotr-mpOTR: chat_protocol_send_message: error_with_info\n");
	chat_info_free(info);
error_with_message:
	fprintf(stderr, "libotr-mpOTR: chat_protocol_send_message: error_with_message\n");
	free(message);
error_with_buf:
	fprintf(stderr, "libotr-mpOTR: chat_protocol_send_message: error_with_buf\n");
	free(buf);
error:
	fprintf(stderr, "libotr-mpOTR: chat_protocol_send_message: error\n");
	return 1;

}

int chat_protocol_verify_sign(ChatContext ctx, const char *sender, const unsigned char *msg, const size_t msglen) {
	Signature *sign;
	ChatParticipant theSender;
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

int chat_protocol_pending_queue_add(ChatContext ctx, const char *sender, unsigned char *msg, size_t msglen)
{
	ChatPending pending;
	OtrlListNode node;

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

int chat_protocol_check_for_unknown_fingerprints(OtrlUserState us, const OtrlMessageAppOps *ops, ChatContext ctx)
{
	OtrlChatFingerprint finger, newFinger;
	OtrlListIterator iter;
	OtrlListNode node1, node2;
	ChatParticipant me, part;
	unsigned int pos, err;

	me = chat_participant_find(chat_context_get_participants_list(ctx), chat_context_get_accountname(ctx), &pos);
	if(!me) { goto error; }

	iter = otrl_list_iterator_new(chat_context_get_participants_list(ctx));
	if(!iter) { goto error; }

	while(otrl_list_iterator_has_next(iter)) {
		node1 = otrl_list_iterator_next(iter);
		part = otrl_list_node_get_payload(node1);

		if(part != me) {
			finger = chat_participant_get_fingerprint(part);
			if(finger == NULL) { goto error_with_iter; }

			// Check if this fingerprint is not in our list. If so, store it to our list
			node2 = otrl_list_find(us->chat_fingerprints, finger);
			if(!node2) {
				newFinger = chat_fingerprint_new(otrl_chat_fingerprint_get_accountname(finger),
						otrl_chat_fingerprint_get_protocol(finger),
						otrl_chat_fingerprint_get_username(finger),
						otrl_chat_fingerprint_get_bytes(finger),
						otrl_chat_fingerprint_is_trusted(finger));
				if(!newFinger) { goto error_with_iter; }

				err = chat_fingerprint_add(us->chat_fingerprints, newFinger);
				if(err) { goto error_with_newFinger; }

				ops->chat_fingerprints_write(NULL);
			}
		}
	}

	otrl_list_iterator_free(iter);

	return 0;

error_with_newFinger:
	chat_fingerprint_free(newFinger);
error_with_iter:
	otrl_list_iterator_free(iter);
error:
	return 1;
}

int chat_protocol_emit_event(const OtrlMessageAppOps *ops, const ChatContext ctx, OtrlChatEvent event)
{
	OtrlChatInfo info;

	info = chat_info_new(ctx);
	if(!info) { goto error; }

	ops->chat_handle_event(NULL, info, event);

	chat_info_free(info);

	return 0;

error:
	return 1;
}

int chat_protocol_emit_consensus_events(const OtrlMessageAppOps *ops, const ChatContext ctx)
{
	OtrlChatEvent event;
	OtrlListIterator iter;
	OtrlListNode cur;
	ChatParticipant me, part;
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

int chat_protocol_emit_offer_received_event(const OtrlMessageAppOps *ops, const ChatContext ctx, const char *username)
{
	OtrlChatEvent event;
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

int chat_protocol_emit_starting_event(const OtrlMessageAppOps *ops, const ChatContext ctx)
{
	OtrlChatEvent event;
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

int chat_protocol_emit_started_event(const OtrlMessageAppOps *ops, const ChatContext ctx)
{
	OtrlChatEvent event;
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

int chat_protocol_emit_unverified_participant_events(const OtrlMessageAppOps *ops, const ChatContext ctx)
{
	OtrlChatEvent event;
	OtrlListIterator iter;
	OtrlListNode cur;
	ChatParticipant me, part;
	OtrlChatFingerprint fnprnt;
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

int chat_protocol_emit_plaintext_received_event(const OtrlMessageAppOps *ops, const ChatContext ctx, const char *sender, const char *message)
{
	OtrlChatEvent event;
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

int chat_protocol_emit_private_received_event(const OtrlMessageAppOps *ops, const ChatContext ctx, const char *sender)
{
	OtrlChatEvent event;
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

int chat_protocol_emit_finished_event(const OtrlMessageAppOps *ops, const ChatContext ctx)
{
	OtrlChatEvent event;
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

int chat_protocol_handle_message(OtrlUserState us, const OtrlMessageAppOps *ops, ChatContext ctx, const char *sender, const unsigned char *message, size_t messagelen, char **newmessagep, int *ignore, int *pending)
{
	int err, ignore_message = 0, ispending = 0, isrejected = 0;
	ChatMessageType type;
	ChatMessage *msg = NULL, *msgToSend = NULL;

	fprintf(stderr, "libotr-mpOTR: chat_protocol_handle_message: start\n");

	err = chat_message_parse_type(message, messagelen, &type);
	if(err) { goto error; }

	//TODO Dimitris: a new participant in an already initialized private session maybe should be handled better
	if(chat_message_type_contains_sid(type)) {
		ChatOfferInfo offer_info = chat_context_get_offer_info(ctx);

		if(NULL == offer_info || CHAT_OFFERSTATE_FINISHED != chat_offer_info_get_state(offer_info)) {
			ispending = 1;
		} else {
			unsigned char *sid;
			err = chat_message_parse_sid(message, messagelen, &sid);
			if(err) { goto error; }

			if(memcmp(sid, chat_context_get_sid(ctx), CHAT_OFFER_SID_LENGTH)) {
				// rejecting
				isrejected = 1;
			}

			free(sid);
		}
	}

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

	if(!ispending && !isrejected) {

		msg = chat_message_parse(message, messagelen, sender);
		if(!msg) { goto error; }

		// handle offer messages
		if(chat_offer_is_my_message(msg)) {

			// TODO Dimtiris: Check if we have this already and free it
			if(NULL == chat_context_get_offer_info(ctx)) {

				// Library-Application Communication
				chat_protocol_emit_offer_received_event(ops, ctx, sender);

				err = chat_protocol_participants_list_init(us, ops, ctx);
				if(err) { goto error_with_msg; }

				err = chat_offer_info_init(ctx, otrl_list_size(chat_context_get_participants_list(ctx)));
				if(err) { goto error_with_msg; }
			}

			ChatOfferInfo offer_info = chat_context_get_offer_info(ctx);

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
					ChatIdKey *idkey = chat_privkeydh_find_or_generate(us, ops, chat_context_get_accountname(ctx), chat_context_get_protocol(ctx));
					if(!idkey) { goto error_with_msg; }

					chat_context_set_identity_key(ctx, idkey);

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

		// handle DSKE messages
		} else if(chat_dske_is_my_message(msg)) {
			ChatOfferInfo offer_info = chat_context_get_offer_info(ctx);
			ChatDSKEInfo dske_info = chat_context_get_dske_info(ctx);
			ChatGKAInfo gka_info = chat_context_get_gka_info(ctx);

			if(NULL == dske_info || NULL == offer_info || chat_offer_info_get_state(offer_info) != CHAT_OFFERSTATE_FINISHED) {
				ispending = 1;
			} else if(CHAT_DSKESTATE_FINISHED == chat_dske_info_get_state(dske_info)) {
				// reject
			} else {
				err = chat_dske_handle_message(ctx, msg, &msgToSend);
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

					err = chat_protocol_check_for_unknown_fingerprints(us, ops, ctx);
					if(err) { goto error_with_msg; }

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

		// handle GKA messages
		} else if(chat_gka_is_my_message(msg)) {
			ChatDSKEInfo dske_info = chat_context_get_dske_info(ctx);
			ChatGKAInfo gka_info = chat_context_get_gka_info(ctx);

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

		// handle attest messages
		} else if(chat_attest_is_my_message(msg)) {

			ChatGKAInfo gka_info = chat_context_get_gka_info(ctx);
			ChatAttestInfo attest_info = chat_context_get_attest_info(ctx);

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

		// handle data messages
		} else if(chat_communication_is_my_message(msg)) {

			ChatAttestInfo attest_info = chat_context_get_attest_info(ctx);

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

		// handle shutdown messages
		} else if (chat_shutdown_is_my_message(msg)) {

			ChatAttestInfo attest_info = chat_context_get_attest_info(ctx);

			if(NULL == attest_info || CHAT_ATTESTSTATE_FINISHED != chat_attest_info_get_state(attest_info)) {
				// reject
			} else {
				ChatShutdownInfo shutdown_info = chat_context_get_shutdown_info(ctx);
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

int chat_protocol_handle_pending(OtrlUserState us, const OtrlMessageAppOps *ops, ChatContext ctx) {
	OtrlListIterator iter;
	OtrlListNode cur;
	ChatPending pending;
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
	ChatContext ctx;
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
	ChatContext ctx;
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
	ChatContext ctx;
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
	ChatContext ctx;
	ChatShutdownInfo shutdown_info;
	OtrlList context_list;
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
