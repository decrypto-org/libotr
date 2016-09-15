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

#include "userstate.h"
#include "message.h"
#include "chat_token.h"
#include "chat_message.h"
#include "chat_types.h"
#include "chat_context.h"
#include "chat_offer.h"
#include "chat_auth.h"
#include "chat_enc.h"
#include "chat_participant.h"
#include "chat_dske.h"
#include "chat_privkeydh.h"
#include "chat_fingerprint.h"
#include "chat_attest.h"
#include "chat_shutdown.h"
#include "chat_pending.h"
#include "chat_communication.h"
#include "chat_info.h"
#include "chat_event.h"
#include "b64.h"

//TODO Check every list find function to be optimized based on the sort


int chat_protocol_app_info_refresh(const OtrlMessageAppOps *ops, OtrlChatContext *ctx)
{
	OtrlChatInfo *info;

	fprintf(stderr, "libotr-mpOTR: chat_protocol_app_info_refresh: start\n");

	info = chat_info_create_with_level(ctx);
	if(!info) { goto error; }

	ops->chat_info_refresh(NULL, info);

	chat_info_free(info);

	fprintf(stderr, "libotr-mpOTR: chat_protocol_app_info_refresh: end\n");

	return 0;

error:
	return 1;
}

int chat_protocol_participants_list_load_fingerprints(OtrlUserState us, OtrlChatContext *ctx)
{
	OtrlListNode *cur = NULL, *node = NULL, *node2 = NULL;
	OtrlChatFingerprint *fngrprnt = NULL, *newfinger = NULL;

	for (cur = ctx->participants_list->head; cur != NULL; cur = cur->next) {
		ChatParticipant *participant = cur->payload;

		for(node = us->chat_fingerprints->head; node != NULL; node = node->next) {
			fngrprnt = node->payload;

			if(strcmp(fngrprnt->username, participant->username) == 0 &&
				strcmp(fngrprnt->accountname, ctx->accountname) == 0 &&
				strcmp(fngrprnt->protocol, ctx->protocol) == 0) {

				newfinger = chat_fingerprint_new(fngrprnt->accountname, fngrprnt->protocol, fngrprnt->username, fngrprnt->fingerprint, fngrprnt->isTrusted);
				if(!newfinger) { goto error; }

				node2 = otrl_list_insert(participant->fingerprints, newfinger);
				if(!node2) { goto error_with_newfinger; }
			}

		}
	}

	return 0;

error_with_newfinger:
	chat_fingerprint_free(newfinger);
error:
	return 1;
}

int chat_protocol_participants_list_init(OtrlUserState us, const OtrlMessageAppOps *ops, OtrlChatContext *ctx)
{
	int err;
	char **usernames;
	unsigned int usernames_size;
	OtrlChatInfo *info;

	fprintf(stderr, "libotr-mpOTR: chat_protocol_participants_list_init: start\n");

	info = chat_info_create(ctx);
	if(!info) { goto error; }

	usernames = ops->chat_get_participants(NULL, info, &usernames_size);
	if(!usernames) { goto error_with_info; }

	err = chat_participant_list_from_usernames(ctx->participants_list, usernames, usernames_size);
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
	otrl_list_clear(ctx->participants_list);
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

int chat_protocol_reset(OtrlUserState us, OtrlChatContext *ctx)
{
	int err;

	err = chat_context_reset(ctx);
	if(err) { goto error; }

	//chat_context_remove(us, ctx);

	return 0;

error:
	return 1;
}

int chat_protocol_add_sign(OtrlChatContext *ctx, unsigned char **msg, size_t *msglen)
{
	Signature *aSign;
	unsigned char *sig = NULL, *buf;
	size_t siglen;
	int err;

	aSign = chat_sign_sign(ctx->signing_key, *msg, *msglen);
	if(!aSign) { goto error; }

	err = chat_sign_signature_serialize(aSign, &sig, &siglen);
	if(err) { goto error_with_aSign; }

	buf = malloc((*msglen+siglen) * sizeof *buf);
	if(!buf) { goto error_with_sig; }

	memcpy(buf, *msg, *msglen);
	memcpy(&buf[*msglen], sig, siglen);

	free(*msg);
	free(sig);
	chat_sign_destroy_signature(aSign);

	*msg = buf;
	*msglen = *msglen+siglen;
	return 0;

error_with_sig:
	free(sig);
error_with_aSign:
	chat_sign_destroy_signature(aSign);
error:
	return 1;
}

int chat_protocol_send_message(const OtrlMessageAppOps *ops, OtrlChatContext *ctx, ChatMessage *msg)
{
	OtrlChatInfo *info;
	char *message;
	unsigned char *buf;
	size_t buflen;
	int err;

	fprintf(stderr, "libotr-mpOTR: chat_protocol_send_message: start\n");

	buf = chat_message_serialize(msg, &buflen);
	if(!buf) { goto error; }

	if(chat_message_type_should_be_signed(msg->msgType) && ctx->sign_state == CHAT_SINGSTATE_SINGED) {
		err = chat_protocol_add_sign(ctx, &buf, &buflen);
		if(err) { goto error_with_buf; }
	}

	message = otrl_base64_otr_encode(buf, buflen);
	if(!message) { goto error_with_buf; }

	info = chat_info_create(ctx);
	if(!info) { goto error_with_message; }

	ops->chat_inject_message(NULL, info, message);

	chat_info_free(info);
	free(message);
	free(buf);

	fprintf(stderr, "libotr-mpOTR: chat_protocol_send_message: end\n");

	return 0;

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

int chat_protocol_verify_sign(OtrlChatContext *ctx, const char *sender, const unsigned char *msg, const size_t msglen) {
	Signature *sign;
	ChatParticipant *theSender;
	unsigned int their_pos;
	int err;

	err = chat_sign_signature_parse(&msg[msglen-CHAT_SIGN_SIGNATURE_LENGTH], &sign);
	if(err) {
		goto error;
	}

	theSender = chat_participant_find(ctx, sender, &their_pos);
	if(!theSender) {
		goto error_with_sign;
	}

	err = chat_sign_verify(theSender->sign_key, msg, msglen - CHAT_SIGN_SIGNATURE_LENGTH, sign);
	if(err) {
		goto error_with_sign;
	}
	fprintf(stderr, "libotr-mpOTR: chat_protocol_verify_sign: after chat_sign_verify\n");

	chat_sign_destroy_signature(sign);

	return 0;

error_with_sign:
	chat_sign_destroy_signature(sign);
error:
	return 1;
}

int chat_protocol_pending_queue_add(OtrlChatContext *ctx, const char *sender, unsigned char *msg, size_t msglen)
{
	ChatPendingPtr pending;
	OtrlListNode *node;

	pending = chat_pending_create(sender, msg, msglen);
	if(!pending) { goto error; }

	node = otrl_list_append(ctx->pending_list, (PayloadPtr)pending);
	if(!node) { goto error_with_pending; }

	return 0;

error_with_pending:
	chat_pending_free(pending);
error:
	return 1;
}

int chat_protocol_check_for_unknown_fingerprints(OtrlUserState us, const OtrlMessageAppOps *ops, OtrlChatContext *ctx)
{
	OtrlChatFingerprint *finger = NULL;
	OtrlChatFingerprint *newFinger = NULL;
	ChatParticipant *me = NULL;
	ChatParticipant *part = NULL;
	unsigned int pos, err;
	OtrlListNode *cur = NULL;

	me = chat_participant_find(ctx, ctx->accountname, &pos);
	if(!me) { goto error; }

	for(cur = ctx->participants_list->head; cur != NULL; cur=cur->next) {
		part = cur->payload;

		if(part != me) {
			finger = part->fingerprint;
			if(finger == NULL) { goto error; }

			/*
			if(!finger->isTrusted) {
				char *finger_hex = otrl_chat_fingerprint_bytes_to_hex(finger->fingerprint);
				if(finger_hex) {
					fprintf(stderr,"chat_protocol_handle_message: NOT TRUSTED FINGERPRINT: %s, %s, %s, %s\n", finger->accountname, finger->protocol, finger->username, finger_hex);
					free(finger_hex);
				}
			}
			*/

			// Check if this fingerprint is not in our list. If so, store it to our list
			OtrlListNode *node = otrl_list_find(us->chat_fingerprints, finger);
			if(!node) {
				OtrlChatFingerprint *newFinger = chat_fingerprint_new(finger->accountname, finger->protocol, finger->username, finger->fingerprint, finger->isTrusted);
				if(!newFinger) { goto error; }

				err = chat_fingerprint_add(us, newFinger);
				if(err) { goto error_with_newFinger; }

				ops->chat_fingerprints_write(NULL);

				/*
				char *finger_hex = otrl_chat_fingerprint_bytes_to_hex(newFinger->fingerprint);
				if(finger_hex) {
					fprintf(stderr,"chat_protocol_handle_message: Adding fingerprint: %s, %s, %s, %s\n", newFinger->accountname, newFinger->protocol, newFinger->username, finger_hex);
					free(finger_hex);
				}
				*/
			}
		}
	}

	return 0;

error_with_newFinger:
	chat_fingerprint_free(newFinger);
error:
	return 1;
}

int chat_protocol_emit_event(const OtrlMessageAppOps *ops, const OtrlChatContext *ctx, OtrlChatEvent *event)
{
	OtrlChatInfo *info = NULL;

	info = chat_info_create(ctx);
	if(!info) { goto error; }

	ops->chat_handle_event(NULL, info, event);

	chat_info_free(info);

	return 0;

error:
	return 1;
}

int chat_protocol_emit_consensus_events(const OtrlMessageAppOps *ops, const OtrlChatContext *ctx)
{
	OtrlChatEvent *event;
	OtrlListNode *cur = NULL;
	ChatParticipant * me = NULL;
	unsigned int pos;
	int err;

	me = chat_participant_find(ctx, ctx->accountname, &pos);
	if(!me) { goto error; }

	for(cur = ctx->participants_list->head;	cur != NULL; cur=cur->next) {
		ChatParticipant *part = cur->payload;
		if(part != me && !part->consensus) {
			event = chat_event_consensus_broken_create(part->username);
			if(!event) { goto error; }

			err = chat_protocol_emit_event(ops, ctx, event);
			if(err) { goto error_with_event; }

			chat_event_free(event);
		}
	}

	return 0;

error_with_event:
	chat_event_free(event);
error:
	return 1;
}

int chat_protocol_emit_offer_received_event(const OtrlMessageAppOps *ops, const OtrlChatContext *ctx, const char *username)
{
	OtrlChatEvent *event;
	int err;

	event = chat_event_offer_received_create(username);
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

int chat_protocol_emit_started_event(const OtrlMessageAppOps *ops, const OtrlChatContext *ctx)
{
	OtrlChatEvent *event;
	int err;

	event = chat_event_started_create();
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

int chat_protocol_emit_finished_event(const OtrlMessageAppOps *ops, const OtrlChatContext *ctx)
{
	OtrlChatEvent *event;
	int err;

	event = chat_event_finished_create();
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

int chat_protocol_handle_message(OtrlUserState us, const OtrlMessageAppOps *ops, OtrlChatContext *ctx, const char *sender, const unsigned char *message, size_t messagelen, char **newmessagep, int *ignore, int *pending)
{
	int err, ignore_message = 0, ispending = 0, isrejected = 0;
	ChatMessageType type;
	ChatMessage *msg = NULL, *msgToSend = NULL;

	fprintf(stderr, "libotr-mpOTR: chat_protocol_handle_message: start\n");

	err = chat_message_parse_type(message, messagelen, &type);
	if(err) { goto error; }

	if(chat_message_type_contains_sid(type)) {
		if(!ctx->offer_info || ctx->offer_info->state != CHAT_OFFERSTATE_FINISHED) {
			ispending = 1;
		} else {
			unsigned char *sid;
			err = chat_message_parse_sid(message, messagelen, &sid);
			if(err) { goto error; }

			if(memcmp(sid, ctx->sid, CHAT_OFFER_SID_LENGTH)) {
				// rejecting
				isrejected = 1;
			}

			free(sid);
		}
	}

	if(!ispending && !isrejected ) {
		if(chat_message_type_should_be_signed(type)){
			if(ctx->sign_state != CHAT_SINGSTATE_SINGED) {
				ispending = 1;
			} else {
				err = chat_protocol_verify_sign(ctx, sender, message, messagelen);
				if(err) { goto error; }
				messagelen -= CHAT_SIGN_SIGNATURE_LENGTH;
			}
		}
	}

	fprintf(stderr, "libotr-mpOTR: chat_protocol_handle_message: ispending: %d, isrejected: %d \n", ispending, isrejected);
	if(!ispending && !isrejected) {

		msg = chat_message_parse(message, messagelen, sender);
		if(!msg) { goto error; }

		// handle offer messages
		if(chat_offer_is_my_message(msg)) {
			// TODO Dimtiris: Check if we have this already and free it
			if(!ctx->offer_info) {

				// Library-Application Communication
				chat_protocol_emit_offer_received_event(ops, ctx, sender);

				err = chat_protocol_participants_list_init(us, ops, ctx);
				if(err) { goto error_with_msg; }

				err = chat_offer_info_init(ctx, otrl_list_length(ctx->participants_list));
				if(err) { goto error_with_msg; }
			}

			if(ctx->offer_info->state == CHAT_OFFERSTATE_FINISHED) {
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

				if(ctx->offer_info && ctx->offer_info->state == CHAT_OFFERSTATE_FINISHED) {

					// Load or generate our private key
					ChatIdKey *idkey = chat_privkeydh_find_or_generate(us, ops, ctx->accountname, ctx->protocol);
					if(!idkey) { goto error_with_msg; }
					ctx->identity_key = idkey;

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

		// handle dske messages
		} else if(chat_dske_is_my_message(msg)) {

			if(!ctx->dske_info || !ctx->offer_info || ctx->offer_info->state != CHAT_OFFERSTATE_FINISHED) {
				ispending = 1;
			} else if(ctx->dske_info->state == CHAT_DSKESTATE_FINISHED) {
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
				if(ctx->dske_info && ctx->dske_info->state == CHAT_DSKESTATE_FINISHED &&
						(!ctx->gka_info || ctx->gka_info->state == CHAT_GKASTATE_NONE)) {

					err = chat_protocol_check_for_unknown_fingerprints(us, ops, ctx);
					if(err) { goto error_with_msg; }

					ctx->sign_state = CHAT_SINGSTATE_SINGED;

					err = chat_auth_init(ctx, &msgToSend);
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

		// handle authentication messages
		} else if(chat_auth_is_my_message(msg)) {


			if(!ctx->dske_info || ctx->dske_info->state != CHAT_DSKESTATE_FINISHED) {
				ispending = 1;
			} else if(ctx->gka_info->state == CHAT_GKASTATE_FINISHED) {
				// reject
			} else {
				err = chat_auth_handle_message(ctx, msg, &msgToSend);
				if(err) { goto error_with_msg; }

				if(msgToSend) {
					err = chat_protocol_send_message(ops, ctx, msgToSend);
					if(err) { goto error_with_msgToSend; }
					chat_message_free(msgToSend);
					msgToSend = NULL;
				}

				if(ctx->gka_info->state == CHAT_GKASTATE_FINISHED) {
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

			if(!ctx->attest_info || ctx->gka_info->state != CHAT_GKASTATE_FINISHED) {
				ispending = 1;
			} else if(ctx->attest_info->state == CHAT_ATTESTSTATE_FINISHED) {
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

				if(ctx->attest_info && ctx->attest_info->state == CHAT_ATTESTSTATE_FINISHED) {
					// Library-Application Communication
					chat_protocol_emit_started_event(ops, ctx);
					chat_protocol_app_info_refresh(ops, ctx);

					chat_shutdown_init(ctx);
				}
			}
			ignore_message = 1;

		// handle data messages
		} else if(chat_communication_is_my_message(msg)) {

			//TODO Dimitris: check pending and rejecting statements
			if(!ctx->enc_info || (ctx->attest_info && ctx->attest_info->state != CHAT_ATTESTSTATE_FINISHED)) {
				ispending = 1;
			/*} else if(ctx->attest_info->state == CHAT_ATTESTSTATE_FINISHED) {
				// reject*/
			} else {
				char *plaintext;
				err = chat_communication_handle_msg(ctx, msg, NULL, &plaintext);
				if(err) { goto error_with_msg; }
				*newmessagep = plaintext;
			}

		// handle shutdown messages
		} else if (chat_shutdown_is_my_message(msg)) {
	        fprintf(stderr, "libotr-mpOTR: chat_protocol_handle_message: is shutdown\n");
			if(!ctx->attest_info || ctx->attest_info->state != CHAT_ATTESTSTATE_FINISHED) {
				// reject
			} else {

				ChatShutdownState prevState = ctx->shutdown_info.state;

				err = chat_shutdown_handle_message(ctx, msg, &msgToSend);
				if(err) { goto error_with_msg; }

				if(msgToSend) {
					err = chat_protocol_send_message(ops, ctx, msgToSend);
					if(err) { goto error_with_msgToSend; }
					chat_message_free(msgToSend);
					msgToSend = NULL;
				}

				if(ctx->shutdown_info.state == CHAT_SHUTDOWNSTATE_AWAITING_DIGESTS && prevState == CHAT_SHUTDOWNSTATE_AWAITING_SHUTDOWNS) {
					err = chat_shutdown_send_digest(ctx, &msgToSend);
					if(err) { goto error_with_msgToSend;}

					err = chat_protocol_send_message(ops, ctx, msgToSend);
					if(err) { goto error_with_msgToSend; }

					chat_message_free(msgToSend);
					msgToSend = NULL;
				}

				if(ctx->shutdown_info.state == CHAT_SHUTDOWNSTATE_AWAITING_ENDS && prevState == CHAT_SHUTDOWNSTATE_AWAITING_DIGESTS) {
	                fprintf(stderr, "libotr-mpOTR: chat_protocol_handle_message: should send end\n");
					err = chat_shutdown_send_end(ctx, &msgToSend);
					if(err) { goto error_with_msgToSend;}

					err = chat_protocol_send_message(ops, ctx, msgToSend);
					if(err) { goto error_with_msgToSend; }

					chat_message_free(msgToSend);
					msgToSend = NULL;
				}

				if(ctx->shutdown_info.state == CHAT_SHUTDOWNSTATE_FINISHED) {
					ctx->msg_state = OTRL_MSGSTATE_FINISHED;

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

					err = chat_protocol_reset(us, ctx);
					if(err) { goto error_with_msg; }
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

int chat_protocol_handle_pending(OtrlUserState us, const OtrlMessageAppOps *ops, OtrlChatContext *ctx) {
	OtrlListNode *cur, *next;
	ChatPendingPtr pending;
	unsigned short int flag = 1;
	int err, ispending, ignore;

	fprintf(stderr, "libotr-mpOTR: chat_protocol_handle_pending: start\n");

	if(otrl_list_length(ctx->pending_list) > 0) {
		fprintf(stderr, "=========================================================\n");
		fprintf(stderr, "libotr-mpOTR: chat_protocol_handle_pending: PENDING LIST:\n");
		otrl_list_dump(ctx->pending_list);
		fprintf(stderr, "=========================================================\n");
	}

	while(flag) {
		flag = 0;
		cur = ctx->pending_list->head;
		while(cur != NULL) {
			pending = cur->payload;
			next = cur->next;

			// TODO newmessagep NULL????????
			err = chat_protocol_handle_message(us, ops, ctx, chat_pending_get_sender(pending), chat_pending_get_msg(pending), chat_pending_get_msglen(pending), NULL, &ignore, &ispending);
			if(err) { goto error; }

			if(!ispending) {
				otrl_list_remove_and_free(ctx->pending_list, cur);
				flag = 1;
			}
			cur = next;
		}
	}

	fprintf(stderr, "libotr-mpOTR: chat_protocol_handle_pending: end\n");

	return 0;
error:
	return 1;
}

int otrl_chat_protocol_receiving(OtrlUserState us, const OtrlMessageAppOps *ops,
	void *opdata, const char *accountname, const char *protocol,
	const char *sender, otrl_chat_token_t chat_token, const char *message,
	char **newmessagep,	OtrlTLV **tlvsp)
{
	OtrlChatContext * ctx;
	int ignore_message = 0; // flag to determine if the message should be ignored
	int ispending, err;
	unsigned char *buf;
	size_t buflen;

	fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_receiving: start\n");

	if( !accountname || !protocol || !sender || !message || !newmessagep) { goto error; }

	ctx = chat_context_find_or_add(us, ops, accountname, protocol, chat_token);
	if(!ctx) { goto error; }

	if(!chat_message_is_otr(message)) {
		if (ctx->msg_state != OTRL_MSGSTATE_PLAINTEXT) {
			if(ops->handle_msg_event) {
				ops->handle_msg_event(/*opdata*/ NULL, OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED, NULL,  message, gcry_error(GPG_ERR_NO_ERROR));
				ignore_message = 1;
			}
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
	OtrlChatContext * ctx;
	unsigned char *buf;
	ChatMessage *msg;
	size_t buflen;
	int err;

	fprintf(stderr, "libotr-mpOTR: otrl_chat_message_sending: start\n");

	if( !accountname || !protocol || !message) { goto error; }

	ctx = chat_context_find_or_add(us, ops, accountname, protocol, chat_token);
	if(!ctx) { goto error; }

	switch(ctx->msg_state) {
		case OTRL_MSGSTATE_PLAINTEXT:
			fprintf(stderr, "libotr-mpOTR: otrl_chat_message_sending: case OTRL_MSGSTATE_PLAINTEXT\n");
			break;
		case OTRL_MSGSTATE_ENCRYPTED:
			fprintf(stderr, "libotr-mpOTR: otrl_chat_message_sending: case OTRL_MSGSTATE_ENCRYPTED\n");

			err = chat_communication_broadcast(ctx, message, &msg);
			if(err) { goto error; }

			buf = chat_message_serialize(msg, &buflen);
			if(!buf) { goto error_with_msg; }

			if(chat_message_type_should_be_signed(msg->msgType) && ctx->sign_state == CHAT_SINGSTATE_SINGED) {
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
	OtrlChatContext *ctx;
	int err;

	fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_send_query: start\n");

	// TODO Dimtiris: What happens if we have already a context????

	ctx = chat_context_find_or_add(us, ops, accountname, protocol, chat_token);
	if(!ctx) { goto error; }

	err = chat_protocol_participants_list_init(us, ops, ctx);
	if(err) { goto error; }

	err = chat_offer_start(ctx, &msgToSend);
	if(err) { goto error; }

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
	OtrlChatContext *ctx;
	int err;

	fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_shutdown: start\n");

	// TODO only find not add
	ctx = chat_context_find(us, ops, accountname, protocol, chat_token);
	if(!ctx) { goto error; }

	if(ctx->shutdown_info.state != CHAT_SHUTDOWNSTATE_AWAITING_SHUTDOWNS) { goto error; }

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
