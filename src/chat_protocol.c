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
#include "b64.h"

//TODO Check every list find function to be optimized based on the sort


int chat_protocol_app_info_refresh(const OtrlMessageAppOps *ops, OtrlChatContext *ctx)
{
	OtrlChatInfo *info;

	fprintf(stderr, "libotr-mpOTR: chat_protocol_app_info_refresh: start\n");

	unsigned int pos;
	ChatParticipant *me = chat_participant_find(ctx, ctx->accountname, &pos);

	info = malloc(sizeof *info);
	if(!info) { goto error; }

	info->accountname = ctx->accountname;
	info->protocol = ctx->protocol;
	info->chat_token = ctx->the_chat_token;

	unsigned char untrusted = 0;
	OtrlListNode *cur;
	switch(ctx->msg_state) {

		case OTRL_MSGSTATE_PLAINTEXT:
			fprintf(stderr, "libotr-mpOTR: chat_protocol_app_info_refresh: case OTRL_MSGSTATE_PLAINTEXT\n");
			info->level = LEVEL_NONE;
			break;

		case OTRL_MSGSTATE_ENCRYPTED:
			fprintf(stderr, "libotr-mpOTR: chat_protocol_app_info_refresh: case OTRL_MSGSTATE_ENCRYPTED\n");
			for(cur = ctx->participants_list->head; cur != NULL && !untrusted; cur = cur->next) {
				ChatParticipant *part = cur->payload;

				fprintf(stderr, "libotr-mpOTR: chat_protocol_app_info_refresh: loop for participant: %s\n", part->username);

				if(part != me) {
					ChatFingerprint *finger = part->fingerprint;

					fprintf(stderr, "libotr-mpOTR: chat_protocol_app_info_refresh: is trusted: %d\n", finger->isTrusted);
					if (finger != NULL && !finger->isTrusted) {
						untrusted = 1;
					}
				}
			}

			fprintf(stderr, "libotr-mpOTR: chat_protocol_app_info_refresh: untrusted: %d\n", untrusted);
			info->level = (untrusted) ? LEVEL_UNVERIFIED : LEVEL_PRIVATE;

			fprintf(stderr, "libotr-mpOTR: chat_protocol_app_info_refresh: info->level: %d\n", info->level);
			break;

		case OTRL_MSGSTATE_FINISHED:
			fprintf(stderr, "libotr-mpOTR: chat_protocol_app_info_refresh: case OTRL_MSGSTATE_FINISHED\n");
			info->level = LEVEL_FINISHED;
	}

	ops->chat_info_refresh(NULL, info);
	free(info);

	fprintf(stderr, "libotr-mpOTR: chat_protocol_app_info_refresh: end\n");

	return 0;

error:
	return 1;
}

int chat_protocol_usernames_check_or_free(char **usernames, unsigned int usernames_size){
    unsigned char error = 0;

    if(!usernames)
    	return 1;

    /* Check if every username is allocated */
    for(size_t i = 0; i < usernames_size; i++)
    	if(!usernames[i]) {
    		error = 1;
    		break;
    	}

    /* If a username was not allocated then we must deallocate every username
       and the usernames array itself */
    if(error){
    	for(size_t i = 0; i < usernames_size; i++)
    		free(usernames[i]);
    	free(usernames);
    	return 1;
    }

    return 0;
}

int chat_protocol_participants_list_init(OtrlUserState us, const OtrlMessageAppOps *ops, OtrlChatContext *ctx)
{
	int err;
	char **usernames;
	unsigned int usernames_size;
	OtrlListNode *cur = NULL;
	OtrlListNode *node = NULL, *node2 = NULL;

	fprintf(stderr, "libotr-mpOTR: chat_protocol_participants_list_init: start\n");

	usernames = ops->chat_get_participants(NULL, ctx->accountname, ctx->protocol, ctx->the_chat_token, &usernames_size);

	err = chat_protocol_usernames_check_or_free(usernames,usernames_size);
	if(err) { goto error; }

	err = chat_participant_list_from_usernames(ctx->participants_list, usernames, usernames_size);
	if(err) { goto error_with_usernames; }

	for(unsigned int i = 0; i < usernames_size; i++) { free(usernames[i]); }
	free(usernames);

	// TODO better implementation to load trusted fingerprints

	for (cur = ctx->participants_list->head; cur != NULL; cur = cur->next) {
		ChatParticipant *participant = cur->payload;

		for(node = us->chat_fingerprints->head; node != NULL; node = node->next) {
			ChatFingerprint *fngrprnt = node->payload;

			if(strcmp(fngrprnt->username, participant->username) == 0 &&
				strcmp(fngrprnt->accountname, ctx->accountname) == 0 &&
				strcmp(fngrprnt->protocol, ctx->protocol) == 0) {

				ChatFingerprint *newfinger = chat_fingerprint_new(fngrprnt->accountname, fngrprnt->protocol, fngrprnt->username, fngrprnt->fingerprint, fngrprnt->isTrusted);
				if(!newfinger) { goto error; }

				node2 = otrl_list_insert(participant->fingerprints, newfinger);
				if(!node2) {
					chat_fingerprint_destroy(newfinger);
					goto error;
				}
			}

		}
	}

	fprintf(stderr, "libotr-mpOTR: chat_protocol_participants_list_init: end\n");

    return 0;

error_with_usernames:
	for(unsigned int i = 0; i < usernames_size; i++) { free(usernames[i]); }
    free(usernames);
error:
	return 1;
}

void chat_protocol_reset(OtrlUserState us, OtrlChatContext *ctx)
{
	chat_context_remove(us, ctx);
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
	char *message, *token;
	unsigned char *buf;
	size_t buflen;
	int chat_flag = 1;
	int err;

	fprintf(stderr, "libotr-mpOTR: chat_protocol_send_message: start\n");

	buf = chat_message_serialize(msg, &buflen);
	if(!buf) { goto error; }

	fprintf(stderr, "libotr-mpOTR: chat_protocol_send_message: before chat_message_type_should_be_signed\n");
	if(chat_message_type_should_be_signed(msg->msgType) && ctx->sign_state == CHAT_SINGSTATE_SINGED) {
		err = chat_protocol_add_sign(ctx, &buf, &buflen);
		if(err) { goto error_with_buf; }
	}

	fprintf(stderr, "libotr-mpOTR: chat_protocol_send_message: before otrl_base64_otr_encode\n");
	message = otrl_base64_otr_encode(buf, buflen);
	if(!message) { goto error_with_buf; }

	// TODO Dimtiris: this is a work-around to pass the token as a recipient string. We should change that ASAP
	// 				  maybe define another callback with this prototype:
	//				  inject_chat_message(const char * accountname, const char *protocol, otrl_chat_token_t token, const char *message)
	token = malloc(sizeof(int));
	if(!token) { goto error_with_message; }

	memcpy(token, (char*)ctx->the_chat_token, sizeof(int));
	ops->inject_message(&chat_flag, ctx->accountname, ctx->protocol, token, message);

	free(token);
	free(buf);
	free(message);

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
	chat_pending_destroy(pending);
error:
	return 1;
}

int chat_protocol_handle_message(OtrlUserState us, const OtrlMessageAppOps *ops, OtrlChatContext *ctx, const char *sender, const unsigned char *message, size_t messagelen, char **newmessagep, int *ignore, int *pending)
{
	int err, ignore_message = 0, ispending = 0, isrejected = 0;
	ChatMessageType type;
	ChatMessage *msg = NULL, *msgToSend = NULL;
	unsigned int our_pos;

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
		fprintf(stderr, "libotr-mpOTR: chat_protocol_handle_message: before message parse\n");
		msg = chat_message_parse(message, messagelen, sender);
		if(!msg) { goto error; }
	    fprintf(stderr, "libotr-mpOTR: chat_protocol_handle_message: after message parse\n");
		// handle offer messages
		if(chat_offer_is_my_message(msg)) {
			// TODO Dimtiris: Check if we have this already and free it
			if(!ctx->offer_info) {
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
				if(ctx->dske_info && ctx->dske_info->state == CHAT_DSKESTATE_FINISHED && ctx->gka_info.state == CHAT_GKASTATE_NONE) {

					fprintf(stderr,"chat_protocol_handle_message: before looping participants\n");

					unsigned int pos;
					ChatParticipant *me = chat_participant_find(ctx, ctx->accountname, &pos);

					// Check for unverified participants
					OtrlListNode *cur;
					for(cur = ctx->participants_list->head; cur != NULL; cur=cur->next) {
						ChatParticipant *part = cur->payload;

						if(part != me) {

						ChatFingerprint *finger = part->fingerprint;

							if(finger == NULL) { fprintf(stderr,"chat_protocol_handle_message: finger == NULL!!!!\n"); }

							// TODO Dimitris: info to the user
							fprintf(stderr,"chat_protocol_handle_message: before if(!finger->isTrusted)\n");
							if(!finger->isTrusted) {
								fprintf(stderr,"chat_protocol_handle_message: before otrl_chat_fingerprint_bytes_to_hex\n");
								char *finger_hex = otrl_chat_fingerprint_bytes_to_hex(finger->fingerprint);
								if(finger_hex) {
									fprintf(stderr,"chat_protocol_handle_message: NOT TRUSTED FINGERPRINT: %s, %s, %s, %s\n", finger->accountname, finger->protocol, finger->username, finger_hex);
									free(finger_hex);
								}
							}

							fprintf(stderr,"chat_protocol_handle_message: before otrl_list_find\n");
							OtrlListNode *node = otrl_list_find(us->chat_fingerprints, finger);
							if(!node) {
								fprintf(stderr,"chat_protocol_handle_message: before chat_fingerprint_new\n");
								ChatFingerprint *newFinger = chat_fingerprint_new(finger->accountname, finger->protocol, finger->username, finger->fingerprint, finger->isTrusted);
								//TODO error handling
								fprintf(stderr,"chat_protocol_handle_message: before chat_fingerprint_add\n");
								chat_fingerprint_add(us, newFinger);
								fprintf(stderr,"chat_protocol_handle_message: before chat_fingerprints_write\n");
								ops->chat_fingerprints_write(NULL);

								fprintf(stderr,"chat_protocol_handle_message: before otrl_chat_fingerprint_bytes_to_hex\n");
								char *finger_hex = otrl_chat_fingerprint_bytes_to_hex(newFinger->fingerprint);
								if(finger_hex) {
									fprintf(stderr,"chat_protocol_handle_message: Adding fingerprint: %s, %s, %s, %s\n", newFinger->accountname, newFinger->protocol, newFinger->username, finger_hex);
									free(finger_hex);
								}
							}
						}
					}


					ctx->sign_state = CHAT_SINGSTATE_SINGED;
					err = chat_participant_get_position(ctx->participants_list, ctx->accountname, &our_pos);
					if(err) { goto error_with_msg;  }
					if(our_pos == 0 ) {
						err = chat_auth_init(ctx, &msgToSend);
						if(err) { goto error_with_msg; }
						err = chat_protocol_send_message(ops, ctx, msgToSend);
						if(err) { goto error_with_msgToSend; }
						chat_message_free(msgToSend);
						msgToSend = NULL;
					} else {
						ctx->gka_info.state = CHAT_GKASTATE_AWAITING_UPFLOW;
					}
				}
			}
			ignore_message = 1;

		// handle authentication messages
		} else if(chat_auth_is_my_message(msg)) {


			if(!ctx->dske_info || ctx->dske_info->state != CHAT_DSKESTATE_FINISHED) {
				ispending = 1;
			} else if(ctx->gka_info.state == CHAT_GKASTATE_FINISHED) {
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

				if(ctx->gka_info.state == CHAT_GKASTATE_FINISHED) {
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

			if(!ctx->attest_info || ctx->gka_info.state != CHAT_GKASTATE_FINISHED) {
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
					chat_protocol_app_info_refresh(ops, ctx);
					chat_shutdown_init(ctx);
				}
			}
			ignore_message = 1;

		// handle data messages
		} else if(chat_communication_is_my_message(msg)) {
			// TODO handle the case we need to add this to the pending queue

			char *plaintext;
			err = chat_communication_handle_msg(ctx, msg, NULL, &plaintext);
			if(err) { goto error_with_msg; }
			*newmessagep = plaintext;
			//ChatMessagePayloadData *payload = msg->payload;
			//switch(ctx->msg_state) {

				//case OTRL_MSGSTATE_PLAINTEXT:
				//case OTRL_MSGSTATE_FINISHED:
					///* TODO if plaintext or finished ignore the message. In the future handle this more gracefully */
					//goto error_with_msg;
					//break;

				//case OTRL_MSGSTATE_ENCRYPTED:
					//plaintext = chat_enc_decrypt(ctx, payload->ciphertext, payload->datalen, payload->ctr, sender);
					///* TODO ignore if there was an error. handle this more gracefully in the future */
					//if (!plaintext) { goto error_with_msg; }
					//*newmessagep = plaintext;
					//break;
			//}

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

					chat_protocol_app_info_refresh(ops, ctx);

					chat_protocol_reset(us, ctx);
				}
			}

			ignore_message = 1;
		}
	}
	fprintf(stderr, "libotr-mpOTR: chat_protocol_handle_message: after my_message if\n");

	fprintf(stderr, "libotr-mpOTR: chat_protocol_handle_message: almost end\n");

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
		fprintf(stderr, "libotr-mpOTR: chat_protocol_handle_pending: in while #1\n");
		flag = 0;
		cur = ctx->pending_list->head;
		while(cur != NULL) {
			fprintf(stderr, "libotr-mpOTR: chat_protocol_handle_pending: in while #2\n");
			pending = cur->payload;

			fprintf(stderr, "libotr-mpOTR: chat_protocol_handle_pending: before next = cur->next\n");
			next = cur->next;

			// TODO newmessagep NULL????????
			err = chat_protocol_handle_message(us, ops, ctx, chat_pending_get_sender(pending), chat_pending_get_msg(pending), chat_pending_get_msglen(pending), NULL, &ignore, &ispending);
			if(err) { goto error; }

			fprintf(stderr, "libotr-mpOTR: chat_protocol_handle_pending: before if\n");

			if(!ispending) {
				fprintf(stderr, "libotr-mpOTR: chat_protocol_handle_pending: in if(!ispending)\n");
				otrl_list_remove_and_destroy(ctx->pending_list, cur);
				flag = 1;
			}
			fprintf(stderr, "libotr-mpOTR: chat_protocol_handle_pending: before cur = next\n");
			cur = next;
			fprintf(stderr, "libotr-mpOTR: chat_protocol_handle_pending: after cur = next\n");
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
			ctx = chat_context_find_or_add(us, ops, accountname, protocol, chat_token);
			if(!ctx) { goto error_with_buf; }
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

			//ciphertext = chat_enc_encrypt(ctx, message);
			//if(!ciphertext) { goto error; }

			//// TODO maybe get length from chat_enc_encrypt so that we can support other modes of aes
			//datalen = strlen(message);

			//msg = chat_message_data_create(ctx, ctx->enc_info.ctr, datalen, ciphertext);
			//if(!msg) { goto error_with_ciphertext; }

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

	ctx = chat_context_find_or_add(us, ops, accountname, protocol, chat_token);
	if(!ctx) { goto error; }

	// TODO Dimtiris: Check if we have this already and free it
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
