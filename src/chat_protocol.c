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
#include "b64.h"

//TODO Check every list find function to be optimized based on the sort

void chat_protocol_reset(OtrlUserState us, OtrlChatContext *ctx)
{
	/*
	ctx->msg_state = OTRL_MSGSTATE_PLAINTEXT;
	otrl_list_clear(ctx->participants_list);
	if(ctx->offer_info) {
		chat_offer_info_destroy(ctx);
	}
	if(ctx->attest_info) {
		chat_attest_info_destroy(ctx);
	}
	chat_dske_destroy_info(&ctx->dske_info);
	chat_auth_gka_info_destroy(&ctx->gka_info);
	chat_enc_info_destroy(&ctx->enc_info);
	ctx->sign_state = OTRL_CHAT_SINGSTATE_NONE;
	chat_sign_destroy_key(ctx->signing_key);
	ctx->signing_key = NULL;
	// signing_key, identity_key, sid????
	ctx->shutdown_info.state = OTRL_CHAT_SHUTDOWNSTATE_NONE;*/
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

int chat_protocol_send_message(const OtrlMessageAppOps *ops, OtrlChatContext *ctx, OtrlChatMessage *msg)
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
	if(chat_message_type_should_be_signed(msg->msgType) && ctx->sign_state == OTRL_CHAT_SINGSTATE_SINGED) {
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
	free(message);
error_with_buf:
	free(buf);
error:
	return 1;

}

int chat_protocol_verify_sign(OtrlChatContext *ctx, const char *sender, const unsigned char *msg, const size_t msglen) {
	Signature *sign;
	OtrlChatParticipant *theSender;
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

	chat_sign_destroy_signature(sign);

	return 0;

error_with_sign:
	chat_sign_destroy_signature(sign);
error:
	return 1;
}

int otrl_chat_protocol_receiving(OtrlUserState us, const OtrlMessageAppOps *ops,
	void *opdata, const char *accountname, const char *protocol,
	const char *sender, otrl_chat_token_t chat_token, const char *message,
	char **newmessagep,	OtrlTLV **tlvsp)
{
	OtrlChatContext * ctx;
	OtrlChatMessage *msg = NULL, *msgToSend = NULL;
	int ignore_message = 0; // flag to determine if the message should be ignored
	int free_message = 1, err;
	unsigned int our_pos;
	unsigned char *buf;
	size_t buflen;
	char *plaintext;

	fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_receiving: start\n");

	if( !accountname || !protocol || !sender || !message || !newmessagep) { goto error; }

	ctx = chat_context_find_or_add(us, accountname, protocol, chat_token);
	if(!ctx) { goto error; }

	if(chat_message_is_otr(message)) {
		fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_receiving: in if chat_message_is_otr(message)\n");
		err = otrl_base64_otr_decode(message, &buf, &buflen);
		if(err) { goto error; }

		// signature verification
		OtrlChatMessageType type;
		fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_receiving: before chat_message_parse_type\n");
		err = chat_message_parse_type(buf, buflen, &type);
		if(err) {
			free(buf);
			goto error;
		}

		if(chat_message_type_should_be_signed(type)){
			fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_receiving: in if(chat_message_type_should_be_signed(type)\n");
			if(ctx->sign_state == OTRL_CHAT_SINGSTATE_SINGED) {
				err = chat_protocol_verify_sign(ctx, sender, buf, buflen);
				if(err) {
					free(buf);
					goto error;
				}
				buflen -= CHAT_SIGN_SIGNATURE_LENGTH;
			}
		}

		fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_receiving: before chat_message_parse\n");
		msg = chat_message_parse(buf, buflen, sender);
		fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_receiving: after chat_message_parse\n");
		free(buf);
		if(!msg) { goto error; }

	} else {
		//TODO maybe do something else
		fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_receiving: in else\n");
		msg = malloc(sizeof *msg);
		if(!msg) { goto error; }
		msg->protoVersion = 0;
		msg->msgType = OTRL_MSGTYPE_NOTOTR;
		msg->senderInsTag = 0;
		msg->senderName = strdup(sender);
		if(!msg->senderName) {
			free(msg);
			goto error;
		}
		msg->chatInsTag = 0;
		msg->payload = NULL;
		msg->payload_free = NULL;
		msg->payload_serialize = NULL;
	}

	// TODO Dimitris: code refactoring, change checking against values using the appropriate handling functions
	// 				  using err and msgToSend

	// handle unparsed messages, work around for signed gka messages, received before we finish dske
	if(!msg) {
		//TODO save as pending signed message and add the handling section
		ignore_message = 1;
	}
	// handle not otr messages
	else if(msg->msgType == OTRL_MSGTYPE_CHAT_NOTOTR) {
		fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_receiving: case OTRL_MSGTYPE_NOTOTR\n");

		if (ctx->msg_state != OTRL_MSGSTATE_PLAINTEXT) {
			fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_receiving: in if ctx->msg_state != OTRL_MSGSTATE_PLAINTEXT\n");
			if(ops->handle_msg_event) {
				ops->handle_msg_event(/*opdata*/ NULL, OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED, NULL,  message, gcry_error(GPG_ERR_NO_ERROR));
				ignore_message = 1;
			}
		}
	//handle offer messages
	} else if(chat_offer_is_my_message(msg)) {
		fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_receiving: in chat_offer_is_my_message\n");
		err = chat_offer_handle_message(ops, ctx, msg, &msgToSend);
		//TODO check if i should initiate dske
		if(err) { goto error_with_msg; }

		if(msgToSend) {
			err = chat_protocol_send_message(ops, ctx, msgToSend);
			if(err) { goto error_with_msgToSend; }
			chat_message_free(msgToSend);
			msgToSend = NULL;
		}

		//TODO maybe check if we were already finished?
		if(ctx->offer_info && ctx->offer_info->state == OTRL_CHAT_OFFERSTATE_FINISHED) {

			// Load or generate our private key
			ChatIdKey *idkey = chat_privkeydh_find_or_generate(us, ops, ctx->accountname, ctx->protocol);
			if(!idkey) { goto error_with_msg; }
			ctx->identity_key = idkey;

			// Load participants' fingerprints
			OtrlListNode *cur;
			for(cur=ctx->participants_list->head; cur!=NULL; cur=cur->next) {
				OtrlChatParticipant *participant = cur->payload;
				ChatFingerprint *fnprnt = chat_fingerprint_find(us, ctx->accountname, ctx->protocol, participant->username);
				participant->fingerprint = fnprnt;
			}

			// Initiate dske
			err = chat_dske_init(ctx, &msgToSend);
			if(err) { goto error_with_msg; }
			err = chat_protocol_send_message(ops, ctx, msgToSend);
			if(err) { goto error_with_msgToSend; }
			chat_message_free(msgToSend);
			msgToSend = NULL;
		}
		ignore_message = 1;

	// handle dske messages
	} else if(chat_dske_is_my_message(msg)) {
		fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_receiving: in chat_dske_is_my_message\n");
		err = chat_dske_handle_message(ctx, msg, &msgToSend, &free_message);
		if(err) { goto error_with_msg; }

		if(msgToSend) {
			err = chat_protocol_send_message(ops, ctx, msgToSend);
			if(err) { goto error_with_msgToSend; }
			chat_message_free(msgToSend);
			msgToSend = NULL;
		}

		// TODO maybe reject messages intended to other recipients before handling them :)
		if(ctx->dske_info && ctx->dske_info->state == OTRL_CHAT_DSKESTATE_FINISHED && ctx->gka_info.state == OTRL_CHAT_GKASTATE_NONE) {
			ctx->sign_state = OTRL_CHAT_SINGSTATE_SINGED;
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
				ctx->gka_info.state = OTRL_CHAT_GKASTATE_AWAITING_UPFLOW;


				// handle pending gka messages
				OtrlListNode *cur;
				for(cur = ctx->participants_list->head; cur!=NULL; cur=cur->next) {
					OtrlChatParticipant *participant = cur->payload;
					OtrlChatMessage *pendingMsg = participant->pending_message;
					int free_pending_msg = 1;
					if(pendingMsg) {
						if(chat_auth_is_auth_message(pendingMsg)) {
							err = chat_auth_handle_message(ctx, pendingMsg, &msgToSend, &free_pending_msg);
							if(err) { goto error_with_msgToSend; }

							if(msgToSend) {
								err = chat_protocol_send_message(ops, ctx, msgToSend);
								if(err) { goto error_with_msgToSend; }
								chat_message_free(msgToSend);
								msgToSend = NULL;
							}

							if(free_pending_msg) {
								free(pendingMsg);
								participant->pending_message = NULL;
							}
						}
					}
				}

				if(ctx->gka_info.state == OTRL_CHAT_GKASTATE_FINISHED) {
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
		}
	// handle authentication messages
	} else if(chat_auth_is_auth_message(msg)) {
		fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_receiving: in chat_auth_is_auth_message\n");
		//TODO Dimitris: in case of error should I check if free of msgToSend is needed?
		err = chat_auth_handle_message(ctx, msg, &msgToSend, &free_message);
		if(err) { goto error_with_msg; }

		if(msgToSend) {
			err = chat_protocol_send_message(ops, ctx, msgToSend);
			if(err) { goto error_with_msgToSend; }
			chat_message_free(msgToSend);
			msgToSend = NULL;
		}

		if(ctx->gka_info.state == OTRL_CHAT_GKASTATE_FINISHED) {
			err = chat_attest_init(ctx, &msgToSend);
			if(err) { goto error_with_msg; }
			if(msgToSend) {
				err = chat_protocol_send_message(ops, ctx, msgToSend);
				if(err) { goto error_with_msgToSend; }
				chat_message_free(msgToSend);
				msgToSend = NULL;
			}
		}

		ignore_message = 1;

	// handle attest messages
	} else if(chat_attest_is_my_message(msg)) {
		fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_receiving: in chat_attest_is_my_message\n");
		err = chat_attest_handle_message(ctx, msg, &msgToSend);
		if(err) { goto error_with_msg; }

		if(msgToSend) {
			err = chat_protocol_send_message(ops, ctx, msgToSend);
			if(err) { goto error_with_msgToSend; }
			chat_message_free(msgToSend);
			msgToSend = NULL;
		}

		if(ctx->attest_info && ctx->attest_info->state == OTRL_CHAT_ATTESTSTATE_FINISHED) {
			chat_shutdown_init(ctx);
		}

		ignore_message = 1;

	// handle data messages
	} else if(msg->msgType == OTRL_MSGTYPE_CHAT_DATA) {

		fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_receiving: case OTRL_MSGTYPE_CHAT_DATA\n");

		OtrlChatMessagePayloadData *payload = msg->payload;
		switch(ctx->msg_state) {

			case OTRL_MSGSTATE_PLAINTEXT:
			case OTRL_MSGSTATE_FINISHED:
				/* TODO if plaintext or finished ignore the message. In the future handle this more gracefully */
				fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_receiving: case OTRL_MSGSTATE_PLAINTEXT OR OTRL_MSGSTATE_FINISHED\n");
				goto error_with_msg;
				break;

			case OTRL_MSGSTATE_ENCRYPTED:
				fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_receiving: case OTRL_MSGSTATE_ENCRYPTED\n");
				plaintext = chat_enc_decrypt(ctx, payload->ciphertext, payload->datalen, payload->ctr, sender);
				/* TODO ignore if there was an error. handle this more gracefully in the future */
				if (!plaintext) { goto error_with_msg; }
				//fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_receiving: plaintext: %s\n", plaintext);
				*newmessagep = plaintext;
				break;
		}

	// handle shutdown messages
	} else if (chat_shutdown_is_my_message(msg)) {
		fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_receiving: in chat_shutdown_is_my_message\n");
		err = chat_shutdown_handle_message(ctx, msg, &msgToSend);
		if(err) { goto error_with_msg; }

		if(msgToSend) {
			err = chat_protocol_send_message(ops, ctx, msgToSend);
			if(err) { goto error_with_msgToSend; }
			chat_message_free(msgToSend);
			msgToSend = NULL;
		}

		if(ctx->shutdown_info.state == OTRL_CHAT_SHUTDOWNSTATE_FINISHED) {
			err = chat_shutdown_release_secrets(ctx, &msgToSend);
			if(err) { goto error_with_msgToSend;}

			err = chat_protocol_send_message(ops, ctx, msgToSend);
			if(err) { goto error_with_msgToSend; }
			chat_message_free(msgToSend);
			msgToSend = NULL;

			chat_protocol_reset(us, ctx);
		}

		ignore_message = 1;
	}

	if(free_message) {
		chat_message_free(msg);
	}

	fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_receiving: end\n");
	return ignore_message;

error_with_msgToSend:
	chat_message_free(msgToSend);
error_with_msg:
	chat_message_free(msg);
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
	unsigned char *ciphertext, *buf;
	OtrlChatMessage *msg;
	size_t datalen, buflen;
	int err;

	fprintf(stderr, "libotr-mpOTR: otrl_chat_message_sending: start\n");

	if( !accountname || !protocol || !message) { goto error; }

	ctx = chat_context_find_or_add(us, accountname, protocol, chat_token);
	if(!ctx) { goto error; }

	switch(ctx->msg_state) {
		case OTRL_MSGSTATE_PLAINTEXT:
			fprintf(stderr, "libotr-mpOTR: otrl_chat_message_sending: case OTRL_MSGSTATE_PLAINTEXT\n");
			break;
		case OTRL_MSGSTATE_ENCRYPTED:
			fprintf(stderr, "libotr-mpOTR: otrl_chat_message_sending: case OTRL_MSGSTATE_ENCRYPTED\n");

			ciphertext = chat_enc_encrypt(ctx, message);
			if(!ciphertext) { goto error; }

			// TODO maybe get length from chat_enc_encrypt so that we can support other modes of aes
			datalen = strlen(message);

			msg = chat_message_data_create(ctx, ctx->enc_info.ctr, datalen, ciphertext);
			if(!msg) { goto error_with_ciphertext; }

			buf = chat_message_serialize(msg, &buflen);
			if(!buf) { goto error_with_msg; }

			if(chat_message_type_should_be_signed(msg->msgType) && ctx->sign_state == OTRL_CHAT_SINGSTATE_SINGED) {
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
error_with_ciphertext:
	free(ciphertext);
error:
	return 1;
}

int otrl_chat_protocol_send_query(OtrlUserState us,
		const OtrlMessageAppOps *ops,
		const char *accountname, const char *protocol,
		otrl_chat_token_t chat_token, OtrlFragmentPolicy fragPolicy)
{
	OtrlChatMessage *msgToSend;
	OtrlChatContext *ctx;
	int err;

	ctx = chat_context_find_or_add(us, accountname, protocol, chat_token);
	if(!ctx) { goto error; }

	err = chat_offer_init(ops, ctx, &msgToSend);
	if(err) { goto error; }

	err = chat_protocol_send_message(ops, ctx, msgToSend);
	if(err) { goto error_with_msg; }

	chat_message_free(msgToSend);

	return 0;

error_with_msg:
	chat_message_free(msgToSend);
error:
	return 1;
}

int otrl_chat_protocol_shutdown(OtrlUserState us, const OtrlMessageAppOps *ops,
		const char *accountname, const char *protocol, otrl_chat_token_t chat_token)
{
	OtrlChatMessage *msgToSend;
	OtrlChatContext *ctx;
	int err;

	fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_showtdown: start\n");

	// TODO only find not add
	ctx = chat_context_find(us, accountname, protocol, chat_token);
	if(!ctx) { goto error; }

	if(ctx->shutdown_info.state != OTRL_CHAT_SHUTDOWNSTATE_AWAITING_ENDS) { goto error; }

	err = chat_shutdown_send_end(ctx, &msgToSend);
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
