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
#include "b64.h"

int otrl_chat_protocol_receiving(OtrlUserState us, const OtrlMessageAppOps *ops,
	void *opdata, const char *accountname, const char *protocol,
	const char *sender, otrl_chat_token_t chat_token, const char *message,
	char **newmessagep,	OtrlTLV **tlvsp)
{
	OtrlChatContext * ctx;
	OtrlChatMessage *msg, *msgToSend = NULL;
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
		msg = chat_message_parse(buf, buflen, sender);
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
		msg->chatInsTag = 0;
		msg->payload = NULL;
		msg->payload_free = NULL;
		msg->payload_serialize = NULL;
	}

	// TODO Dimitris: code refactoring, change checking against values using the appropriate handling functions
	// 				  using err and msgToSend
	if(msg->msgType == OTRL_MSGTYPE_CHAT_NOTOTR) {
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
			err = chat_message_send(ops, ctx, msgToSend);
			if(err) { goto error_with_msgToSend; }
			chat_message_free(msgToSend);
		}

		//TODO maybe check if we were already finished?
		if(ctx->offer_state == OTRL_CHAT_OFFERSTATE_FINISHED) {
			ChatIdKey *idkey = chat_privkeydh_find_or_generate(us, ops, ctx->accountname, ctx->protocol);
			if(!idkey) { goto error_with_msg; }
			ctx->identity_key = idkey;

			// TODO load participant fingerprints
			OtrlListNode *cur;
			for(cur=ctx->participants_list->head; cur!=NULL; cur=cur->next) {
				OtrlChatParticipant *participant = cur->payload;
				ChatFingerprint *fnprnt = chat_fingerprint_find(us, ctx->accountname, ctx->protocol, participant->username);
				participant->fingerprint = fnprnt;
			}

			err = chat_dske_init(ctx, &msgToSend);
			if(err) { goto error_with_msg; }
			err = chat_message_send(ops, ctx, msgToSend);
			if(err) { goto error_with_msgToSend; }
			chat_message_free(msgToSend);
		}
		ignore_message = 1;

	// handle dske messages
	} else if(chat_dske_is_my_message(msg)) {
		fprintf(stderr, "libotr-mpOTR: otrl_chat_protocol_receiving: in chat_dske_is_my_message\n");
		err = chat_dske_handle_message(ctx, msg, &msgToSend, &free_message);
		if(err) { goto error_with_msg; }

		if(msgToSend) {
			err = chat_message_send(ops, ctx, msgToSend);
			if(err) { goto error_with_msgToSend; }
		}

		if(ctx->dske_info.state == OTRL_CHAT_DSKESTATE_FINISHED) {
			ctx->sign_state = OTRL_CHAT_SINGSTATE_SINGED;
			err = chat_participant_get_position(ctx->participants_list, ctx->accountname, &our_pos);
			if(err) { goto error_with_msg;  }
			if(our_pos == 0 ) {
				err = chat_auth_init(ctx, &msgToSend);
				if(err) { goto error_with_msg; }
				err = chat_message_send(ops, ctx, msgToSend);
				if(err) { goto error_with_msgToSend; }
				chat_message_free(msgToSend);
			} else {
				ctx->gka_info.state = OTRL_CHAT_GKASTATE_AWAITING_UPFLOW;

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
								err = chat_message_send(ops, ctx, msgToSend);
								if(err) { goto error_with_msgToSend; }
								chat_message_free(msgToSend);
							}

							if(free_pending_msg) {
								free(pendingMsg);
								participant->pending_message = NULL;
							}
						}
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
			err = chat_message_send(ops, ctx, msgToSend);
			if(err) { goto error_with_msgToSend; }
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
				*newmessagep = plaintext;
				break;
		}
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
				// TODO attach the sign to the serialized message and save it to *messagep
				//Signature *signature = chat_sign_sign(ctx->signing_key, buf, buflen);
			}
			*messagep = otrl_base64_otr_encode(buf, buflen);
			if(!*messagep) { goto error_with_buf; }

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
	OtrlChatMessage *msg;
	OtrlChatContext *ctx;
	int err;

	//TODO this is for testing reasons only.
	/*
	int keyexists = chat_privkeydh_key_exists(us, accountname, protocol);
	if(!keyexists) {
		ops->chat_privkey_create(NULL, accountname, protocol);
	}*/

	ctx = chat_context_find_or_add(us, accountname, protocol, chat_token);
	if(!ctx) { goto error; }

	//err = chat_auth_init(ops, ctx, &msg);
	//if(err) { goto error; }

	err = chat_offer_init(ops, ctx, &msg);
	if(err) { goto error; }

	err = chat_message_send(ops, ctx, msg);
	if(err) { goto error_with_msg; }

	chat_message_free(msg);

	return 0;

error_with_msg:
	chat_message_free(msg);
error:
	return 1;
}



