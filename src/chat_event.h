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

#ifndef CHAT_EVENT_H_
#define CHAT_EVENT_H_

typedef enum {
	OTRL_CHAT_EVENT_OFFER_RECEIVED, 		/* emitted when we received an offer */
	OTRL_CHAT_EVENT_STARTING,				/* emitted when the protocol attempts to start a private session */
	OTRL_CHAT_EVENT_STARTED,				/* emitted when the private session has started */
	OTRL_CHAT_EVENT_UNVERIFIED_PARTICIPANT,	/* emitted when the private session has started with an unverified participant in it */
	OTRL_CHAT_EVENT_PLAINTEXT_RECEIVED,		/* emitted when we receive a plaintext message while in a private session */
	OTRL_CHAT_EVENT_PRIVATE_RECEIVED,		/* emitted when we receive a private message while NOT in a private session */
	OTRL_CHAT_EVENT_CONSENSUS_BROKEN, 		/* emitted when there was no consensus with a participant */
	OTRL_CHAT_EVENT_FINISHED				/* emitted when a private session was finished */
} OtrlChatEventType;

typedef void * OtrlChatEventData;
typedef struct OtrlChatEventStruct * OtrlChatEvent;
typedef struct OtrlChatEventParticipantDataStruct * OtrlChatEventParticipantData;
typedef struct OtrlChatEventMessageDataStruct * OtrlChatEventMessageData;

char * otrl_chat_event_participant_data_get_username(OtrlChatEventParticipantData data);
char * otrl_chat_event_message_data_get_username(OtrlChatEventMessageData data);
char * otrl_chat_event_message_data_get_message(OtrlChatEventMessageData data);

void chat_event_free(OtrlChatEvent event);
OtrlChatEventType otrl_chat_event_get_type(OtrlChatEvent event);
OtrlChatEventData otrl_chat_event_get_data(OtrlChatEvent event);
OtrlChatEvent chat_event_offer_received_new(const char *username);
OtrlChatEvent chat_event_starting_new();
OtrlChatEvent chat_event_started_new();
OtrlChatEvent chat_event_unverified_participant_new(const char *username);
OtrlChatEvent chat_event_plaintext_received_new(const char *username, const char *message);
OtrlChatEvent chat_event_private_received_new(const char *username);
OtrlChatEvent chat_event_consensus_broken_new(const char *username);
OtrlChatEvent chat_event_finished_new();

#endif /* CHAT_EVENT_H_ */
