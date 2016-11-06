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

#include "chat_event.h"

#include <stdlib.h>
#include <string.h>

struct OtrlChatEventParticipantData {
	char *username;
};

struct OtrlChatEventMessageData {
	char *username;
	char *message;
};

struct OtrlChatEvent {
	OtrlChatEventType type;
	void *data;
	void (*data_free)(OtrlChatEventDataPtr);
};

OtrlChatEventParticipantDataPtr chat_event_participant_data_new(const char *username)
{
	OtrlChatEventParticipantDataPtr data;

	data = malloc(sizeof *data);
	if(!data) { goto error; }

	data->username = strdup(username);
	if(!data->username) { goto error_with_data; }

	return data;

error_with_data:
	free(data);
error:
	return NULL;
}

void chat_event_participant_data_free(OtrlChatEventDataPtr data)
{
	 OtrlChatEventParticipantDataPtr part_data = data;
	 if(part_data) {
		 free(part_data->username);
	 }
	 free(part_data);
}

char * otrl_chat_event_participant_data_get_username(OtrlChatEventParticipantDataPtr data)
{
	return data->username;
}

OtrlChatEventMessageDataPtr chat_event_message_data_new(const char *username, const char *message)
{
	OtrlChatEventMessageDataPtr data;

	data = malloc(sizeof *data);
	if(!data) { goto error; }

	data->username = strdup(username);
	if(!data->username) { goto error_with_data; }

	data->message = strdup(message);
	if(!data->message) { goto error_with_username; }

	return data;

error_with_username:
	free(data->username);
error_with_data:
	free(data);
error:
	return NULL;
}

void chat_event_message_data_free(OtrlChatEventDataPtr data)
{
	OtrlChatEventMessageDataPtr msg_data = data;

	if(msg_data) {
		free(msg_data->username);
		free(msg_data->message);
	}
	free(msg_data);
}

char * otrl_chat_event_message_data_get_username(OtrlChatEventMessageDataPtr data)
{
	return data->username;
}

char * otrl_chat_event_message_data_get_message(OtrlChatEventMessageDataPtr data)
{
	return data->message;
}

OtrlChatEventPtr chat_event_new(OtrlChatEventType type, OtrlChatEventDataPtr data, void (*data_free)(void *))
{
	OtrlChatEventPtr event;

	event = malloc(sizeof *event);
	if(!event) { goto error; }

	event->type = type;
	event->data = data;
	event->data_free = data_free;

	return event;

error:
	return NULL;
}

void chat_event_free(OtrlChatEventPtr event)
{
	if(event) {
		if(event->data_free && event->data) {
			event->data_free(event->data);
		}
	}
	free(event);
}

OtrlChatEventType otrl_chat_event_get_type(OtrlChatEventPtr event)
{
	return event->type;
}

OtrlChatEventDataPtr otrl_chat_event_get_data(OtrlChatEventPtr event)
{
	return event->data;
}

OtrlChatEventPtr chat_event_offer_received_new(const char *username)
{
	OtrlChatEventPtr event;
	OtrlChatEventParticipantDataPtr data;

	data = chat_event_participant_data_new(username);
	if(!data) { goto error; }

	event = chat_event_new(OTRL_CHAT_EVENT_OFFER_RECEIVED, data, chat_event_participant_data_free);
	if(!event) { goto error_with_data; }

	return event;

error_with_data:
	chat_event_participant_data_free(data);
error:
	return NULL;
}

OtrlChatEventPtr chat_event_starting_new()
{
	OtrlChatEventPtr event;

	event = chat_event_new(OTRL_CHAT_EVENT_STARTING, NULL, NULL);
	if(!event) { goto error; }

	return event;

error:
	return NULL;
}

OtrlChatEventPtr chat_event_started_new()
{
	OtrlChatEventPtr event;

	event = chat_event_new(OTRL_CHAT_EVENT_STARTED, NULL, NULL);
	if(!event) { goto error; }

	return event;

error:
	return NULL;
}

OtrlChatEventPtr chat_event_unverified_participant_new(const char *username)
{
	OtrlChatEventPtr event;
	OtrlChatEventParticipantDataPtr data;

	data = chat_event_participant_data_new(username);
	if(!data) { goto error; }

	event = chat_event_new(OTRL_CHAT_EVENT_UNVERIFIED_PARTICIPANT, data, chat_event_participant_data_free);
	if(!event) { goto error_with_data; }

	return event;

error_with_data:
	chat_event_participant_data_free(data);
error:
	return NULL;
}

OtrlChatEventPtr chat_event_plaintext_received_new(const char *username, const char *message)
{
	OtrlChatEventPtr event;
	OtrlChatEventMessageDataPtr data;

	data = chat_event_message_data_new(username, message);
	if(!data) { goto error; }

	event = chat_event_new(OTRL_CHAT_EVENT_PLAINTEXT_RECEIVED, data, chat_event_message_data_free);
	if(!event) { goto error_with_data; }

	return event;

error_with_data:
	chat_event_message_data_free(data);
error:
	return NULL;
}

OtrlChatEventPtr chat_event_private_received_new(const char *username)
{
	OtrlChatEventPtr event;
	OtrlChatEventParticipantDataPtr data;

	data = chat_event_participant_data_new(username);
	if(!data) { goto error; }

	event = chat_event_new(OTRL_CHAT_EVENT_PRIVATE_RECEIVED, data, chat_event_participant_data_free);
	if(!event) { goto error_with_data; }

	return event;

error_with_data:
	chat_event_message_data_free(data);
error:
	return NULL;
}

OtrlChatEventPtr chat_event_consensus_broken_new(const char *username)
{
	OtrlChatEventPtr event;
	OtrlChatEventParticipantDataPtr data;

	data = chat_event_participant_data_new(username);
	if(!data) { goto error; }

	event = chat_event_new(OTRL_CHAT_EVENT_CONSENSUS_BROKEN, data, chat_event_participant_data_free);
	if(!event) { goto error_with_data; }

	return event;

error_with_data:
	chat_event_participant_data_free(data);
error:
	return NULL;
}

OtrlChatEventPtr chat_event_finished_new()
{
	OtrlChatEventPtr event;

	event = chat_event_new(OTRL_CHAT_EVENT_FINISHED, NULL, NULL);
	if(!event) { goto error; }

	return event;

error:
	return NULL;
}
