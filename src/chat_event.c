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

#include "chat_types.h"

void chat_event_free(OtrlChatEvent *event)
{
	if(event) {
		if(event->data_free && event->data) {
			event->data_free(event->data);
		}
	}

	free(event);
}

OtrlChatEvent *chat_event_create(OtrlChatEventType type, void *data, void (*data_free)(void *))
{
	OtrlChatEvent * event;

	event = malloc(sizeof *event);
	if(!event) { goto error; }

	event->type = type;
	event->data = data;
	event->data_free = data_free;

	return event;

error:
	return NULL;
}

 void chat_event_participant_data_free(OtrlChatEventDataPtr data)
{
	 OtrlChatEventParticipantData *part_data = data;
	 if(part_data) {
		 free(part_data->username);
	 }
	 free(part_data);
}

OtrlChatEventParticipantData *chat_event_participant_data_create(const char *username)
{
	OtrlChatEventParticipantData *data;

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

void chat_event_message_data_free(OtrlChatEventDataPtr data)
{
	OtrlChatEventMessageData *msg_data = data;

	if(msg_data) {
		free(msg_data->username);
		free(msg_data->message);
	}
	free(msg_data);
}

OtrlChatEventMessageData *chat_event_message_data_create(const char *username, const char *message)
{
	OtrlChatEventMessageData *data;

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

OtrlChatEvent *chat_event_offer_received_create(const char *username)
{
	OtrlChatEvent *event;
	OtrlChatEventParticipantData *data;

	data = chat_event_participant_data_create(username);
	if(!data) { goto error; }

	event = chat_event_create(OTRL_CHAT_EVENT_OFFER_RECEIVED, data, chat_event_participant_data_free);
	if(!event) { goto error_with_data; }

	return event;

error_with_data:
	chat_event_participant_data_free(data);
error:
	return NULL;
}

OtrlChatEvent *chat_event_starting_create()
{
	OtrlChatEvent *event;

	event = chat_event_create(OTRL_CHAT_EVENT_STARTING, NULL, NULL);
	if(!event) { goto error; }

	return event;

error:
	return NULL;
}

OtrlChatEvent *chat_event_started_create()
{
	OtrlChatEvent *event;

	event = chat_event_create(OTRL_CHAT_EVENT_STARTED, NULL, NULL);
	if(!event) { goto error; }

	return event;

error:
	return NULL;
}

OtrlChatEvent *chat_event_unverified_participant_create(const char *username)
{
	OtrlChatEvent *event;
	OtrlChatEventParticipantData *data;

	data = chat_event_participant_data_create(username);
	if(!data) { goto error; }

	event = chat_event_create(OTRL_CHAT_EVENT_UNVERIFIED_PARTICIPANT, data, chat_event_participant_data_free);
	if(!event) { goto error_with_data; }

	return event;

error_with_data:
	chat_event_participant_data_free(data);
error:
	return NULL;
}

OtrlChatEvent *chat_event_plaintext_received_create(const char *username, const char *message)
{
	OtrlChatEvent *event;
	OtrlChatEventMessageData *data;

	data = chat_event_message_data_create(username, message);
	if(!data) { goto error; }

	event = chat_event_create(OTRL_CHAT_EVENT_PLAINTEXT_RECEIVED, data, chat_event_message_data_free);
	if(!event) { goto error_with_data; }

	return event;

error_with_data:
	chat_event_message_data_free(data);
error:
	return NULL;
}

OtrlChatEvent *chat_event_private_received_create(const char *username)
{
	OtrlChatEvent *event;
	OtrlChatEventParticipantData *data;

	data = chat_event_participant_data_create(username);
	if(!data) { goto error; }

	event = chat_event_create(OTRL_CHAT_EVENT_PRIVATE_RECEIVED, data, chat_event_participant_data_free);
	if(!event) { goto error_with_data; }

	return event;

error_with_data:
	chat_event_message_data_free(data);
error:
	return NULL;
}

OtrlChatEvent *chat_event_consensus_broken_create(const char *username)
{
	OtrlChatEvent *event;
	OtrlChatEventParticipantData *data;

	data = chat_event_participant_data_create(username);
	if(!data) { goto error; }

	event = chat_event_create(OTRL_CHAT_EVENT_CONSENSUS_BROKEN, data, chat_event_participant_data_free);
	if(!event) { goto error_with_data; }

	return event;

error_with_data:
	chat_event_participant_data_free(data);
error:
	return NULL;
}

OtrlChatEvent *chat_event_finished_create()
{
	OtrlChatEvent *event;

	event = chat_event_create(OTRL_CHAT_EVENT_FINISHED, NULL, NULL);
	if(!event) { goto error; }

	return event;

error:
	return NULL;
}
