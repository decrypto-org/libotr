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

 void chat_event_consensus_participant_data_free(OtrlChatEventDataPtr data)
{
	 OtrlChatEventConsensusParticipantData *part_data = data;
	 if(part_data) {
		 free(part_data->username);
	 }
	 free(part_data);
}

OtrlChatEventConsensusParticipantData *chat_event_consensus_participant_data_create(const char *username)
{
	OtrlChatEventConsensusParticipantData *data;

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
