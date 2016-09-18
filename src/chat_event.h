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

void chat_event_free(OtrlChatEvent *event);
OtrlChatEvent *chat_event_offer_received_create(const char *username);
OtrlChatEvent *chat_event_starting_create();
OtrlChatEvent *chat_event_started_create();
OtrlChatEvent *chat_event_unverified_participant_create(const char *username);
OtrlChatEvent *chat_event_plaintext_received_create(const char *username, const char *message);
OtrlChatEvent *chat_event_private_received_create(const char *username);
OtrlChatEvent *chat_event_consensus_broken_create(const char *username);
OtrlChatEvent *chat_event_finished_create();

#endif /* CHAT_EVENT_H_ */
