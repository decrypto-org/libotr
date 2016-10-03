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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <list.h>
#include "chat_pending.h"

struct ChatPendingStruct {
	char *sender;
	unsigned char *msg;
	size_t msglen;
};

size_t chat_pending_size()
{
	return sizeof(struct ChatPendingStruct);
}

ChatPending chat_pending_new(const char *sender, const unsigned char *msg, size_t msglen)
{
	ChatPending pending;

	pending = malloc(sizeof *pending);
	if(!pending) { goto error; }

	pending->sender = strdup(sender);
	if(!pending->sender) { goto error_with_pending; }

	pending->msg = malloc(msglen * sizeof *(pending->msg));
	memcpy(pending->msg, msg, msglen);
	if(!pending->msg) { goto error_with_sender; }

	pending->msglen = msglen;

	return pending;

error_with_sender:
	free(pending->sender);
error_with_pending:
	free(pending);
error:
	return NULL;
}

void chat_pending_free(ChatPending pending)
{
	if(pending) {
		free(pending->sender);
		free(pending->msg);
	}
    free(pending);
}

char *chat_pending_get_sender(ChatPending pending)
{
	assert(pending && "Is validated by the caller");
	return pending->sender;
}

unsigned char *chat_pending_get_msg(ChatPending pending)
{
	assert(pending && "Is validated by the caller");
	return pending->msg;
}

size_t chat_pending_get_msglen(ChatPending pending)
{
	assert(pending && "Is validated by the caller");
	return pending->msglen;
}


int chat_pending_compare(ChatPending a, ChatPending b)
{
	int eq;
	size_t minlen;

	assert(a && "Is validated by the caller");
	assert(b && "Is validated by the caller");

	eq = strcmp(a->sender, b->sender);
	if(eq == 0) {
		minlen = (a->msglen < b->msglen) ? a->msglen : b->msglen;
		eq = memcmp(a->msg, b->msg, minlen);
		if(eq == 0) {
			eq = (a->msglen < b->msglen) ? -1 : 1;
		}
	}

	return eq;
}

void chat_pending_print(ChatPending pending)
{
	assert(pending && "Is validated by the caller");

	fprintf(stderr, "Pending:\n");
	fprintf(stderr, "|- msglen: %lu\n", pending->msglen);
	fprintf(stderr, "|- msg: ");
	for(unsigned int i=0; i < pending->msglen; i++) {
		fprintf(stderr, "%02X", pending->msg[i]);
	}
	fprintf(stderr, "\n");
}

int chat_pending_compareOp(OtrlListPayload a, OtrlListPayload b)
{
	ChatPending a1 = a, b1 = b;
	return chat_pending_compare(a1, b1);
}

void chat_pending_printOp(OtrlListNode a)
{
	ChatPending pending;

	pending = otrl_list_node_get_payload(a);
	chat_pending_print(pending);
}

void chat_pending_freeOp(OtrlListPayload a)
{
	ChatPending pending = a;
	chat_pending_free(pending);
}

struct OtrlListOpsStruct chat_pending_listOps = {
		chat_pending_compareOp,
		chat_pending_printOp,
		chat_pending_freeOp
};

