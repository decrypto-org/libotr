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

#include "list.h"

struct OtrlListNode {
	struct OtrlListNode * next;
	struct OtrlListNode * prev;
	OtrlListPayloadPtr payload;
	void (*payload_free)(OtrlListPayloadPtr);
};

struct OtrlList {
	OtrlListNodePtr head;
	OtrlListNodePtr tail;
	unsigned int size;
	size_t payload_size;
	struct OtrlListOpsStruct *ops;
};

OtrlListNodePtr otrl_list_node_new(const OtrlListPayloadPtr payload, void (*payload_free)(OtrlListPayloadPtr))
{
	OtrlListNodePtr node = NULL;

	node = malloc(sizeof *node);
	if(!node) { goto error; }

	node->next = NULL;
	node->prev = NULL;
	node->payload = payload;
	node->payload_free = payload_free;

	return node;

error:
	return NULL;
}

OtrlListPayloadPtr otrl_list_node_get_payload(OtrlListNodePtr node)
{
	return node->payload;
}

OtrlListPayloadPtr otrl_list_node_get_next(OtrlListNodePtr node)
{
	return node->next;
}

void otrl_list_node_free(OtrlListNodePtr node)
{
	if(node->payload && node->payload_free) {
		node->payload_free(node->payload);
	}
	free(node);
}

OtrlListPtr otrl_list_new(struct OtrlListOpsStruct *ops, size_t payload_size)
{
	OtrlListPtr list = NULL;

	if(!ops || !ops->compar) { goto error; }

	list = malloc(sizeof *list);
	if(!list) { goto error; }

	list->ops = ops;
	list->size = 0;
	list->payload_size = payload_size;

	list->head = NULL;
	list->tail = NULL;

	return list;

error:
	return NULL;
}

OtrlListNodePtr otrl_list_get_head(OtrlListPtr list)
{
	if(list) {
		return list->head;
	} else {
		return NULL;
	}
}

OtrlListNodePtr otrl_list_get_tail(OtrlListPtr list)
{
	if(list) {
		return list->tail;
	} else {
		return NULL;
	}
}

OtrlListNodePtr otrl_list_insert(OtrlListPtr list, const OtrlListPayloadPtr payload)
{
	OtrlListNodePtr node, head, cur, next;

	node = otrl_list_node_new(payload, list->ops->payload_free);
	if(!node) { goto error; }

	head = otrl_list_get_head(list);

	// if list is empty
	if(NULL == head) {
		node->prev = NULL;
		node->next = NULL;
		list->head = node;
		list->tail = node;

	//if it should be the first node
	} else if (list->ops->compar(otrl_list_node_get_payload(node), otrl_list_node_get_payload(head)) < 0) {
		node->next = list->head;
		node->prev = NULL;
		list->head->prev = node;
		list->head = node;

	} else {
		cur = head;
		next = cur->next;

		while(NULL != next && list->ops->compar(otrl_list_node_get_payload(node), otrl_list_node_get_payload(next)) > 0) {
			cur = cur->next;
			next = cur->next;
		}

		node->next = next;
		node->prev = cur;
		cur->next = node;

		if(node->next == NULL) {
			list->tail = node;
		}
	}

	list->size++;

	return node;

error:
	return NULL;
}

OtrlListNodePtr otrl_list_prepend(OtrlListPtr list, OtrlListPayloadPtr payload)
{
	OtrlListNodePtr node;

	node = otrl_list_node_new(payload, list->ops->payload_free);
	if(!node) { goto error; }

	node->prev = NULL;
	node->next = list->head;

	// if empty list
	if(list->head == NULL) {
		list->head = node;
		list->tail = node;
	} else {
		list->head->prev = node;
		list->head = node;
	}

	list->size++;

	return node;

error:
	return NULL;
}

OtrlListNodePtr otrl_list_append(OtrlListPtr list, OtrlListPayloadPtr payload)
{
	OtrlListNodePtr node;

	node = otrl_list_node_new(payload, list->ops->payload_free);
	if(!node) { goto error;}

	node->prev = list->tail;
	node->next = NULL;

	// if empty list
	if(list->tail == NULL) {
		list->head = node;
		list->tail = node;
	} else {
		list->tail->next = node;
		list->tail = node;
	}

	list->size++;

	return node;

error:
	return NULL;
}

void otrl_list_remove(OtrlListPtr list, OtrlListNodePtr node)
{
	if(!list || !node) return;

	if(node->prev)
		node->prev->next = node->next;
	else
		list->head = node->next;

	if(node->next)
		node->next->prev = node->prev;
	else
		list->tail = node->prev;

	list->size--;
}

void otrl_list_remove_and_free(OtrlListPtr list, OtrlListNodePtr node)
{
	otrl_list_remove(list, node);
	otrl_list_node_free(node);
}

void otrl_list_clear(OtrlListPtr list)
{
	while(NULL != otrl_list_get_head(list)) {
		otrl_list_remove_and_free(list, otrl_list_get_head(list));
	}
}


void otrl_list_free(OtrlListPtr list)
{
	if(list) {
		otrl_list_clear(list);
	}
	free(list);
}

OtrlListNodePtr otrl_list_find(OtrlListPtr list, OtrlListPayloadPtr target)
{
	OtrlListNodePtr cur;

	cur = otrl_list_get_head(list);
	while(NULL != cur) {
		if(0 == list->ops->compar(target, otrl_list_node_get_payload(cur))) {
			return cur;
		}
		cur = otrl_list_node_get_next(cur);
	}

	return NULL;
}

unsigned int otrl_list_size(OtrlListPtr list)
{
	return list->size;
}

OtrlListNodePtr otrl_list_get(OtrlListPtr list, unsigned int i)
{
	unsigned int j;
	OtrlListNodePtr cur;

	if(!list || i >= otrl_list_size(list)) { goto error; }

	cur = otrl_list_get_head(list);
	for(j=0; j<i; j++) {
		cur = otrl_list_node_get_next(cur);
	}

	return cur;

error:
	return NULL;
}

void otrl_list_foreach(OtrlListPtr list, void (*fun)(OtrlListNodePtr))
{
	OtrlListNodePtr cur;

	cur = otrl_list_get_head(list);
	while(NULL != cur) {
		fun(cur);
		cur = otrl_list_node_get_next(cur);
	}
}

void otrl_list_dump(OtrlListPtr list)
{
	if(list->ops == NULL || list->ops->print == NULL) {
		return;
	}

	otrl_list_foreach(list, list->ops->print);
}

struct OtrlListIterator {
	OtrlListPtr list;
	OtrlListNodePtr next;
};

OtrlListIteratorPtr otrl_list_iterator_new(OtrlListPtr list)
{
	OtrlListIteratorPtr iter;

	if(!list) { goto error; }

	iter = malloc(sizeof *iter);
	if(!iter) { goto error; }

	iter->list = list;
	iter->next = otrl_list_get_head(list);

	return iter;

error:
	return NULL;
}

void otrl_list_iterator_free(OtrlListIteratorPtr iter)
{
	free(iter);
}

int otrl_list_iterator_has_next(OtrlListIteratorPtr iter)
{
	return (iter->next) ? 1 : 0;
}

OtrlListNodePtr otrl_list_iterator_next(OtrlListIteratorPtr iter)
{
	OtrlListNodePtr result;

	result = iter->next;
	if(result) {
		iter->next = otrl_list_node_get_next(result);
	}

	return result;
}
