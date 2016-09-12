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

OtrlList * otrl_list_create(struct OtrlListOpsStruct *ops, size_t payload_size)
{
	OtrlList *list = NULL;

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

OtrlListNode * otrl_list_node_create(const PayloadPtr payload) {
	OtrlListNode *node = NULL;

	node = malloc(sizeof *node);
	if(!node) { goto error; }

	node->payload = payload;
	node->next = NULL;
	node->prev = NULL;

	return node;

error:
	return NULL;
}

OtrlListNode * otrl_list_insert(OtrlList *list, const PayloadPtr payload) {
	OtrlListNode *node = NULL;
	OtrlListNode *cur = NULL;

	node = otrl_list_node_create(payload);
	if(!node) { goto error; }

	// if list is empty
	if(list->head == NULL) {
		node->prev = NULL;
		node->next = NULL;
		list->head = node;
		list->tail = node;

	//if it should be the first node
	} else if (list->ops->compar(node->payload, list->head->payload) < 0) {
		node->next = list->head;
		node->prev = NULL;
		list->head->prev = node;
		list->head = node;

	} else {
		for(cur = list->head; cur->next!=NULL && list->ops->compar(node->payload, cur->next->payload) > 0; cur = cur->next);
		node->next = cur->next;
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

OtrlListNode * otrl_list_prepend(OtrlList *list, PayloadPtr payload) {
	OtrlListNode *node = NULL;

	node = otrl_list_node_create(payload);
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

OtrlListNode * otrl_list_append(OtrlList *list, PayloadPtr payload) {
	OtrlListNode *node = NULL;

	node = otrl_list_node_create(payload);
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

void otrl_list_remove(OtrlList *list, OtrlListNode *node)
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

void otrl_list_remove_and_free(OtrlList *list, OtrlListNode *node)
{
	otrl_list_remove(list, node);
	otrl_list_node_free(list, node);
}

void otrl_list_foreach(OtrlList *list, void (*fun)(OtrlListNode *) )
{
	OtrlListNode *cur = list->head;

	if(!cur)
		return;

	fun(cur);
	while( (cur = cur->next) )
		fun(cur);

}

void otrl_list_dump(OtrlList *list)
{
	if(list->ops == NULL || list->ops->print == NULL) {
		return;
	}

	otrl_list_foreach(list, list->ops->print);
}


void otrl_list_node_free(OtrlList *list, OtrlListNode *node)
{
	list->ops->payload_free(node->payload);
	free(node);
}

void otrl_list_clear(OtrlList *list)
{
	while( list->head != NULL) {
		otrl_list_remove_and_free(list, list->head);
	}
}


void otrl_list_free(OtrlList *list)
{
	if(list) {
		otrl_list_clear(list);
	}
	free(list);
}

OtrlListNode * otrl_list_find(OtrlList *list, PayloadPtr target)
{
	OtrlListNode *cur = NULL;
	int res;

	cur = list->head;

	// check if the list is empty
	if(cur == NULL) { goto error; }

	while(cur != NULL) {
		res = list->ops->compar(target, cur->payload);
		if(res == 0)
			return cur;
		cur = cur->next;
	}

	return NULL;

error:
	return NULL;
}

OtrlListNode * otrl_list_get(OtrlList *list, unsigned int i)
{
	unsigned int j;
	OtrlListNode *cur;

	if(!list || i >= list->size) { goto error; }

	cur = list->head;
	for(j=0; j<i; j++) {
		cur = cur->next;
	}

	return cur;

error:
	return NULL;
}

OtrlListNode * otrl_list_get_last(OtrlList *list)
{
	if(list) {
		return list->tail;
	} else {
		return NULL;
	}
}

OtrlListNode * otrl_list_get_first(OtrlList *list)
{
	if(list) {
		return list->head;
	} else {
		return NULL;
	}
}

unsigned int otrl_list_length(OtrlList *list)
{
	return list->size;
}
