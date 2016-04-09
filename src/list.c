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

OtrlList * otrl_list_init(struct OtrlListOpsStruct *ops, size_t payload_size)
{
	OtrlList *aList = malloc(sizeof *aList);

	if(!aList || !ops || !ops->compar)
		return NULL;

	aList->ops = ops;
	aList->payload_size = payload_size;

	aList->head = NULL;
	aList->tail = NULL;

	return aList;
}

OtrlListNode * otrl_list_node_create(PayloadPtr payload) {
	OtrlListNode *aNode;

	aNode = malloc(sizeof *aNode);
	if(aNode) {
		aNode->payload = payload;
		aNode->next = NULL;
		aNode->prev = NULL;
	}

	return aNode;
}

OtrlListNode * otrl_list_insert(OtrlList *aList, PayloadPtr payload) {
	OtrlListNode *aNode, *cur;

	aNode = otrl_list_node_create(payload);
	if(aNode) {
		if(aList->head == NULL || aList->ops->compar(aNode->payload, aList->head->payload) > 0) {
			aNode->next = aList->head;
			if(aList->head)
				aList->head->prev = aNode;
			aList->head = aNode;
			aList->tail = aNode;
		} else {
			for(cur = aList->head; cur->next!=NULL && aList->ops->compar(aNode->payload, cur->next->payload) < 0; cur = cur->next);
			aNode->next = cur->next;
			aNode->prev = cur;
			cur->next = aNode;
		}
	}

	return aNode;
}

void otrl_list_foreach(OtrlList *aList, void (*fun)(OtrlListNode *) )
{
	OtrlListNode *cur = aList->head;

	if(!cur)
		return;

	fun(cur);
	while( (cur = cur->next) )
		fun(cur);

}

void otrl_list_dump(OtrlList *aList)
{
	if(aList->ops == NULL || aList->ops->toString == NULL) {
		return;
	}

	otrl_list_foreach(aList, aList->ops->toString);
}


void otrl_list_node_destroy(OtrlListNode *aNode)
{
	free(aNode);
}

void otrl_list_destroy(OtrlList *aList)
{
	OtrlListNode *cur;

	cur = aList->head;

	/* Destroy each node in the list */
	while( (cur = cur->next) ){
		aList->ops->payload_destroy(cur->prev);
		otrl_list_node_destroy(cur->prev);
	}

	/* And the last one */
	aList->ops->payload_destroy(aList->tail);
	otrl_list_node_destroy(aList->tail);

	/* Destroy the ops struct */
	free(aList->ops);

	free(aList);

}

OtrlListNode * otrl_list_find(OtrlList *aList, PayloadPtr target)
{
	OtrlListNode *cur = NULL;
	int res;
	cur = aList->head;

	// check if the list is empty
	if(cur == NULL)
		return NULL;

	while(cur != NULL) {
		res = aList->ops->compar(target, cur->payload);
		if(res == 0)
			return cur;
		if(res > 0)
			break;
		cur = cur->next;
	}

	return NULL;
}

