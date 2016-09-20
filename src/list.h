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

#ifndef LIST_H_
#define LIST_H_

#include <stddef.h>

typedef void * OtrlListPayload;
typedef struct OtrlListNodeStruct * OtrlListNode;
typedef struct OtrlListStruct * OtrlList;
typedef struct OtrlListIteratorStruct * OtrlListIterator;

struct OtrlListOpsStruct {
	int (*compar)(OtrlListPayload, OtrlListPayload);  	/* function for comparing elements */

	/* TODO
	 * Why does this function accepts a list
	 * node and not a payload like the rest? Maybe
	 * refactor?
	 */
	void (*print)(OtrlListNode);             /* Prints element on stderr */
	void (*payload_free)(OtrlListPayload);
};

OtrlListPayload otrl_list_node_get_payload(OtrlListNode node);

OtrlList otrl_list_new(struct OtrlListOpsStruct *ops, size_t payload_size);
OtrlListNode otrl_list_get_head(OtrlList list);
OtrlListNode otrl_list_get_tail(OtrlList list);
OtrlListNode otrl_list_insert(OtrlList list, const OtrlListPayload payload);
OtrlListNode otrl_list_prepend(OtrlList list, OtrlListPayload payload);
OtrlListNode otrl_list_append(OtrlList list, OtrlListPayload payload);
void otrl_list_remove(OtrlList list, OtrlListNode node);
void otrl_list_remove_and_free(OtrlList list, OtrlListNode node);
void otrl_list_clear(OtrlList list);
void otrl_list_free(OtrlList list);
OtrlListNode otrl_list_find(OtrlList list, OtrlListPayload target);
unsigned int otrl_list_size(OtrlList list);
OtrlListNode otrl_list_get(OtrlList list, unsigned int i);
void otrl_list_foreach(OtrlList list, void (*fun)(OtrlListNode));
void otrl_list_dump(OtrlList list);

OtrlListIterator otrl_list_iterator_new(OtrlList list);
void otrl_list_iterator_free(OtrlListIterator iter);
int otrl_list_iterator_has_next(OtrlListIterator iter);
OtrlListNode otrl_list_iterator_next(OtrlListIterator iter);

#endif /* LIST_H_ */
