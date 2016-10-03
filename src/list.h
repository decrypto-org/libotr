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

typedef void * OtrlListPayloadPtr;
typedef struct OtrlListNode * OtrlListNodePtr;
typedef struct OtrlList * OtrlListPtr;
typedef struct OtrlListIterator * OtrlListIteratorPtr;

struct OtrlListOpsStruct {
	int (*compar)(OtrlListPayloadPtr, OtrlListPayloadPtr);  	/* function for comparing elements */

	/* TODO
	 * Why does this function accepts a list
	 * node and not a payload like the rest? Maybe
	 * refactor?
	 */
	void (*print)(OtrlListNodePtr);             /* Prints element on stderr */
	void (*payload_free)(OtrlListPayloadPtr);
};

OtrlListPayloadPtr otrl_list_node_get_payload(OtrlListNodePtr node);

OtrlListPtr otrl_list_new(struct OtrlListOpsStruct *ops, size_t payload_size);
OtrlListNodePtr otrl_list_get_head(OtrlListPtr list);
OtrlListNodePtr otrl_list_get_tail(OtrlListPtr list);
OtrlListNodePtr otrl_list_insert(OtrlListPtr list, const OtrlListPayloadPtr payload);
OtrlListNodePtr otrl_list_prepend(OtrlListPtr list, OtrlListPayloadPtr payload);
OtrlListNodePtr otrl_list_append(OtrlListPtr list, OtrlListPayloadPtr payload);
void otrl_list_remove(OtrlListPtr list, OtrlListNodePtr node);
void otrl_list_remove_and_free(OtrlListPtr list, OtrlListNodePtr node);
void otrl_list_clear(OtrlListPtr list);
void otrl_list_free(OtrlListPtr list);
OtrlListNodePtr otrl_list_find(OtrlListPtr list, OtrlListPayloadPtr target);
unsigned int otrl_list_size(OtrlListPtr list);
OtrlListNodePtr otrl_list_get(OtrlListPtr list, unsigned int i);
void otrl_list_foreach(OtrlListPtr list, void (*fun)(OtrlListNodePtr));
void otrl_list_dump(OtrlListPtr list);

OtrlListIteratorPtr otrl_list_iterator_new(OtrlListPtr list);
void otrl_list_iterator_free(OtrlListIteratorPtr iter);
int otrl_list_iterator_has_next(OtrlListIteratorPtr iter);
OtrlListNodePtr otrl_list_iterator_next(OtrlListIteratorPtr iter);

#endif /* LIST_H_ */
