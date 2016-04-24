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

typedef struct OtrlListNodeStruct OtrlListNode;

typedef void * PayloadPtr;

struct OtrlListNodeStruct {
	struct OtrlListNodeStruct * next;
	struct OtrlListNodeStruct * prev;
	PayloadPtr payload;
};

struct OtrlListOpsStruct {
	int (*compar)(PayloadPtr, PayloadPtr);  	/* function for comparing elements */
	void (*toString)(OtrlListNode*);             /* String representation of elements */
	void (*payload_destroy)(PayloadPtr);
};

typedef struct OtrlListStruct {
	OtrlListNode * head;
	OtrlListNode * tail;
	unsigned int size;
	size_t payload_size;
	struct OtrlListOpsStruct *ops;
} OtrlList;


/*
 * Function: otrl_list_init
 * ------------------------
 * initializes a new list
 *
 * ops: a pointer to a struct containing the functions that implement the proper ops for the payload type
 * payload_size: the size of the list node payload
 *
 * returns: a pointer to the new list
 * 			returns NULL in error
 */
OtrlList * otrl_list_init(struct OtrlListOpsStruct *ops, size_t payload_size);


/*
 * Function: otrl_list_node_new
 * ------------------------
 * creates a new list node
 *
 * payload: the payload to be contained in the created list node
 *
 * returns: a pointer to the new list node
 * 			returns NULL in error
 */
OtrlListNode * otrl_list_node_create(const PayloadPtr payload);

/*
 * Function: otrl_list_insert
 * ------------------------
 * inserts a list node into a sorted list
 *
 * list: a pointer to the list in which the node will be inserted
 * payload: a pointer to the node to be inserted
 *
 * returns: a pointer to the inserted list node
 * 			returns NULL if error
 */
OtrlListNode * otrl_list_insert(OtrlList *list, const PayloadPtr payload);

/*
 * Function: otrl_list_prepend
 * ------------------------
 * prepends a list node to the head o a list
 *
 * list: a pointer to the list in which the node will be prepended
 * payload: a pointer to the node to be prepended
 *
 * returns: a pointer to the prepended list node
 * 			returns NULL if error
 */
OtrlListNode * otrl_list_prepend(OtrlList *list, PayloadPtr payload);

/*
 * Function: otrl_list_append
 * ------------------------
 * appends a list node to the end of a list
 *
 * list: a pointer to the list to which the node will be appended
 * payload: a pointer to the node to be appended
 *
 * returns: a pointer to the appended list node
 * 			returns NULL if error
 */
OtrlListNode * otrl_list_append(OtrlList *list, PayloadPtr payload);

void otrl_list_remove(OtrlList *list, OtrlListNode *node);
void otrl_list_remove_and_destroy(OtrlList *list, OtrlListNode *node);


/*
 * Function: otrl_list_foreach
 * ------------------------
 * applies a function on every node of a list
 *
 * list: a pointer to the list, the nodes of which the function will be applied on
 * fun: a pointer to the function to be applied on the nodes
 */
void otrl_list_foreach(OtrlList *list, void (*fun)(OtrlListNode *) );


/*
 * Function: otrl_list_find
 * ------------------------
 * finds a node containing a specific payload value
 *
 * list: a pointer to the list in which to search for the target
 * target: the value of the payload we want to find
 *
 * returns: a pointer to the first list node containing the payload value
 * 			returns NULL if there is no such node
 */
OtrlListNode * otrl_list_find(OtrlList *list, PayloadPtr target);

OtrlListNode * otrl_list_get(OtrlList *list, unsigned int i);

/*
 * Function: otrl_list_get_last
 * ------------------------
 * returns a pointer to the tail node
 *
 * list: a pointer to the list
 *
 * returns: a pointer to the the tail node
 * 			returns NULL if the list is empty
 */
OtrlListNode * otrl_list_get_last(OtrlList *list);

/*
 * Function: otrl_list_dump
 * ------------------------
 * prints the contents of a list
 *
 * list: a pointer to the list to be printed
 */
void otrl_list_dump(OtrlList *list);


void otrl_list_clear(OtrlList *list);

/*
 * Function: otrl_list_destroy
 * ------------------------
 * deletes a list
 *
 * list: a pointer to the list to be destroyed
 */
void otrl_list_destroy(OtrlList *list);


/*
 * Function: otrl_node_destroy
 * ------------------------
 * deletes a list node
 *
 * list: the list
 * node: a pointer to the node to be destroyed
 */
void otrl_list_node_destroy(OtrlList *list, OtrlListNode *node);

unsigned int otrl_list_length(OtrlList *list);

#endif /* LIST_H_ */
