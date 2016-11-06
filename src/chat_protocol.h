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

#ifndef CHAT_PROTOCOL_H_
#define CHAT_PROTOCOL_H_

int otrl_chat_protocol_id_key_read_file(OtrlUserState us, FILE *privf);
int otrl_chat_protocol_id_keys_write_file(OtrlUserState us, FILE *privf);
int otrl_chat_protocol_id_key_generate_new(OtrlUserState us, const OtrlMessageAppOps *ops, const char *accountname, const char *protocol);
OtrlListPtr otrl_chat_protocol_id_key_list_create(OtrlUserState us);

int otrl_chat_protocol_fingerprints_read_file(OtrlUserState us, FILE *fingerfile);
int otrl_chat_protocol_fingerprints_write_file(OtrlUserState us, FILE *fingerfile);
void otrl_chat_protocol_fingerprint_verify(OtrlUserState us, const OtrlMessageAppOps *ops, OtrlChatFingerprintPtr fnprnt);
void otrl_chat_protocol_fingerprint_forget(OtrlUserState us, const OtrlMessageAppOps *ops, OtrlChatFingerprintPtr fnprnt);

int chat_protocol_reset(ChatContextPtr ctx);

 int otrl_chat_protocol_receiving(OtrlUserState us, const OtrlMessageAppOps *ops,
 	void *opdata, const char *accountname, const char *protocol,
 	const char *sender, otrl_chat_token_t chat_token, const char *message,
 	char **newmessagep,	OtrlTLV **tlvsp);

 int otrl_chat_protocol_sending(OtrlUserState us,
 	const OtrlMessageAppOps *ops,
 	void *opdata, const char *accountname, const char *protocol,
 	const char *message, otrl_chat_token_t chat_token, OtrlTLV *tlvs,
 	char **messagep, OtrlFragmentPolicy fragPolicy);

 int otrl_chat_protocol_send_query(OtrlUserState us,
 		const OtrlMessageAppOps *ops,
 		const char *accountname, const char *protocol,
 		otrl_chat_token_t chat_token, OtrlFragmentPolicy fragPolicy);

 int otrl_chat_protocol_shutdown(OtrlUserState us, const OtrlMessageAppOps *ops,
 		const char *accountname, const char *protocol, otrl_chat_token_t chat_token);

#endif /* CHAT_PROTOCOL_H_ */
