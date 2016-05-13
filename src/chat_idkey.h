#ifndef CHAT_IDKEY_H
#define CHAT_IDKEY_H

typedef struct {
	DH_keypair keyp;
	char* accountname;
	char* protocol;
} ChatIdKey;

typedef struct {
	void (*init)(ChatIdKey*);
	void (*destroy_key)(ChatIdKey*);
	ChatIdKey * (*parse)(gcry_sexp_t);
	gcry_error_t (*generate_key)(ChatIdKey**);
	gcry_error_t (*serialize)(ChatIdKey*, gcry_sexp_t*);
} ChatIdKeyManager;

struct OtrlListOpsStruct chat_idkey_listOps;

ChatIdKeyManager chat_id_key_manager;
#endif /* CHAT_IDKEY_H */
