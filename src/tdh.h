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

#ifndef TDH_H
#define TDH_H

#include <gcrypt.h>
#include "dh.h"

#define TDH_MAC_LENGTH 32
/*
 * This struct is used internally to store the cryptographic algorithms for
 * sending and receiving the confirmation message of the triple dh exchange
 */
typedef struct {


    gcry_cipher_hd_t sendenc;           /* Sending cipher for confirmation message */

    gcry_cipher_hd_t rcvenc;            /* Receiving cipher for confirmation message */

    gcry_md_hd_t sendmac;               /* Sending mac for confirmation message */

    gcry_md_hd_t rcvmac;                /* Receiving mac for confirmation message */


} state;


/*
 * This struct is seen by the end users. It stores all necessary information
 * needed to perform the exchange, from computing the shared secret to the
 * crypto algorithms needed to send and receive the confirmation messages
 */
typedef struct {
    DH_keypair longterm;                /* Our long term DH key */
    DH_keypair ephemeral;               /* Our ephemeral key just for this exchange */

    gcry_mpi_t their_pub_long;          /* Their long term public key */
    gcry_mpi_t their_pub_eph;           /* Their ephemeral public key */

    state state;                    /* Crypto algorithms to be used */

} TripleDH_handshake;

/**
  Initializes a tripleDH handshake. It does not allocate the struct
  itself

  @param handshake the handshake to be initialized
*/
void tdh_handshake_init(TripleDH_handshake *handshake);

/**
  Loads a long term keypair in the handshake to be used for computing
  the shared secret

  @param handshake the handshake that the keypair will be loaded into
  @param longterm the long term keypair to load
*/
void tdh_handshake_load_longterm(TripleDH_handshake *handshake,
	DH_keypair *longterm);

void tdh_handshake_load_ephemeral(TripleDH_handshake *handshake,
                                DH_keypair *ephemeral);



/**
  Generates an ephemeral dh key just for this handshake. It will be used to
  compute the shared secret

  @param handshake the handshake that the secret key will be generated for
*/
//void tdh_handshake_gen_ephemeral(TripleDH_handshake *handshake);
gcry_error_t tdh_handshake_gen_ephemeral(DH_keypair *ephemeral);

/**
  Loads the other party's long term and ephemeral public keys needed to
  compute the shared secret

  @param handshake the handshake the keys will be loaded into
  @param their_long the long term public key
  @param their_eph the ephemeral public key
*/
gcry_error_t tdh_handshake_load_their_pub(TripleDH_handshake *handshake,
	gcry_mpi_t their_long, gcry_mpi_t their_eph);


/**
  Encrypt a message using the shared secret of this handshake

  Encrypt a message using the sending cipher in this handshake. If in is not
  null then it must contain the message to be encrypted and inlen must have
  its size. If in is NULL then inlen must be zero. In this case the message
  to be encrypted must be in out and its length in outsize, and the encryption
  will be performed in place. Overlapping buffers are not allowed.
  In any case if no error is returned then out point to the encrypted message.

  @param the handshake struct we are using for encryption
  @param out a pointer pointing to an allocated buffer that will hold the
   ciphertext
  @param outsize the allocated size in bytes of the memory pointed by out
  @param in a pointer pointing to the plaintext. If NULL then out must point to the
   plaintext and encyrption will happen in place
  @param inlen the size of the plaintext
  @return 0 if no error, non-zero otherwise
*/
gcry_error_t tdh_handshake_encrypt(TripleDH_handshake *handshake,
	unsigned char *out, size_t outsize,
	unsigned char *in, size_t inlen);

/**
  Decrypts a message using the shared secret of this handshake

  Decrypts a message using the receiving cipher in handshake. Arguments values
  use the same convention as encrypt

  @param handshake the handshake struct we are using for decryption
  @param out a pointer pointing to an allocated buffer that will hold the
   plaintext
  @param outsize the allocated size in bytes of the memory pointed by out
  @param in a pointer pointing to the ciphertext. If NULL then out must point to the
   plaintext and decryption will happen in place
  @param inlen the size of the ciphertext
  @return 0 if no error, non-zero otherwise
*/
gcry_error_t tdh_handshake_decrypt(TripleDH_handshake *handshake,
	unsigned char *out, size_t outsize,
	const unsigned char *in, size_t inlen);

/**
  Generates a MAC for the message to be sent

  Generated a MAC for the message to be sent using the sending hmac in
  handshake. For the time being the mac length is hardcoded to be 32 bytes.

  @param handshake the handshake struct we are using for mac'ing
  @param out a buffer that will hold the mac. it needs to be allocated by the
   caller
  @param in a buffer holding the message to be mac'd
  @param inlen the size of the message to be mac'd
*/
gcry_error_t tdh_handshake_mac(TripleDH_handshake *hs, unsigned char *out,
                               const unsigned char *in, size_t inlen,
                               const unsigned char *assoc_data, size_t assoc_datalen);

/**
  Verify a message using the provided mac

  @param handshake the handshake struct we are using for the verification
  @param mac a buffer holding the mac
  @param msg a buffer holding the message to be verified
  @param msglen the length of the message to be verified
*/
gcry_error_t tdh_handshake_mac_verify(TripleDH_handshake *hs, char unsigned mac[TDH_MAC_LENGTH],
                                      const unsigned char *msg, size_t msglen,
                                      const unsigned char *assoc_data, size_t assoc_datalen);

/**
  Compute the shared secrets of this handshake

  This function must be called afterr all the necessary keys are loadid in
  the handshake struct and the ephemeral key is generated. It will compute
  a session id, a sending/receiving cipher and a sending/receiving mac using
  the shared secret that was derived from the handshake. The exchange is NOT
  authenticated before the first message is sent.

  @param handshake the handshake that the shared secret will be created for
*/
gcry_error_t tdh_handshake_compute_keys(TripleDH_handshake *handshake);
#endif /* TDH_H */
