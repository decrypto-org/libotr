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
#include <gcrypt.h>
#include <string.h>

#include "chat_privkeydh.h"
#include "dh.h"
#include "tdh.h"
//#include "debug.h"

void tdh_handshake_destroy(TripleDH_handshake *handshake)
{
	gcry_mpi_release(handshake->their_pub_eph);
	gcry_mpi_release(handshake->their_pub_long);

	otrl_dh_keypair_free(&handshake->ephemeral);
	otrl_dh_keypair_free(&handshake->longterm);
}

/*
 * Initialises a triple dh handshake
 */
void tdh_handshake_init(TripleDH_handshake *handshake)
{
    otrl_dh_keypair_init(&handshake->longterm);
    otrl_dh_keypair_init(&handshake->ephemeral);

    handshake->their_pub_long = NULL;
    handshake->their_pub_eph  = NULL;

    handshake->state.sendenc = NULL;
    handshake->state.rcvenc  = NULL;
    handshake->state.sendmac = NULL;
    handshake->state.rcvmac  = NULL;

}

/*
 * Loads our long term keypair longterm in handshake to be used for computing
 * the shared secret
 */
void tdh_handshake_load_longterm(TripleDH_handshake *handshake,
        DH_keypair *longterm)
{

    otrl_dh_keypair_copy(&(handshake->longterm), longterm);
    return;
}

/*
 * Generates an ephemeral dh key.
 */
gcry_error_t tdh_handshake_gen_ephemeral(DH_keypair *ephemeral)
{
    gcry_error_t err;
    err = otrl_dh_gen_keypair(DH1536_GROUP_ID,ephemeral);
    return err;
}

/*
 * Loads an ephemeral dh key in the handshake.
 */
void tdh_handshake_load_ephemeral(TripleDH_handshake *handshake,
                                DH_keypair *ephemeral)
{
    otrl_dh_keypair_copy(&(handshake->ephemeral), ephemeral);
    return;
}
/*
 * Loads the other party's long term (their_long) and ephemeral (their_eph)
 * public keys needed for computing the shared secret
 */
gcry_error_t tdh_handshake_load_their_pub(TripleDH_handshake *handshake,
        gcry_mpi_t their_long, gcry_mpi_t their_eph)
{
    /* Check if both longterm and ephemeral public keys are valid */
    if ( otrl_dh_is_inrange(their_long) ||
           otrl_dh_is_inrange(their_eph) ) {
        /*one of the public keys were out of range */
        return gcry_error(GPG_ERR_INV_VALUE);
    }

    /* Just copy the provided public keys in the handshake data */
    handshake->their_pub_long = gcry_mpi_copy(their_long);
    handshake->their_pub_eph  = gcry_mpi_copy(their_eph);

    return gcry_error(GPG_ERR_NO_ERROR);
}

/*
 * Encrypt a message using the sending cipher in hs. If in is not null then
 * it must contain the message to be encrypted and inlen must have its size.
 * If in is NULL then inlen must be zero. In this case the message to be
 * encrypted must be in out and its length in outsize, and the encryption
 * will be performed in place. Overlapping buffers not allowed.
 * In any case if the function returns with no errors then out will have
 * the encrypted message and outsize will contain its length.
 *
 * This is just a wrapper around gcry_cipher_encrypt.
 */
gcry_error_t tdh_handshake_encrypt(TripleDH_handshake *hs,
                                        unsigned char *out, size_t outsize,
                                        unsigned char *in, size_t inlen)
{
    gcry_error_t err;

    if(out) {
        err = gcry_cipher_encrypt(hs->state.sendenc, out, outsize, in, inlen);
        return err;
    }
    return 0;
}

/*
 * Decrypts a message using the receiving cipher in hs. Argument values
 * conform to the encryption pattern as above.
 *
 * This is just a wrapper around gcry_cipher_decrypt.
 */
gcry_error_t tdh_handshake_decrypt(TripleDH_handshake *hs,
                                        unsigned char *out, size_t outsize,
                                        const unsigned char *in, size_t inlen)
{
    gcry_error_t err;
    err = gcry_cipher_decrypt(hs->state.rcvenc, out, outsize, in, inlen);
    return err;
}


/*
 * Generate the MAC of in using the sending HMAC in hs. The length of the
 * input is inlen. The MAC is returned in out which must be an allready
 * allocated buffer. Currently the size of the MAC is hardcoded to be 32
 * bytes.
 */
gcry_error_t tdh_handshake_mac(TripleDH_handshake *hs, unsigned char *out,
                               const unsigned char *in, size_t inlen,
                               const unsigned char *assoc_data, size_t assoc_datalen)
{
    //if (!in) {
    //    return gcry_error(GPG_ERR_NOT_IMPLEMENTED);
    //}


    gcry_md_reset(hs->state.sendmac);
    if(inlen > 0)
        gcry_md_write(hs->state.sendmac, in, inlen);

    if(assoc_datalen > 0)
        gcry_md_write(hs->state.sendmac, assoc_data, assoc_datalen);

    memmove(out, gcry_md_read(hs->state.sendmac, GCRY_MD_SHA256), 32);

    return gcry_error(GPG_ERR_NO_ERROR);
}


/*
 * Verify if mac is a valid MAC for msg, using receiving mac from hs
 */
gcry_error_t tdh_handshake_mac_verify(TripleDH_handshake *hs, unsigned char mac[32],
                                      const unsigned char *msg, size_t msglen,
                                      const unsigned char *assoc_data, size_t assoc_datalen)
{
    unsigned char my_mac[32];

    gcry_md_reset(hs->state.rcvmac);
    gcry_md_write(hs->state.rcvmac, msg, msglen);
    if(assoc_datalen > 0)
        gcry_md_write(hs->state.rcvmac, assoc_data, assoc_datalen);
    memmove(my_mac, gcry_md_read(hs->state.rcvmac, GCRY_MD_SHA256), 32);

    return memcmp(my_mac, mac, 32);
}

/*
 * This function must be called after all the necessary values are loaded in
 * handshake and the ephemeral key is generated. It will then compute a session
 * id and sending and receiving ciphers/macs using the shared secret that can be
 * calculated by a triple dh exchange. The exchange is still NOT authenticated.
 */
gcry_error_t tdh_handshake_compute_keys(TripleDH_handshake *handshake)
{
    gcry_mpi_t gab, gAb, gaB;
    size_t gab_len, gAb_len, gaB_len;
    size_t base = 0;
    unsigned char *sdata;
    unsigned char *hashdata;
    unsigned char ctr[16];
    unsigned char sendbyte, rcvbyte;
    gcry_error_t err = gcry_error(GPG_ERR_NO_ERROR);

    /* Init ctr to zero */
    memset(ctr, 0, 16);
    /* Alocate and calculate g^ab */
    gab = gcry_mpi_snew(700);
    if (!gab) {
        return gcry_error(GPG_ERR_ENOMEM);
    }


    if (!handshake->ephemeral.priv) {
        return gpg_error(GPG_ERR_GENERAL);
    }
    if (!handshake->their_pub_eph) {
        return gpg_error(GPG_ERR_GENERAL);
    }

    otrl_dh_powm(gab, handshake->their_pub_eph, handshake->ephemeral.priv);
    /* Allocate  g^Ab */
    gAb = gcry_mpi_snew(700);

    /* Allocate g^aB */
    gaB = gcry_mpi_snew(700);


    /* We must decide if we are high or low in the exchange. To do so we
     * compare the longterm public keys. This is done because we calculate
     * values g^Ab and g^aB. Thus because we must concatenate them we must
     * decide in what order the concatenation happens. */
    if (gcry_mpi_cmp(handshake->longterm.pub, handshake->their_pub_long) > 0 ) {
        /* We are high */
        sendbyte = 0x01;
        rcvbyte  = 0x02;

        otrl_dh_powm(gAb, handshake->their_pub_eph, handshake->longterm.priv);
        otrl_dh_powm(gaB, handshake->their_pub_long, handshake->ephemeral.priv);

    }
    else {
        /* We are low */
        sendbyte = 0x02;
        rcvbyte  = 0x01;

        otrl_dh_powm(gaB, handshake->their_pub_eph, handshake->longterm.priv);
        otrl_dh_powm(gAb, handshake->their_pub_long, handshake->ephemeral.priv);
    }

    /* Get their respective lengths in the right format */
    gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &gab_len, gab);
    gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &gAb_len, gAb);
    gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &gaB_len, gaB);

    /* Allocate memory to store them as plain bytes. We need 4 extra bytes
     * for the length of each secret, plus one additional byte to use in key
     * derivation */
    sdata = gcry_malloc_secure(1 + 4 + gab_len + 4 + gAb_len + 4 + gaB_len);
    if (!sdata) {
        gcry_mpi_release(gab);
        gcry_mpi_release(gAb);
        gcry_mpi_release(gaB);
        return gcry_error(GPG_ERR_ENOMEM);
    }

    /* Disregard first byte for now, write gab_len and then gab */
    sdata[1] = (gab_len >> 24) & 0xff;
    sdata[2] = (gab_len >> 16) & 0xff;
    sdata[3] = (gab_len >> 8) & 0xff;
    sdata[4] = gab_len & 0xff;
    gcry_mpi_print(GCRYMPI_FMT_USG, sdata+5, gab_len, NULL, gab);
    gcry_mpi_release(gab);
    /* Increase base by the bytes written */
    base += 4 + gab_len;

    /* Write gAb_len and then gAb */
    sdata[1+base] = (gAb_len >> 24) & 0xff;
    sdata[2+base] = (gAb_len >> 16) & 0xff;
    sdata[3+base] = (gAb_len >> 8) & 0xff;
    sdata[4+base] = gAb_len & 0xff;
    gcry_mpi_print(GCRYMPI_FMT_USG, sdata+base+5, gAb_len, NULL, gAb);
    gcry_mpi_release(gAb);
    /* Increase base by the bytes written */
    base += 4 + gAb_len;

    /* Write gaB_len and then gaB */
    sdata[1+base] = (gaB_len >> 24) & 0xff;
    sdata[2+base] = (gaB_len >> 16) & 0xff;
    sdata[3+base] = (gaB_len >> 8) & 0xff;
    sdata[4+base] = gaB_len & 0xff;
    gcry_mpi_print(GCRYMPI_FMT_USG, sdata+base+5, gaB_len,
            NULL, gaB);
    gcry_mpi_release(gaB);
    /* Increase base by the bytes written */
    base += 4 + gaB_len;

    /* Calculate session id by hashing 0x00 || gab || gAb || gaB
     * and using the first 16 bytes of the hash */
    hashdata = gcry_malloc_secure(32);

    /* Calculate sending encryption key by hashing  sendbyte || gab || gAb || gaB
     * and using the hash as the key */
    sdata[0] = sendbyte;
    gcry_md_hash_buffer(GCRY_MD_SHA256, hashdata, sdata, base+1);
    err = gcry_cipher_open(&(handshake->state.sendenc), GCRY_CIPHER_AES256,
            GCRY_CIPHER_MODE_CTR, GCRY_CIPHER_SECURE);
    if (err) goto err;
    err = gcry_cipher_setkey(handshake->state.sendenc, hashdata, 32);
    if (err) goto err;
    err = gcry_cipher_setctr(handshake->state.sendenc, ctr, 16);
    if (err) goto err;

    /* Calculate the sending MAC key by hashing sendbyte+2 || gab || gAb || gaB
     * and using the whole hash as the key */
    sdata[0]= sendbyte + 2;
    gcry_md_hash_buffer(GCRY_MD_SHA256, hashdata, sdata, base+1);

    err = gcry_md_open(&(handshake->state.sendmac), GCRY_MD_SHA256,
                       GCRY_MD_FLAG_HMAC);
    if (err) goto err;
    err = gcry_md_setkey(handshake->state.sendmac, hashdata, 32);
    if (err) goto err;

    /* Calculate receiving encryption key by hashing  rcvbyte || gab || gAb || gaB
     * and using the hash as the key */
    sdata[0] = rcvbyte;
    gcry_md_hash_buffer(GCRY_MD_SHA256, hashdata, sdata, base+1);
    err = gcry_cipher_open(&(handshake->state.rcvenc), GCRY_CIPHER_AES256,
            GCRY_CIPHER_MODE_CTR, GCRY_CIPHER_SECURE);
    if (err) goto err;
    err = gcry_cipher_setkey(handshake->state.rcvenc, hashdata, 32);
    if (err) goto err;
    err = gcry_cipher_setctr(handshake->state.rcvenc, ctr, 16);
    if (err) goto err;

    /* Calculate the receiving MAC key by hashing rcvbyte+2 || gab || gAb || gaB
     * and using the hash as the key */
    sdata[0]= rcvbyte + 2;
    gcry_md_hash_buffer(GCRY_MD_SHA256, hashdata, sdata, base+1);

    err = gcry_md_open(&(handshake->state.rcvmac), GCRY_MD_SHA256,
                       GCRY_MD_FLAG_HMAC);
    if (err) goto err;
    err = gcry_md_setkey(handshake->state.rcvmac, hashdata, 32);
    if (err) goto err;

    gcry_free(sdata);
    gcry_free(hashdata);
    return gcry_error(GPG_ERR_NO_ERROR);

err:
    gcry_cipher_close(handshake->state.sendenc);
    gcry_cipher_close(handshake->state.rcvenc);
    gcry_md_close(handshake->state.sendmac);
    gcry_md_close(handshake->state.rcvmac);

    handshake->state.sendenc = NULL;
    handshake->state.rcvenc  = NULL;
    handshake->state.sendmac = NULL;
    handshake->state.rcvmac  = NULL;

    gcry_free(sdata);
    gcry_free(hashdata);
    return err;
}


/*
int main(int argc, char **argv)
{

    unsigned char * buf = NULL;
    gcry_mpi_t key = NULL;
    size_t written;
    gcry_error_t err;
    unsigned char message[16] = "must be readabl";
    unsigned char mac[32];
    FILE *fp;
    int i;
    TripleDH_handshake hs_a, hs_b;
    DH_keypair *a_keypair, *b_keypair;

    if(!gcry_check_version(NULL))
    {
	fputs("gcrypt version missmatch\n", stderr);
	exit(2);
    }

    //gcry_control(GCRYCTL_DISABLE_SECMEM, 0);

    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    otrl_dh_init();

    tdh_handshake_init(&hs_a);
    tdh_handshake_init(&hs_b);


    a_keypair = gcry_malloc_secure(sizeof(DH_keypair));
    b_keypair = gcry_malloc_secure(sizeof(DH_keypair));


    fp = fopen("apriv", "rb");

    otrl_chat_privkeydh_read_FILEp(a_keypair, fp);

    fclose(fp);
    fopen("bpriv", "rb");

    otrl_chat_privkeydh_read_FILEp(b_keypair, fp);

    fclose(fp);
    tdh_handshake_load_longterm(&hs_a, a_keypair);
    tdh_handshake_load_longterm(&hs_b, b_keypair);

    tdh_handshake_gen_ephemeral(&hs_a);
    tdh_handshake_gen_ephemeral(&hs_b);


    tdh_handshake_load_their_pub(&hs_a, hs_b.longterm.pub,
                                       hs_b.ephemeral.pub);

    tdh_handshake_load_their_pub(&hs_b, hs_a.longterm.pub,
                                      hs_a.ephemeral.pub);

    tdh_handshake_compute_keys(&hs_a);
    tdh_handshake_compute_keys(&hs_b);

    err = tdh_handshake_encrypt(&hs_a, message, 16, NULL, 0);
    if(err)
        fprintf(stderr, "something went wrong when encrypting\n");
    fwrite(message, sizeof(unsigned char), 16, stderr);
    fprintf(stderr, "\n");
    tdh_handshake_mac(&hs_a, mac, message, 16);

    for(i = 0; i<16; i++)
        fprintf(stderr, "%02X", mac[i]);
    fprintf(stderr,"\n");


    if(!tdh_handshake_mac_verify(&hs_b, mac, message,16))
        fprintf(stderr,"message is not verified");
    err = tdh_handshake_decrypt(&hs_b, message, 16, NULL, 0);
    if(err)
        fprintf(stderr, "something went wrong when decrypting\n");

    fprintf(stderr, "%s\n", message);

}
*/
