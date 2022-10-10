/*
 * Copyright (C) 2019-2022 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "ogs-proto.h"

#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>



#define PLMN_ID_DIGIT1(x) (((x) / 100) % 10)
#define PLMN_ID_DIGIT2(x) (((x) / 10) % 10)
#define PLMN_ID_DIGIT3(x) ((x) % 10)

uint32_t ogs_plmn_id_hexdump(void *plmn_id)
{
    uint32_t hex;
    ogs_assert(plmn_id);
    memcpy(&hex, plmn_id, sizeof(ogs_plmn_id_t));
    hex = be32toh(hex) >> 8;
    return hex;
}

uint16_t ogs_plmn_id_mcc(ogs_plmn_id_t *plmn_id)
{
    return plmn_id->mcc1 * 100 + plmn_id->mcc2 * 10 + plmn_id->mcc3;
}
uint16_t ogs_plmn_id_mnc(ogs_plmn_id_t *plmn_id)
{
    return plmn_id->mnc1 == 0xf ? plmn_id->mnc2 * 10 + plmn_id->mnc3 :
        plmn_id->mnc1 * 100 + plmn_id->mnc2 * 10 + plmn_id->mnc3;
}
uint16_t ogs_plmn_id_mnc_len(ogs_plmn_id_t *plmn_id)
{
    return plmn_id->mnc1 == 0xf ? 2 : 3;
}

void *ogs_plmn_id_build(ogs_plmn_id_t *plmn_id, 
        uint16_t mcc, uint16_t mnc, uint16_t mnc_len)
{
    plmn_id->mcc1 = PLMN_ID_DIGIT1(mcc);
    plmn_id->mcc2 = PLMN_ID_DIGIT2(mcc);
    plmn_id->mcc3 = PLMN_ID_DIGIT3(mcc);

    if (mnc_len == 2)
        plmn_id->mnc1 = 0xf;
    else
        plmn_id->mnc1 = PLMN_ID_DIGIT1(mnc);

    plmn_id->mnc2 = PLMN_ID_DIGIT2(mnc);
    plmn_id->mnc3 = PLMN_ID_DIGIT3(mnc);

    return plmn_id;
}

void *ogs_nas_from_plmn_id(
        ogs_nas_plmn_id_t *ogs_nas_plmn_id, ogs_plmn_id_t *plmn_id)
{
    memcpy(ogs_nas_plmn_id, plmn_id, OGS_PLMN_ID_LEN);
    if (plmn_id->mnc1 != 0xf) {
        ogs_nas_plmn_id->mnc1 = plmn_id->mnc1;
        ogs_nas_plmn_id->mnc2 = plmn_id->mnc2;
        ogs_nas_plmn_id->mnc3 = plmn_id->mnc3;
    }
    return ogs_nas_plmn_id;
}
void *ogs_nas_to_plmn_id(
        ogs_plmn_id_t *plmn_id, ogs_nas_plmn_id_t *ogs_nas_plmn_id)
{
    memcpy(plmn_id, ogs_nas_plmn_id, OGS_PLMN_ID_LEN);
    if (plmn_id->mnc1 != 0xf) {
        plmn_id->mnc1 = ogs_nas_plmn_id->mnc1;
        plmn_id->mnc2 = ogs_nas_plmn_id->mnc2;
        plmn_id->mnc3 = ogs_nas_plmn_id->mnc3;
    }
    return plmn_id;
}

char *ogs_serving_network_name_from_plmn_id(ogs_plmn_id_t *plmn_id)
{
    ogs_assert(plmn_id);
    return ogs_msprintf("5G:mnc%03d.mcc%03d.3gppnetwork.org",
            ogs_plmn_id_mnc(plmn_id), ogs_plmn_id_mcc(plmn_id));
}

char *ogs_plmn_id_mcc_string(ogs_plmn_id_t *plmn_id)
{
    ogs_assert(plmn_id);
    return ogs_msprintf("%03d", ogs_plmn_id_mcc(plmn_id));
}

char *ogs_plmn_id_mnc_string(ogs_plmn_id_t *plmn_id)
{
    ogs_assert(plmn_id);
    if (ogs_plmn_id_mnc_len(plmn_id) == 2)
        return ogs_msprintf("%02d", ogs_plmn_id_mnc(plmn_id));
    else
        return ogs_msprintf("%03d", ogs_plmn_id_mnc(plmn_id));
}

char *ogs_plmn_id_to_string(ogs_plmn_id_t *plmn_id, char *buf)
{
    ogs_assert(plmn_id);
    ogs_assert(buf);

    if (ogs_plmn_id_mnc_len(plmn_id) == 2)
        ogs_snprintf(buf, OGS_PLMNIDSTRLEN, "%03d%02d",
                ogs_plmn_id_mcc(plmn_id), ogs_plmn_id_mnc(plmn_id));
    else
        ogs_snprintf(buf, OGS_PLMNIDSTRLEN, "%03d%03d",
                ogs_plmn_id_mcc(plmn_id), ogs_plmn_id_mnc(plmn_id));

    return buf;
}

uint32_t ogs_amf_id_hexdump(ogs_amf_id_t *amf_id)
{
    uint32_t hex;

    ogs_assert(amf_id);

    memcpy(&hex, amf_id, sizeof(ogs_amf_id_t));
    hex = be32toh(hex) >> 8;

    return hex;
}

ogs_amf_id_t *ogs_amf_id_from_string(ogs_amf_id_t *amf_id, const char *hex)
{
    char hexbuf[sizeof(ogs_amf_id_t)];

    ogs_assert(amf_id);
    ogs_assert(hex);

    OGS_HEX(hex, strlen(hex), hexbuf);

    amf_id->region = hexbuf[0];
    amf_id->set1 = hexbuf[1];
    amf_id->set2 = (hexbuf[2] & 0xc0) >> 6;
    amf_id->pointer = hexbuf[2] & 0x3f;

    return amf_id;
}

#define OGS_AMFIDSTRLEN    (sizeof(ogs_amf_id_t)*2+1)
char *ogs_amf_id_to_string(ogs_amf_id_t *amf_id)
{
    char *str = NULL;
    ogs_assert(amf_id);

    str = ogs_calloc(1, OGS_AMFIDSTRLEN);
    ogs_expect_or_return_val(str, NULL);

    ogs_hex_to_ascii(amf_id, sizeof(ogs_amf_id_t), str, OGS_AMFIDSTRLEN);

    return str;
}

uint8_t ogs_amf_region_id(ogs_amf_id_t *amf_id)
{
    ogs_assert(amf_id);
    return amf_id->region;
}
uint16_t ogs_amf_set_id(ogs_amf_id_t *amf_id)
{
    ogs_assert(amf_id);
    return (amf_id->set1 << 2) + amf_id->set2;
}
uint8_t ogs_amf_pointer(ogs_amf_id_t *amf_id)
{
    ogs_assert(amf_id);
    return amf_id->pointer;
}

ogs_amf_id_t *ogs_amf_id_build(ogs_amf_id_t *amf_id,
        uint8_t region, uint16_t set, uint8_t pointer)
{
    amf_id->region = region;
    amf_id->set1 = set >> 2;
    amf_id->set2 = set & 0x3;
    amf_id->pointer = pointer;

    return amf_id;
}

/* Convert an EC key's public key to a binary array. */
int ec_key_public_key_to_bin(const EC_KEY  *ec_key,
                             uint8_t      **pubk,     // out (must free)
                             size_t        *pubk_len) // out
{
        const EC_GROUP *ec_group   = EC_KEY_get0_group(ec_key);
        const EC_POINT *pub        = EC_KEY_get0_public_key(ec_key);
        BIGNUM         *pub_bn     = BN_new();
        BN_CTX         *pub_bn_ctx = BN_CTX_new();

        BN_CTX_start(pub_bn_ctx);

        EC_POINT_point2bn(ec_group, pub, POINT_CONVERSION_COMPRESSED,
                          pub_bn, pub_bn_ctx);

        *pubk_len = BN_num_bytes(pub_bn);
        *pubk = (uint8_t*)OPENSSL_malloc(*pubk_len);

        if (BN_bn2bin(pub_bn, *pubk) != *pubk_len)
            return -1;

        BN_CTX_end(pub_bn_ctx);
        BN_CTX_free(pub_bn_ctx);
        BN_clear_free(pub_bn);

        return 0;
}

/* Convert an EC key's private key to a binary array. */
int ec_key_private_key_to_bin(const EC_KEY  *ec_key,
                              uint8_t      **privk,     // out (must free)
                              size_t        *privk_len) // out
{
        const BIGNUM *priv = EC_KEY_get0_private_key(ec_key);

        *privk_len = BN_num_bytes(priv);
        *privk = (uint8_t*)OPENSSL_malloc(*privk_len);

        if (BN_bn2bin(priv, *privk) != *privk_len)
            return -1;

        return 0;
}

/* Convert a public key binary array to an EC point. */
int ec_key_public_key_bin_to_point(const EC_GROUP  *ec_group,
                                   const uint8_t   *pubk,
                                   const size_t     pubk_len,
                                   EC_POINT       **pubk_point) // out
{
        BIGNUM   *pubk_bn;
        BN_CTX   *pubk_bn_ctx;

        *pubk_point = EC_POINT_new(ec_group);

        pubk_bn = BN_bin2bn(pubk, pubk_len, NULL);
        pubk_bn_ctx = BN_CTX_new();
        BN_CTX_start(pubk_bn_ctx);

        EC_POINT_bn2point(ec_group, pubk_bn, *pubk_point, pubk_bn_ctx);

        BN_CTX_end(pubk_bn_ctx);
        BN_CTX_free(pubk_bn_ctx);
        BN_clear_free(pubk_bn);

        return 0;
}

/* (TX) Generate an ephemeral EC key and associated shared symmetric key. */
int ecies_transmitter_generate_symkey(const int       curve,
                                      const uint8_t  *peer_pubk,
                                      const size_t    peer_pubk_len,
                                      uint8_t       **epubk,         // out (must free)
                                      size_t         *epubk_len,     // out
                                      uint8_t       **skey,          // out (must free)
                                      size_t         *skey_len)      // out
{
        EC_KEY         *ec_key          = NULL; /* ephemeral keypair */
        const EC_GROUP *ec_group        = NULL;
        EC_POINT       *peer_pubk_point = NULL;

        /* Create and initialize a new empty key pair on the curve. */
        ec_key = EC_KEY_new_by_curve_name(curve);
        EC_KEY_generate_key(ec_key);
        ec_group = EC_KEY_get0_group(ec_key);

        /* Allocate a buffer to hold the shared symmetric key. */
        *skey_len = ((EC_GROUP_get_degree(ec_group) + 7) / 8);
        *skey     = (uint8_t*)OPENSSL_malloc(*skey_len);

        /* Convert the peer public key to an EC point. */
        ec_key_public_key_bin_to_point(ec_group, peer_pubk, peer_pubk_len,
                                       &peer_pubk_point);

        /* Generate the shared symmetric key (diffie-hellman primitive). */
        *skey_len = ECDH_compute_key(*skey, *skey_len, peer_pubk_point,
                                     ec_key, NULL);

        /* Write the ephemeral key's public key to the output buffer. */
        ec_key_public_key_to_bin(ec_key, epubk, epubk_len);

        return 0;
}

/* (RX) Generate the shared symmetric key. */
int ecies_receiver_generate_symkey(const EC_KEY   *ec_key,
                                   const uint8_t  *peer_pubk,
                                   const size_t    peer_pubk_len,
                                   uint8_t       **skey,          // out (must free)
                                   size_t         *skey_len)      // out
{
        const EC_GROUP *ec_group        = EC_KEY_get0_group(ec_key);
        EC_POINT       *peer_pubk_point = NULL;

        /* Allocate a buffer to hold the shared symmetric key. */
        *skey_len = ((EC_GROUP_get_degree(ec_group) + 7) / 8);
        *skey     = (uint8_t*)OPENSSL_malloc(*skey_len);

        /* Convert the peer public key to an EC point. */
        ec_key_public_key_bin_to_point(ec_group, peer_pubk, peer_pubk_len,
                                       &peer_pubk_point);

        /* Generate the shared symmetric key (diffie-hellman primitive). */
        *skey_len = ECDH_compute_key(*skey, *skey_len, peer_pubk_point,
                                     (EC_KEY *)ec_key, NULL);

        return 0;
}

/* Encrypt plaintext data using 256b AES-GCM. */
int aes_gcm_256b_encrypt(uint8_t  *plaintext,
                         size_t    plaintext_len,
                         uint8_t  *skey,
                         uint8_t  *aad,
                         size_t    aad_len,
                         uint8_t **iv,             // out (must free)
                         uint8_t  *iv_len,         // out
                         uint8_t **tag,            // out (must free)
                         uint8_t  *tag_len,        // out
                         uint8_t **ciphertext,     // out (must free)
                         uint8_t  *ciphertext_len) // out
{
        EVP_CIPHER_CTX *ctx;
        int len;

        /* Allocate buffers for the IV, tag, and ciphertext. */
        *iv_len = 12;
        *iv = (uint8_t*)OPENSSL_malloc(*iv_len);
        *tag_len = 12;
        *tag = (uint8_t*)OPENSSL_malloc(*tag_len);
        *ciphertext = (uint8_t*)OPENSSL_malloc((plaintext_len + 0xf) & ~0xf);

        /* Initialize the context and encryption operation. */
        ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);

        /* Generate a new random IV. */
        RAND_pseudo_bytes(*iv, *iv_len);

        /* Prime the key and IV. */
        EVP_EncryptInit_ex(ctx, NULL, NULL, skey, *iv);

        /* Prime with any additional authentication data. */
        if (aad && aad_len)
            EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);

        /* Encrypt the data. */
        EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len);
        *ciphertext_len = len;

        /* Finalize the encryption session. */
        EVP_EncryptFinal_ex(ctx, (*ciphertext + len), &len);
        *ciphertext_len += len;

        /* Get the authentication tag. */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, *tag_len, *tag);

        EVP_CIPHER_CTX_free(ctx);

        return 0;
}

/* Decrypt ciphertext data using 256b AES-GCM. */
int aes_gcm_256b_decrypt(uint8_t  *ciphertext,
                         size_t    ciphertext_len,
                         uint8_t  *skey,
                         uint8_t  *aad,
                         size_t    aad_len,
                         uint8_t  *iv,
                         uint8_t   iv_len,
                         uint8_t  *tag,
                         size_t    tag_len,
                         uint8_t **plaintext,     // out (must free)
                         uint8_t  *plaintext_len) // out
{
        EVP_CIPHER_CTX *ctx;
        int len, rc;

        /* Allocate a buffer for the plaintext. */
        *plaintext = (uint8_t*)OPENSSL_malloc(ciphertext_len);

        /* Initialize the context and encryption operation. */
        ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);

        /* Prime the key and IV (+length). */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);
        EVP_DecryptInit_ex(ctx, NULL, NULL, skey, iv);

        /* Prime with any additional authentication data. */
        if (aad && aad_len)
                EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len);

        /* Decrypt the data. */
        EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len);
        *plaintext_len = len;

        /* Set the expected tag value. */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag);

        /* Finalize the decryption session. Returns 0 with a bad tag! */
        rc = EVP_DecryptFinal_ex(ctx, (*plaintext + len), &len);

        EVP_CIPHER_CTX_free(ctx);

        if (rc > 0)
        {
                *plaintext_len += len;
                return 0;
        }
        return -1;
}

int ecies_receiver_load_key(char     *filename,
                            EC_KEY  **ec_key,    // out
                            int      *curve,     // out
                            uint8_t **pubk,      // out (must free)
                            size_t   *pubk_len,  // out
                            uint8_t **privk,     // out (must free)
                            size_t   *privk_len) // out
{
        const EC_GROUP *ec_group = NULL;
        BIO            *bio_key  = NULL;
        BIO            *bio_out  = NULL; /* stdout */

        /*
         * Create a BIO object wrapping a file pointer to read the EC key file
         * in DER format. Then read in and parse the EC key from the file.
         */
        bio_key = BIO_new_file(filename, "r");
        if (bio_key == NULL)
                return -1;
        *ec_key = d2i_ECPrivateKey_bio(bio_key, NULL);
        if (*ec_key == NULL)
                return 2;
        BIO_free(bio_key);
        /* Get the curve parameters from the EC key. */
        ec_group = EC_KEY_get0_group(*ec_key);

        /* Create a BIO object wrapping stdout. */
        bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

        /* Set the point conversion outputs to always be 'uncompressed'. */
        EC_KEY_set_conv_form(*ec_key, POINT_CONVERSION_COMPRESSED);

        /* Get the EC key's public key in a binary array format. */
        ec_key_public_key_to_bin(*ec_key, pubk, pubk_len);

        /* Get the EC key's private key in a binary array format. */
        ec_key_private_key_to_bin(*ec_key, privk, privk_len);

        /* Get the EC key's curve name. */
        *curve = EC_GROUP_get_curve_name(ec_group);

        return 0;
}

int ecies_transmitter_send_message(uint8_t        *msg,
                                   size_t          msg_len,
                                   int             curve,
                                   const uint8_t  *peer_pubk,
                                   const uint8_t   peer_pubk_len,
                                   uint8_t       **epubk,          // out (must free)
                                   size_t         *epubk_len,      // out
                                   uint8_t       **iv,             // out (must free)
                                   uint8_t        *iv_len,         // out
                                   uint8_t       **tag,            // out (must free)
                                   uint8_t        *tag_len,        // out
                                   uint8_t       **ciphertext,     // out (must free)
                                   uint8_t        *ciphertext_len) // out
{
        uint8_t *skey      = NULL; // DH generated shared symmetric key
        size_t   skey_len  = 0;

        /* Generate the shared symmetric key (transmitter). */
        ecies_transmitter_generate_symkey(curve, peer_pubk, peer_pubk_len,
                                          epubk, epubk_len, &skey, &skey_len);
        if (skey_len != 32)
            return skey_len;

        /* Encrypt the data using 256b AES-GCM. */
        aes_gcm_256b_encrypt(msg, msg_len, skey, NULL, 0,
                             iv, iv_len, tag, tag_len,
                             ciphertext, ciphertext_len);

        free(skey);

        return 0;
}

char* ecies_receiver_recv_message(const EC_KEY  *ec_key,
                                const uint8_t *peer_pubk,
                                const uint8_t  peer_pubk_len,
                                uint8_t       *iv,
                                uint32_t       iv_len,
                                uint8_t       *tag,
                                uint32_t       tag_len,
                                uint8_t       *ciphertext,
                                uint32_t       ciphertext_len)
{
        // Shared symmetric encryption key (DH generated)
        uint8_t *skey     = NULL;
        size_t   skey_len = 0;

        // Decrypted data (plaintext)
        uint8_t *plaintext     = NULL;
        uint8_t  plaintext_len = 0;

        /* Generate the shared symmetric key (receiver). */
        ecies_receiver_generate_symkey(ec_key, peer_pubk, peer_pubk_len,
                                       &skey, &skey_len);
        // ogs_error("skey len value ::::: %zu\n", skey_len);
        if (skey_len != 32)
            return "skey_len";
                // err("Invalid symkey length %lub (expecting 256b)\n",
                //     (skey_len * 8));

        /* Decrypt the data using 256b AES-GCM. */
        aes_gcm_256b_decrypt(ciphertext, ciphertext_len, skey, NULL, 0,
                             iv, iv_len, tag, tag_len,
                             &plaintext, &plaintext_len);

        free(skey);
        return (char*)plaintext;
}



uint8_t *decrypt(char *protectionScheamaId, char *homeNetworkPublicKeyIdentifier, uint8_t *schemeOutput){
    EC_KEY *ec_key = NULL; // EC key from key file

        // Receiver's EC Key (public, private, curve)
        uint8_t *pubk      = NULL;
        size_t   pubk_len  = 0;
        uint8_t *privk     = NULL;
        size_t   privk_len = 0;
        int      curve;

        // Transmitter's ephemeral public EC Key
        size_t   epubk_len = 33;
        uint8_t *epubk     = OPENSSL_malloc(epubk_len);

        // AES-GCM encrypted data (IV, authentication tag, ciphertext)
        uint8_t  iv_len         = 12;
        uint8_t *iv             = OPENSSL_malloc(iv_len);

        uint8_t  tag_len        = 8;
        uint8_t *tag            = OPENSSL_malloc(tag_len);

        uint8_t  ciphertext_len = (strlen(schemeOutput)) / 2 - epubk_len - tag_len - iv_len;
        uint8_t *ciphertext     = OPENSSL_malloc(ciphertext_len);
        int i=0;
        for( i=0;i<epubk_len;i++)
        {
            uint8_t c = (schemeOutput[i * 2] > '9' ? schemeOutput[i*2] - 'a' +10 : schemeOutput[i*2] - '0') * 16  + (schemeOutput[i * 2 + 1] > '9' ? schemeOutput[i*2+1] - 'a' +10 : schemeOutput[i*2+1] - '0') ;
            epubk[i] = c;
            // ogs_error("%c%c     %d      %d", schemeOutput[2*i],schemeOutput[2*i+1], i,epubk[i] );
        }
        for( i=epubk_len;i<epubk_len+ciphertext_len;i++)
        {
            uint8_t c = (schemeOutput[i * 2] > '9' ? schemeOutput[i*2] - 'a' +10 : schemeOutput[i*2] - '0') * 16  + (schemeOutput[i * 2 + 1] > '9' ? schemeOutput[i*2+1] - 'a' +10 : schemeOutput[i*2+1] - '0') ;
            ciphertext[i-epubk_len] = c;
            // ogs_error("%c%c     %zu", schemeOutput[2*i],schemeOutput[2*i+1], i-epubk_len);
        }
        for( i=epubk_len+ciphertext_len;i<epubk_len+ciphertext_len+iv_len;i++)
        {
            uint8_t c = (schemeOutput[i * 2] > '9' ? schemeOutput[i*2] - 'a' +10 : schemeOutput[i*2] - '0') * 16  + (schemeOutput[i * 2 + 1] > '9' ? schemeOutput[i*2+1] - 'a' +10 : schemeOutput[i*2+1] - '0') ;
            iv[i-epubk_len-ciphertext_len] = c;
            // ogs_error("%c%c     %zu", schemeOutput[2*i],schemeOutput[2*i+1], i-epubk_len-ciphertext_len);
        }
        for( i=epubk_len+ciphertext_len+iv_len;i<epubk_len+ciphertext_len+iv_len+tag_len;i++)
        {
            uint8_t c = (schemeOutput[i * 2] > '9' ? schemeOutput[i*2] - 'a' +10 : schemeOutput[i*2] - '0') * 16  + (schemeOutput[i * 2 + 1] > '9' ? schemeOutput[i*2+1] - 'a' +10 : schemeOutput[i*2+1] - '0') ;
            tag[i-epubk_len-ciphertext_len-iv_len] = c;
            // ogs_error("%c%c     %zu", schemeOutput[2*i],schemeOutput[2*i+1], i -epubk_len-ciphertext_len-iv_len);
        }

        /* ECIES Receiver loads the EC key. */
        ecies_receiver_load_key("/home/baadalvm/Testing/ecies/keyout.der", &ec_key, &curve,
                                &pubk, &pubk_len, &privk, &privk_len);
        return ecies_receiver_recv_message(ec_key, epubk, epubk_len,
                                    iv, iv_len, tag, tag_len,
                                    ciphertext, ciphertext_len);

        
}

char *ogs_supi_from_suci(char *suci)
{
#define MAX_SUCI_TOKEN 16
    char *array[MAX_SUCI_TOKEN];
    char *p, *tmp;
    int i;
    char *supi = NULL;

    ogs_assert(suci);
    tmp = ogs_strdup(suci);
    ogs_expect_or_return_val(tmp, NULL);

    p = tmp;
    i = 0;
    while((array[i++] = strsep(&p, "-"))) {
        /* Empty Body */
    }

    SWITCH(array[0])
    CASE("suci")
        SWITCH(array[1])
        CASE("0")   /* SUPI format : IMSI */
            if (array[2] && array[3] && array[7])
                supi = ogs_msprintf("imsi-%s%s%s",
                        array[2], array[3], array[7]);
            // ogs_error("array %d     :   %s", 0, array[0] );
            // ogs_error("array %d     :   %s", 1, array[1] );
            // ogs_error("array %d     :   %s", 2, array[2] );
            // ogs_error("array %d     :   %s", 3, array[3] );
            // ogs_error("array %d     :   %s", 4, array[4] );
            // ogs_error("array %d     :   %s", 5, array[5] );
            // ogs_error("array %d     :   %s", 6, array[6] );
            // ogs_error("array %d     :   %s", 7, array[7] );
            struct timespec start, end;
            struct timespec elapsed;
            clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
            // clock_t elapsed_time = clock();
            char* schemeOutputOriginal = (char*) decrypt(array[5],array[6],(uint8_t*) array[7]);
            // elapsed_time = clock() - elapsed_time;
            // double time_taken = ((double)elapsed_time) / CLOCKS_PER_SEC;
            clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);
            if ((end.tv_nsec-start.tv_nsec)<0) {
                elapsed.tv_sec = end.tv_sec-start.tv_sec-1;
                elapsed.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
            } else {
                elapsed.tv_sec = end.tv_sec-start.tv_sec;
                elapsed.tv_nsec = end.tv_nsec-start.tv_nsec;
            }
            ogs_info("BEYOND 5G SUCI to SUPI decryption time:%f ms",((float)elapsed.tv_sec)*1e3+((float)elapsed.tv_nsec)*1e-6);
            // ogs_error("schemeOutputOriginal :   %s", schemeOutputOriginal );
            // ogs_error("schemeOutputOriginal length :   %zu", strlen(schemeOutputOriginal) );
            // ogs_error("schemeOutputOriginal length :   %d", schemeOutputOriginal[0] );
            supi = ogs_msprintf("imsi-%s%s%s",
                        array[2], array[3], schemeOutputOriginal);
            break;
        DEFAULT
            ogs_error("Not implemented [%s]", array[1]);
            break;
        END
        break;
    DEFAULT
        ogs_error("Not implemented [%s]", array[0]);
        break;
    END

    ogs_free(tmp);
    return supi;
}

char *ogs_supi_from_supi_or_suci(char *supi_or_suci)
{
    char *type = NULL;
    char *supi = NULL;
    ogs_assert(supi_or_suci);
    type = ogs_id_get_type(supi_or_suci);
    if (!type) {
        ogs_error("ogs_id_get_type[%s] failed", supi_or_suci);
        goto cleanup;
    }
    SWITCH(type)
    CASE("imsi")
        supi = ogs_strdup(supi_or_suci);
        ogs_expect(supi);
        break;
    CASE("suci")
        supi = ogs_supi_from_suci(supi_or_suci);
        ogs_expect(supi);
        break;
    DEFAULT
        ogs_error("Not implemented [%s]", type);
        break;
    END

cleanup:
    if (type)
        ogs_free(type);
    return supi;
}

char *ogs_id_get_type(char *str)
{
    char *token, *p, *tmp;
    char *type = NULL;

    ogs_assert(str);
    tmp = ogs_strdup(str);
    if (!tmp) {
        ogs_error("ogs_strdup[%s] failed", str);
        goto cleanup;
    }

    p = tmp;
    token = strsep(&p, "-");
    if (!token) {
        ogs_error("strsep[%s] failed", str);
        goto cleanup;
    }
    type = ogs_strdup(token);
    if (!type) {
        ogs_error("ogs_strdup[%s:%s] failed", str, token);
        goto cleanup;
    }

cleanup:
    if (tmp)
        ogs_free(tmp);
    return type;
}

char *ogs_id_get_value(char *str)
{
    char *token, *p, *tmp;
    char *ueid = NULL;

    ogs_assert(str);
    tmp = ogs_strdup(str);
    if (!tmp) {
        ogs_error("ogs_strdup[%s] failed", str);
        goto cleanup;
    }

    p = tmp;
    token = strsep(&p, "-");
    if (!token) {
        ogs_error("strsep[%s] failed", str);
        goto cleanup;
    }
    token = strsep(&p, "-");
    if (!token) {
        ogs_error("strsep[%s] failed", str);
        goto cleanup;
    }
    ueid = ogs_strdup(token);
    if (!ueid) {
        ogs_error("ogs_strdup[%s:%s] failed", str, token);
        goto cleanup;
    }

cleanup:
    if (tmp)
        ogs_free(tmp);
    return ueid;
}

char *ogs_s_nssai_sd_to_string(ogs_uint24_t sd)
{
    char *string = NULL;

    if (sd.v == OGS_S_NSSAI_NO_SD_VALUE)
        return NULL;

    string = ogs_uint24_to_0string(sd);
    ogs_expect(string);

    return string;
}

ogs_uint24_t ogs_s_nssai_sd_from_string(const char *hex)
{
    ogs_uint24_t sd;

    sd.v = OGS_S_NSSAI_NO_SD_VALUE;
    if (hex == NULL)
        return sd;

    return ogs_uint24_from_string((char *)hex);
}

int ogs_fqdn_build(char *dst, char *src, int length)
{
    int i = 0, j = 0;

    for (i = 0, j = 0; i < length; i++, j++) {
        if (src[i] == '.') {
            dst[i-j] = j;
            j = -1;
        } else {
            dst[i+1] = src[i];
        }
    }
    dst[i-j] = j;

    return length+1;
}

int ogs_fqdn_parse(char *dst, char *src, int length)
{
    int i = 0, j = 0;
    uint8_t len = 0;

    while (i+1 < length) {
        len = src[i++];
        if ((j + len + 1) > length) {
            ogs_error("Invalid FQDN encoding[len:%d] + 1 > length[%d]",
                    len, length);
            ogs_log_hexdump(OGS_LOG_ERROR, (unsigned char *)src, length);
            return 0;
        }
        memcpy(&dst[j], &src[i], len);

        i += len;
        j += len;
        
        if (i+1 < length)
            dst[j++] = '.';
        else
            dst[j] = 0;
    }

    return j;
}

/* 8.13 Protocol Configuration Options (PCO) 
 * 10.5.6.3 Protocol configuration options in 3GPP TS 24.008 */
int ogs_pco_parse(ogs_pco_t *pco, unsigned char *data, int data_len)
{
    ogs_pco_t *source = (ogs_pco_t *)data;
    int size = 0;
    int i = 0;

    ogs_assert(pco);
    ogs_assert(data);
    ogs_assert(data_len);

    memset(pco, 0, sizeof(ogs_pco_t));

    pco->ext = source->ext;
    pco->configuration_protocol = source->configuration_protocol;
    size++;

    while(size < data_len && i < OGS_MAX_NUM_OF_PROTOCOL_OR_CONTAINER_ID) {
        ogs_pco_id_t *id = &pco->ids[i];
        ogs_assert(size + sizeof(id->id) <= data_len);
        memcpy(&id->id, data + size, sizeof(id->id));
        id->id = be16toh(id->id);
        size += sizeof(id->id);

        ogs_assert(size + sizeof(id->len) <= data_len);
        memcpy(&id->len, data + size, sizeof(id->len));
        size += sizeof(id->len);

        id->data = data + size;
        size += id->len;

        i++;
    }
    pco->num_of_id = i;
    ogs_assert(size == data_len);
    
    return size;
}
int ogs_pco_build(unsigned char *data, int data_len, ogs_pco_t *pco)
{
    ogs_pco_t target;
    int size = 0;
    int i = 0;

    ogs_assert(pco);
    ogs_assert(data);
    ogs_assert(data_len);

    memcpy(&target, pco, sizeof(ogs_pco_t));

    ogs_assert(size + 1 <= data_len);
    memcpy(data + size, &target, 1);
    size += 1;

    ogs_assert(target.num_of_id <= OGS_MAX_NUM_OF_PROTOCOL_OR_CONTAINER_ID);
    for (i = 0; i < target.num_of_id; i++) {
        ogs_pco_id_t *id = &target.ids[i];

        ogs_assert(size + sizeof(id->id) <= data_len);
        id->id = htobe16(id->id);
        memcpy(data + size, &id->id, sizeof(id->id));
        size += sizeof(id->id);

        ogs_assert(size + sizeof(id->len) <= data_len);
        memcpy(data + size, &id->len, sizeof(id->len));
        size += sizeof(id->len);

        ogs_assert(size + id->len <= data_len);
        memcpy(data + size, id->data, id->len);
        size += id->len;
    }

    return size;
}

int ogs_ip_to_sockaddr(ogs_ip_t *ip, uint16_t port, ogs_sockaddr_t **list)
{
    ogs_sockaddr_t *addr = NULL, *addr6 = NULL;

    ogs_assert(ip);
    ogs_assert(list);

    addr = ogs_calloc(1, sizeof(ogs_sockaddr_t));
    if (!addr) {
        ogs_error("ogs_calloc() failed");
        return OGS_ERROR;
    }
    addr->ogs_sa_family = AF_INET;
    addr->ogs_sin_port = htobe16(port);

    addr6 = ogs_calloc(1, sizeof(ogs_sockaddr_t));
    if (!addr6) {
        ogs_error("ogs_calloc() failed");
        ogs_free(addr);
        return OGS_ERROR;
    }
    addr6->ogs_sa_family = AF_INET6;
    addr6->ogs_sin_port = htobe16(port);

    if (ip->ipv4 && ip->ipv6) {
        addr->next = addr6;

        addr->sin.sin_addr.s_addr = ip->addr;
        memcpy(addr6->sin6.sin6_addr.s6_addr, ip->addr6, OGS_IPV6_LEN);

        *list = addr;
    } else if (ip->ipv4) {
        addr->sin.sin_addr.s_addr = ip->addr;
        ogs_free(addr6);

        *list = addr;
    } else if (ip->ipv6) {
        memcpy(addr6->sin6.sin6_addr.s6_addr, ip->addr6, OGS_IPV6_LEN);
        ogs_free(addr);

        *list = addr6;
    } else {
        ogs_error("No IPv4 and IPv6");
        ogs_free(addr);
        ogs_free(addr6);
        return OGS_ERROR;
    }

    return OGS_OK;
}

int ogs_sockaddr_to_ip(
        ogs_sockaddr_t *addr, ogs_sockaddr_t *addr6, ogs_ip_t *ip)
{
    ogs_expect_or_return_val(ip, OGS_ERROR);
    ogs_expect_or_return_val(addr || addr6, OGS_ERROR);

    memset(ip, 0, sizeof(ogs_ip_t));

    if (addr && addr6) {
        ip->ipv4 = 1;
        ip->ipv6 = 1;
        ip->len = OGS_IPV4V6_LEN;
        ip->addr = addr->sin.sin_addr.s_addr;
        memcpy(ip->addr6, addr6->sin6.sin6_addr.s6_addr, OGS_IPV6_LEN);
    } else if (addr) {
        ip->ipv4 = 1;
        ip->len = OGS_IPV4_LEN;
        ip->addr = addr->sin.sin_addr.s_addr;
    } else if (addr6) {
        ip->ipv6 = 1;
        ip->len = OGS_IPV6_LEN;
        memcpy(ip->addr6, addr6->sin6.sin6_addr.s6_addr, OGS_IPV6_LEN);
    } else
        ogs_assert_if_reached();

    return OGS_OK;
}

char *ogs_ipv4_to_string(uint32_t addr)
{
    char *buf = NULL;

    buf = ogs_calloc(1, OGS_ADDRSTRLEN);
    ogs_expect_or_return_val(buf, NULL);

    return (char*)OGS_INET_NTOP(&addr, buf);
}

char *ogs_ipv6addr_to_string(uint8_t *addr6)
{
    char *buf = NULL;
    ogs_assert(addr6);

    buf = ogs_calloc(1, OGS_ADDRSTRLEN);
    ogs_expect_or_return_val(buf, NULL);

    return (char *)OGS_INET6_NTOP(addr6, buf);
}

char *ogs_ipv6prefix_to_string(uint8_t *addr6, uint8_t prefixlen)
{
    char *buf = NULL;
    uint8_t tmp[OGS_IPV6_LEN];
    ogs_assert(addr6);

    memset(tmp, 0, OGS_IPV6_LEN);
    memcpy(tmp, addr6, prefixlen >> 3);

    buf = ogs_calloc(1, OGS_ADDRSTRLEN);
    ogs_expect_or_return_val(buf, NULL);

    if (OGS_INET6_NTOP(tmp, buf) == NULL) {
        ogs_fatal("Invalid IPv6 address");
        ogs_log_hexdump(OGS_LOG_FATAL, addr6, OGS_IPV6_LEN);
        ogs_assert_if_reached();
    }
    return ogs_mstrcatf(buf, "/%d", prefixlen);
}

int ogs_ipv4_from_string(uint32_t *addr, char *string)
{
    int rv;
    ogs_sockaddr_t tmp;

    ogs_assert(addr);
    ogs_assert(string);

    rv = ogs_inet_pton(AF_INET, string, &tmp);
    if (rv != OGS_OK) {
        ogs_error("Invalid IPv4 string = %s", string);
        return OGS_ERROR;
    }

    *addr = tmp.sin.sin_addr.s_addr;

    return OGS_OK;
}

int ogs_ipv6addr_from_string(uint8_t *addr6, char *string)
{
    int rv;
    ogs_sockaddr_t tmp;

    ogs_assert(addr6);
    ogs_assert(string);

    rv = ogs_inet_pton(AF_INET6, string, &tmp);
    if (rv != OGS_OK) {
        ogs_error("Invalid IPv6 string = %s", string);
        return OGS_ERROR;
    }

    memcpy(addr6, tmp.sin6.sin6_addr.s6_addr, OGS_IPV6_LEN);

    return OGS_OK;
}

int ogs_ipv6prefix_from_string(uint8_t *addr6, uint8_t *prefixlen, char *string)
{
    int rv;
    ogs_sockaddr_t tmp;
    char *v = NULL, *pv = NULL, *ipstr = NULL, *mask_or_numbits = NULL;

    ogs_assert(addr6);
    ogs_assert(prefixlen);
    ogs_assert(string);
    pv = v = ogs_strdup(string);
    ogs_expect_or_return_val(v, OGS_ERROR);

    ipstr = strsep(&v, "/");
    if (ipstr)
        mask_or_numbits = v;

    if (!ipstr || !mask_or_numbits) {
        ogs_error("Invalid IPv6 Prefix string = %s", v);
        ogs_free(v);
        return OGS_ERROR;
    }

    rv = ogs_inet_pton(AF_INET6, ipstr, &tmp);
    ogs_expect_or_return_val(rv == OGS_OK, rv);

    memcpy(addr6, tmp.sin6.sin6_addr.s6_addr, OGS_IPV6_LEN);
    *prefixlen = atoi(mask_or_numbits);

    ogs_free(pv);
    return OGS_OK;
}

int ogs_sockaddr_to_user_plane_ip_resource_info(
    ogs_sockaddr_t *addr, ogs_sockaddr_t *addr6,
    ogs_user_plane_ip_resource_info_t *info)
{
    ogs_assert(addr || addr6);
    ogs_assert(info);

    if (addr) {
        info->v4 = 1;
        info->addr = addr->sin.sin_addr.s_addr;
    }
    if (addr6) {
        info->v6 = 1;
        memcpy(info->addr6, addr6->sin6.sin6_addr.s6_addr, OGS_IPV6_LEN);
    }

    return OGS_OK;
}

int ogs_user_plane_ip_resource_info_to_sockaddr(
    ogs_user_plane_ip_resource_info_t *info,
    ogs_sockaddr_t **addr, ogs_sockaddr_t **addr6)
{
    ogs_assert(addr && addr6);
    ogs_assert(info);

    *addr = NULL;
    *addr6 = NULL;

    if (info->v4) {
        *addr = ogs_calloc(1, sizeof(**addr));
        ogs_assert(*addr);
        (*addr)->sin.sin_addr.s_addr = info->addr;
        (*addr)->ogs_sa_family = AF_INET;
    }

    if (info->v6) {
        *addr6 = ogs_calloc(1, sizeof(**addr6));
        ogs_assert(*addr6);
        memcpy((*addr6)->sin6.sin6_addr.s6_addr, info->addr6, OGS_IPV6_LEN);
        (*addr6)->ogs_sa_family = AF_INET6;
    }

    return OGS_OK;
}

ogs_slice_data_t *ogs_slice_find_by_s_nssai(
        ogs_slice_data_t *slice_data, int num_of_slice_data,
        ogs_s_nssai_t *s_nssai)
{
    int i;

    ogs_assert(slice_data);
    ogs_assert(num_of_slice_data);
    ogs_assert(s_nssai);

    /* Compare S-NSSAI */
    for (i = 0; i < num_of_slice_data; i++) {
        if (s_nssai->sst == slice_data[i].s_nssai.sst &&
                s_nssai->sd.v == slice_data[i].s_nssai.sd.v) {
            return slice_data + i;
        }
    }

    return NULL;
}

void ogs_subscription_data_free(ogs_subscription_data_t *subscription_data)
{
    int i, j;

    ogs_assert(subscription_data);

    for (i = 0; i < subscription_data->num_of_slice; i++) {
        ogs_slice_data_t *slice_data = &subscription_data->slice[i];

        for (j = 0; j < slice_data->num_of_session; j++) {
            if (slice_data->session[j].name)
                ogs_free(slice_data->session[j].name);
        }

        slice_data->num_of_session = 0;
    }

    subscription_data->num_of_slice = 0;

    subscription_data->num_of_msisdn = 0;
}

void ogs_session_data_free(ogs_session_data_t *session_data)
{
    int i;

    ogs_assert(session_data);

    if (session_data->session.name)
        ogs_free(session_data->session.name);

    for (i = 0; i < session_data->num_of_pcc_rule; i++)
        OGS_PCC_RULE_FREE(&session_data->pcc_rule[i]);
}

void ogs_ims_data_free(ogs_ims_data_t *ims_data)
{
    int i, j, k;

    ogs_assert(ims_data);

    for (i = 0; i < ims_data->num_of_media_component; i++) {
        ogs_media_component_t *media_component = &ims_data->media_component[i];

        for (j = 0; j < media_component->num_of_sub; j++) {
            ogs_media_sub_component_t *sub = &media_component->sub[j];

            for (k = 0; k < sub->num_of_flow; k++) {
                ogs_flow_t *flow = &sub->flow[k];

                if (flow->description) {
                    ogs_free(flow->description);
                } else
                    ogs_assert_if_reached();
            }
        }
    }
}

static int flow_rx_to_gx(ogs_flow_t *rx_flow, ogs_flow_t *gx_flow)
{
    int len;
    char *from_str, *to_str;

    ogs_assert(rx_flow);
    ogs_assert(gx_flow);

    if (!strncmp(rx_flow->description,
                "permit out", strlen("permit out"))) {
        gx_flow->direction = OGS_FLOW_DOWNLINK_ONLY;
        gx_flow->description = ogs_strdup(rx_flow->description);
        ogs_assert(gx_flow->description);

    } else if (!strncmp(rx_flow->description,
                "permit in", strlen("permit in"))) {
        gx_flow->direction = OGS_FLOW_UPLINK_ONLY;

        /* 'permit in' should be changed
         * 'permit out' in Gx Diameter */
        len = strlen(rx_flow->description)+2;
        gx_flow->description = ogs_calloc(1, len);
        ogs_assert(gx_flow->description);
        strcpy(gx_flow->description, "permit out");
        from_str = strstr(&rx_flow->description[strlen("permit in")], "from");
        ogs_assert(from_str);
        to_str = strstr(&rx_flow->description[strlen("permit in")], "to");
        ogs_assert(to_str);
        strncat(gx_flow->description,
            &rx_flow->description[strlen("permit in")],
            strlen(rx_flow->description) -
                strlen("permit in") - strlen(from_str));
        strcat(gx_flow->description, "from");
        strcat(gx_flow->description, &to_str[strlen("to")]);
        strcat(gx_flow->description, " to");
        strncat(gx_flow->description, &from_str[strlen("from")],
                strlen(from_str) - strlen(to_str) - strlen("from") - 1);
        ogs_assert(len == strlen(gx_flow->description)+1);
    } else {
        ogs_error("Invalid Flow Descripton : [%s]", rx_flow->description);
        return OGS_ERROR;
    }

    return OGS_OK;
}

int ogs_pcc_rule_num_of_flow_equal_to_media(
        ogs_pcc_rule_t *pcc_rule, ogs_media_component_t *media_component)
{
    int rv;
    int i, j, k;
    int matched = 0;
    int new = 0;

    ogs_assert(pcc_rule);
    ogs_assert(media_component);

    for (i = 0; i < media_component->num_of_sub; i++) {
        ogs_media_sub_component_t *sub = &media_component->sub[i];

        for (j = 0; j < sub->num_of_flow; j++) {
            new++;
        }
    }

    if (new == 0) {
        /* No new flow in Media-Component */
        return pcc_rule->num_of_flow;
    }

    for (i = 0; i < media_component->num_of_sub; i++) {
        ogs_media_sub_component_t *sub = &media_component->sub[i];

        for (j = 0; j < sub->num_of_flow &&
                    j < OGS_MAX_NUM_OF_FLOW_IN_MEDIA_SUB_COMPONENT; j++) {
            ogs_flow_t gx_flow;
            ogs_flow_t *rx_flow = &sub->flow[j];

            rv = flow_rx_to_gx(rx_flow, &gx_flow);
            if (rv != OGS_OK) {
                ogs_error("flow reformatting error");
                return OGS_ERROR;
            }

            for (k = 0; k < pcc_rule->num_of_flow; k++) {
                if (gx_flow.direction == pcc_rule->flow[k].direction &&
                    !strcmp(gx_flow.description,
                        pcc_rule->flow[k].description)) {
                    matched++;
                    break;
                }
            }

            OGS_FLOW_FREE(&gx_flow);
        }
    }

    return matched;
}

int ogs_pcc_rule_install_flow_from_media(
        ogs_pcc_rule_t *pcc_rule, ogs_media_component_t *media_component)
{
    int rv;
    int i, j;

    ogs_assert(pcc_rule);
    ogs_assert(media_component);

    /* Remove Flow from PCC Rule */
    for (i = 0; i < pcc_rule->num_of_flow; i++) {
        OGS_FLOW_FREE(&pcc_rule->flow[i]);
    }
    pcc_rule->num_of_flow = 0;

    for (i = 0; i < media_component->num_of_sub; i++) {
        ogs_media_sub_component_t *sub = &media_component->sub[i];

        /* Copy Flow to PCC Rule */
        for (j = 0; j < sub->num_of_flow &&
                    j < OGS_MAX_NUM_OF_FLOW_IN_MEDIA_SUB_COMPONENT; j++) {
            ogs_flow_t *rx_flow = NULL;
            ogs_flow_t *gx_flow = NULL;

            if (pcc_rule->num_of_flow < OGS_MAX_NUM_OF_FLOW_IN_PCC_RULE) {
                rx_flow = &sub->flow[j];
                gx_flow = &pcc_rule->flow[pcc_rule->num_of_flow];

                rv = flow_rx_to_gx(rx_flow, gx_flow);
                if (rv != OGS_OK) {
                    ogs_error("flow reformatting error");
                    return OGS_ERROR;
                }

                pcc_rule->num_of_flow++;
            } else {
                ogs_error("Overflow: Number of Flow");
                return OGS_ERROR;
            }
        }
    }

    return OGS_OK;
}

int ogs_pcc_rule_update_qos_from_media(
        ogs_pcc_rule_t *pcc_rule, ogs_media_component_t *media_component)
{
    int rv;
    int i, j;

    ogs_assert(pcc_rule);
    ogs_assert(media_component);

    pcc_rule->qos.mbr.downlink = 0;
    pcc_rule->qos.mbr.uplink = 0;
    pcc_rule->qos.gbr.downlink = 0;
    pcc_rule->qos.gbr.uplink = 0;

    for (i = 0; i < media_component->num_of_sub; i++) {
        ogs_media_sub_component_t *sub = &media_component->sub[i];

        for (j = 0; j < sub->num_of_flow &&
                    j < OGS_MAX_NUM_OF_FLOW_IN_MEDIA_SUB_COMPONENT; j++) {
            ogs_flow_t gx_flow;
            ogs_flow_t *rx_flow = &sub->flow[j];

            rv = flow_rx_to_gx(rx_flow, &gx_flow);
            if (rv != OGS_OK) {
                ogs_error("flow reformatting error");
                return OGS_ERROR;
            }

            if (gx_flow.direction == OGS_FLOW_DOWNLINK_ONLY) {
                if (sub->flow_usage == OGS_FLOW_USAGE_RTCP) {
                    if (media_component->rr_bandwidth &&
                        media_component->rs_bandwidth) {
                        pcc_rule->qos.mbr.downlink +=
                            (media_component->rr_bandwidth +
                            media_component->rs_bandwidth);
                    } else if (media_component->max_requested_bandwidth_dl) {
                        if (media_component->rr_bandwidth &&
                            !media_component->rs_bandwidth) {
                            pcc_rule->qos.mbr.downlink +=
                                ogs_max(0.05 *
                                    media_component->max_requested_bandwidth_dl,
                                    media_component->rr_bandwidth);
                        }
                        if (!media_component->rr_bandwidth &&
                            media_component->rs_bandwidth) {
                            pcc_rule->qos.mbr.downlink +=
                                ogs_max(0.05 *
                                    media_component->max_requested_bandwidth_dl,
                                    media_component->rs_bandwidth);
                        }
                        if (!media_component->rr_bandwidth &&
                            !media_component->rs_bandwidth) {
                            pcc_rule->qos.mbr.downlink +=
                                0.05 *
                                    media_component->max_requested_bandwidth_dl;
                        }
                    }
                } else {
                    if (gx_flow.description) {
                        pcc_rule->qos.mbr.downlink +=
                            media_component->max_requested_bandwidth_dl;
                        pcc_rule->qos.gbr.downlink +=
                            media_component->min_requested_bandwidth_dl;
                    }
                }
            } else if (gx_flow.direction == OGS_FLOW_UPLINK_ONLY) {
                if (sub->flow_usage == OGS_FLOW_USAGE_RTCP) {
                    if (media_component->rr_bandwidth &&
                        media_component->rs_bandwidth) {
                        pcc_rule->qos.mbr.uplink +=
                            (media_component->rr_bandwidth +
                            media_component->rs_bandwidth);
                    } else if (media_component->max_requested_bandwidth_ul) {
                        if (media_component->rr_bandwidth &&
                            !media_component->rs_bandwidth) {
                            pcc_rule->qos.mbr.uplink +=
                                ogs_max(0.05 *
                                    media_component->max_requested_bandwidth_ul,
                                    media_component->rr_bandwidth);
                        }
                        if (!media_component->rr_bandwidth &&
                            media_component->rs_bandwidth) {
                            pcc_rule->qos.mbr.uplink +=
                                ogs_max(0.05 *
                                    media_component->max_requested_bandwidth_ul,
                                    media_component->rs_bandwidth);
                        }
                        if (!media_component->rr_bandwidth &&
                            !media_component->rs_bandwidth) {
                            pcc_rule->qos.mbr.uplink +=
                                0.05 *
                                    media_component->max_requested_bandwidth_ul;
                        }
                    }
                } else {
                    if (gx_flow.description) {
                        pcc_rule->qos.mbr.uplink +=
                            media_component->max_requested_bandwidth_ul;
                        pcc_rule->qos.gbr.uplink +=
                            media_component->min_requested_bandwidth_ul;
                    }
                }
            } else
                ogs_assert_if_reached();

            OGS_FLOW_FREE(&gx_flow);
        }
    }

    if (pcc_rule->qos.mbr.downlink == 0) {
        pcc_rule->qos.mbr.downlink +=
            media_component->max_requested_bandwidth_dl;
        pcc_rule->qos.mbr.downlink +=
            (media_component->rr_bandwidth + media_component->rs_bandwidth);
    }

    if (pcc_rule->qos.mbr.uplink == 0) {
        pcc_rule->qos.mbr.uplink +=
            media_component->max_requested_bandwidth_ul;
        pcc_rule->qos.mbr.uplink +=
            (media_component->rr_bandwidth + media_component->rs_bandwidth);
    }

    if (pcc_rule->qos.gbr.downlink == 0)
        pcc_rule->qos.gbr.downlink = pcc_rule->qos.mbr.downlink;
    if (pcc_rule->qos.gbr.uplink == 0)
        pcc_rule->qos.gbr.uplink = pcc_rule->qos.mbr.uplink;

    return OGS_OK;
}
