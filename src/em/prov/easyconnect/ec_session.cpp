/**
 * Copyright 2025 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include "ec_base.h"
#include "ec_session.h"
#include "ec_util.h"
#include "em_crypto.h"
#include "em.h"
#include "aes_siv.h"

std::pair<uint8_t*, uint16_t> ec_session_t::create_auth_request()
{

    ec_dpp_capabilities_t caps = {{
        .enrollee = 0,
        .configurator = 1
    }};

    printf("%s:%d Enter\n", __func__, __LINE__);

    uint8_t* buff = (uint8_t*) calloc(EC_FRAME_BASE_SIZE, 1);

    ec_frame_t    *frame = (ec_frame_t *)buff;
    frame->frame_type = ec_frame_type_auth_req;

    if (init_session(NULL) != 0) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d Failed to initialize session parameters\n", __func__, __LINE__);
        return std::make_pair<uint8_t*, uint16_t>(NULL, 0);
    }

    if (compute_intermediate_key(true) != 0) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d failed to generate key\n", __func__, __LINE__);
        return std::make_pair<uint8_t*, uint16_t>(NULL, 0);
    }

    uint8_t* attribs = NULL;
    uint16_t attrib_len = 0;

    // Performs a SHA-256 hash on the DER-encoded ASN.1 SubjectPublicKeyInfo and stored in `m_params.responder_keyhash`
    if (compute_key_hash(m_data.responder_boot_key, m_params.responder_keyhash) < 1) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        return std::make_pair<uint8_t*, uint16_t>(NULL, 0);
    }

    attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_resp_bootstrap_key_hash, SHA256_DIGEST_LENGTH, m_params.responder_keyhash);

    // Initiator (Config/PA) Bootstrapping Key Hash
    // TODO: Store key locally, revisit the specifics
    if (compute_key_hash(m_data.initiator_boot_key, m_params.initiator_keyhash) < 1) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        return std::make_pair<uint8_t*, uint16_t>(NULL, 0);
    }

    attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_init_bootstrap_key_hash, SHA256_DIGEST_LENGTH, m_params.initiator_keyhash);

    // Initiator Protocol Key
    uint8_t protocol_key_buff[1024];
    BN_bn2bin((const BIGNUM *)m_params.x,
            &protocol_key_buff[BN_num_bytes(m_params.prime) - BN_num_bytes(m_params.x)]);
    BN_bn2bin((const BIGNUM *)m_params.y,
            &protocol_key_buff[2*BN_num_bytes(m_params.prime) - BN_num_bytes(m_params.x)]);

    // Initiator Protocol Key (P_I)
    attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_init_proto_key, 2*BN_num_bytes(m_params.prime), protocol_key_buff);

    // Protocol Version
    if (m_cfgrtr_ver > 1) {
        attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_proto_version, m_cfgrtr_ver);
    }

    // Channel Attribute (optional)
    //TODO: REVISIT THIS
    /*
If the Initiator prefers to use a different channel for going
through the rest of the DPP Authentication and DPP Configuration exchanges to avoid off channel operations (for
example, when operating as an AP), the Initiator adds the optional Channel attribute to the message.
    */
    if (m_data.ec_freqs[0] != 0){
        int base_freq = m_data.ec_freqs[0]; 
        uint16_t chann_attr = ec_util::freq_to_channel_attr(base_freq);
        attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_channel, sizeof(uint16_t), (uint8_t *)&chann_attr);
    }


    // Wrapped Data (with Initiator Nonce and Initiator Capabilities)
    // EasyMesh 8.2.2 Table 36
    attribs = add_wrapped_data_attr(frame, attribs, &attrib_len, true, m_params.k1, [&](){
        uint8_t* wrap_attribs = NULL;
        uint16_t wrapped_len = 0;
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_init_nonce, m_params.noncelen, m_params.initiator_nonce);
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_init_caps, caps.byte);
        return std::make_pair(wrap_attribs, wrapped_len);
    });

    if (!(frame = ec_util::copy_attrs_to_frame(frame, attribs, attrib_len))) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d unable to copy attributes to frame\n", __func__, __LINE__);
        free(attribs);
        return std::make_pair<uint8_t*, uint16_t>(NULL, 0);
    }

    free(attribs);

    return std::make_pair((uint8_t*)frame, EC_FRAME_BASE_SIZE + attrib_len);

}

std::pair<uint8_t *, uint16_t> ec_session_t::create_auth_resp(ec_status_code_t dpp_status)
{

    uint8_t* buff = (uint8_t*) calloc(EC_FRAME_BASE_SIZE, 1);

    ec_frame_t    *frame = (ec_frame_t *)buff;
    frame->frame_type = ec_frame_type_auth_rsp; 

    uint8_t* attribs = NULL;
    uint16_t attrib_len = 0;



   if (dpp_status == DPP_STATUS_NOT_COMPATIBLE) {

    attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_dpp_status, (uint8_t)dpp_status);
    attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_resp_bootstrap_key_hash, sizeof(m_params.responder_keyhash), m_params.responder_keyhash);
    // Conditional (Only included for mutual authentication)
    if (m_params.mutual) {
        attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_init_bootstrap_key_hash, sizeof(m_params.initiator_keyhash), m_params.initiator_keyhash);
    }
    if (m_data.version > 1) {
        attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_proto_version, (uint8_t)m_data.version);
    }

    attribs = add_wrapped_data_attr(frame, attribs, &attrib_len, true, m_params.k1, [&](){
        uint8_t* wrap_attribs = NULL;
        uint16_t wrapped_len = 0;

        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_init_nonce, m_params.noncelen, m_params.initiator_nonce);
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_resp_caps, sizeof(m_data.ec_caps), (uint8_t*)&m_data.ec_caps);

        return std::make_pair(wrap_attribs, wrapped_len);
    });
    } else {
        RAND_bytes(m_params.responder_nonce, m_params.noncelen);
        

    }




    if (!(frame = ec_util::copy_attrs_to_frame(frame, attribs, attrib_len))) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d unable to copy attributes to frame\n", __func__, __LINE__);
        free(attribs);
        return std::make_pair<uint8_t*, uint16_t>(NULL, 0);
    }
    free(attribs);

    return std::make_pair((uint8_t*)frame, EC_FRAME_BASE_SIZE + attrib_len);
}

int ec_session_t::create_pres_ann(uint8_t *buff)
{

    ec_frame_t *frame = (ec_frame_t *)buff;
    frame->frame_type = ec_frame_type_presence_announcement; 

    // Compute the hash of the responder boot key 
    uint8_t resp_boot_key_chirp_hash[SHA512_DIGEST_LENGTH];
    if (compute_key_hash(m_data.responder_boot_key, resp_boot_key_chirp_hash, "chirp") < 1) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d unable to compute \"chirp\" responder bootstrapping key hash\n", __func__, __LINE__);
        return -1;
    }

    uint8_t* attribs = frame->attributes;
    uint16_t attrib_len = 0;

    attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_resp_bootstrap_key_hash, SHA256_DIGEST_LENGTH, resp_boot_key_chirp_hash);

    return attrib_len;
}

std::pair<uint8_t *, uint16_t> ec_session_t::create_recfg_auth_req()
{

    uint8_t* buff = (uint8_t*) calloc(EC_FRAME_BASE_SIZE, 1);

    ec_frame_t    *frame = (ec_frame_t *)buff;
    frame->frame_type = ec_frame_type_presence_announcement; 

    // Compute the hash of the responder boot key 
    uint8_t resp_boot_key_chirp_hash[SHA512_DIGEST_LENGTH];
    if (compute_key_hash(m_data.responder_boot_key, resp_boot_key_chirp_hash, "chirp") < 1) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d unable to compute \"chirp\" responder bootstrapping key hash\n", __func__, __LINE__);
        return std::make_pair<uint8_t*, uint16_t>(NULL, 0);
    }

    uint8_t* attribs = NULL;
    uint16_t attrib_len = 0;

    // TODO: Add the transaction ID, connector
    uint8_t trans_id = 0;
    char json_connector[] = "connector";

    attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_trans_id, trans_id);
    attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_proto_version, (uint8_t)m_data.version);
    attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_dpp_connector, strlen(json_connector), (uint8_t*)json_connector);
    attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_config_nonce, m_params.noncelen, m_params.responder_nonce); //TODO: Revisit this


    if (!(frame = ec_util::copy_attrs_to_frame(frame, attribs, attrib_len))) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d unable to copy attributes to frame\n", __func__, __LINE__);
        free(attribs);
        return std::make_pair<uint8_t*, uint16_t>(NULL, 0);
    }
    free(attribs);

    return std::make_pair((uint8_t*)frame, EC_FRAME_BASE_SIZE + attrib_len);
}

std::pair<uint8_t *, uint16_t> ec_session_t::create_auth_cnf()
{

    uint8_t* buff = (uint8_t*) calloc(EC_FRAME_BASE_SIZE, 1);

    ec_frame_t    *frame = (ec_frame_t *)buff;
    frame->frame_type = ec_frame_type_auth_cnf; 

    uint8_t* attribs = NULL;
    uint16_t attrib_len = 0;

    // TODO: Move DPP status outside
    ec_status_code_t dpp_status = DPP_STATUS_OK; // TODO

    uint8_t* key = (dpp_status == DPP_STATUS_OK ? m_params.k2 : m_params.ke);

    attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_dpp_status, (uint8_t)dpp_status);
    attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_resp_bootstrap_key_hash, sizeof(m_params.responder_keyhash), m_params.responder_keyhash);
    // Conditional (Only included for mutual authentication)
    if (m_params.mutual) {
        attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_init_bootstrap_key_hash, sizeof(m_params.initiator_keyhash), m_params.initiator_keyhash);
    }

    attribs = add_wrapped_data_attr(frame, attribs, &attrib_len, true, key, [&](){
        uint8_t* wrap_attribs = NULL;
        uint16_t wrapped_len = 0;
        if (dpp_status == DPP_STATUS_OK) {
            wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_init_auth_tag, sizeof(m_params.iauth), m_params.iauth);
        } else {
            wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_resp_nonce, m_params.noncelen, m_params.responder_nonce);
        }
        return std::make_pair(wrap_attribs, wrapped_len);
    });

    if (!(frame = ec_util::copy_attrs_to_frame(frame, attribs, attrib_len))) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d unable to copy attributes to frame\n", __func__, __LINE__);
        free(attribs);
        return std::make_pair<uint8_t*, uint16_t>(NULL, 0);
    }
    free(attribs);

    return std::make_pair((uint8_t*)frame, EC_FRAME_BASE_SIZE + attrib_len);
}

std::pair<uint8_t *, uint16_t> ec_session_t::create_recfg_auth_cnf()
{

    uint8_t* buff = (uint8_t*) calloc(EC_FRAME_BASE_SIZE, 1);

    ec_frame_t    *frame = (ec_frame_t *)buff;
    frame->frame_type = ec_frame_type_auth_cnf; 

    uint8_t* attribs = NULL;
    uint16_t attrib_len = 0;

    // TODO: Move DPP status outside
    ec_status_code_t dpp_status = DPP_STATUS_OK; // TODO

    // TODO: Add transaction ID outside this function
    uint8_t trans_id = 0;
    ec_dpp_reconfig_flags_t reconfig_flags = {
        .connector_key = 1, // DONT REUSE
    };

    attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_dpp_status, (uint8_t)dpp_status);

    attribs = add_wrapped_data_attr(frame, attribs, &attrib_len, false, m_params.ke, [&](){
        uint8_t* wrap_attribs = NULL;
        uint16_t wrapped_len = 0;

        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_trans_id, trans_id);
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_proto_version, (uint8_t)m_data.version);
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_config_nonce, m_params.noncelen, m_params.initiator_nonce);
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_enrollee_nonce, m_params.noncelen, m_params.enrollee_nonce);
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_reconfig_flags, sizeof(reconfig_flags), (uint8_t*)&reconfig_flags);

        return std::make_pair(wrap_attribs, wrapped_len);
    });

    if (!(frame = ec_util::copy_attrs_to_frame(frame, attribs, attrib_len))) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d unable to copy attributes to frame\n", __func__, __LINE__);
        free(attribs);
        return std::make_pair<uint8_t*, uint16_t>(NULL, 0);
    }
    free(attribs);

    return std::make_pair((uint8_t*)frame, EC_FRAME_BASE_SIZE + attrib_len);
}


/**
 * Called by 802.11 handler, this means that this _should_ only happen inside the **proxy agent**
 */
int ec_session_t::handle_pres_ann(uint8_t *buff, unsigned int len)
{
    ec_frame_t *frame = (ec_frame_t *)buff;

    ec_attribute_t *attrib = ec_util::get_attrib(frame->attributes, len-EC_FRAME_BASE_SIZE, ec_attrib_id_resp_bootstrap_key_hash);
    if (!attrib) {
        return -1;
    }

    // TODO: Come back to this
    memcpy(m_params.responder_keyhash, attrib->data, attrib->length);

    // Call function to handle the presence announcement for hash. 
    // If EasyConnect base, function will just create authentication request and send it
    // If EasyMesh base, function will send chirp notification to the controller

    return 0;	
}

/**
 *  Called by 802.11 handler. This mean sthat this _should_ only happen inside the **enrollee agent**.
 */
int ec_session_t::handle_auth_req(uint8_t *buff, unsigned int len)
{
    ec_frame_t *frame = (ec_frame_t *)buff;

    size_t attrs_len = len - EC_FRAME_BASE_SIZE;

    ec_attribute_t *B_r_hash_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_resp_bootstrap_key_hash);
    if (!B_r_hash_attr) return -1;

    if (memcmp(B_r_hash_attr->data, m_params.responder_keyhash, B_r_hash_attr->length) != 0) {
        printf("%s:%d Responder key hash mismatch\n", __func__, __LINE__);
        return -1;
    }

    ec_attribute_t *B_i_hash_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_init_bootstrap_key_hash);
    if (!B_i_hash_attr) return -1;

    if (memcmp(B_i_hash_attr->data, m_params.initiator_keyhash, B_i_hash_attr->length) == 0) {
        printf("%s:%d Initiator key hash matched, mutual authentication can now occur\n", __func__, __LINE__);
        // Mutual authentication can now occur
        m_params.mutual = true;
        // TODO: UNKNOWN:
        /*
        Specifically, the Responder shall request mutual authentication when the hash of the Responder
    bootstrapping key in the authentication request indexes an entry in the bootstrapping table corresponding to a
    bidirectional bootstrapping method, for example, PKEX or BTLE.
        */
    }




   ec_attribute_t *channel_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_channel);
    if (channel_attr && channel_attr->length == sizeof(uint16_t)) {
        /*
        the Responder determines whether it can use the requested channel for the
following exchanges. If so, it sends the DPP Authentication Response frame on that channel. If not, it discards the DPP
Authentication Request frame without replying to it.
        */
        uint16_t op_chan = *(uint16_t*)channel_attr->data;
        printf("%s:%d Channel attribute: %d\n", __func__, __LINE__, op_chan);

        uint8_t op_class = (uint8_t)(op_chan >> 8);
        uint8_t channel = (uint8_t)(op_chan & 0x00ff);
        printf("%s:%d op_class: %d channel %d\n", __func__, __LINE__, op_class, channel);
        //TODO: Check One-Wifi for channel selection if possible
        // Maybe just attempt to send it on the channel
    }

    if (compute_intermediate_key(true) != 0) {
        printf("%s:%d failed to generate k1 to attempt unwrap\n", __func__, __LINE__);
        return -1;
    }

    ec_attribute_t *wrapped_data_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_wrapped_data);
    if (!wrapped_data_attr) {
        printf("%s:%d No wrapped data attribute found\n", __func__, __LINE__);
        return -1;
    }
    auto [wrapped_data, wrapped_len] = unwrap_wrapped_attrib(wrapped_data_attr, frame, false, m_params.k1); 
    if (wrapped_data == NULL || wrapped_len == 0) {
        printf("%s:%d failed to unwrap wrapped data\n", __func__, __LINE__);
        return -1;
    }

    ec_attribute_t *init_caps_attr = ec_util::get_attrib(wrapped_data, wrapped_len, ec_attrib_id_init_caps);
    if (!init_caps_attr) {
        printf("%s:%d No initiator capabilities attribute found\n", __func__, __LINE__);
        return -1;
    }
    ec_dpp_capabilities_t init_caps = {
        .byte = init_caps_attr->data[0]
    };

    if (!check_supports_init_caps(init_caps)) {
        printf("%s:%d Initiator capabilities not supported\n", __func__, __LINE__);

        auto [resp_frame, resp_len] = create_auth_resp(DPP_STATUS_NOT_COMPATIBLE);
        if (resp_frame == NULL || resp_len == 0) {
            printf("%s:%d failed to create response frame\n", __func__, __LINE__);
            return -1;
        }
/*
it shall respond with a DPP Authentication
Response frame indicating failure by adding the DPP Status field set to STATUS_NOT_COMPATIBLE, a hash of its
public bootstrapping key, a hash of the Initiator’s public bootstrapping key if it is doing mutual authentication, Protocol
Version attribute if it was sent in the DPP Authentication Request frame and is version 2 or higher, and Wrapped Data
element consisting of the Initiator’s nonce and the Responder’s desired capabilities wrapped with k1:
*/
        return -1;
    }

    //TODO/NOTE: Unknown: If need more time to process, respond `STATUS_RESPONSE_PENDING` (EasyConnect 6.3.3)
    // If the Responder needs more time to respond, e.g., to complete bootstrapping of the Initiator’s bootstrapping key

    //The Responder first selects capabilities that support the Initiator—for example,
    //  if the Initiator states it is a Configurator, then the Responder takes on the Enrollee role.
    auto [resp_frame, resp_len] = create_auth_resp(DPP_STATUS_OK);
    if (resp_frame == NULL || resp_len == 0) {
        printf("%s:%d failed to create response frame\n", __func__, __LINE__);
        return -1;
    }
    // TODO: Send the response frame

    return 0;	
}



int ec_session_t::init_session(ec_data_t* ec_data)
{
    const EC_POINT *init_pub_key, *resp_pub_key = NULL;
    const BIGNUM *proto_priv;

    if (ec_data != NULL) {
        memset(&m_data, 0, sizeof(ec_data_t));
        memcpy(&m_data, ec_data, sizeof(ec_data_t));
    }

    if (m_data.type == ec_session_type_cfg) {
        // Set in DPP URI 

        resp_pub_key = EC_KEY_get0_public_key(m_data.responder_boot_key);
        if (resp_pub_key == NULL) {
            printf("%s:%d Could not get responder bootstrap public key\n", __func__, __LINE__);
            return -1;
        }
        m_params.group = EC_KEY_get0_group(m_data.responder_boot_key);

    } else if (m_data.type == ec_session_type_recfg) {

        m_params.group = EC_KEY_get0_group(m_data.initiator_boot_key);
        m_params.responder_connector = EC_POINT_new(m_params.group);
    }


    m_params.x = BN_new();
    m_params.y = BN_new();
    m_params.m = BN_new();
    m_params.n = BN_new();
    m_params.prime = BN_new();
    m_params.bnctx = BN_CTX_new();

    if (!m_params.x || !m_params.y || !m_params.m || !m_params.n || 
        !m_params.prime || !m_params.bnctx) {
        printf("%s:%d Some BN NULL\n", __func__, __LINE__);
        BN_free(m_params.x);
        BN_free(m_params.y);
        BN_free(m_params.m);
        BN_free(m_params.n);
        BN_free(m_params.prime);
        BN_CTX_free(m_params.bnctx);
        return -1;
    }

    m_params.responder_proto_pt = EC_POINT_new(m_params.group);
    m_params.nid = EC_GROUP_get_curve_name(m_params.group);

    //printf("%s:%d nid: %d\n", __func__, __LINE__, m_params.nid);
    switch (m_params.nid) {
        case NID_X9_62_prime256v1:
            m_params.group_num = 19;
            m_params.digestlen = 32;
            m_params.hashfcn = EVP_sha256();
            break;
        case NID_secp384r1:
            m_params.group_num = 20;
            m_params.digestlen = 48;
            m_params.hashfcn = EVP_sha384();
            break;
        case NID_secp521r1:
            m_params.group_num = 21;
            m_params.digestlen = 64;
            m_params.hashfcn = EVP_sha512();
            break;
        case NID_X9_62_prime192v1:
            m_params.group_num = 25;
            m_params.digestlen = 32;
            m_params.hashfcn = EVP_sha256();
            break;
        case NID_secp224r1:
            m_params.group_num = 26;
            m_params.digestlen = 32;
            m_params.hashfcn = EVP_sha256();
            break;
        default:
            printf("%s:%d nid:%d not handled\n", __func__, __LINE__, m_params.nid);
            return -1;
    }

    m_params.noncelen = m_params.digestlen/2;

    //printf("%s:%d group_num:%d digestlen:%d\n", __func__, __LINE__, m_params.group_num, m_params.digestlen);
    if (m_params.initiator_proto_key != NULL){
        EC_KEY_free(m_params.initiator_proto_key);
        m_params.initiator_proto_key = NULL;
    }
    m_params.initiator_proto_key = EC_KEY_new_by_curve_name(m_params.nid);
    if (m_params.initiator_proto_key == NULL) {
        printf("%s:%d Could not create protocol key\n", __func__, __LINE__);
        return -1;
    }

    if (EC_KEY_generate_key(m_params.initiator_proto_key) == 0) {
        printf("%s:%d Could not generate protocol key\n", __func__, __LINE__);
        return -1;
    }

    init_pub_key = EC_KEY_get0_public_key(m_params.initiator_proto_key);
    if (init_pub_key == NULL) {
        printf("%s:%d Could not get initiator protocol public key\n", __func__, __LINE__);
        return -1;
    }

    proto_priv = EC_KEY_get0_private_key(m_params.initiator_proto_key);
    if (proto_priv == NULL) {
        printf("%s:%d Could not get initiator protocol private key\n", __func__, __LINE__);
        return -1;
    }

    if ((m_params.N = EC_POINT_new(m_params.group)) == NULL) {
        printf("%s:%d unable to create bignums to initiate DPP!\n", __func__, __LINE__);
        return -1;
    }


    if ((m_params.M = EC_POINT_new(m_params.group)) == NULL) {
        printf("%s:%d unable to create bignums to initiate DPP!\n", __func__, __LINE__);
        return -1;
    }


    if (EC_POINT_get_affine_coordinates_GFp(m_params.group, init_pub_key, m_params.x,
                m_params.y, m_params.bnctx) == 0) {
        printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        return -1;
    }

    if (m_data.type == ec_session_type_cfg) {

        if (EC_POINT_mul(m_params.group, m_params.M, NULL, resp_pub_key, proto_priv, m_params.bnctx) == 0) {
            printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
            return -1;
        }


        printf("Point M:\n");
        ec_util::print_ec_point(m_params.group, m_params.bnctx, m_params.M);

        if (EC_POINT_get_affine_coordinates_GFp(m_params.group, m_params.M,
                    m_params.m, NULL, m_params.bnctx) == 0) {
            printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
            return -1;

        }
    }
    
    RAND_bytes(m_params.initiator_nonce, m_params.noncelen);
    if (EC_GROUP_get_curve_GFp(m_params.group, m_params.prime, NULL, NULL,
                m_params.bnctx) == 0) {
        printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        return -1;
    }


    return 0;

}


/**
 * TODO: Come up with a better prefix than "handle" (maybe "process", "parse", ""), "handle" makes it seem like 802.11
 * 
 * Called by controller/configurator to do EasyConnect things
 */
int ec_session_t::handle_chirp_notification(em_dpp_chirp_value_t *chirp_tlv, uint16_t tlv_len)
{
    // TODO: Currently only handling controller side

    mac_addr_t mac = {0};
    uint8_t hash[255] = {0}; // Max hash length to avoid dynamic allocation
    uint8_t hash_len = 0;

    if (ec_util::parse_dpp_chirp_tlv(chirp_tlv, tlv_len, &mac, (uint8_t**)&hash, &hash_len) < 0) {
        printf("%s:%d: Failed to parse DPP Chirp TLV\n", __func__, __LINE__);
        return -1;
    }

    // Validate hash
    // Compute the hash of the responder boot key 
    uint8_t resp_boot_key_chirp_hash[SHA512_DIGEST_LENGTH];
    if (compute_key_hash(m_data.responder_boot_key, resp_boot_key_chirp_hash, "chirp") < 1) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d unable to compute \"chirp\" responder bootstrapping key hash\n", __func__, __LINE__);
        return -1;
    }

    if (memcmp(hash, resp_boot_key_chirp_hash, hash_len) != 0) {
        // Hashes don't match, don't initiate DPP authentication
        printf("%s:%d: Chirp notification hash and DPP URI hash did not match! Stopping DPP!\n", __func__, __LINE__);
        return -1;
    }

    auto [auth_frame, auth_frame_len] = create_auth_request();
    if (auth_frame == NULL || auth_frame_len == 0) {
        printf("%s:%d: Failed to create authentication request frame\n", __func__, __LINE__);
        return -1;
    }

    // Create Auth Request Encap TLV: EasyMesh 5.3.4
    em_encap_dpp_t* encap_dpp_tlv = ec_util::create_encap_dpp_tlv(0, 0, &mac, 0, auth_frame, auth_frame_len);
    if (encap_dpp_tlv == NULL) {
        printf("%s:%d: Failed to create Encap DPP TLV\n", __func__, __LINE__);
        return -1;
    }

    free(auth_frame);

    // Create Auth Request Chirp TLV: EasyMesh 5.3.4
    size_t data_size = sizeof(mac_addr_t) + hash_len + sizeof(uint8_t);
    em_dpp_chirp_value_t* chirp = (em_dpp_chirp_value_t*)calloc(sizeof(em_dpp_chirp_value_t) + data_size, 1);
    if (chirp == NULL) {
        printf("%s:%d: Failed to allocate memory for chirp TLV\n", __func__, __LINE__);
        free(encap_dpp_tlv);
        return -1;
    }
    chirp->mac_present = 1;
    chirp->hash_valid = 1;

    uint8_t* tmp = chirp->data;
    memcpy(tmp, mac, sizeof(mac_addr_t));
    tmp += sizeof(mac_addr_t);

    *tmp = hash_len;
    tmp++;

    memcpy(tmp, hash, hash_len); 

    // Send the encapsulated DPP message (with Encap TLV and Chirp TLV)
    this->m_send_prox_encap_dpp_msg(encap_dpp_tlv, sizeof(em_encap_dpp_t) + auth_frame_len, chirp, sizeof(em_dpp_chirp_value_t) + data_size);

    free(encap_dpp_tlv);
    free(chirp);
    
    return 0;

}

/**
 * TODO: Come up with a better prefix than "handle" (maybe "process", "parse", etc), "handle" makes it seem like 802.11
 * 
 * Called by controller/configurator to do EasyConnect things
 */
int ec_session_t::handle_proxy_encap_dpp_msg(em_encap_dpp_t *encap_tlv, uint16_t encap_tlv_len, em_dpp_chirp_value_t *chirp_tlv, uint16_t chirp_tlv_len)
{

    if (encap_tlv == NULL || encap_tlv_len == 0) {
        printf("%s:%d: Encap DPP TLV is empty\n", __func__, __LINE__);
        return -1;
    }

    
    mac_addr_t dest_mac = {0};
    uint8_t frame_type = 0;
    uint8_t* encap_frame = NULL;
    uint8_t encap_frame_len = 0;

    if (ec_util::parse_encap_dpp_tlv(encap_tlv, encap_tlv_len, &dest_mac, &frame_type, &encap_frame, &encap_frame_len) < 0) {
        printf("%s:%d: Failed to parse Encap DPP TLV\n", __func__, __LINE__);
        return -1;
    }

    mac_addr_t chirp_mac = {0};
    uint8_t chirp_hash[255] = {0}; // Max hash length to avoid dynamic allocation
    uint8_t chirp_hash_len = 0;

    ec_frame_type_t ec_frame_type = (ec_frame_type_t)frame_type;
    switch (ec_frame_type) {
        case ec_frame_type_auth_req: {
            if (chirp_tlv == NULL || chirp_tlv_len == 0) {
                printf("%s:%d: Chirp TLV is empty\n", __func__, __LINE__);
                return -1;
            }
            if (ec_util::parse_dpp_chirp_tlv(chirp_tlv, chirp_tlv_len, &chirp_mac, (uint8_t**)&chirp_hash, &chirp_hash_len) < 0) {
                printf("%s:%d: Failed to parse DPP Chirp TLV\n", __func__, __LINE__);
                return -1;
            }
            std::string chirp_hash_str = ec_util::hash_to_hex_string(chirp_hash, chirp_hash_len);
            printf("%s:%d: Chirp TLV Hash: %s\n", __func__, __LINE__, chirp_hash_str.c_str());
            
            // Store the encap frame keyed by the chirp hash in the map
            std::vector<uint8_t> encap_frame_vec(encap_frame, encap_frame + encap_frame_len);
            m_chirp_hash_frame_map[chirp_hash_str] = encap_frame_vec;
            break;
        }
        case ec_frame_type_recfg_auth_req: {
            printf("%s:%d: Encap DPP frame type (%d) not handled\n", __func__, __LINE__, ec_frame_type);
            std::vector<uint8_t> encap_frame_vec(encap_frame, encap_frame + encap_frame_len);
            // Will be compared against incoming presence announcement hash and mac-addr
            m_stored_recfg_auth_frames.push_back(encap_frame_vec); 
            break;
        }
        case ec_frame_type_recfg_announcement: {
            auto [recfg_auth_frame, recfg_auth_frame_len] = create_recfg_auth_req();
            if (recfg_auth_frame == NULL || recfg_auth_frame_len == 0) {
                printf("%s:%d: Failed to create reconfiguration authentication request frame\n", __func__, __LINE__);
                return -1;
            }
            em_encap_dpp_t* encap_dpp_tlv = ec_util::create_encap_dpp_tlv(0, 0, &dest_mac, ec_frame_type_recfg_auth_req, recfg_auth_frame, recfg_auth_frame_len);
            if (encap_dpp_tlv == NULL) {
                printf("%s:%d: Failed to create Encap DPP TLV\n", __func__, __LINE__);
                free(recfg_auth_frame);
                return -1;
            }
            free(recfg_auth_frame);
            // Send the encapsulated ReCfg Auth Request message (with Encap TLV)
            // TODO: SEND TO ALL AGENTS
            this->m_send_prox_encap_dpp_msg(encap_dpp_tlv, sizeof(em_encap_dpp_t) + recfg_auth_frame_len, NULL, 0);
            free(encap_dpp_tlv);
            break;
        }
        case ec_frame_type_auth_rsp: {
            break;
        }
        case ec_frame_type_recfg_auth_rsp: {

            break;
        }
        case ec_frame_type_auth_cnf:
        case ec_frame_type_recfg_auth_cnf: {
            break;
        }
            
        default:
            printf("%s:%d: Encap DPP frame type (%d) not handled\n", __func__, __LINE__, ec_frame_type);
            break;
    }
    // Parse out dest STA mac address and hash value then validate against the hash in the 
    // ec_session dpp uri info public key. 
    // Then construct an Auth request frame and send back in an Encap message

}

uint8_t* ec_session_t::add_wrapped_data_attr(ec_frame_t *frame, uint8_t* frame_attribs, uint16_t* non_wrapped_len, bool use_aad, uint8_t* key, std::function<std::pair<uint8_t*, uint16_t>()> create_wrap_attribs)
{
    siv_ctx ctx;

    // Initialize AES-SIV context
    switch(m_params.digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, key, SIV_256);
            break;
        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, key, SIV_384);
            break;
        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, key, SIV_512);
            break;
        default:
            printf("%s:%d Unknown digest length\n", __func__, __LINE__);
            return NULL;
    }

    // Use the provided function to create wrap_attribs and wrapped_len
    auto [wrap_attribs, wrapped_len] = create_wrap_attribs();

    // Encapsulate the attributes in a wrapped data attribute
    uint16_t wrapped_attrib_len = wrapped_len + AES_BLOCK_SIZE;
    ec_attribute_t *wrapped_attrib = (ec_attribute_t *)calloc(sizeof(ec_attribute_t) + wrapped_attrib_len, 1); 
    wrapped_attrib->attr_id = ec_attrib_id_wrapped_data;
    wrapped_attrib->length = wrapped_attrib_len;
    memset(wrapped_attrib->data, 0, wrapped_attrib_len);

    /**
    * Encrypt attributes using SIV mode with two additional authenticated data (AAD) inputs:
    * 1. The frame structure and 2. Non-wrapped attributes (per EasyMesh 6.3.1.4)
    * The synthetic IV/tag is stored in the first AES_BLOCK_SIZE bytes of wrapped_attrib->data
    */
   if (use_aad) {
        if (frame == NULL || frame_attribs == NULL || non_wrapped_len == NULL) {
            printf("%s:%d: AAD input is NULL, AAD encryption failed!\n", __func__, __LINE__);
            return NULL;
        }
        siv_encrypt(&ctx, wrap_attribs, &wrapped_attrib->data[AES_BLOCK_SIZE], wrapped_len, wrapped_attrib->data, 2,
            frame, sizeof(ec_frame_t),
            frame_attribs, *non_wrapped_len);
    } else {
        siv_encrypt(&ctx, wrap_attribs, &wrapped_attrib->data[AES_BLOCK_SIZE], wrapped_len, wrapped_attrib->data, 0);
    }

    // Add the wrapped data attribute to the frame
    uint8_t* ret_frame_attribs = ec_util::add_attrib(frame_attribs, non_wrapped_len, ec_attrib_id_wrapped_data, wrapped_attrib_len, (uint8_t *)wrapped_attrib);


    free(wrap_attribs);

    return ret_frame_attribs;
}

std::pair<uint8_t*, size_t> ec_session_t::unwrap_wrapped_attrib(ec_attribute_t* wrapped_attrib, ec_frame_t *frame, bool uses_aad, uint8_t* key)
{
    siv_ctx ctx;

    // Initialize AES-SIV context
    switch(m_params.digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, key, SIV_256);
            break;
        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, key, SIV_384);
            break;
        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, key, SIV_512);
            break;
        default:
            printf("%s:%d Unknown digest length\n", __func__, __LINE__);
            return std::pair<uint8_t*, size_t>(NULL, 0);
    }

    uint8_t* wrapped_ciphertext = wrapped_attrib->data + AES_BLOCK_SIZE;
    size_t wrapped_len = wrapped_attrib->length - AES_BLOCK_SIZE;

    uint8_t* unwrap_attribs = (uint8_t*)calloc(wrapped_len, 1);
    int result = -1;
    if (uses_aad) {
        if (frame == NULL) {
            printf("%s:%d: AAD input is NULL, AAD decryption failed!\n", __func__, __LINE__);
            return std::pair<uint8_t*, size_t>(NULL, 0);
        }
        result = siv_decrypt(&ctx, wrapped_ciphertext, unwrap_attribs, wrapped_len, wrapped_attrib->data, 2,
            frame, sizeof(ec_frame_t),
            frame->attributes, ((uint8_t*)wrapped_attrib) - frame->attributes); // Non-wrapped attributes
    } else {
        result = siv_decrypt(&ctx, wrapped_ciphertext, unwrap_attribs, wrapped_len, wrapped_attrib->data, 0);
    }

    if (result < 0) {
        printf("%s:%d: Failed to decrypt and authenticate wrapped data\n", __func__, __LINE__);
        free(unwrap_attribs);
        return std::pair<uint8_t*, size_t>(NULL, 0);
    }

    return std::pair<uint8_t*, size_t>(unwrap_attribs, wrapped_len);
}

int ec_session_t::handle_recv_ec_action_frame(ec_frame_t *frame, size_t len)
{
    if (!ec_util::validate_frame(frame)) {
        printf("%s:%d: frame validation failed\n", __func__, __LINE__);
        return -1;
    }
    switch (frame->frame_type) {
        case ec_frame_type_presence_announcement:
            return handle_pres_ann((uint8_t *)frame, len);
        case ec_frame_type_auth_req:
            return handle_auth_req((uint8_t *)frame, len);
        default:
            printf("%s:%d: frame type (%d) not handled\n", __func__, __LINE__, frame->frame_type);
            break;
    }
    return 0;
}

bool ec_session_t::check_supports_init_caps(ec_dpp_capabilities_t caps)
{
    // Currently just returning true for all capabilities
    return true;
}

ec_session_t::ec_session_t(std::function<int(em_dpp_chirp_value_t*, size_t)> send_chirp_notification,
                            std::function<int(em_encap_dpp_t*, size_t, em_dpp_chirp_value_t*, size_t)> send_prox_encap_dpp_msg)
                            : m_send_chirp_notification(send_chirp_notification), m_send_prox_encap_dpp_msg(send_prox_encap_dpp_msg)
{
    // Initialize member variables
    m_cfgrtr_ver = 0;
    m_enrollee_ver = 0;
    m_activation_status = ActStatus_Idle;
    memset(&m_enrollee_mac, 0, sizeof(mac_address_t));
    memset(&m_params, 0, sizeof(ec_params_t));
    memset(&m_data, 0, sizeof(ec_data_t));
}

ec_session_t::~ec_session_t() 
{
    // Clean up any allocated resources if necessary
}

