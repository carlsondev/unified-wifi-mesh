/**
 * Copyright 2023 Comcast Cable Communications Management, LLC
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

#ifndef EC_SESSION_H
#define EC_SESSION_H

#include "em_base.h"
#include "ec_base.h"

#include <type_traits>
#include <map>
#include <string>
#include <functional>
#include <vector>


class ec_session_t {
    mac_address_t   m_enrollee_mac;
    unsigned char m_cfgrtr_ver;
    unsigned char m_enrollee_ver;
    ec_params_t    m_params; 
    wifi_activation_status_t    m_activation_status;
    ec_data_t   m_data;

    /*
     * Map from Chirp Hash to DPP Authentication Request
     */
    std::map<std::string, std::vector<uint8_t>> m_chirp_hash_frame_map;
    /*
     * Vector of all cached DPP Reconfiguration Authentication Requests.
     * Hash does not matter since it is compared against the Controllers C-sign key
     */
    std::vector<std::vector<uint8_t>> m_stored_recfg_auth_frames;


    /**
     * @brief Send a chirp notification to the peer
     * 
     * @param chirp_tlv The chirp TLV to send
     * @param len The length of the chirp TLV
     * @return int 0 if successful, -1 otherwise
     */
    std::function<int(em_dpp_chirp_value_t*, size_t)> m_send_chirp_notification;

    /**
     * @brief Send a proxied encapsulated DPP message
     * 
     * @param encap_dpp_tlv The 1905 Encap DPP TLV to include in the message
     * @param encap_dpp_len The length of the 1905 Encap DPP TLV
     * @param chirp_tlv The chirp value to include in the message. If NULL, the message will not include a chirp value
     * @param chirp_len The length of the chirp value
     * @return int 0 if successful, -1 otherwise
     */
    std::function<int(em_encap_dpp_t*, size_t, em_dpp_chirp_value_t*, size_t)> m_send_prox_encap_dpp_msg;

    /**
     * @brief Compute the hash of the provided key with an optional prefix
     * 
     * @param key The key to hash
     * @param digest The buffer to store the hash
     * @param prefix The optional prefix to add to the key before hashing (NULL by default)
     * @return int The length of the hash
     */
    int compute_key_hash(EC_KEY *key, uint8_t *digest, const char *prefix = NULL);

    /**
     * @brief Handle a presence announcement frame
     * 
     * @param buff The frame to handle
     * @param len The length of the frame
     * @return int 0 if successful, -1 otherwise
     */
    int handle_pres_ann(uint8_t *buff, unsigned int len);

    /**
     * @brief Handle a authentication request frame
     * 
     * @param buff The frame to handle
     * @param len The length of the frame
     * @return int 0 if successful, -1 otherwise
     */
    int handle_auth_req(uint8_t *buff, unsigned int len);


    /**
     * @brief Compute intermediate key (k1 or k2)
     * 
     * @param is_first If true, compute k1; if false, compute k2
     * @return 0 on success, -1 on failure
     */
    int compute_intermediate_key(bool is_first);

    int compute_ke(uint8_t *ke_buffer);

    /**
     * @brief Called when recieving a Authentication Request,
     *         this function checks that the "Responder" (self) is capable of 
     *         supporting the role indicated by the Initiator's capabilities.
     * 
     */
    bool check_supports_init_caps(ec_dpp_capabilities_t caps);

    /**
     * Calculates L = ((b_R + p_R) modulo q) * B_I then gets the x-coordinate of the result
     * 
     * @param group The EC_GROUP representing the elliptic curve
     * @param bR Private Responder Bootstrapping Key
     * @param pR Private Responder Protocol Key
     * @param BI Public Initiator Bootstrapping Key
     * @return EC_POINT* The calculated L point X value, or NULL on failure. Caller must free with BN_free()
     */
    BIGNUM* calculate_Lx(const BIGNUM* bR, const BIGNUM* pR, const EC_POINT* BI);

    /**
     * @brief Add a wrapped data attribute to a frame
     * 
     * @param frame The frame to use as AAD. Can be NULL if no AAD is needed
     * @param frame_attribs The attributes to add the wrapped data attribute to and to use as AAD
     * @param non_wrapped_len The length of the non-wrapped attributes (`frame_attribs`, In/Out)
     * @param use_aad Whether to use AAD in the encryption
     * @param key The key to use for encryption
     * @param create_wrap_attribs A function to create the attributes to wrap and their length. Memory is handled by function (see note)
     * @return uint8_t* The new frame attributes with the wrapped data attribute added
     * 
     * @warning The `create_wrap_attribs` function will allocate heap-memory which is freed inside the `add_wrapped_data_attr` function.
     *     **The caller should not use statically allocated memory in `create_wrap_attribs` or free the memory returned by `create_wrap_attribs`.**
     */
    uint8_t* add_wrapped_data_attr(ec_frame_t *frame, uint8_t* frame_attribs, uint16_t* non_wrapped_len, 
        bool use_aad, uint8_t* key, std::function<std::pair<uint8_t*, uint16_t>()> create_wrap_attribs);
   

    /**
     * @brief Unwrap a wrapped data attribute
     * 
     * @param wrapped_attrib The wrapped attribute to unwrap (retreieved using `get_attribute`)
     * @param frame The frame to use as AAD. Can be NULL if no AAD is needed
     * @param uses_aad Whether the wrapped attribute uses AAD
     * @param key The key to use for decryption
     * @return std::pair<uint8_t*, size_t> A heap allocated buffer of unwrapped attributes on success which can then be fetched via `get_attribute`,
     *         along with the length of that buffer. The buffer is NULL and the size is 0 on failure.
     * 
     * @warning The caller is responsible for freeing the memory returned by this function
     */
    std::pair<uint8_t*, size_t> unwrap_wrapped_attrib(ec_attribute_t* wrapped_attrib, ec_frame_t *frame, bool uses_aad, uint8_t* key);
        
    /**
     * @brief Implements the HMAC-based Key Derivation Function (HKDF) as specified in RFC 5869
     *
     * This implementation allows skipping the extract phase if pre-extracted input is provided.
     *
     * @param h         Pointer to the EVP_MD digest to use for HMAC operations (e.g., EVP_sha256())
     * @param skip      If non-zero, skips the extract phase and treats ikm as the prk directly
     * @param ikm       Pointer to the input keying material
     * @param ikmlen    Length of the input keying material in bytes
     * @param salt      Pointer to the optional salt value (can be NULL). In the spec, a null salt is represented as "<>".
     * @param saltlen   Length of the salt in bytes (can be 0)
     * @param info      Pointer to the optional context and application specific information (can be NULL)
     * @param infolen   Length of the info in bytes (can be 0)
     * @param okm       Pointer to the buffer for storing the output keying material (must be pre-allocated)
     * @param okmlen    Length of the output keying material to be generated in bytes
     *
     * @return The length of the output keying material in bytes on success, 0 on failure
     */
    int hkdf(const EVP_MD *h, int skip, uint8_t *ikm, int ikmlen, 
            uint8_t *salt, int saltlen, uint8_t *info, int infolen, 
            uint8_t *okm, int okmlen);


    /**
     * @brief Abstracted HKDF computation that handles both simple and complex inputs
     * 
     * This function provides a unified interface for HKDF computations, handling both
     * simple single-input operations and more complex operations with multiple inputs.
     * It properly formats BIGNUMs with appropriate padding based on prime length.
     *
     * @param key_out Buffer to store the output key (must be pre-allocated)
     * @param key_out_len Length of the output key
     * @param info_str Information string for HKDF
     * @param bn_inputs Array of BIGNUMs to use as IKM
     * @param bn_count Number of BIGNUMs in the array
     * @param raw_salt Raw salt buffer (can be NULL)
     * @param raw_salt_len Length of raw salt buffer
     * 
     * @return Length of the output key on success, 0 on failure
     */
    int compute_hkdf_key(uint8_t *key_out, int key_out_len, const char *info_str,
        const BIGNUM **x_val_inputs, int x_val_count, 
        uint8_t *raw_salt, int raw_salt_len);

public:
    int init_session(ec_data_t* ec_data);

    /**
     * @brief Create an authentication request `ec_frame_t` with the necessary attributes 
     * 
     * @return std::pair<uint8_t*, uint16_t> The buffer containing the `ec_frame_t` and the length of the frame
     * 
     * @warning The caller is responsible for freeing the memory returned by this function
     */
    std::pair<uint8_t*, uint16_t> create_auth_request();

    /**
     * @brief Create an authentication response `ec_frame_t` with the necessary attributes 
     * 
     * @return std::pair<uint8_t*, uint16_t> The buffer containing the `ec_frame_t` and the length of the frame
     * 
     * @warning The caller is responsible for freeing the memory returned by this function
     */
    std::pair<uint8_t*, uint16_t> create_auth_resp(ec_status_code_t dpp_status);

    /*
    * @brief Create an reconfiguration presence announcement `ec_frame_t` with the necessary attributes 
    * 
    * @return std::pair<uint8_t*, uint16_t> The buffer containing the `ec_frame_t` and the length of the frame
    * 
    * @warning The caller is responsible for freeing the memory returned by this function
    */
   std::pair<uint8_t*, uint16_t> create_recfg_auth_req();

    /**
     * @brief Create an authentication confirm frame `ec_frame_t` with the necessary attributes
     * 
     * @return std::pair<uint8_t*, uint16_t> The buffer containing the `ec_frame_t` and the length of the frame
     * 
     * @warning The caller is responsible for freeing the memory returned by this function
     */
    std::pair<uint8_t *, uint16_t> create_auth_cnf();

    /**
     * @brief Create a reconfiguration authentication confirm frame `ec_frame_t` with the necessary attributes
     * 
     * @return std::pair<uint8_t*, uint16_t> The buffer containing the `ec_frame_t` and the length of the frame
     * 
     * @warning The caller is responsible for freeing the memory returned by this function
     */
    std::pair<uint8_t *, uint16_t> create_recfg_auth_cnf();

    /**
     * @brief Create a presence announcement frame in a pre-allocated buffer
     * 
     * @param buff The buffer to store the frame
     * @return int The length of the frame
     */
    std::pair<uint8_t *, uint16_t> create_pres_ann();

    /**
     * @brief Handle a chirp notification msg tlv and send the next message
     * 
     * @param chirp_tlv The chirp TLV to parse and handle
     * @param tlv_len The length of the chirp TLV
     * @return int 0 if successful, -1 otherwise
     */
    int handle_chirp_notification(em_dpp_chirp_value_t* chirp_tlv, uint16_t tlv_len);

    /**
     * @brief Handle a proxied encapsulated DPP message TLVs (including chirp value) and send the next message
     * 
     * @param encap_tlv The 1905 Encap DPP TLV to parse and handle
     * @param encap_tlv_len The length of the 1905 Encap DPP TLV
     * @param chirp_tlv The DPP Chirp Value TLV to parse and handle (NULL if not present)
     * @param chirp_tlv_len The length of the DPP Chirp Value TLV (0 if not present)
     * @return int 0 if successful, -1 otherwise
     */
    int handle_proxy_encap_dpp_msg(em_encap_dpp_t *encap_tlv, uint16_t encap_tlv_len, em_dpp_chirp_value_t *chirp_tlv, uint16_t chirp_tlv_len);
    
    /**
     * @brief Handles DPP action frames directed at this nodes ec_session
     * 
     * @param frame The frame recieved to handle
     * @param len The length of the frame
     * @return int 0 if successful, -1 otherwise
     */
    int handle_recv_ec_action_frame(ec_frame_t* frame, size_t len);

    /**
     * @brief Construct an EC session
     * 
     * @param send_chirp_notification The function to send a chirp notification
     * @param send_prox_encap_dpp_msg The function to send a proxied encapsulated DPP message
     */
    ec_session_t( std::function<int(em_dpp_chirp_value_t*, size_t)> send_chirp_notification,
                   std::function<int(em_encap_dpp_t*, size_t, em_dpp_chirp_value_t*, size_t)> send_prox_encap_dpp_msg);
    ~ec_session_t();
};

#endif
