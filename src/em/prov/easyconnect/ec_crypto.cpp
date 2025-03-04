#include "ec_session.h"
#include "em_crypto.h"
#include "util.h"  

int ec_session_t::compute_key_hash(EC_KEY *key, uint8_t *digest, const char *prefix)
{
    BIO *bio;
    uint8_t *asn1;
    int asn1len;
    uint8_t *addr[2];      // Array of addresses for our two elements
    uint32_t len[2];       // Array of lengths for our two elements
    
    // Setup the BIO for key conversion
    if ((bio = BIO_new(BIO_s_mem())) == NULL) {
        return -1;
    }

    // Convert key to DER format
    i2d_EC_PUBKEY_bio(bio, key);
    (void)BIO_flush(bio);
    asn1len = BIO_get_mem_data(bio, &asn1);

    // Set up our data elements for hashing
    addr[0] = (uint8_t *)prefix;
    len[0] = strlen(prefix);
    addr[1] = asn1;
    len[1] = asn1len;

    // Call platform_SHA256 with our two elements
    uint8_t result = em_crypto_t::platform_SHA256(2, addr, len, digest);

    BIO_free(bio);
    
    if (result == 0) {
        return -1;
    }
    
    return SHA256_DIGEST_LENGTH;
}

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
 * @param x_val_inputs Array of BIGNUMs to use as IKM (Concatenated if > 1)
 * @param x_val_count Number of BIGNUMs in the array
 * @param raw_salt Raw salt buffer (can be NULL)
 * @param raw_salt_len Length of raw salt buffer
 * 
 * @return Length of the output key on success, 0 on failure
 */
int ec_session_t::compute_hkdf_key(uint8_t *key_out, int key_out_len, const char *info_str,
                     const BIGNUM **x_val_inputs, int x_val_count, 
                     uint8_t *raw_salt, int raw_salt_len)
{
    unsigned int primelen = 0;
    uint8_t *bn_buffer = NULL;
    uint8_t *ikm = NULL;
    int ikm_len = 0;
    int result = 0;
    
    // Calculate prime length for padding and format BIGNUMs
    primelen = BN_num_bytes(m_params.prime);
    bn_buffer = (uint8_t *)malloc(primelen * x_val_count);
    if (bn_buffer == NULL) {
        perror("malloc");
        return 0;
    }
    memset(bn_buffer, 0, primelen * x_val_count);
    
    // Format each X Val BIGNUM with proper padding
    for (int i = 0; i < x_val_count; i++) {
        if (x_val_inputs[i] != NULL) {
            unsigned int offset = primelen - BN_num_bytes(x_val_inputs[i]);
            BN_bn2bin(x_val_inputs[i], bn_buffer + (i * primelen) + offset);
        }
    }
    
    // Use formatted BIGNUMs as IKM
    ikm = bn_buffer;
    ikm_len = primelen * x_val_count;
    
    // Call the hkdf function
    result = hkdf(m_params.hashfcn, 0, ikm, ikm_len, raw_salt, raw_salt_len, 
                 (uint8_t *)info_str, strlen(info_str), 
                 key_out, key_out_len);
    
    // Free allocated memory
    if (bn_buffer != NULL) {
        free(bn_buffer);
    }
    
    return result;
}


int ec_session_t::compute_intermediate_key(bool is_first)
{       
    // The key to store
    uint8_t *key = is_first ? m_params.k1 : m_params.k2;
    
    // The BIGNUM to use
    const BIGNUM *bn_inputs[1] = { is_first ? m_params.m : m_params.n };
    
    // The info string
    const char *info = is_first ? "first intermediate key" : "second intermediate key";
    
    // Compute the key
    if (compute_hkdf_key(key, m_params.digestlen, info, bn_inputs, 1, NULL, 0) == 0) {
        printf("%s:%d: Failed in hashing\n", __func__, __LINE__);
        return -1;
    }
    
    printf("Key:\n");
    util::print_hex_dump(m_params.digestlen, key);
    
    return 0;
}


BIGNUM* ec_session_t::calculate_Lx(const BIGNUM* bR, const BIGNUM* pR, const EC_POINT* BI)
{
    EC_POINT* L = NULL;
    BIGNUM *sum, *order, *L_x = NULL;
    int success = 0;
    
    // Get the order of the curve (q)
    if (!(order = BN_new()) || !EC_GROUP_get_order(m_params.group, order, m_params.bnctx))
        goto cleanup;
    
    // Calculate (bR + pR) mod q
    if (!(sum = BN_new()) || !BN_mod_add(sum, bR, pR, order, m_params.bnctx))
        goto cleanup;
    
    // Create result point L
    if (!(L = EC_POINT_new(m_params.group)))
        goto cleanup;
    
    // Calculate L = sum * BI (point multiplication)
    if (!EC_POINT_mul(m_params.group, L, NULL, BI, sum, m_params.bnctx))
        goto cleanup;
    
    if (EC_POINT_get_affine_coordinates_GFp(m_params.group, L, L_x, NULL, m_params.bnctx) == 0)
    success = 1;
    
cleanup:
    if (sum) BN_free(sum);
    if (order) BN_free(order);
    
    if (!success && L_x) {
        BN_free(L_x);
        L_x = NULL;
    }
    
    return L_x;
}

/**
 * @brief Compute ke using nonces and coordinate values
 * 
 * @param ke_buffer Buffer to store ke (must be pre-allocated)
 * @param I_nonce Initiator nonce
 * @param I_nonce_len Length of initiator nonce
 * @param R_nonce Responder nonce
 * @param R_nonce_len Length of responder nonce
 * @param include_L Whether to include L.x for mutual authentication
 * @return Length of ke on success, 0 on failure
 */
int ec_session_t::compute_ke(uint8_t *ke_buffer)
{
    // Create concatenated nonces buffer (Initiator Nonce | Responder Nonce)
    int total_nonce_len = m_params.noncelen * 2;
    uint8_t *nonces = (uint8_t *)calloc(total_nonce_len, 1);
    if (nonces == NULL) {
        printf("%s:%d: Failed to allocate memory for nonces\n", __func__, __LINE__);
        return 0;
    }
    
    // Copy nonces
    memcpy(nonces, m_params.initiator_nonce, m_params.noncelen);
    memcpy(nonces + m_params.noncelen, m_params.responder_nonce, m_params.noncelen);
    
    // Set up BIGNUM array of X values (M, N, and possibly L if mutual auth)
    int x_count = m_params.mutual ? 3 : 2;
    const BIGNUM **x_val_array = (const BIGNUM **)calloc(x_count, sizeof(BIGNUM *));
    if (x_val_array == NULL) {
        free(nonces);
        printf("%s:%d: Failed to allocate memory for X values\n", __func__, __LINE__);
        return 0;
    }
    
    x_val_array[0] = m_params.m;  // M.x
    x_val_array[1] = m_params.n;  // N.x
    if (m_params.mutual) {
        x_val_array[2] = m_params.l;  // L.x if doing mutual auth
    }
    
    // Compute the key
    int result = compute_hkdf_key(
        ke_buffer,
        m_params.digestlen,
        "DPP Key",
        x_val_array,        // Concatenated X Vals for IKM
        x_count,
        nonces,              // Concatenated Nonces as salt
        total_nonce_len
    );
    
    // Free allocated memory
    free(nonces);
    free(x_val_array);
    
    return result;
}

int ec_session_t::hkdf (const EVP_MD *h, int skip, uint8_t *ikm, int ikmlen,
        uint8_t *salt, int saltlen, uint8_t *info, int infolen,
        uint8_t *okm, int okmlen)
{
    uint8_t *prk, *tweak, ctr, *digest;
    int len;
    unsigned int digestlen, prklen, tweaklen;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX ctx;
#else
    HMAC_CTX *ctx = HMAC_CTX_new();
#endif

    digestlen = prklen = EVP_MD_size(h);
    if ((digest = (uint8_t *)malloc(digestlen)) == NULL) {
        perror("malloc");
        return 0;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX_init(&ctx);
#else
    HMAC_CTX_reset(ctx);
#endif

    if (!skip) {
        /*
         * if !skip then do HKDF-extract
         */
        if ((prk = (uint8_t *)malloc(digestlen)) == NULL) {
            free(digest);
            perror("malloc");
            return 0;
        }
        /*
         * if there's no salt then use all zeros
         */
        if (!salt || (saltlen == 0)) {
            if ((tweak = (uint8_t *)malloc(digestlen)) == NULL) {
                free(digest);
                free(prk);
                perror("malloc");
                return 0;
            }
            memset(tweak, 0, digestlen);
            tweaklen = saltlen;
        } else {
            tweak = salt;
            tweaklen = saltlen;
        }
        (void)HMAC(h, tweak, tweaklen, ikm, ikmlen, prk, &prklen);
        if (!salt || (saltlen == 0)) {
            free(tweak);
        }
    } else {
        prk = ikm;
        prklen = ikmlen;
    }
    memset(digest, 0, digestlen);
    digestlen = 0;
    ctr = 0;
    len = 0;
    while (len < okmlen) {
        /*
         * T(0) = all zeros
         * T(n) = HMAC(prk, T(n-1) | info | counter)
         * okm = T(0) | ... | T(n)
         */
        ctr++;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        HMAC_Init_ex(&ctx, prk, prklen, h, NULL);
        HMAC_Update(&ctx, digest, digestlen);
#else
        HMAC_Init_ex(ctx, prk, prklen, h, NULL);
        HMAC_Update(ctx, digest, digestlen);
#endif
        if (info && (infolen != 0)) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            HMAC_Update(&ctx, info, infolen);
#else
            HMAC_Update(ctx, info, infolen);
#endif
        }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        HMAC_Update(&ctx, &ctr, sizeof(uint8_t));
        HMAC_Final(&ctx, digest, &digestlen);
#else
        HMAC_Update(ctx, &ctr, sizeof(uint8_t));
        HMAC_Final(ctx, digest, &digestlen);
#endif
        if ((len + digestlen) > okmlen) {
            memcpy(okm + len, digest, okmlen - len);
        } else {
            memcpy(okm + len, digest, digestlen);
        }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        HMAC_CTX_cleanup(&ctx);
#else
        HMAC_CTX_free(ctx);
#endif
        len += digestlen;
    }
    if (!skip) {
        free(prk);
    }
    free(digest);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX_cleanup(&ctx);
#else
    HMAC_CTX_free(ctx);
#endif

    return okmlen;
}
