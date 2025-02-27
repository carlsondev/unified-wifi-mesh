#include <ctype.h>
#include <arpa/inet.h>

#include "ec_util.h"
#include "util.h"

void ec_util::init_frame(ec_frame_t *frame)
{
    memset(frame, 0, sizeof(ec_frame_t));
    frame->category = 0x04;
    frame->action = 0x09;
    frame->oui[0] = 0x50;
    frame->oui[1] = 0x6f;
    frame->oui[2] = 0x9a;
    frame->oui_type = DPP_OUI_TYPE;
    frame->crypto_suite = 0x01; // Section 3.3 (Currently only 0x01 is defined)
}

ec_attribute_t *ec_util::get_attrib(uint8_t *buff, uint16_t len, ec_attrib_id_t id)
{
    unsigned int total_len = 0;
    ec_attribute_t *attrib = (ec_attribute_t *)buff;

    while (total_len < len) {
        if (attrib->attr_id == id) {
            return attrib;
        }

        total_len += (get_ec_attr_size(attrib->length));
        attrib = (ec_attribute_t *)((uint8_t*)attrib + get_ec_attr_size(attrib->length));
    }

    return NULL;
}


uint8_t* ec_util::add_attrib(uint8_t *buff, uint16_t* buff_len, ec_attrib_id_t id, uint16_t len, uint8_t *data)
{
    if (data == NULL || len == 0) {
        fprintf(stderr, "Invalid input\n");
        return NULL;
    }

    
    // Add extra space for the new attribute
    uint16_t new_len = *buff_len + get_ec_attr_size(len);
    // Original start pointer to use for realloc
    uint8_t* base_ptr = NULL;
    if (buff != NULL) base_ptr = buff - *buff_len;
    if ((base_ptr = (uint8_t*)realloc(base_ptr, new_len)) == NULL) {
        fprintf(stderr, "Failed to realloc\n");
        return NULL;
    }

    // Get the start of the new section based on the re-allocated pointer
    uint8_t* tmp = base_ptr + *buff_len;

    memset(tmp, 0, get_ec_attr_size(len));
    ec_attribute_t *attr = (ec_attribute_t *)tmp;
    // EC attribute id and length are in host byte order according to the spec (8.1)
    attr->attr_id = id;
    attr->length = len;
    memcpy(attr->data, data, len);

    *buff_len += get_ec_attr_size(len);
    // Return the next attribute in the buffer
    return tmp + get_ec_attr_size(len);
}

uint16_t ec_util::freq_to_channel_attr(unsigned int freq)
{
    auto op_chan = util::em_freq_to_chan(freq);

    auto [op_class, channel] = op_chan;
    return ((channel << 8) | (0x00ff & op_class));
}

int ec_util::parse_dpp_chirp_tlv(em_dpp_chirp_value_t* chirp_tlv, uint16_t chirp_tlv_len, mac_addr_t *mac, uint8_t **hash, uint8_t *hash_len)
{
    if (chirp_tlv == NULL || chirp_tlv_len == 0) {
        fprintf(stderr, "Invalid input\n");
        return -1;
    }

    uint16_t data_len = chirp_tlv_len - sizeof(em_dpp_chirp_value_t);
    // Parse TLV
    bool mac_addr_present = chirp_tlv->mac_present;
    bool hash_valid = chirp_tlv->hash_valid;

    uint8_t *data_ptr = chirp_tlv->data;
    if (mac_addr_present && data_len >= sizeof(mac_addr_t)) {
        memcpy(*mac, data_ptr, sizeof(mac_addr_t));
        data_ptr += sizeof(mac_addr_t);
        data_len -= sizeof(mac_addr_t);
    }

    if (!hash_valid || data_len <= 0) {
        // Clear (Re)configuration state, agent side
        return 0;
    }

    *hash_len = *data_ptr;
    data_ptr++;
    if (data_len < *hash_len) {
        fprintf(stderr, "Invalid chirp tlv\n");
        return NULL;
    }
    memcpy(*hash, data_ptr, *hash_len);

    return 0;
}

int ec_util::parse_encap_dpp_tlv(em_encap_dpp_t *encap_tlv, uint16_t encap_tlv_len, mac_addr_t *dest_mac, uint8_t *frame_type, uint8_t **encap_frame, uint8_t *encap_frame_len)
{
    if (encap_tlv == NULL || encap_tlv_len == 0) {
        fprintf(stderr, "Invalid input\n");
        return -1;
    }

    uint16_t data_len = encap_tlv_len - sizeof(em_encap_dpp_t);
    // Parse TLV
    bool mac_addr_present = encap_tlv->enrollee_mac_addr_present;

    // Copy mac address if present
    uint8_t *data_ptr = encap_tlv->data;
    if (mac_addr_present && data_len >= sizeof(mac_addr_t)) {
        memcpy(*dest_mac, data_ptr, sizeof(mac_addr_t));
        data_ptr += sizeof(mac_addr_t);
        data_len -= sizeof(mac_addr_t);
    } else {
        memset(*dest_mac, 0, sizeof(mac_addr_t));
    }

    if (data_len < sizeof(uint8_t) + sizeof(uint16_t)) {
        fprintf(stderr, "Invalid encap tlv\n");
        return -1;
    }

    // Get frame type
    *frame_type = *data_ptr;
    data_ptr++;

    // Get frame length
    *encap_frame_len = htons(*((uint16_t *)data_ptr));
    data_ptr += sizeof(uint16_t);

    if (data_len < *encap_frame_len) {
        fprintf(stderr, "Invalid encap tlv\n");
        return -1;
    }

    // Copy frame
    memcpy(*encap_frame, data_ptr, *encap_frame_len);

    return 0;
}

em_encap_dpp_t * ec_util::create_encap_dpp_tlv(bool dpp_frame_indicator, uint8_t content_type, mac_addr_t *dest_mac, uint8_t frame_type, uint8_t *encap_frame, uint8_t encap_frame_len)
{
    size_t data_size = sizeof(em_encap_dpp_t) + sizeof(uint8_t) + sizeof(uint16_t) + encap_frame_len;
    if (dest_mac != NULL) {
        data_size += sizeof(mac_addr_t);
    }
    em_encap_dpp_t *encap_tlv = NULL;

    if ((encap_tlv = (em_encap_dpp_t *)calloc(data_size, 1)) == NULL){
        fprintf(stderr, "Failed to allocate memory\n");
        return NULL;
    }
    (encap_tlv)->dpp_frame_indicator = dpp_frame_indicator;
    (encap_tlv)->content_type = content_type;
    (encap_tlv)->enrollee_mac_addr_present = (dest_mac != NULL) ? 1 : 0;

    uint8_t *data_ptr = (encap_tlv)->data;
    if (dest_mac != NULL) {
        memcpy(data_ptr, dest_mac, sizeof(mac_addr_t));
        data_ptr += sizeof(mac_addr_t);
    }

    *data_ptr = frame_type;
    data_ptr++;

    *((uint16_t *)data_ptr) = htons(encap_frame_len);
    data_ptr += sizeof(uint16_t);

    memcpy(data_ptr, encap_frame, encap_frame_len);

    return encap_tlv;
}

ec_frame_t *ec_util::copy_attrs_to_frame(ec_frame_t *frame, uint8_t *attrs, uint16_t attrs_len)
{
    uint16_t new_len = EC_FRAME_BASE_SIZE + attrs_len;
    ec_frame_t* new_frame = (ec_frame_t *) realloc((uint8_t*)frame, new_len);
    if (new_frame == NULL) {
        printf("%s:%d unable to realloc memory\n", __func__, __LINE__);
        return NULL; 
    }
    memcpy(new_frame->attributes, attrs, attrs_len);

    return new_frame;

}

bool ec_util::validate_frame(const ec_frame_t *frame)
{
    if ((frame->category != 0x04) 
            || (frame->action != 0x09)
            || (frame->oui[0] != 0x50)
            || (frame->oui[1] != 0x6f)
            || (frame->oui[2] != 0x9a)
            || (frame->oui_type != DPP_OUI_TYPE)
            || (frame->crypto_suite != 0x01) ) {
        return false;
    }

    return true;
}

std::string ec_util::hash_to_hex_string(const uint8_t *hash, size_t hash_len) {
    char output[hash_len * 2 + 1];
    for (size_t i = 0; i < hash_len; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[hash_len * 2] = '\0'; // Null-terminate the string
    return std::string(output);
}

void ec_util::print_bignum (BIGNUM *bn)
{
    unsigned char *buf;
    int len;

    len = BN_num_bytes(bn);
    if ((buf = (unsigned char *)malloc(len)) == NULL) {
        printf("Could not print bignum\n");
        return;
    }
    BN_bn2bin(bn, buf);
    util::print_hex_dump(len, buf);
    free(buf);
}

void ec_util::print_ec_point (const EC_GROUP *group, BN_CTX *bnctx, EC_POINT *point)
{
    BIGNUM *x = NULL, *y = NULL;

    if ((x = BN_new()) == NULL) {
        printf("%s:%d:Could not print ec_point\n", __func__, __LINE__);
        return;
    }

    if ((y = BN_new()) == NULL) {
        BN_free(x);
        printf("%s:%d:Could not print ec_point\n", __func__, __LINE__);
        return;
    }

    if (EC_POINT_get_affine_coordinates_GFp(group, point, x, y, bnctx) == 0) {
        BN_free(y);
        BN_free(x);
        printf("%s:%d:Could not print ec_point\n", __func__, __LINE__);
        return;

    }

    printf("POINT.x:\n");
    print_bignum(x);
    printf("POINT.y:\n");
    print_bignum(y);

    BN_free(y);
    BN_free(x);
}