#include "config.h"
#include <epan/packet.h>

#define CAN_UDP_PORT 12345

static int proto_can;
static int hf_can_identifier = -1;
static int hf_can_dlc = -1;
static int hf_can_data = -1;

static gint ett_can = -1;
static int dissect_can(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_);

void
proto_register_can(void)
{
    // Define the header fields for Wireshark
    static hf_register_info hf[] = {
        { &hf_can_identifier,
          { "CAN Identifier", "can_udp.identifier",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "CAN Identifier", HFILL }},
        { &hf_can_dlc,
          { "Data Length Code", "can_udp.dlc",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Data Length Code", HFILL }},
        { &hf_can_data,
          { "CAN Data", "can_udp.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "CAN Data", HFILL }},
    };

    // Define the subtree used to group fields in the protocol tree
    static gint *ett[] = {
        &ett_can,
    };	
//printf("Registering CAN protocol\n"); Debug output
    proto_can = proto_register_protocol (
        "Custom CAN UDP Protocol",
	"CAN_UDP",
	"can_udp"
	);
    // Register the header fields and subtrees
    proto_register_field_array(proto_can, hf, array_length(hf));  // Ensure this is called
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_can(void)
{
    static dissector_handle_t can_handle;

    can_handle = create_dissector_handle(dissect_can, proto_can);
    dissector_add_uint("udp.port", CAN_UDP_PORT, can_handle);
}

static int
dissect_can(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CAN_UDP");
    col_clear(pinfo->cinfo,COL_INFO);

    guint offset = 0;

    // Create protocol tree
    proto_item *ti = proto_tree_add_item(tree, proto_can, tvb, 0, -1, ENC_NA);
    proto_tree *can_tree = proto_item_add_subtree(ti, ett_can);

    // Extract and display CAN Identifier (2 bytes)
    guint16 can_id = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(can_tree, hf_can_identifier, tvb, offset, 2, can_id);
    offset += 2;

    // Extract and display Data Length Code (DLC) (1 byte)
    guint8 dlc = tvb_get_uint8(tvb, offset) & 0x0F;  // Only bits [3:0] for DLC
    proto_tree_add_uint(can_tree, hf_can_dlc, tvb, offset, 1, dlc);
    offset += 1;

    // Extract and display CAN Data (up to DLC bytes)
    proto_tree_add_item(can_tree, hf_can_data, tvb, offset, dlc, ENC_NA);

    return tvb_captured_length(tvb);
}
