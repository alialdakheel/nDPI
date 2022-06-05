/*
 * cipio.c
 *
 *
 *
 */

#include "ndpi_protocol_ids.h"
#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_CIPIO
#include "ndpi_api.h"

#define CIPIO_PORT 2222

/* EtherNet/IP function codes */
/*
 *#define NOP                0x0000
 *#define LIST_SERVICES      0x0004
 *#define LIST_IDENTITY      0x0063
 *#define LIST_INTERFACES    0x0064
 *#define REGISTER_SESSION   0x0065
 *#define UNREGISTER_SESSION 0x0066
 *#define SEND_RR_DATA       0x006F
 *#define SEND_UNIT_DATA     0x0070
 *#define INDICATE_STATUS    0x0072
 *#define CANCEL             0x0073
 *
 *static const u_int16_t enip_cmd_vals[] = {
 *  NOP,               
 *  LIST_SERVICES,     
 *  LIST_IDENTITY,     
 *  LIST_INTERFACES,   
 *  REGISTER_SESSION,  
 *  UNREGISTER_SESSION,
 *  SEND_RR_DATA,      
 *  SEND_UNIT_DATA,    
 *  INDICATE_STATUS,   
 *  CANCEL,            
 *};
 */

/* ******************************************************** */

/*
 *void ndpi_search_enip_tcp(struct ndpi_detection_module_struct *ndpi_struct,
 *        struct ndpi_flow_struct *flow) {
 *  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
 *
 *  NDPI_LOG_DBG(ndpi_struct, "search ENIP\n");
 *
 *  [> An ENIP packet is at least 4 bytes long includes at least command <]
 *  if (packet->tcp) {
 *    if (packet->payload_packet_len >= 4) {
 *      [> check if command is valid. <]
 *      u_int16_t enip_cmd = ntohs(get_u_int16_t(packet->payload, 0));
 *      for (uint8_t i = 0; i < 10; i++) {
 *        if (enip_cmd == enip_cmd_vals[i]) {
 *          NDPI_LOG_INFO(ndpi_struct, "found ENIP\n");
 *          ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ENIP, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
 *          return;
 *        }
 *      }
 *    }
 *  }
 *  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
 *}
 */

void ndpi_search_cipio_udp(struct ndpi_detection_module_struct *ndpi_struct,
			  struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t d_port = 0;

  NDPI_LOG_DBG(ndpi_struct, "search CIPIO\n");

  /* An CIP i/o packet is at least one item with length 6 bytes long */
  if (packet->udp != NULL) {
    d_port = ntohs(packet->udp->dest);
    if (d_port == CIPIO_PORT){
      if (packet->payload_packet_len >= 6) {
        NDPI_LOG_INFO(ndpi_struct, "found CIPIO\n");
        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_CIPIO, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
        return;
      }
    }
  }
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

/* ******************************************************** */

void init_cipio_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			 u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) {
	
  ndpi_set_bitmask_protocol_detection("CIPIO", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_CIPIO,
				      ndpi_search_cipio_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
