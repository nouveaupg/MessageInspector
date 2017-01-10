#pragma once

#include "openpgp_packet.h"

typedef enum OpenPGPMessageTypes
{
	OPENPGP_MSG_TYPE_INVALID,
	OPENPGP_MSG_TYPE_PUBLIC_KEY_BLOCK,
	OPENPGP_MSG_TYPE_PRIVATE_KEY_BLOCK,
	OPENPGP_MSG_TYPE_SIGNATURE,
	OPENPGP_MSG_TYPE_MESSAGE
} OPENPGP_MESSAGE_TYPE;

typedef struct OpenPGPMessage {
	unsigned char *bytes;
	unsigned long length;
	unsigned long header_pos;
	unsigned long footer_pos;
	unsigned long decoded_data_len;
	long target_checksum;
	long calculated_checksum;
	OPENPGP_MESSAGE_TYPE type;
	int validity; // the maximum strictness value this message has been validated with
	// strictness - default = 0, positive numbers more strict, negative less
} OPENPGP_MESSAGE;

#ifdef __cplusplus
extern "C" {
#endif

	OPENPGP_MESSAGE *search_for_openpgp_msg(void *utf8_buffer, unsigned long buffer_len,int strictness);
	// scans argument *buffer for OpenPGP ascii armor header and footer lines. Interprets text as UTF-8
	// returns new OPENPGP_MESSAGE object if successful, NULL if no lines were found
	OPENPGP_MESSAGE_TYPE validate_message(OPENPGP_MESSAGE *in, int strictness);
	// validates OPENPGP_MESSAGE *in. strictness default = 0
	// if *in is validated, in->type is set.
	// validation consists of decoding Base64 message data and ensuring the checksum matches
	OPENPGP_PACKET *packetize_openpgp_message(OPENPGP_MESSAGE *message);
	// seperates OpenPGP message into a packet chain
	// returns first OpenPGP packet from *message if successful
	OPENPGP_MESSAGE *generate_openpgp_message(OPENPGP_PACKET *packet_chain, OPENPGP_MESSAGE_TYPE type);
	// generates a ascii armored OpenPGP message using the supplied packet chain
	extern long crc_checksum(void *buffer, unsigned long data_len);
	// the checksum OpenPGP uses to validated armoured data before splitting into packets
	// we also use this as a hashing function to quickly locate OpenPGP message markers in a buffer
	int next_line_pos(char *utf8_buffer, unsigned long buffer_len);
	unsigned long get_base64_decoded_len(OPENPGP_MESSAGE *in);
	unsigned char *base64_decoded_msg_data(OPENPGP_MESSAGE *in);
	long get_msg_checksum(OPENPGP_MESSAGE *in);
	int is_char_base64(char c);

#ifdef __cplusplus
}
#endif