#pragma once

typedef struct OpenPGPPacket {
	unsigned char *data;
	unsigned long data_len;
	short tag;
	unsigned char *new_packet;

	struct OpenPGPPacket *next;
} OPENPGP_PACKET;