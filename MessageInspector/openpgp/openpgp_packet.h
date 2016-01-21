#pragma once

typedef struct OpenPGPPacket {
	unsigned char *data;
	unsigned long data_len;
	short tag;

	struct OpenPGPPacket *next;
} OPENPGP_PACKET;