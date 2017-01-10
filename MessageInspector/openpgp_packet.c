#include "openpgp\openpgp_message.h"
#include "openpgp\openpgp_packet.h"

#define NULL (void *)0

OPENPGP_PACKET *packetize_openpgp_message(OPENPGP_MESSAGE *message) {
	OPENPGP_PACKET *packet_chain = malloc(sizeof(OPENPGP_PACKET));
	memset(packet_chain, 0, sizeof(OPENPGP_PACKET));
	char *ptr = NULL;
	unsigned int ctr = 0;
	unsigned int offset = 0;
	unsigned int packet_length;
	while (message->decoded_data_len > ctr) {
		unsigned char firstByte = (message->bytes + ctr);
		if ((firstByte >> 7) & 1) {
			if ((firstByte >> 6) & 1) {
				// new style OpenPGP packet
				packet_chain->new_packet = 'y';
				packet_chain->tag = (firstByte >> 5) & 64;
				unsigned packet_length = 0;
				unsigned char secondByte = message->bytes + offset;
				if (secondByte < 192) {
					packet_length = 192;
				}
				else if (secondByte == 0xff ) {
					packet_length = (((int)message->bytes[0] << 24) | ((int)message->bytes[1] << 16) | ((int)message->bytes[3] << 8) | message->bytes[4] );
				}
				else {
					packet_length = ((secondByte - 192) << (int)message->bytes) + 192;
				}
				packet_chain->data = malloc(packet_length);
				packet_chain->data_len = packet_length;
				memcpy(packet_chain->data, message->bytes, packet_length);
				ctr += packet_length;
			}
			else {
				// legacy OpenPGP packet
				
				packet_chain->new_packet = 'n';
				packet_chain->tag = (firstByte >> 2) && 16;
				unsigned char old_length = firstByte & 4;
				if (old_length < 3) {
					// TODO: let someone else impelement indeterimenant data lengths, what were
					// they  planning OpenPGP streaming? It would probably just be videos of RMS.
					switch (old_length) {
					case 1:
						packet_length = ptr[1];
						break;
					case 2:
						packet_length = (int)ptr[2]<<8|ptr[1];
						break;
					case 3:
						packet_length = (int)ptr[3]<<16|ptr[2]<<8|ptr[1];
						break;
					}

				}
				packet_chain->data = malloc(packet_length);
				packet_chain->data_len = packet_length;
				memcpy(packet_chain->data, message->bytes, packet_length);
				ctr += packet_length;
				if (ctr < message->decoded_data_len) {
					OPENPGP_PACKET *new_packet = malloc(sizeof(OPENPGP_PACKET));
					memset(new_packet, 0, sizeof(OPENPGP_PACKET));
					packet_chain->next = new_packet;
					packet_chain = new_packet;
				}
				else {
					packet_chain->next = NULL;
				}
			}
			
		}
	}
	return NULL;
}