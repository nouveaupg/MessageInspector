#include <string.h>

#include "openpgp_message.h"
#include "base64.h"

OPENPGP_MESSAGE *search_for_openpgp_msg(void *utf8_buffer, unsigned long buffer_len, int strictness) {
	OPENPGP_MESSAGE *output = 0;
	OPENPGP_MESSAGE_TYPE type = OPENPGP_MSG_TYPE_INVALID;
	unsigned long start_offset = 0;
	unsigned long end_offset = 0;

	int accumulator = 0;
	char *ptr = (char *)utf8_buffer;
	for (unsigned long i = 0; i < buffer_len; i++) {
		if (ptr[i] == '-') {
			accumulator++;
			if (accumulator == 5) {
				char *header = (ptr + i + 1);
				// TODO: add more types of messages
				if (strncmp("BEGIN PGP PUBLIC KEY BLOCK", header,strlen("BEGIN PGP PUBLIC KEY BLOCK")) == 0) {
					start_offset = i;
					type = OPENPGP_MSG_TYPE_PUBLIC_KEY_BLOCK;
					break;
				}
				accumulator = 0;
			}
		}
	}
	if (start_offset > 0) {
		accumulator = 0;
		for (unsigned long j = start_offset; j < buffer_len; j++) {
			if (ptr[j] == '-') {
				accumulator++;
				if (accumulator == 5) {
					char *footer = (ptr + j + 1);
					// TODO: add more types of messages
					if (type == OPENPGP_MSG_TYPE_PUBLIC_KEY_BLOCK) {
						if (strncmp("END PGP PUBLIC KEY BLOCK",footer,strlen("END PGP PUBLIC KEY BLOCK")) == 0) {
							end_offset = j;
							break;
						}
					}
					accumulator = 0;
				}
			}
		}
	}

	if (strictness <= 0) {
		// default strictness, only header is checked
		if (start_offset > 0) {
			output = (OPENPGP_MESSAGE *)malloc(sizeof(OPENPGP_MESSAGE));
			memset(output, 0, sizeof(OPENPGP_MESSAGE));
			output->type = type;
			output->bytes = utf8_buffer;
			output->length = buffer_len;
			output->header_pos = start_offset;
			output->footer_pos = end_offset;
			output->validity = strictness;
		}
	}
	else {
		// enhanced strictness, header and footer must match
		if (start_offset > 0 && end_offset > 0 && start_offset < end_offset) {
			output = (OPENPGP_MESSAGE *)malloc(sizeof(OPENPGP_MESSAGE));
			memset(output, 0, sizeof(OPENPGP_MESSAGE));
			output->type = type;
			output->bytes = utf8_buffer;
			output->length = buffer_len;
			output->header_pos = start_offset;
			output->footer_pos = end_offset;
			output->validity = strictness;
		}
	}

	return output;
}

OPENPGP_MESSAGE_TYPE validate_message(OPENPGP_MESSAGE *in, int strictness) {
	unsigned char *decoded_data = 0;
	unsigned long decoded_data_len = get_base64_decoded_len(in);
	if (decoded_data_len > 0) {
		decoded_data = base64_decoded_msg_data(in);
		long message_checksum = get_msg_checksum(in);
		long crc = crc_checksum(decoded_data, decoded_data_len);
		free(decoded_data);

		if (strictness >= 0) {
			// default strictness, require crc to match
			if (crc == message_checksum) {
				if (in->validity > strictness) {
					in->validity = strictness;
				}
				return in->type;
			}
		}
		else {
			if (in->validity > strictness) {
				in->validity = strictness;
			}
			return in->type;
		}
	}

	return OPENPGP_MSG_TYPE_INVALID;
}

// copied from RFC 4880
long crc_checksum(void *buffer, unsigned long data_len) {
	// really a safe piece of code because it only reads memory and updates the Cyclic Redundancy Check
	// so no error checking
	unsigned char *ptr = buffer;
	long crc = 0xB704CEL;
	for (unsigned long x = 0; x < data_len; x++) {
		crc ^= (long)ptr[x] << 16;
		for (int j = 0; j < 8; j++) {
			crc <<= 1;
			if (crc & 0x1000000) {
				crc ^= 0x1864CFBL;
			}
		}
	}
	return crc & 0xFFFFFFL;
}

int next_line_pos(char * utf8_buffer, unsigned long buffer_len)
{
	for (unsigned long x = 0; x < buffer_len; x++) {
		if (utf8_buffer[x] == '\r') {
			// make sure there is enough room in the buffer to peek the next character
			if ((x + 1) < buffer_len) {
				if (utf8_buffer[x + 1] == '\n') {
					if ((x + 2) < buffer_len) {
						return x + 2;
					}
				}
			}
		}
		else if(utf8_buffer[x] == '\n') {
			return x + 1;
		}
	}
	return -1;
}

int is_char_base64(char c)
{
	if (c >= 65 && c <= 90) {
		return 1;
	}
	if (c >= 97 && c <= 122) {
		return 1;
	}
	if (c >= 48 && c <= 57) {
		return 1;
	}
	if (c == 61) {
		return 1;
	}
	if (c == 47) {
		return 1;
	}
	if (c == 43) {
		return 1;
	}
	return 0;
}

unsigned long get_base64_decoded_len(char *utf8_buffer, unsigned long buffer_len) {
	unsigned char *ptr = utf8_buffer;
	unsigned long remainder = buffer_len;
	unsigned int base64_encoded_data_len = 0;

	int pos = next_line_pos(ptr, remainder);
	int line_len;
	while (pos != -1) {
		line_len = 0;
		for (int x = 0; x < pos; x++) {
			// we ignore all lines with a dash or colon (because they aren't Base64 data)
			if (ptr[x] == '-' || ptr[x] == ':') {
				line_len = 0;
				break;
			}
			line_len += is_char_base64(ptr[x]);
		}
		base64_encoded_data_len += line_len;
		if (*ptr == '=') {
			break;
		}
		ptr = (ptr + pos);
		remainder = remainder - pos;
		pos = next_line_pos(ptr, remainder);
	}

	if (base64_encoded_data_len > 0) {
		unsigned char *base64_encoded_data = malloc(base64_encoded_data_len+1);
		// Base64 decoding library needs a null terminated string
		base64_encoded_data[base64_encoded_data_len] = 0;
		if (base64_encoded_data) {
			unsigned int encoded_pos = 0;
			ptr = utf8_buffer;
			remainder = buffer_len;
			pos = next_line_pos(ptr,remainder);

			while (pos != -1) {
				line_len = 0;
				for (int x = 0; x < pos; x++) {
					// we ignore all lines with a dash or colon (because they aren't Base64 data)
					if (ptr[x] == '-' || ptr[x] == ':') {
						line_len = 0;
						break;
					}
					line_len += is_char_base64(ptr[x]);
				}

				if (line_len > 0) {
					for (int z = 0; z < pos; z++) {
						if (is_char_base64(ptr[z])) {
							base64_encoded_data[encoded_pos++] = ptr[z];
						}
						if (encoded_pos == base64_encoded_data_len) {
							break;
						}
					}
				}

				if (*ptr == '=') {
					break;
				}
				ptr = (ptr + pos);
				remainder = remainder - pos;
				pos = next_line_pos(ptr, remainder);
			}

			if (encoded_pos == base64_encoded_data_len) {
				int base64_decoded_len = Base64decode_len(base64_encoded_data);
				if (base64_decoded_len > 0) {
					return base64_decoded_len;
				}
			}
		}
	}
	return 0;
}