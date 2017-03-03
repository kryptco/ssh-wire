#ifndef _SSHWIRE_H_
#define _SSHWIRE_H_

#include <stdint.h>

uint8_t kr_verify_signature(
		uint8_t const* pubkey_ptr, size_t pubkey_len,
		uint8_t const* sig_ptr, size_t sig_len,
		uint8_t const* msg_ptr, size_t msg_len);

#endif
