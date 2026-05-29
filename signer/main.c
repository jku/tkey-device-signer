// SPDX-FileCopyrightText: 2022 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

#include <mldsa_native.h>
#include <fips202/fips202.h>
#include <monocypher/monocypher-ed25519.h>
#include <stdbool.h>
#include <tkey/assert.h>
#include <tkey/debug.h>
#include <tkey/io.h>
#include <tkey/led.h>
#include <tkey/proto.h>
#include <tkey/tk1_mem.h>
#include <tkey/touch.h>

#include "app_proto.h"
#include "platform.h"

// clang-format off
static volatile uint32_t *cdi           = (volatile uint32_t *) TK1_MMIO_TK1_CDI_FIRST;
static volatile uint32_t *cpu_mon_ctrl  = (volatile uint32_t *) TK1_MMIO_TK1_CPU_MON_CTRL;
static volatile uint32_t *cpu_mon_first = (volatile uint32_t *) TK1_MMIO_TK1_CPU_MON_FIRST;
static volatile uint32_t *cpu_mon_last  = (volatile uint32_t *) TK1_MMIO_TK1_CPU_MON_LAST;
static volatile uint32_t *app_addr      = (volatile uint32_t *) TK1_MMIO_TK1_APP_ADDR;
static volatile uint32_t *app_size      = (volatile uint32_t *) TK1_MMIO_TK1_APP_SIZE;
static volatile uint32_t *ver		= (volatile uint32_t *) TK1_MMIO_TK1_VERSION;
// clang-format on

// Touch timeout in seconds
#define TOUCH_TIMEOUT 30
#define MAX_SIGN_SIZE 4096

const uint8_t app_name0[4] = "tk1 ";
const uint8_t app_name1[4] = "mlds"; // ML-DSA
const uint32_t app_version = 0x00000004;

enum state {
	STATE_STARTED,
	STATE_LOADING,
	STATE_SIGNING,
	STATE_SIGNATURE_READY,
	STATE_FAILED,
};

// Context for the loading of a message
struct context {
	uint8_t secret_key[2560]; // ML-DSA-44 secret key
	uint8_t pubkey[1312];     // ML-DSA-44 public key
	uint8_t signature[2420];  // ML-DSA-44 signature
	uint8_t message[MAX_SIGN_SIZE];
	uint32_t left; // Bytes left to receive
	uint32_t message_size;
	uint16_t msg_idx; // Where we are currently loading a message
};

// Incoming packet from client
struct packet {
	struct frame_header hdr;      // Framing Protocol header
	uint8_t cmd[CMDLEN_MAXBYTES]; // Application level protocol
};

static enum state started_commands(enum state state, struct context *ctx,
				   struct packet pkt);
static enum state loading_commands(enum state state, struct context *ctx,
				   struct packet pkt);
static enum state signing_commands(enum state state, struct context *ctx,
				   struct packet pkt);
static enum state signature_ready_commands(enum state state, struct context *ctx,
					   struct packet pkt);
static int read_command(struct frame_header *hdr, uint8_t *cmd);
static void wipe_context(struct context *ctx);

static void wipe_context(struct context *ctx)
{
	secure_wipe(ctx->message, MAX_SIGN_SIZE);
	ctx->left = 0;
	ctx->message_size = 0;
	ctx->msg_idx = 0;
}

// started_commands() allows only these commands:
//
// - CMD_FW_PROBE
// - CMD_GET_NAMEVERSION
// - CMD_GET_FIRMWARE_HASH
// - CMD_GET_PUBKEY
// - CMD_SET_SIZE
//
// Anything else sent leads to state 'failed'.
//
// Arguments: the current state, the context and the incoming command.
// Returns: The new state.
static enum state started_commands(enum state state, struct context *ctx,
				   struct packet pkt)
{
	uint8_t rsp[CMDLEN_MAXBYTES] = {0}; // Response
	size_t rsp_left =
	    CMDLEN_MAXBYTES; // How many bytes left in response buf

	debug_puts("started_commands, command: ");
	debug_putinthex(pkt.cmd[0]);
	debug_lf();

	// Smallest possible payload length (cmd) is 1 byte.
	switch (pkt.cmd[0]) {
	case CMD_FW_PROBE:
		// Firmware probe. Allowed in this protocol state.
		// State unchanged.
		break;

	case CMD_GET_NAMEVERSION:
		debug_puts("CMD_GET_NAMEVERSION\n");
		if (pkt.hdr.len != 1) {
			// Bad length
			state = STATE_FAILED;
			break;
		}

		memcpy_s(rsp, rsp_left, app_name0, sizeof(app_name0));
		rsp_left -= sizeof(app_name0);

		memcpy_s(&rsp[4], rsp_left, app_name1, sizeof(app_name1));
		rsp_left -= sizeof(app_name1);

		memcpy_s(&rsp[8], rsp_left, &app_version, sizeof(app_version));

		appreply(pkt.hdr, RSP_GET_NAMEVERSION, rsp);

		// state unchanged
		break;

	case CMD_GET_FIRMWARE_HASH: {
		uint32_t fw_len = 0;

		debug_puts("APP_CMD_GET_FIRMWARE_HASH\n");
		if (pkt.hdr.len != 32) {
			rsp[0] = STATUS_BAD;
			appreply(pkt.hdr, RSP_GET_FIRMWARE_HASH, rsp);

			state = STATE_FAILED;
			break;
		}

		fw_len = pkt.cmd[1] + (pkt.cmd[2] << 8) + (pkt.cmd[3] << 16) +
			 (pkt.cmd[4] << 24);

		if (fw_len == 0 || fw_len > 8192) {
			debug_puts("FW size must be > 0 and <= 8192\n");
			rsp[0] = STATUS_BAD;
			appreply(pkt.hdr, RSP_GET_FIRMWARE_HASH, rsp);

			state = STATE_FAILED;
			break;
		}

		rsp[0] = STATUS_OK;
		crypto_sha512(&rsp[1], (void *)TK1_ROM_BASE, fw_len);
		appreply(pkt.hdr, RSP_GET_FIRMWARE_HASH, rsp);

		// state unchanged
		break;
	}

	case CMD_GET_PUBKEY_CHUNK: {
		debug_puts("CMD_GET_PUBKEY_CHUNK\n");
		if (pkt.hdr.len != 4) {
			// Bad length
			state = STATE_FAILED;
			break;
		}

		uint8_t chunk_idx = pkt.cmd[1];
		if (chunk_idx > 10) {
			debug_puts("Bad chunk index\n");
			state = STATE_FAILED;
			break;
		}

		uint32_t offset = chunk_idx * 120;
		uint32_t size = 120;
		if (chunk_idx == 10) {
			size = 1312 - 1200; // 112 bytes
		}

		rsp[0] = STATUS_OK;
		rsp[1] = chunk_idx;
		memcpy_s(rsp + 2, CMDLEN_MAXBYTES - 2, &ctx->pubkey[offset], size);
		if (size < 120) {
			secure_wipe(rsp + 2 + size, 120 - size);
		}

		appreply(pkt.hdr, RSP_GET_PUBKEY_CHUNK, rsp);
		// state unchanged
		break;
	}

	case CMD_SET_SIZE: {
		uint32_t local_message_size = 0;

		debug_puts("CMD_SET_SIZE\n");
		// Bad length
		if (pkt.hdr.len != 32) {
			rsp[0] = STATUS_BAD;
			appreply(pkt.hdr, RSP_SET_SIZE, rsp);

			state = STATE_FAILED;
			break;
		}

		// cmd[1..4] contains the size.
		local_message_size = pkt.cmd[1] + (pkt.cmd[2] << 8) +
				     (pkt.cmd[3] << 16) + (pkt.cmd[4] << 24);

		if (local_message_size == 0 ||
		    local_message_size > MAX_SIGN_SIZE) {
			debug_puts("Message size not within range!\n");
			rsp[0] = STATUS_BAD;
			appreply(pkt.hdr, RSP_SET_SIZE, rsp);

			state = STATE_FAILED;
			break;
		}

		// Set the real message size used later and reset
		// where we load the data
		ctx->message_size = local_message_size;
		ctx->left = ctx->message_size;
		ctx->msg_idx = 0;

		rsp[0] = STATUS_OK;
		appreply(pkt.hdr, RSP_SET_SIZE, rsp);

		state = STATE_LOADING;
		break;
	}

	default:
		debug_puts("Got unknown initial command: 0x");
		debug_puthex(pkt.cmd[0]);
		debug_lf();

		state = STATE_FAILED;
		break;
	}

	return state;
}

// loading_commands() allows only these commands:
//
// - CMD_LOAD_DATA
//
// Anything else sent leads to state 'failed'.
//
// Arguments: the current state, the context and the incoming command.
// Returns: The new state.
static enum state loading_commands(enum state state, struct context *ctx,
				   struct packet pkt)
{
	uint8_t rsp[CMDLEN_MAXBYTES] = {0}; // Response
	int nbytes = 0;			    // Bytes to write to memory

	switch (pkt.cmd[0]) {
	case CMD_LOAD_DATA: {
		debug_puts("CMD_LOAD_DATA\n");

		// Bad length
		if (pkt.hdr.len != CMDLEN_MAXBYTES) {
			rsp[0] = STATUS_BAD;
			appreply(pkt.hdr, RSP_LOAD_DATA, rsp);

			state = STATE_FAILED;
			break;
		}

		if (ctx->left > CMDLEN_MAXBYTES - 1) {
			nbytes = CMDLEN_MAXBYTES - 1;
		} else {
			nbytes = ctx->left;
		}

		memcpy_s(&ctx->message[ctx->msg_idx],
			 MAX_SIGN_SIZE - ctx->msg_idx, pkt.cmd + 1, nbytes);

		ctx->msg_idx += nbytes;
		ctx->left -= nbytes;

		rsp[0] = STATUS_OK;
		appreply(pkt.hdr, RSP_LOAD_DATA, rsp);

		if (ctx->left == 0) {

			state = STATE_SIGNING;
			break;
		}

		// state unchanged
		break;
	}

	default:
		debug_puts("Got unknown loading command: 0x");
		debug_puthex(pkt.cmd[0]);
		debug_lf();

		state = STATE_FAILED;
		break;
	}

	return state;
}

// signing_commands() allows only these commands:
//
// - CMD_GET_SIG
//
// Anything else sent leads to state 'failed'.
//
// Arguments: the current state, the context, the incoming command
// packet, and the secret key.
//
// Returns: The new state.
static enum state signing_commands(enum state state, struct context *ctx,
				   struct packet pkt)
{
	uint8_t rsp[CMDLEN_MAXBYTES] = {0}; // Response
	bool touched = false;

	switch (pkt.cmd[0]) {
	case CMD_GET_SIG:
		debug_puts("CMD_GET_SIG\n");
		if (pkt.hdr.len != 1) {
			// Bad length
			state = STATE_FAILED;
			break;
		}

#ifndef TKEY_SIGNER_APP_NO_TOUCH
		touched = touch_wait(LED_GREEN, TOUCH_TIMEOUT);

		if (!touched) {
			rsp[0] = STATUS_BAD;
			appreply(pkt.hdr, RSP_GET_SIG, rsp);

			state = STATE_STARTED;
			break;
		}
#endif
		debug_puts("Touched, now let's sign\n");

		// Prepare domain separation prefix
		MLD_ALIGN uint8_t pre[2 + 255];
		size_t pre_len = mldsa_prepare_domain_separation_prefix(pre, NULL, 0, NULL, 0, MLD_PREHASH_NONE);
		if (pre_len == 0) {
			debug_puts("prepare prefix failed\n");
			state = STATE_FAILED;
			break;
		}

		// Run deterministic ML-DSA-44 signing
		uint8_t rnd[32] = {0};
		size_t siglen = 0;
		int res = mldsa_signature_internal(ctx->signature, &siglen, ctx->message,
						   ctx->message_size, pre, pre_len, rnd,
						   ctx->secret_key, 0);

		if (res != 0) {
			debug_puts("mldsa_signature_internal failed\n");
			rsp[0] = STATUS_BAD;
			appreply(pkt.hdr, RSP_GET_SIG, rsp);

			state = STATE_FAILED;
			break;
		}

		debug_puts("Signature computed!\n");
		rsp[0] = STATUS_OK;
		appreply(pkt.hdr, RSP_GET_SIG, rsp);

		state = STATE_SIGNATURE_READY;
		break;

	default:
		debug_puts("Got unknown signing command: 0x");
		debug_puthex(pkt.cmd[0]);
		debug_lf();

		state = STATE_FAILED;
		break;
	}

	return state;
}

// signature_ready_commands() allows only these commands:
//
// - CMD_GET_SIG_CHUNK
// - CMD_SET_SIZE (for session reset)
//
// Anything else sent leads to state 'failed'.
//
// Arguments: the current state, the context and the incoming command.
// Returns: The new state.
static enum state signature_ready_commands(enum state state, struct context *ctx,
					   struct packet pkt)
{
	uint8_t rsp[CMDLEN_MAXBYTES] = {0}; // Response

	switch (pkt.cmd[0]) {
	case CMD_GET_SIG_CHUNK: {
		debug_puts("CMD_GET_SIG_CHUNK\n");
		if (pkt.hdr.len != 4) {
			// Bad length
			state = STATE_FAILED;
			break;
		}

		uint8_t chunk_idx = pkt.cmd[1];
		if (chunk_idx > 20) {
			debug_puts("Bad chunk index\n");
			state = STATE_FAILED;
			break;
		}

		uint32_t offset = chunk_idx * 120;
		uint32_t size = 120;
		if (chunk_idx == 20) {
			size = 2420 - 2400; // 20 bytes
		}

		rsp[0] = STATUS_OK;
		rsp[1] = chunk_idx;
		memcpy_s(rsp + 2, CMDLEN_MAXBYTES - 2, &ctx->signature[offset], size);
		if (size < 120) {
			secure_wipe(rsp + 2 + size, 120 - size);
		}

		appreply(pkt.hdr, RSP_GET_SIG_CHUNK, rsp);

		if (chunk_idx == 20) {
			// Wipe signature and context
			secure_wipe(ctx->signature, 2420);
			wipe_context(ctx);
			state = STATE_STARTED;
		}
		break;
	}

	case CMD_SET_SIZE: {
		// Lazy wipe before restarting
		secure_wipe(ctx->signature, 2420);
		wipe_context(ctx);

		// Now let started_commands handle the CMD_SET_SIZE command
		// to transition to STATE_LOADING
		state = started_commands(STATE_STARTED, ctx, pkt);
		break;
	}

	default:
		debug_puts("Unexpected command in signature ready state: 0x");
		debug_puthex(pkt.cmd[0]);
		debug_lf();

		secure_wipe(ctx->signature, 2420);
		wipe_context(ctx);
		state = STATE_FAILED;
		break;
	}

	return state;
}

// read_command takes a frame header and a command to fill in after
// parsing. It returns 0 on success.
static int read_command(struct frame_header *hdr, uint8_t *cmd)
{
	uint8_t in = 0;
	uint8_t available = 0;
	enum ioend endpoint = IO_NONE;

	memset(hdr, 0, sizeof(struct frame_header));
	memset(cmd, 0, CMDLEN_MAXBYTES);

	if (*ver >= CASTORVERSION) {
		if (readselect(IO_CDC, &endpoint, &available) < 0) {
			debug_puts("readselect errror");
			return -1;
		}

		if (read(IO_CDC, &in, 1, 1) < 0) {
			return -1;
		}
	} else {
		if (uart_read(&in, 1, 1) < 0) {
			return -1;
		}
	}

	if (parseframe(in, hdr) == -1) {
		debug_puts("Couldn't parse header\n");
		return -1;
	}

	if (*ver >= CASTORVERSION) {
		for (uint8_t n = 0; n < hdr->len;) {
			if (readselect(IO_CDC, &endpoint, &available) < 0) {
				debug_puts("readselect errror");
				return -1;
			}

			// Read as much as is available of what we expect from
			// the frame.
			available = available > hdr->len ? hdr->len : available;

			debug_puts("reading ");
			debug_putinthex(available);
			debug_lf();

			int nbytes = read(IO_CDC, &cmd[n], CMDLEN_MAXBYTES - n,
					  available);
			if (nbytes < 0) {
				debug_puts("read: buffer overrun\n");

				return -1;
			}

			n += nbytes;
		}
	} else {
		if (uart_read(cmd, CMDLEN_MAXBYTES, hdr->len) < 0) {
			return -1;
		}
	}

	// Well-behaved apps are supposed to check for a client
	// attempting to probe for firmware. In that case destination
	// is firmware and we just reply NOK, discarding all bytes
	// already read.
	if (hdr->endpoint == DST_FW) {
		appreply_nok(*hdr);
		debug_puts("Responded NOK to message meant for fw\n");
		cmd[0] = CMD_FW_PROBE;

		return 0;
	}

	// Is it for us? If not, return error after having discarded
	// all bytes.
	if (hdr->endpoint != DST_SW) {
		debug_puts("Message not meant for app. endpoint was 0x");
		debug_puthex(hdr->endpoint);
		debug_lf();

		return -1;
	}

	return 0;
}

int main(void)
{
	struct context ctx = {0};
	enum state state = STATE_STARTED;
	struct packet pkt = {0};

	// Use Execution Monitor on RAM after app
	*cpu_mon_first = *app_addr + *app_size;
	*cpu_mon_last = TK1_RAM_BASE + TK1_RAM_SIZE;
	*cpu_mon_ctrl = 1;

	led_set(LED_BLUE);

#ifdef TKEY_DEBUG
	config_endpoints(IO_CDC | IO_DEBUG);
#endif

	// Generate a public/private keypair from CDI
	MLD_ALIGN uint8_t cdi_buf[32];
	wordcpy(cdi_buf, (const void *)cdi, 8); // copy 8 words (32 bytes)
	MLD_ALIGN uint8_t seeds[64];
	mldsa_shake256(seeds, 64, cdi_buf, 32);
	secure_wipe(cdi_buf, 32);
	int keypair_res = mldsa_keypair_internal(ctx.pubkey, ctx.secret_key, seeds);
	secure_wipe(seeds, 64);
	if (keypair_res != 0) {
		debug_puts("Key generation failed!\n");
		state = STATE_FAILED;
	}

	for (;;) {
		debug_puts("parser state: ");
		debug_putinthex(state);
		debug_lf();

		if (read_command(&pkt.hdr, pkt.cmd) != 0) {
			debug_puts("read_command returned != 0!\n");
			state = STATE_FAILED;
		}

		switch (state) {
		case STATE_STARTED:
			state = started_commands(state, &ctx, pkt);
			break;

		case STATE_LOADING:
			state = loading_commands(state, &ctx, pkt);
			break;

		case STATE_SIGNING:
			state = signing_commands(state, &ctx, pkt);
			break;

		case STATE_SIGNATURE_READY:
			state = signature_ready_commands(state, &ctx, pkt);
			break;

		case STATE_FAILED:
			// fallthrough

		default:
			debug_puts("parser state 0x");
			debug_puthex(state);
			debug_lf();
			secure_wipe(ctx.signature, 2420);
			wipe_context(&ctx);
			assert(1 == 2);
			break; // Not reached
		}
	}
}
