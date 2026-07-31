// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "singbox_ebpf.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
/* BPF_MAP_TYPE_LRU_HASH. Android NDK headers expose it as an enum, not a preprocessor macro. */
#define SB_EBPF_REDIRECT_MAP_TYPE 9U

#define BPF_ALU64_IMM_OP(OP, DST, IMM) ((struct bpf_insn){.code = BPF_ALU64 | BPF_OP(OP) | BPF_K, .dst_reg = DST, .imm = (int32_t)(IMM)})
#define BPF_ALU64_REG_OP(OP, DST, SRC) ((struct bpf_insn){.code = BPF_ALU64 | BPF_OP(OP) | BPF_X, .dst_reg = DST, .src_reg = SRC})
#define BPF_ALU32_IMM_OP(OP, DST, IMM) ((struct bpf_insn){.code = BPF_ALU | BPF_OP(OP) | BPF_K, .dst_reg = DST, .imm = (int32_t)(IMM)})
#define BPF_ALU32_REG_OP(OP, DST, SRC) ((struct bpf_insn){.code = BPF_ALU | BPF_OP(OP) | BPF_X, .dst_reg = DST, .src_reg = SRC})
#define BPF_MOV64_REG(DST, SRC) BPF_ALU64_REG_OP(BPF_MOV, DST, SRC)
#define BPF_MOV64_IMM(DST, IMM) BPF_ALU64_IMM_OP(BPF_MOV, DST, IMM)
#define BPF_MOV32_REG(DST, SRC) BPF_ALU32_REG_OP(BPF_MOV, DST, SRC)
#define BPF_ST_MEM(SIZE, DST, OFF, IMM) ((struct bpf_insn){.code = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM, .dst_reg = DST, .off = OFF, .imm = (int32_t)(IMM)})
#define BPF_STX_MEM(SIZE, DST, SRC, OFF) ((struct bpf_insn){.code = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM, .dst_reg = DST, .src_reg = SRC, .off = OFF})
#define BPF_LDX_MEM(SIZE, DST, SRC, OFF) ((struct bpf_insn){.code = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM, .dst_reg = DST, .src_reg = SRC, .off = OFF})
#define BPF_JMP_IMM_OP(OP, DST, IMM, OFF) ((struct bpf_insn){.code = BPF_JMP | BPF_OP(OP) | BPF_K, .dst_reg = DST, .off = OFF, .imm = (int32_t)(IMM)})
#define BPF_JMP_REG_OP(OP, DST, SRC, OFF) ((struct bpf_insn){.code = BPF_JMP | BPF_OP(OP) | BPF_X, .dst_reg = DST, .src_reg = SRC, .off = OFF})
#define BPF_CALL_FUNC(FUNC) ((struct bpf_insn){.code = BPF_JMP | BPF_CALL, .imm = FUNC})
#define BPF_EXIT_INSN() ((struct bpf_insn){.code = BPF_JMP | BPF_EXIT})
#define BPF_ENDIAN_OP(DST, SIZE) ((struct bpf_insn){.code = BPF_ALU | BPF_END | BPF_TO_BE, .dst_reg = DST, .imm = SIZE})

enum {
    STACK_IFINDEX_KEY = -8,
    STACK_REDIRECT_KEY = -96,
    STACK_ORIGINAL_DST = -144,
    STACK_UDP_PEER_KEY = -168,
    STACK_UDP_PEER_VALUE = -192,
    STACK_SAVED_V6_LAST_WORD = -200,
    STACK_SAVED_PORT = -204,
    STACK_SAVED_V6_WORD1 = -212,
    STACK_SAVED_V6_WORD2 = -216,
    STACK_COOKIE_KEY = -232,
};

struct bpf_builder {
    struct bpf_insn insns[512];
    size_t count;
    bool overflow;
};

static void close_fd(int *fd) {
    if (fd != NULL && *fd >= 0) {
        close(*fd);
        *fd = -1;
    }
}

static uint32_t ipv4_redirect_host_mask(uint32_t prefix_bits) {
    if (prefix_bits > 32U) return 0U;
    if (prefix_bits == 0U) return UINT32_MAX;
    if (prefix_bits == 32U) return 0U;
    return UINT32_MAX >> prefix_bits;
}

static uint32_t ipv4_redirect_prefix(const uint8_t prefix[4], uint32_t prefix_bits) {
    if (prefix == NULL || prefix_bits > 32U) return 0U;
    uint32_t address = 0U;
    memcpy(&address, prefix, sizeof(address));
    return ntohl(address) & ~ipv4_redirect_host_mask(prefix_bits);
}

static uint32_t ipv6_redirect_word(const uint8_t prefix[16], size_t offset) {
    if (prefix == NULL || offset > 12U) return 0U;
    uint32_t value = 0U;
    memcpy(&value, prefix + offset, sizeof(value));
    return value;
}

static void init_runtime(struct sb_ebpf_inbound_runtime *runtime) {
    memset(runtime, -1, sizeof(*runtime));
}

static void emit(struct bpf_builder *builder, struct bpf_insn insn) {
    if (builder->count < ARRAY_SIZE(builder->insns)) {
        builder->insns[builder->count++] = insn;
    } else {
        builder->overflow = true;
    }
}

static size_t emit_jump(struct bpf_builder *builder, struct bpf_insn insn) {
    size_t index = builder->count;
    emit(builder, insn);
    return index;
}

static void patch_jump(struct bpf_builder *builder, size_t jump_index, size_t target_index) {
    builder->insns[jump_index].off = (int16_t)(target_index - jump_index - 1U);
}

static void emit_ld_map_fd(struct bpf_builder *builder, int dst_reg, int map_fd) {
    emit(builder, (struct bpf_insn){
        .code = BPF_LD | BPF_DW | BPF_IMM,
        .dst_reg = (uint8_t)dst_reg,
        .src_reg = BPF_PSEUDO_MAP_FD,
        .imm = map_fd,
    });
    emit(builder, (struct bpf_insn){.code = 0, .imm = 0});
}

static void emit_ctx_st32(struct bpf_builder *builder, int offset, uint32_t imm) {
    emit(builder, BPF_MOV64_IMM(BPF_REG_0, imm));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, offset));
}

static size_t emit_exit(struct bpf_builder *builder, int result) {
    size_t label = builder->count;
    emit(builder, BPF_MOV64_IMM(BPF_REG_0, result));
    emit(builder, BPF_EXIT_INSN());
    return label;
}

static void emit_inbound_network_filter(
    struct bpf_builder *builder,
    const struct sb_ebpf_inbound_config *config,
    uint8_t protocol,
    bool protocol_from_context,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    uint8_t network = config->inbound_network;
    if (network == SB_EBPF_NETWORK_BOTH) return;
    if (protocol_from_context) {
        uint8_t allowed_protocol = network == SB_EBPF_NETWORK_TCP
            ? SB_EBPF_PROTO_TCP
            : SB_EBPF_PROTO_UDP;
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, protocol)));
        bypass_jumps[(*bypass_jump_count)++] =
            emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, allowed_protocol, 0));
    } else if ((protocol == SB_EBPF_PROTO_TCP && !(network & SB_EBPF_NETWORK_TCP)) ||
               (protocol == SB_EBPF_PROTO_UDP && !(network & SB_EBPF_NETWORK_UDP))) {
        bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
    }
}

static int create_redirect_map(uint32_t max_entries) {
    return sb_ebpf_create_map(
        (enum bpf_map_type)SB_EBPF_REDIRECT_MAP_TYPE,
        sizeof(struct sb_ebpf_redirect_key),
        sizeof(struct sb_ebpf_original_dst),
        max_entries,
        0U);
}

static int create_udp_peer_map(uint32_t max_entries) {
    return sb_ebpf_create_map(
        (enum bpf_map_type)SB_EBPF_REDIRECT_MAP_TYPE,
        sizeof(struct sb_ebpf_udp_peer_key),
        sizeof(struct sb_ebpf_udp_peer_value),
        max_entries,
        0U);
}

static int create_bypass_socket_cookie_map(uint32_t max_entries) {
    return sb_ebpf_create_map(
        (enum bpf_map_type)SB_EBPF_REDIRECT_MAP_TYPE,
        sizeof(uint64_t),
        sizeof(uint8_t),
        max_entries,
        0U);
}

static void emit_zero_region(struct bpf_builder *builder, int base_off, size_t size) {
    for (size_t off = 0; off < size; off += sizeof(uint32_t)) {
        emit(builder, BPF_ST_MEM(BPF_W, BPF_REG_10, (int16_t)(base_off + (int)off), 0));
    }
}

static void emit_socket_cookie_bypass(
    struct bpf_builder *builder,
    int bypass_socket_cookie_map_fd,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (bypass_socket_cookie_map_fd < 0) return;

    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    size_t no_cookie = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_COOKIE_KEY));
    emit_ld_map_fd(builder, BPF_REG_1, bypass_socket_cookie_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_COOKIE_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    bypass_jumps[(*bypass_jump_count)++] =
        emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_0, 0, 0));
    patch_jump(builder, no_cookie, builder->count);
}

static void emit_connected_udp_original_flag(
    struct bpf_builder *builder,
    bool protocol_from_context) {
    if (!protocol_from_context) return;

    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, type)));
    size_t not_udp = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_4, SOCK_DGRAM, 0));
    emit(builder, BPF_ST_MEM(
        BPF_B,
        BPF_REG_10,
        STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, flags),
        SB_EBPF_ORIGINAL_DST_FLAG_CONNECTED_UDP));
    patch_jump(builder, not_udp, builder->count);
}

static void emit_udp_peer_cache_update_v4(
    struct bpf_builder *builder,
    int udp_peer_map_fd,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (udp_peer_map_fd < 0) return;

    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip4)));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_7, 0, 0));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_8, 0, 0));

    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));

    emit_zero_region(builder, STACK_UDP_PEER_KEY, sizeof(struct sb_ebpf_udp_peer_key));
    emit_zero_region(builder, STACK_UDP_PEER_VALUE, sizeof(struct sb_ebpf_udp_peer_value));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_UDP_PEER_KEY + (int)offsetof(struct sb_ebpf_udp_peer_key, cookie)));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_KEY + (int)offsetof(struct sb_ebpf_udp_peer_key, family), AF_INET));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, family), AF_INET));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, protocol), SB_EBPF_PROTO_UDP));
    emit(builder, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_8, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, port)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, addr)));

    emit_ld_map_fd(builder, BPF_REG_1, udp_peer_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UDP_PEER_KEY));
    emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_3, STACK_UDP_PEER_VALUE));
    emit(builder, BPF_MOV64_IMM(BPF_REG_4, BPF_ANY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_update_elem));
}

static void emit_udp_peer_cache_update_v4mapped(
    struct bpf_builder *builder,
    int udp_peer_map_fd,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (udp_peer_map_fd < 0) return;

    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_7, 0, 0));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_8, 0, 0));

    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));

    emit_zero_region(builder, STACK_UDP_PEER_KEY, sizeof(struct sb_ebpf_udp_peer_key));
    emit_zero_region(builder, STACK_UDP_PEER_VALUE, sizeof(struct sb_ebpf_udp_peer_value));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_UDP_PEER_KEY + (int)offsetof(struct sb_ebpf_udp_peer_key, cookie)));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_KEY + (int)offsetof(struct sb_ebpf_udp_peer_key, family), AF_INET));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, family), AF_INET));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, protocol), SB_EBPF_PROTO_UDP));
    emit(builder, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_8, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, port)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, addr)));

    emit_ld_map_fd(builder, BPF_REG_1, udp_peer_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UDP_PEER_KEY));
    emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_3, STACK_UDP_PEER_VALUE));
    emit(builder, BPF_MOV64_IMM(BPF_REG_4, BPF_ANY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_update_elem));
}

static void emit_udp_peer_cache_update_v6(
    struct bpf_builder *builder,
    int udp_peer_map_fd,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (udp_peer_map_fd < 0) return;

    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_8));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_9));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_4));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, 0, 0));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_5, 0, 0));

    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));

    emit_zero_region(builder, STACK_UDP_PEER_KEY, sizeof(struct sb_ebpf_udp_peer_key));
    emit_zero_region(builder, STACK_UDP_PEER_VALUE, sizeof(struct sb_ebpf_udp_peer_value));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_UDP_PEER_KEY + (int)offsetof(struct sb_ebpf_udp_peer_key, cookie)));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_KEY + (int)offsetof(struct sb_ebpf_udp_peer_key, family), AF_INET6));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, family), AF_INET6));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, protocol), SB_EBPF_PROTO_UDP));
    emit(builder, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_5, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, port)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, addr)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_8, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, addr) + 4));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_9, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, addr) + 8));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_4, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, addr) + 12));

    emit_ld_map_fd(builder, BPF_REG_1, udp_peer_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UDP_PEER_KEY));
    emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_3, STACK_UDP_PEER_VALUE));
    emit(builder, BPF_MOV64_IMM(BPF_REG_4, BPF_ANY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_update_elem));
}

static void emit_udp_peer_cache_update(
    struct bpf_builder *builder,
    int udp_peer_map_fd,
    bool ipv6,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (ipv6) {
        emit_udp_peer_cache_update_v6(builder, udp_peer_map_fd, bypass_jumps, bypass_jump_count);
    } else {
        emit_udp_peer_cache_update_v4(builder, udp_peer_map_fd, bypass_jumps, bypass_jump_count);
    }
}

static void emit_udp_peer_cache_restore_v4(
    struct bpf_builder *builder,
    int udp_peer_map_fd) {
    if (udp_peer_map_fd < 0) return;

    size_t missing_ip = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_7, 0, 0));
    size_t has_complete_peer = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_8, 0, 0));
    patch_jump(builder, missing_ip, builder->count);

    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    size_t no_cookie = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit_zero_region(builder, STACK_UDP_PEER_KEY, sizeof(struct sb_ebpf_udp_peer_key));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_UDP_PEER_KEY + (int)offsetof(struct sb_ebpf_udp_peer_key, cookie)));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_KEY + (int)offsetof(struct sb_ebpf_udp_peer_key, family), AF_INET));
    emit_ld_map_fd(builder, BPF_REG_1, udp_peer_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UDP_PEER_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    size_t no_peer = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, family)));
    size_t wrong_family = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, AF_INET, 0));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, protocol)));
    size_t wrong_proto = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SB_EBPF_PROTO_UDP, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, addr)));
    emit(builder, BPF_LDX_MEM(BPF_H, BPF_REG_8, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, port)));

    size_t done = builder->count;
    patch_jump(builder, has_complete_peer, done);
    patch_jump(builder, no_cookie, done);
    patch_jump(builder, no_peer, done);
    patch_jump(builder, wrong_family, done);
    patch_jump(builder, wrong_proto, done);
}

static void emit_udp_peer_cache_restore_v6(
    struct bpf_builder *builder,
    int udp_peer_map_fd) {
    if (udp_peer_map_fd < 0) return;

    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_8));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_9));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_4));
    size_t missing_addr = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, 0, 0));
    size_t has_complete_peer = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_5, 0, 0));
    patch_jump(builder, missing_addr, builder->count);

    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    size_t no_cookie = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit_zero_region(builder, STACK_UDP_PEER_KEY, sizeof(struct sb_ebpf_udp_peer_key));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_UDP_PEER_KEY + (int)offsetof(struct sb_ebpf_udp_peer_key, cookie)));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_KEY + (int)offsetof(struct sb_ebpf_udp_peer_key, family), AF_INET6));
    emit_ld_map_fd(builder, BPF_REG_1, udp_peer_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UDP_PEER_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    size_t no_peer = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, family)));
    size_t wrong_family = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, AF_INET6, 0));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, protocol)));
    size_t wrong_proto = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SB_EBPF_PROTO_UDP, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, addr)));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, addr) + 4));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, addr) + 8));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, addr) + 12));
    emit(builder, BPF_LDX_MEM(BPF_H, BPF_REG_5, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, port)));
    size_t restored_peer = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));

    size_t fallback = builder->count;
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    size_t done = builder->count;
    patch_jump(builder, restored_peer, done);
    patch_jump(builder, has_complete_peer, done);
    patch_jump(builder, no_cookie, fallback);
    patch_jump(builder, no_peer, fallback);
    patch_jump(builder, wrong_family, fallback);
    patch_jump(builder, wrong_proto, fallback);
}

static void emit_ipv4_destination_bypass(
    struct bpf_builder *builder,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_7, 0, 0));

    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_2, 32));
    emit(builder, BPF_ALU64_IMM_OP(BPF_AND, BPF_REG_2, 0xff000000U));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, 0x7f000000U, 0));
}

static void emit_ipv4_mapped_ipv6_check_jumps(
    struct bpf_builder *builder,
    size_t *not_mapped_jumps,
    size_t *not_mapped_jump_count) {
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
    not_mapped_jumps[(*not_mapped_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    not_mapped_jumps[(*not_mapped_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_2, 32));
    not_mapped_jumps[(*not_mapped_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, 0x0000ffffU, 0));
}

static void emit_ipv6_destination_bypass(
    struct bpf_builder *builder,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_8));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_9));
    size_t not_zero_or_loopback = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, 0, 0));
    emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_4));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_3, 32));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_3, 0, 0));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_3, 1, 0));
    patch_jump(builder, not_zero_or_loopback, builder->count);

}

static void emit_redirect_update_and_rewrite(
    struct bpf_builder *builder,
    const struct sb_ebpf_inbound_config *config,
    int redirect_map_fd,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t listen_port,
    size_t *drop_jumps,
    size_t *drop_jump_count) {
    uint32_t redirect_prefix = ipv4_redirect_prefix(
        config->redirect_ipv4_prefix,
        config->redirect_ipv4_prefix_bits);
    uint32_t redirect_host_mask = ipv4_redirect_host_mask(config->redirect_ipv4_prefix_bits);
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_prandom_u32));
    emit(builder, BPF_MOV32_REG(BPF_REG_9, BPF_REG_0));
    emit(builder, BPF_ALU32_IMM_OP(BPF_AND, BPF_REG_9, redirect_host_mask));
    emit(builder, BPF_ALU32_IMM_OP(BPF_OR, BPF_REG_9, redirect_prefix));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_9, 32));
    if (protocol_from_context) {
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, type)));
        emit(builder, BPF_MOV64_IMM(BPF_REG_5, SB_EBPF_PROTO_TCP));
        size_t not_udp = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_4, SOCK_DGRAM, 0));
        emit(builder, BPF_MOV64_IMM(BPF_REG_5, SB_EBPF_PROTO_UDP));
        patch_jump(builder, not_udp, builder->count);
    } else {
        emit(builder, BPF_MOV64_IMM(BPF_REG_5, protocol));
    }

    emit_zero_region(builder, STACK_REDIRECT_KEY, sizeof(struct sb_ebpf_redirect_key));
    emit_zero_region(builder, STACK_ORIGINAL_DST, sizeof(struct sb_ebpf_original_dst));

    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, family), AF_INET));
    emit(builder, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_5, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, protocol)));
    emit(builder, BPF_ST_MEM(BPF_H, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_port), listen_port));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_9, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_addr)));

    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, family), AF_INET));
    emit(builder, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_5, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, protocol)));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_8, 16));
    emit(builder, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_8, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, port)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, addr)));
    emit_connected_udp_original_flag(builder, protocol_from_context);

    emit_ld_map_fd(builder, BPF_REG_1, redirect_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_REDIRECT_KEY));
    emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_3, STACK_ORIGINAL_DST));
    emit(builder, BPF_MOV64_IMM(BPF_REG_4, BPF_ANY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_update_elem));
    drop_jumps[(*drop_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_0, 0, 0));

    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_9, offsetof(struct bpf_sock_addr, user_ip4)));
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_port), htons(listen_port));
}

static void emit_redirect_update_and_rewrite_v6(
    struct bpf_builder *builder,
    const struct sb_ebpf_inbound_config *config,
    int redirect_map_fd,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t listen_port,
    size_t *drop_jumps,
    size_t *drop_jump_count) {
    uint32_t prefix0 = ipv6_redirect_word(config->redirect_ipv6_prefix, 0U);
    uint32_t prefix1 = ipv6_redirect_word(config->redirect_ipv6_prefix, 4U);

    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_4, STACK_SAVED_V6_LAST_WORD));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_5, STACK_SAVED_PORT));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_8, STACK_SAVED_V6_WORD1));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_9, STACK_SAVED_V6_WORD2));

    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_prandom_u32));
    emit(builder, BPF_MOV32_REG(BPF_REG_8, BPF_REG_0));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_prandom_u32));
    emit(builder, BPF_MOV32_REG(BPF_REG_9, BPF_REG_0));

    if (protocol_from_context) {
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, type)));
        emit(builder, BPF_MOV64_IMM(BPF_REG_5, SB_EBPF_PROTO_TCP));
        size_t not_udp = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_4, SOCK_DGRAM, 0));
        emit(builder, BPF_MOV64_IMM(BPF_REG_5, SB_EBPF_PROTO_UDP));
        patch_jump(builder, not_udp, builder->count);
    } else {
        emit(builder, BPF_MOV64_IMM(BPF_REG_5, protocol));
    }

    emit_zero_region(builder, STACK_REDIRECT_KEY, sizeof(struct sb_ebpf_redirect_key));
    emit_zero_region(builder, STACK_ORIGINAL_DST, sizeof(struct sb_ebpf_original_dst));

    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, family), AF_INET6));
    emit(builder, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_5, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, protocol)));
    emit(builder, BPF_ST_MEM(BPF_H, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_port), listen_port));
    emit(builder, BPF_ST_MEM(BPF_W, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_addr), prefix0));
    emit(builder, BPF_ST_MEM(BPF_W, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_addr) + 4, prefix1));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_8, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_addr) + 8));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_9, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_addr) + 12));

    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, family), AF_INET6));
    emit(builder, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_5, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, protocol)));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_10, STACK_SAVED_PORT));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_4, 16));
    emit(builder, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_4, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, port)));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_10, STACK_SAVED_V6_LAST_WORD));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, STACK_SAVED_V6_WORD1));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, STACK_SAVED_V6_WORD2));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, addr)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, addr) + 4));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_2, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, addr) + 8));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_4, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, addr) + 12));
    emit_connected_udp_original_flag(builder, protocol_from_context);

    emit_ld_map_fd(builder, BPF_REG_1, redirect_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_REDIRECT_KEY));
    emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_3, STACK_ORIGINAL_DST));
    emit(builder, BPF_MOV64_IMM(BPF_REG_4, BPF_ANY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_update_elem));
    drop_jumps[(*drop_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_0, 0, 0));

    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_ip6), prefix0);
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_ip6) + 4, prefix1);
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_8, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_9, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_port), htons(listen_port));
}

static void emit_ipv4_mapped_redirect_update_and_rewrite(
    struct bpf_builder *builder,
    const struct sb_ebpf_inbound_config *config,
    int redirect_map_fd,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t listen_port,
    size_t *drop_jumps,
    size_t *drop_jump_count) {
    uint32_t redirect_prefix = ipv4_redirect_prefix(
        config->redirect_ipv4_prefix,
        config->redirect_ipv4_prefix_bits);
    uint32_t redirect_host_mask = ipv4_redirect_host_mask(config->redirect_ipv4_prefix_bits);
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_prandom_u32));
    emit(builder, BPF_MOV32_REG(BPF_REG_9, BPF_REG_0));
    emit(builder, BPF_ALU32_IMM_OP(BPF_AND, BPF_REG_9, redirect_host_mask));
    emit(builder, BPF_ALU32_IMM_OP(BPF_OR, BPF_REG_9, redirect_prefix));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_9, 32));
    if (protocol_from_context) {
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, type)));
        emit(builder, BPF_MOV64_IMM(BPF_REG_5, SB_EBPF_PROTO_TCP));
        size_t not_udp = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_4, SOCK_DGRAM, 0));
        emit(builder, BPF_MOV64_IMM(BPF_REG_5, SB_EBPF_PROTO_UDP));
        patch_jump(builder, not_udp, builder->count);
    } else {
        emit(builder, BPF_MOV64_IMM(BPF_REG_5, protocol));
    }

    emit_zero_region(builder, STACK_REDIRECT_KEY, sizeof(struct sb_ebpf_redirect_key));
    emit_zero_region(builder, STACK_ORIGINAL_DST, sizeof(struct sb_ebpf_original_dst));

    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, family), AF_INET));
    emit(builder, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_5, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, protocol)));
    emit(builder, BPF_ST_MEM(BPF_H, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_port), listen_port));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_9, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_addr)));

    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, family), AF_INET));
    emit(builder, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_5, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, protocol)));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_8, 16));
    emit(builder, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_8, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, port)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, addr)));
    emit_connected_udp_original_flag(builder, protocol_from_context);

    emit_ld_map_fd(builder, BPF_REG_1, redirect_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_REDIRECT_KEY));
    emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_3, STACK_ORIGINAL_DST));
    emit(builder, BPF_MOV64_IMM(BPF_REG_4, BPF_ANY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_update_elem));
    drop_jumps[(*drop_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_0, 0, 0));

    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_ip6), 0);
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_ip6) + 4, 0);
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_ip6) + 8, 0xffff0000U);
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_9, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_port), htons(listen_port));
}

static void emit_ipv4_mapped_redirect_from_regs(
    struct bpf_builder *builder,
    const struct sb_ebpf_inbound_config *config,
    int redirect_map_fd,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t listen_port,
    size_t *bypass_jumps,
    size_t *bypass_jump_count,
    size_t *drop_jumps,
    size_t *drop_jump_count,
    size_t *allow_jumps,
    size_t *allow_jump_count) {
    emit_ipv4_destination_bypass(builder, bypass_jumps, bypass_jump_count);
    emit_ipv4_mapped_redirect_update_and_rewrite(
        builder,
        config,
        redirect_map_fd,
        protocol,
        protocol_from_context,
        listen_port,
        drop_jumps,
        drop_jump_count);
    allow_jumps[(*allow_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
}

static bool emit_ipv4_mapped_ipv6_branch(
    struct bpf_builder *builder,
    const struct sb_ebpf_inbound_config *config,
    int redirect_map_fd,
    int udp_peer_map_fd,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t listen_port,
    enum bpf_attach_type attach_type,
    size_t *bypass_jumps,
    size_t *bypass_jump_count,
    size_t *drop_jumps,
    size_t *drop_jump_count,
    size_t *allow_jumps,
    size_t *allow_jump_count) {
    size_t continue_jumps[8];
    size_t continue_jump_count = 0;
    size_t mapped_jumps[2];
    size_t mapped_jump_count = 0;

    if (attach_type == BPF_CGROUP_UDP6_SENDMSG && protocol == SB_EBPF_PROTO_UDP && !protocol_from_context) {
        emit_ipv4_mapped_ipv6_check_jumps(builder, continue_jumps, &continue_jump_count);
        emit(builder, BPF_MOV64_REG(BPF_REG_7, BPF_REG_4));
        emit(builder, BPF_MOV64_REG(BPF_REG_8, BPF_REG_5));
        mapped_jumps[mapped_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
        for (size_t i = 0; i < continue_jump_count; ++i) {
            patch_jump(builder, continue_jumps[i], builder->count);
        }
        continue_jump_count = 0;

        emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
        emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_8));
        emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_9));
        emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_4));
        continue_jumps[continue_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, 0, 0));
        emit(builder, BPF_MOV64_IMM(BPF_REG_7, 0));
        emit(builder, BPF_MOV64_IMM(BPF_REG_8, 0));
        emit_udp_peer_cache_restore_v4(builder, udp_peer_map_fd);
        continue_jumps[continue_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_7, 0, 0));
        continue_jumps[continue_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_8, 0, 0));
        mapped_jumps[mapped_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
    } else if (attach_type == BPF_CGROUP_INET6_CONNECT && protocol_from_context) {
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, protocol)));
        emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_2));
        size_t tcp_connect = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, SB_EBPF_PROTO_TCP, 0));
        continue_jumps[continue_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SB_EBPF_PROTO_UDP, 0));
        patch_jump(builder, tcp_connect, builder->count);
        emit_ipv4_mapped_ipv6_check_jumps(builder, continue_jumps, &continue_jump_count);
        emit(builder, BPF_MOV64_REG(BPF_REG_7, BPF_REG_4));
        emit(builder, BPF_MOV64_REG(BPF_REG_8, BPF_REG_5));
        size_t tcp_destination = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_3, SB_EBPF_PROTO_TCP, 0));
        emit_udp_peer_cache_update_v4mapped(builder, udp_peer_map_fd, bypass_jumps, bypass_jump_count);
        patch_jump(builder, tcp_destination, builder->count);
    } else {
        return false;
    }

    size_t mapped_label = builder->count;
    for (size_t i = 0; i < mapped_jump_count; ++i) {
        patch_jump(builder, mapped_jumps[i], mapped_label);
    }
    emit_ipv4_mapped_redirect_from_regs(
        builder,
        config,
        redirect_map_fd,
        protocol,
        protocol_from_context,
        listen_port,
        bypass_jumps,
        bypass_jump_count,
        drop_jumps,
        drop_jump_count,
        allow_jumps,
        allow_jump_count);
    size_t continue_label = builder->count;
    for (size_t i = 0; i < continue_jump_count; ++i) {
        patch_jump(builder, continue_jumps[i], continue_label);
    }
    return true;
}

static int build_ipv4_sock_addr_prog(
    const struct sb_ebpf_inbound_config *config,
    int redirect_map_fd,
    int udp_peer_map_fd,
    int bypass_socket_cookie_map_fd,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t listen_port,
    enum bpf_attach_type attach_type,
    const char *name) {
    struct bpf_builder b = {0};
    size_t bypass_jumps[96];
    size_t bypass_jump_count = 0;
    size_t drop_jumps[16];
    size_t drop_jump_count = 0;

    emit(&b, BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));
    emit_socket_cookie_bypass(&b, bypass_socket_cookie_map_fd, bypass_jumps, &bypass_jump_count);
    emit_inbound_network_filter(
        &b, config, protocol, protocol_from_context, bypass_jumps, &bypass_jump_count);
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip4)));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    // Connected UDP send() may not hit UDP_SENDMSG on Android kernels, so CONNECT must continue interception.
    // This can expose the redirect peer via getpeername(), but it avoids direct UDP leakage.
    if (attach_type == BPF_CGROUP_INET4_CONNECT && protocol_from_context) {
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, protocol)));
        size_t tcp_connect = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, SB_EBPF_PROTO_TCP, 0));
        bypass_jumps[bypass_jump_count++] =
            emit_jump(&b, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SB_EBPF_PROTO_UDP, 0));
        emit_udp_peer_cache_update(&b, udp_peer_map_fd, false, bypass_jumps, &bypass_jump_count);
        patch_jump(&b, tcp_connect, b.count);
    }
    if (attach_type == BPF_CGROUP_UDP4_SENDMSG && protocol == SB_EBPF_PROTO_UDP && !protocol_from_context) {
        emit_udp_peer_cache_restore_v4(&b, udp_peer_map_fd);
    }
    emit_ipv4_destination_bypass(&b, bypass_jumps, &bypass_jump_count);
    emit_redirect_update_and_rewrite(
        &b,
        config,
        redirect_map_fd,
        protocol,
        protocol_from_context,
        listen_port,
        drop_jumps,
        &drop_jump_count);
    size_t allow_label = emit_exit(&b, 1);
    size_t drop_label = emit_exit(&b, 0);

    for (size_t i = 0; i < bypass_jump_count; ++i) {
        patch_jump(&b, bypass_jumps[i], allow_label);
    }
    for (size_t i = 0; i < drop_jump_count; ++i) {
        patch_jump(&b, drop_jumps[i], drop_label);
    }

    if (b.overflow) {
        errno = EMSGSIZE;
        return -1;
    }
    return sb_ebpf_load_prog(
        b.insns,
        b.count,
        name,
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        attach_type,
        true);
}

static int build_ipv6_sock_addr_prog(
    const struct sb_ebpf_inbound_config *config,
    int redirect_map_fd,
    int udp_peer_map_fd,
    int bypass_socket_cookie_map_fd,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t listen_port,
    enum bpf_attach_type attach_type,
    const char *name) {
    struct bpf_builder b = {0};
    size_t bypass_jumps[96];
    size_t bypass_jump_count = 0;
    size_t drop_jumps[16];
    size_t drop_jump_count = 0;
    size_t allow_jumps[16];
    size_t allow_jump_count = 0;

    emit(&b, BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));
    emit_socket_cookie_bypass(&b, bypass_socket_cookie_map_fd, bypass_jumps, &bypass_jump_count);
    emit_inbound_network_filter(
        &b, config, protocol, protocol_from_context, bypass_jumps, &bypass_jump_count);
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    bool emitted_v4mapped_branch = false;
    if (config->disable_ipv4) {
        size_t not_mapped_jumps[3];
        size_t not_mapped_jump_count = 0;
        emit_ipv4_mapped_ipv6_check_jumps(&b, not_mapped_jumps, &not_mapped_jump_count);
        allow_jumps[allow_jump_count++] = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
        for (size_t i = 0; i < not_mapped_jump_count; ++i) {
            patch_jump(&b, not_mapped_jumps[i], b.count);
        }
    } else {
        emitted_v4mapped_branch = emit_ipv4_mapped_ipv6_branch(
            &b,
            config,
            redirect_map_fd,
            udp_peer_map_fd,
            protocol,
            protocol_from_context,
            listen_port,
            attach_type,
            bypass_jumps,
            &bypass_jump_count,
            drop_jumps,
            &drop_jump_count,
            allow_jumps,
            &allow_jump_count);
    }
    if (emitted_v4mapped_branch) {
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    }
    // Connected UDP send() may not hit UDP_SENDMSG on Android kernels. Rewrite at CONNECT so all
    // packets reach the inbound listener; UDP6_SENDMSG remains a fallback for sendmsg() callers.
    if (attach_type == BPF_CGROUP_INET6_CONNECT && protocol_from_context) {
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, protocol)));
        size_t tcp_connect = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, SB_EBPF_PROTO_TCP, 0));
        bypass_jumps[bypass_jump_count++] =
            emit_jump(&b, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SB_EBPF_PROTO_UDP, 0));
        emit_udp_peer_cache_update(&b, udp_peer_map_fd, true, bypass_jumps, &bypass_jump_count);
        // map_update_elem() invalidates R1-R5. Reload the destination before the common
        // IPv6 interception path reads the address and port registers.
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
        patch_jump(&b, tcp_connect, b.count);
    }
    if (attach_type == BPF_CGROUP_UDP6_SENDMSG && protocol == SB_EBPF_PROTO_UDP && !protocol_from_context) {
        emit_udp_peer_cache_restore_v6(&b, udp_peer_map_fd);
    }
    emit_ipv6_destination_bypass(&b, bypass_jumps, &bypass_jump_count);
    emit_redirect_update_and_rewrite_v6(
        &b,
        config,
        redirect_map_fd,
        protocol,
        protocol_from_context,
        listen_port,
        drop_jumps,
        &drop_jump_count);
    size_t allow_label = emit_exit(&b, 1);
    size_t drop_label = emit_exit(&b, 0);

    for (size_t i = 0; i < bypass_jump_count; ++i) {
        patch_jump(&b, bypass_jumps[i], allow_label);
    }
    for (size_t i = 0; i < allow_jump_count; ++i) {
        patch_jump(&b, allow_jumps[i], allow_label);
    }
    for (size_t i = 0; i < drop_jump_count; ++i) {
        patch_jump(&b, drop_jumps[i], drop_label);
    }

    if (b.overflow) {
        errno = EMSGSIZE;
        return -1;
    }
    return sb_ebpf_load_prog(
        b.insns,
        b.count,
        name,
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        attach_type,
        true);
}

static int build_ipv4_mapped_ipv6_sock_addr_prog(
    const struct sb_ebpf_inbound_config *config,
    int redirect_map_fd,
    int udp_peer_map_fd,
    int bypass_socket_cookie_map_fd,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t listen_port,
    enum bpf_attach_type attach_type,
    const char *name) {
    struct bpf_builder b = {0};
    size_t bypass_jumps[96];
    size_t bypass_jump_count = 0;
    size_t drop_jumps[16];
    size_t drop_jump_count = 0;
    size_t allow_jumps[16];
    size_t allow_jump_count = 0;

    emit(&b, BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));
    emit_socket_cookie_bypass(&b, bypass_socket_cookie_map_fd, bypass_jumps, &bypass_jump_count);
    emit_inbound_network_filter(
        &b, config, protocol, protocol_from_context, bypass_jumps, &bypass_jump_count);
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    (void)emit_ipv4_mapped_ipv6_branch(
        &b,
        config,
        redirect_map_fd,
        udp_peer_map_fd,
        protocol,
        protocol_from_context,
        listen_port,
        attach_type,
        bypass_jumps,
        &bypass_jump_count,
        drop_jumps,
        &drop_jump_count,
        allow_jumps,
        &allow_jump_count);
    size_t allow_label = emit_exit(&b, 1);
    size_t drop_label = emit_exit(&b, 0);

    for (size_t i = 0; i < bypass_jump_count; ++i) {
        patch_jump(&b, bypass_jumps[i], allow_label);
    }
    for (size_t i = 0; i < allow_jump_count; ++i) {
        patch_jump(&b, allow_jumps[i], allow_label);
    }
    for (size_t i = 0; i < drop_jump_count; ++i) {
        patch_jump(&b, drop_jumps[i], drop_label);
    }

    if (b.overflow) {
        errno = EMSGSIZE;
        return -1;
    }
    return sb_ebpf_load_prog(
        b.insns,
        b.count,
        name,
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        attach_type,
        true);
}

static int build_udp4_recvmsg_prog(
    const struct sb_ebpf_inbound_config *config,
    int redirect_map_fd,
    const char *name) {
    struct bpf_builder b = {0};
    size_t bypass_jumps[8];
    size_t bypass_jump_count = 0;

    emit(&b, BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip4)));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));

    emit(&b, BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
    emit(&b, BPF_ENDIAN_OP(BPF_REG_2, 32));
    uint32_t redirect_host_mask = ipv4_redirect_host_mask(config->redirect_ipv4_prefix_bits);
    uint32_t redirect_network_mask = ~redirect_host_mask;
    uint32_t redirect_prefix = ipv4_redirect_prefix(
        config->redirect_ipv4_prefix,
        config->redirect_ipv4_prefix_bits);
    emit(&b, BPF_ALU64_IMM_OP(BPF_AND, BPF_REG_2, redirect_network_mask));
    bypass_jumps[bypass_jump_count++] = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, redirect_prefix, 0));

    emit_zero_region(&b, STACK_REDIRECT_KEY, sizeof(struct sb_ebpf_redirect_key));
    emit(&b, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, family), AF_INET));
    emit(&b, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, protocol), SB_EBPF_PROTO_UDP));
    emit(&b, BPF_ENDIAN_OP(BPF_REG_8, 16));
    emit(&b, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_8, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_port)));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_addr)));

    emit_ld_map_fd(&b, BPF_REG_1, redirect_map_fd);
    emit(&b, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(&b, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_REDIRECT_KEY));
    emit(&b, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    bypass_jumps[bypass_jump_count++] = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));

    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, offsetof(struct sb_ebpf_original_dst, addr)));
    emit(&b, BPF_LDX_MEM(BPF_H, BPF_REG_8, BPF_REG_0, offsetof(struct sb_ebpf_original_dst, port)));
    emit(&b, BPF_ENDIAN_OP(BPF_REG_8, 16));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_7, offsetof(struct bpf_sock_addr, user_ip4)));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_8, offsetof(struct bpf_sock_addr, user_port)));

    size_t allow_label = emit_exit(&b, 1);
    for (size_t i = 0; i < bypass_jump_count; ++i) {
        patch_jump(&b, bypass_jumps[i], allow_label);
    }

    if (b.overflow) {
        errno = EMSGSIZE;
        return -1;
    }
    return sb_ebpf_load_prog(
        b.insns,
        b.count,
        name,
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        BPF_CGROUP_UDP4_RECVMSG,
        true);
}

static int build_udp6_recvmsg_prog(
    const struct sb_ebpf_inbound_config *config,
    int redirect_map_fd,
    const char *name) {
    struct bpf_builder b = {0};
    size_t bypass_jumps[8];
    size_t bypass_jump_count = 0;

    emit(&b, BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));

    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    emit_ipv4_mapped_ipv6_check_jumps(&b, bypass_jumps, &bypass_jump_count);
    emit(&b, BPF_MOV64_REG(BPF_REG_2, BPF_REG_4));
    emit(&b, BPF_ENDIAN_OP(BPF_REG_2, 32));
    uint32_t redirect_host_mask = ipv4_redirect_host_mask(config->redirect_ipv4_prefix_bits);
    uint32_t redirect_network_mask = ~redirect_host_mask;
    uint32_t redirect_prefix = ipv4_redirect_prefix(
        config->redirect_ipv4_prefix,
        config->redirect_ipv4_prefix_bits);
    emit(&b, BPF_ALU64_IMM_OP(BPF_AND, BPF_REG_2, redirect_network_mask));
    bypass_jumps[bypass_jump_count++] = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, redirect_prefix, 0));

    emit_zero_region(&b, STACK_REDIRECT_KEY, sizeof(struct sb_ebpf_redirect_key));
    emit(&b, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, family), AF_INET));
    emit(&b, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, protocol), SB_EBPF_PROTO_UDP));
    emit(&b, BPF_ENDIAN_OP(BPF_REG_5, 16));
    emit(&b, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_5, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_port)));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_4, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_addr)));

    emit_ld_map_fd(&b, BPF_REG_1, redirect_map_fd);
    emit(&b, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(&b, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_REDIRECT_KEY));
    emit(&b, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    bypass_jumps[bypass_jump_count++] = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));

    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, offsetof(struct sb_ebpf_original_dst, addr)));
    emit(&b, BPF_LDX_MEM(BPF_H, BPF_REG_8, BPF_REG_0, offsetof(struct sb_ebpf_original_dst, port)));
    emit(&b, BPF_ENDIAN_OP(BPF_REG_8, 16));
    emit_ctx_st32(&b, offsetof(struct bpf_sock_addr, user_ip6), 0);
    emit_ctx_st32(&b, offsetof(struct bpf_sock_addr, user_ip6) + 4, 0);
    emit_ctx_st32(&b, offsetof(struct bpf_sock_addr, user_ip6) + 8, 0xffff0000U);
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_7, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_8, offsetof(struct bpf_sock_addr, user_port)));
    size_t v4mapped_allow = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));

    size_t ipv6_lookup_label = b.count;
    for (size_t i = 0; i < bypass_jump_count; ++i) {
        patch_jump(&b, bypass_jumps[i], ipv6_lookup_label);
    }
    bypass_jump_count = 0;

    emit_zero_region(&b, STACK_REDIRECT_KEY, sizeof(struct sb_ebpf_redirect_key));
    emit(&b, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, family), AF_INET6));
    emit(&b, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, protocol), SB_EBPF_PROTO_UDP));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    emit(&b, BPF_ENDIAN_OP(BPF_REG_7, 16));
    emit(&b, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_7, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_port)));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_addr)));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_8, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_addr) + 4));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_9, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_addr) + 8));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_4, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_addr) + 12));

    emit_ld_map_fd(&b, BPF_REG_1, redirect_map_fd);
    emit(&b, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(&b, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_REDIRECT_KEY));
    emit(&b, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    bypass_jumps[bypass_jump_count++] = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));

    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, offsetof(struct sb_ebpf_original_dst, addr)));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, offsetof(struct sb_ebpf_original_dst, addr) + 4));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_0, offsetof(struct sb_ebpf_original_dst, addr) + 8));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_0, offsetof(struct sb_ebpf_original_dst, addr) + 12));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_7, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_8, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_9, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_4, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(&b, BPF_LDX_MEM(BPF_H, BPF_REG_7, BPF_REG_0, offsetof(struct sb_ebpf_original_dst, port)));
    emit(&b, BPF_ENDIAN_OP(BPF_REG_7, 16));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_7, offsetof(struct bpf_sock_addr, user_port)));

    size_t allow_label = emit_exit(&b, 1);
    for (size_t i = 0; i < bypass_jump_count; ++i) {
        patch_jump(&b, bypass_jumps[i], allow_label);
    }
    patch_jump(&b, v4mapped_allow, allow_label);

    if (b.overflow) {
        errno = EMSGSIZE;
        return -1;
    }
    return sb_ebpf_load_prog(
        b.insns,
        b.count,
        name,
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        BPF_CGROUP_UDP6_RECVMSG,
        true);
}

static int open_cgroup_path(const char *path) {
    const char *actual = path != NULL && path[0] != '\0' ? path : SB_EBPF_DEFAULT_CGROUP_PATH;
    return open(actual, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
}

int sb_ebpf_inbound_prepare(
	const char *cgroup_path,
	uint16_t listen_port,
	bool enable_tcp,
	bool enable_udp,
	bool enable_ipv4,
	const uint8_t redirect_ipv4[4],
	uint32_t redirect_ipv4_prefix_bits,
	bool enable_ipv6,
	const uint8_t redirect_ipv6[16],
	uint32_t redirect_ipv6_prefix_bits,
	struct sb_ebpf_inbound_runtime *runtime) {
    if (runtime == NULL || listen_port == 0U || (!enable_tcp && !enable_udp) ||
        (!enable_ipv4 && !enable_ipv6) ||
        (enable_ipv4 && (redirect_ipv4 == NULL ||
                         redirect_ipv4_prefix_bits < 8U ||
                         redirect_ipv4_prefix_bits > 10U)) ||
        (enable_ipv6 && (redirect_ipv6 == NULL || redirect_ipv6_prefix_bits != 64U))) {
        errno = EINVAL;
        return -1;
    }

    init_runtime(runtime);
    struct sb_ebpf_inbound_config config;
    memset(&config, 0, sizeof(config));
    config.inbound_network =
        (enable_tcp ? SB_EBPF_NETWORK_TCP : 0U) |
        (enable_udp ? SB_EBPF_NETWORK_UDP : 0U);
    config.disable_ipv4 = !enable_ipv4;
    if (enable_ipv4) {
        memcpy(config.redirect_ipv4_prefix, redirect_ipv4, sizeof(config.redirect_ipv4_prefix));
        config.redirect_ipv4_prefix_bits = redirect_ipv4_prefix_bits;
    }
    if (enable_ipv6) {
        memcpy(config.redirect_ipv6_prefix, redirect_ipv6, sizeof(config.redirect_ipv6_prefix));
        config.redirect_ipv6_prefix_bits = redirect_ipv6_prefix_bits;
    }
    runtime->redirect_map_fd = create_redirect_map(SB_EBPF_MAX_REDIRECT_MAP_ENTRIES);
    runtime->udp_peer_map_fd = create_udp_peer_map(SB_EBPF_MAX_UDP_PEER_MAP_ENTRIES);
    runtime->bypass_socket_cookie_map_fd = create_bypass_socket_cookie_map(SB_EBPF_MAX_REDIRECT_MAP_ENTRIES);
    if (runtime->redirect_map_fd < 0 || runtime->udp_peer_map_fd < 0 ||
        runtime->bypass_socket_cookie_map_fd < 0) {
        goto fail;
    }

    runtime->cgroup_fd = open_cgroup_path(cgroup_path);
    if (runtime->cgroup_fd < 0 || sb_ebpf_detach_owned_progs(runtime->cgroup_fd) < 0) {
        goto fail;
    }

    if (enable_ipv4) {
        runtime->connect4_prog_fd = build_ipv4_sock_addr_prog(
            &config,
            runtime->redirect_map_fd,
            runtime->udp_peer_map_fd,
            runtime->bypass_socket_cookie_map_fd,
            SB_EBPF_PROTO_TCP,
            true,
            listen_port,
            BPF_CGROUP_INET4_CONNECT,
            "sb_ebpf_conn4");
        if (enable_udp) {
            runtime->udp4_sendmsg_prog_fd = build_ipv4_sock_addr_prog(
                &config,
                runtime->redirect_map_fd,
                runtime->udp_peer_map_fd,
                runtime->bypass_socket_cookie_map_fd,
                SB_EBPF_PROTO_UDP,
                false,
                listen_port,
                BPF_CGROUP_UDP4_SENDMSG,
                "sb_ebpf_udp4");
            runtime->udp4_recvmsg_prog_fd = build_udp4_recvmsg_prog(
                &config,
                runtime->redirect_map_fd,
                "sb_ebpf_urcv4");
        }
    }
    if (enable_ipv6) {
        runtime->connect6_prog_fd = build_ipv6_sock_addr_prog(
            &config,
            runtime->redirect_map_fd,
            runtime->udp_peer_map_fd,
            runtime->bypass_socket_cookie_map_fd,
            SB_EBPF_PROTO_TCP,
            true,
            listen_port,
            BPF_CGROUP_INET6_CONNECT,
            "sb_ebpf_conn6");
        if (enable_udp) {
            runtime->udp6_sendmsg_prog_fd = build_ipv6_sock_addr_prog(
                &config,
                runtime->redirect_map_fd,
                runtime->udp_peer_map_fd,
                runtime->bypass_socket_cookie_map_fd,
                SB_EBPF_PROTO_UDP,
                false,
                listen_port,
                BPF_CGROUP_UDP6_SENDMSG,
                "sb_ebpf_udp6");
            runtime->udp6_recvmsg_prog_fd = build_udp6_recvmsg_prog(
                &config,
                runtime->redirect_map_fd,
                "sb_ebpf_urcv6");
        }
    } else {
        runtime->connect6_v4mapped_prog_fd = build_ipv4_mapped_ipv6_sock_addr_prog(
            &config,
            runtime->redirect_map_fd,
            runtime->udp_peer_map_fd,
            runtime->bypass_socket_cookie_map_fd,
            SB_EBPF_PROTO_TCP,
            true,
            listen_port,
            BPF_CGROUP_INET6_CONNECT,
            "sb_ebpf_c6v4m");
        if (enable_udp) {
            runtime->udp6_v4mapped_sendmsg_prog_fd = build_ipv4_mapped_ipv6_sock_addr_prog(
                &config,
                runtime->redirect_map_fd,
                runtime->udp_peer_map_fd,
                runtime->bypass_socket_cookie_map_fd,
                SB_EBPF_PROTO_UDP,
                false,
                listen_port,
                BPF_CGROUP_UDP6_SENDMSG,
                "sb_ebpf_u6v4m");
            runtime->udp6_v4mapped_recvmsg_prog_fd = build_udp6_recvmsg_prog(
                &config,
                runtime->redirect_map_fd,
                "sb_ebpf_ur6v4m");
        }
    }
    if ((enable_ipv4 &&
         (runtime->connect4_prog_fd < 0 ||
          (enable_udp &&
           (runtime->udp4_sendmsg_prog_fd < 0 || runtime->udp4_recvmsg_prog_fd < 0)))) ||
        (enable_ipv6 &&
         (runtime->connect6_prog_fd < 0 ||
          (enable_udp &&
           (runtime->udp6_sendmsg_prog_fd < 0 || runtime->udp6_recvmsg_prog_fd < 0)))) ||
        (!enable_ipv6 &&
         (runtime->connect6_v4mapped_prog_fd < 0 ||
          (enable_udp &&
           (runtime->udp6_v4mapped_sendmsg_prog_fd < 0 ||
            runtime->udp6_v4mapped_recvmsg_prog_fd < 0))))) {
        goto fail;
    }
    return 0;

fail:
    sb_ebpf_inbound_close(runtime);
    return -1;
}

int sb_ebpf_inbound_attach(struct sb_ebpf_inbound_runtime *runtime) {
    if (runtime == NULL || runtime->cgroup_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    if ((runtime->connect4_prog_fd >= 0 && sb_ebpf_attach_prog(
            runtime->cgroup_fd, runtime->connect4_prog_fd, BPF_CGROUP_INET4_CONNECT) < 0) ||
        (runtime->udp4_sendmsg_prog_fd >= 0 && sb_ebpf_attach_prog(
            runtime->cgroup_fd, runtime->udp4_sendmsg_prog_fd, BPF_CGROUP_UDP4_SENDMSG) < 0) ||
        (runtime->udp4_recvmsg_prog_fd >= 0 && sb_ebpf_attach_prog(
            runtime->cgroup_fd, runtime->udp4_recvmsg_prog_fd, BPF_CGROUP_UDP4_RECVMSG) < 0) ||
        (runtime->connect6_prog_fd >= 0 && sb_ebpf_attach_prog(
            runtime->cgroup_fd, runtime->connect6_prog_fd, BPF_CGROUP_INET6_CONNECT) < 0) ||
        (runtime->udp6_sendmsg_prog_fd >= 0 && sb_ebpf_attach_prog(
            runtime->cgroup_fd, runtime->udp6_sendmsg_prog_fd, BPF_CGROUP_UDP6_SENDMSG) < 0) ||
        (runtime->udp6_recvmsg_prog_fd >= 0 && sb_ebpf_attach_prog(
            runtime->cgroup_fd, runtime->udp6_recvmsg_prog_fd, BPF_CGROUP_UDP6_RECVMSG) < 0) ||
        (runtime->connect6_v4mapped_prog_fd >= 0 && sb_ebpf_attach_prog(
            runtime->cgroup_fd, runtime->connect6_v4mapped_prog_fd, BPF_CGROUP_INET6_CONNECT) < 0) ||
        (runtime->udp6_v4mapped_sendmsg_prog_fd >= 0 && sb_ebpf_attach_prog(
            runtime->cgroup_fd, runtime->udp6_v4mapped_sendmsg_prog_fd, BPF_CGROUP_UDP6_SENDMSG) < 0) ||
        (runtime->udp6_v4mapped_recvmsg_prog_fd >= 0 && sb_ebpf_attach_prog(
            runtime->cgroup_fd, runtime->udp6_v4mapped_recvmsg_prog_fd, BPF_CGROUP_UDP6_RECVMSG) < 0)) {
        int saved = errno;
        sb_ebpf_inbound_close(runtime);
        errno = saved;
        return -1;
    }
    return 0;
}

void sb_ebpf_inbound_close(struct sb_ebpf_inbound_runtime *runtime) {
    if (runtime == NULL) return;
    if (runtime->cgroup_fd >= 0) {
        if (runtime->udp6_recvmsg_prog_fd >= 0) {
            (void)sb_ebpf_detach_prog(runtime->cgroup_fd, runtime->udp6_recvmsg_prog_fd, BPF_CGROUP_UDP6_RECVMSG);
        }
        if (runtime->udp6_sendmsg_prog_fd >= 0) {
            (void)sb_ebpf_detach_prog(runtime->cgroup_fd, runtime->udp6_sendmsg_prog_fd, BPF_CGROUP_UDP6_SENDMSG);
        }
        if (runtime->udp6_v4mapped_recvmsg_prog_fd >= 0) {
            (void)sb_ebpf_detach_prog(runtime->cgroup_fd, runtime->udp6_v4mapped_recvmsg_prog_fd, BPF_CGROUP_UDP6_RECVMSG);
        }
        if (runtime->udp6_v4mapped_sendmsg_prog_fd >= 0) {
            (void)sb_ebpf_detach_prog(runtime->cgroup_fd, runtime->udp6_v4mapped_sendmsg_prog_fd, BPF_CGROUP_UDP6_SENDMSG);
        }
        if (runtime->connect6_prog_fd >= 0) {
            (void)sb_ebpf_detach_prog(runtime->cgroup_fd, runtime->connect6_prog_fd, BPF_CGROUP_INET6_CONNECT);
        }
        if (runtime->connect6_v4mapped_prog_fd >= 0) {
            (void)sb_ebpf_detach_prog(runtime->cgroup_fd, runtime->connect6_v4mapped_prog_fd, BPF_CGROUP_INET6_CONNECT);
        }
        if (runtime->udp4_recvmsg_prog_fd >= 0) {
            (void)sb_ebpf_detach_prog(runtime->cgroup_fd, runtime->udp4_recvmsg_prog_fd, BPF_CGROUP_UDP4_RECVMSG);
        }
        if (runtime->udp4_sendmsg_prog_fd >= 0) {
            (void)sb_ebpf_detach_prog(runtime->cgroup_fd, runtime->udp4_sendmsg_prog_fd, BPF_CGROUP_UDP4_SENDMSG);
        }
        if (runtime->connect4_prog_fd >= 0) {
            (void)sb_ebpf_detach_prog(runtime->cgroup_fd, runtime->connect4_prog_fd, BPF_CGROUP_INET4_CONNECT);
        }
    }
    close_fd(&runtime->udp6_v4mapped_recvmsg_prog_fd);
    close_fd(&runtime->udp6_recvmsg_prog_fd);
    close_fd(&runtime->udp4_recvmsg_prog_fd);
    close_fd(&runtime->udp6_v4mapped_sendmsg_prog_fd);
    close_fd(&runtime->udp6_sendmsg_prog_fd);
    close_fd(&runtime->udp4_sendmsg_prog_fd);
    close_fd(&runtime->connect6_v4mapped_prog_fd);
    close_fd(&runtime->connect6_prog_fd);
    close_fd(&runtime->connect4_prog_fd);
    close_fd(&runtime->bypass_socket_cookie_map_fd);
    close_fd(&runtime->udp_peer_map_fd);
    close_fd(&runtime->redirect_map_fd);
    close_fd(&runtime->cgroup_fd);
}
