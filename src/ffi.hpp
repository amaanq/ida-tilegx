// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#include <cstddef>
#include <cstdint>

// C++ view of the Rust #[repr(C)] ABI in src/types.rs and src/lib.rs.
extern "C" {

struct TgOp {
   uint8_t kind;
   uint8_t dtype;
   uint16_t reg;
   uint32_t _reserved;
   int64_t value;
};

struct TgSlot {
   uint16_t itype;
   uint8_t n_ops;
   uint8_t _reserved;
   TgOp ops[4];
};

struct TgBundle {
   uint8_t n_slots;
   uint8_t _reserved[7];
   TgSlot slots[3];
};

struct TgRowView {
   uint8_t valid;
   uint8_t n_slots;
   uint8_t size;
   uint8_t next_offset;
   uint8_t flags;
   uint8_t slots[3];
};

struct TgCodeRef {
   uint8_t kind;
   uint8_t _reserved[7];
   uint64_t target;
};

struct TgRowRefs {
   uint8_t n_refs;
   uint8_t _reserved[7];
   TgCodeRef refs[12];
};

struct TgMemRef {
   uint8_t kind;
   uint8_t size;
   uint8_t _reserved[6];
   uint64_t target;
};

struct TgDataRef {
   uint8_t kind;
   uint8_t reg;
   uint8_t _reserved[6];
   uint64_t target;
};

struct TgRegAccess {
   uint16_t reg;
   uint8_t op_index;
   uint8_t access;
};

struct TgRegAccesses {
   uint8_t n_accesses;
   uint8_t _reserved[7];
   TgRegAccess accesses[16];
};

struct TgPrologState {
   uint64_t saved_regs;
   int64_t current_sp_delta;
   int64_t min_sp_delta;
   uint32_t frame_size;
   uint8_t rows;
   uint8_t has_frame_pointer;
   uint8_t saved_link;
   uint8_t _reserved[5];
};

struct TgRawFileVerdict {
   uint8_t accepted;
   uint8_t _reserved[3];
   uint32_t score;
   uint32_t decoded_bundles;
   uint32_t total_bundles;
   uint32_t sampled_bytes;
   uint64_t runtime_base;
};

struct TgRowAnalysis {
   TgRowView row;
   TgSlot first_slot;
   TgRowRefs refs;
};

struct TgCodeRows {
   uint8_t n_rows;
   uint8_t offsets[2];
   uint8_t _reserved;
};

struct TgConstState {
   uint64_t valid;
   uint64_t values[64];
   uint8_t depths[64];
};

struct TgAbiLayout {
   uint32_t magic;
   uint32_t version;
   size_t tg_op_size;
   size_t tg_op_align;
   size_t tg_slot_size;
   size_t tg_slot_align;
   size_t tg_bundle_size;
   size_t tg_bundle_align;
   size_t tg_row_view_size;
   size_t tg_row_view_align;
   size_t tg_code_ref_size;
   size_t tg_code_ref_align;
   size_t tg_row_refs_size;
   size_t tg_row_refs_align;
   size_t tg_mem_ref_size;
   size_t tg_mem_ref_align;
   size_t tg_data_ref_size;
   size_t tg_data_ref_align;
   size_t tg_reg_access_size;
   size_t tg_reg_access_align;
   size_t tg_reg_accesses_size;
   size_t tg_reg_accesses_align;
   size_t tg_prolog_state_size;
   size_t tg_prolog_state_align;
   size_t tg_raw_verdict_size;
   size_t tg_raw_verdict_align;
   size_t tg_row_analysis_size;
   size_t tg_row_analysis_align;
   size_t tg_code_rows_size;
   size_t tg_code_rows_align;
   size_t tg_const_state_size;
   size_t tg_const_state_align;
   size_t string_max_bytes;
   size_t string_scan_bytes;
};

int tg_decode_bundle(const uint8_t *bytes, uint64_t pc, TgBundle *out);
int tg_analyze_row(const TgBundle *bundle, uint8_t offset, TgRowAnalysis *out);
int tg_bundle_code_rows(const TgBundle *bundle, TgCodeRows *out);
int tg_row_align_size(const TgBundle *bundle, uint8_t offset);
int tg_row_sp_delta(const TgBundle *bundle, uint8_t offset, int64_t *out);
int tg_row_may_be_func(const TgBundle *bundle, uint8_t offset, int state);
int tg_row_reg_accesses(const TgBundle *bundle, uint8_t offset, TgRegAccesses *out);
void tg_prolog_state_reset(TgPrologState *state);
int tg_prolog_scan_row(const TgBundle *bundle, uint8_t offset, TgPrologState *state);
int tg_likely_c_string(const uint8_t *bytes, size_t len, size_t *out_len);
int tg_find_reg(const char *name);
int tg_autocmt(uint16_t itype, char *out, size_t out_len);
int tg_format_spr(uint32_t spr, char *out, size_t out_len);
void tg_const_state_reset(TgConstState *state);
int tg_const_state_apply_slot(const TgSlot *slot, TgConstState *state, char *out, size_t out_len, TgMemRef *mem_ref,
                              TgDataRef *data_ref);
TgRawFileVerdict tg_detect_raw_tilegx(const uint8_t *bytes, size_t len);
TgAbiLayout tg_abi_layout();

} // extern "C"

static constexpr uint32_t TG_ABI_LAYOUT_MAGIC = 0x54475841;
static constexpr uint32_t TG_ABI_LAYOUT_VERSION = 3;
static constexpr size_t TG_STRING_MAX_BYTES = 512;
static constexpr size_t TG_STRING_SCAN_BYTES = TG_STRING_MAX_BYTES + 1;

static_assert(sizeof(TgOp) == 16, "TgOp layout");
static_assert(alignof(TgOp) == 8, "TgOp alignment");
static_assert(sizeof(TgSlot) == 72, "TgSlot layout");
static_assert(alignof(TgSlot) == 8, "TgSlot alignment");
static_assert(sizeof(TgBundle) == 224, "TgBundle layout");
static_assert(alignof(TgBundle) == 8, "TgBundle alignment");
static_assert(sizeof(TgRowView) == 8, "TgRowView layout");
static_assert(alignof(TgRowView) == 1, "TgRowView alignment");
static_assert(sizeof(TgCodeRef) == 16, "TgCodeRef layout");
static_assert(alignof(TgCodeRef) == 8, "TgCodeRef alignment");
static_assert(sizeof(TgRowRefs) == 200, "TgRowRefs layout");
static_assert(alignof(TgRowRefs) == 8, "TgRowRefs alignment");
static_assert(sizeof(TgMemRef) == 16, "TgMemRef layout");
static_assert(alignof(TgMemRef) == 8, "TgMemRef alignment");
static_assert(sizeof(TgDataRef) == 16, "TgDataRef layout");
static_assert(alignof(TgDataRef) == 8, "TgDataRef alignment");
static_assert(sizeof(TgRegAccess) == 4, "TgRegAccess layout");
static_assert(alignof(TgRegAccess) == 2, "TgRegAccess alignment");
static_assert(sizeof(TgRegAccesses) == 72, "TgRegAccesses layout");
static_assert(alignof(TgRegAccesses) == 2, "TgRegAccesses alignment");
static_assert(sizeof(TgPrologState) == 40, "TgPrologState layout");
static_assert(alignof(TgPrologState) == 8, "TgPrologState alignment");
static_assert(sizeof(TgRawFileVerdict) == 32, "TgRawFileVerdict layout");
static_assert(alignof(TgRawFileVerdict) == 8, "TgRawFileVerdict alignment");
static_assert(sizeof(TgRowAnalysis) == 280, "TgRowAnalysis layout");
static_assert(alignof(TgRowAnalysis) == 8, "TgRowAnalysis alignment");
static_assert(sizeof(TgCodeRows) == 4, "TgCodeRows layout");
static_assert(alignof(TgCodeRows) == 1, "TgCodeRows alignment");
static_assert(sizeof(TgConstState) == 584, "TgConstState layout");
static_assert(alignof(TgConstState) == 8, "TgConstState alignment");
static_assert(sizeof(TgAbiLayout) == 264, "TgAbiLayout layout");
static_assert(alignof(TgAbiLayout) == alignof(size_t), "TgAbiLayout alignment");

static inline bool tg_abi_layout_matches() {
   const TgAbiLayout layout = tg_abi_layout();
   return layout.magic == TG_ABI_LAYOUT_MAGIC && layout.version == TG_ABI_LAYOUT_VERSION &&
          layout.tg_op_size == sizeof(TgOp) && layout.tg_op_align == alignof(TgOp) &&
          layout.tg_slot_size == sizeof(TgSlot) && layout.tg_slot_align == alignof(TgSlot) &&
          layout.tg_bundle_size == sizeof(TgBundle) && layout.tg_bundle_align == alignof(TgBundle) &&
          layout.tg_row_view_size == sizeof(TgRowView) && layout.tg_row_view_align == alignof(TgRowView) &&
          layout.tg_code_ref_size == sizeof(TgCodeRef) && layout.tg_code_ref_align == alignof(TgCodeRef) &&
          layout.tg_row_refs_size == sizeof(TgRowRefs) && layout.tg_row_refs_align == alignof(TgRowRefs) &&
          layout.tg_mem_ref_size == sizeof(TgMemRef) && layout.tg_mem_ref_align == alignof(TgMemRef) &&
          layout.tg_data_ref_size == sizeof(TgDataRef) && layout.tg_data_ref_align == alignof(TgDataRef) &&
          layout.tg_reg_access_size == sizeof(TgRegAccess) && layout.tg_reg_access_align == alignof(TgRegAccess) &&
          layout.tg_reg_accesses_size == sizeof(TgRegAccesses) &&
          layout.tg_reg_accesses_align == alignof(TgRegAccesses) &&
          layout.tg_prolog_state_size == sizeof(TgPrologState) &&
          layout.tg_prolog_state_align == alignof(TgPrologState) &&
          layout.tg_raw_verdict_size == sizeof(TgRawFileVerdict) &&
          layout.tg_raw_verdict_align == alignof(TgRawFileVerdict) &&
          layout.tg_row_analysis_size == sizeof(TgRowAnalysis) &&
          layout.tg_row_analysis_align == alignof(TgRowAnalysis) && layout.tg_code_rows_size == sizeof(TgCodeRows) &&
          layout.tg_code_rows_align == alignof(TgCodeRows) && layout.tg_const_state_size == sizeof(TgConstState) &&
          layout.tg_const_state_align == alignof(TgConstState) && layout.string_max_bytes == TG_STRING_MAX_BYTES &&
          layout.string_scan_bytes == TG_STRING_SCAN_BYTES;
}

static constexpr uint8_t TG_OP_REG = 1;
static constexpr uint8_t TG_OP_IMM = 2;
static constexpr uint8_t TG_OP_NEAR = 3;
static constexpr uint8_t TG_OP_SPR = 4;
static constexpr uint8_t TG_OP_MEM = 5;

static constexpr uint8_t TG_CREF_JUMP = 0;
static constexpr uint8_t TG_CREF_CALL = 1;
static constexpr uint8_t TG_MEMREF_READ = 1;
static constexpr uint8_t TG_MEMREF_WRITE = 2;
static constexpr uint8_t TG_MEMREF_READ_WRITE = 3;
static constexpr uint8_t TG_DATAREF_IMM = 1;
static constexpr uint8_t TG_ACCESS_READ = 1;
static constexpr uint8_t TG_ACCESS_WRITE = 2;

static constexpr uint8_t TG_ROW_CALL = 1 << 0;
static constexpr uint8_t TG_ROW_RET = 1 << 1;
static constexpr uint8_t TG_ROW_COND_JUMP = 1 << 2;
static constexpr uint8_t TG_ROW_STOP = 1 << 3;
static constexpr uint8_t TG_ROW_JUMP = 1 << 4;
static constexpr uint8_t TG_ROW_INDIRECT_JUMP = 1 << 5;
