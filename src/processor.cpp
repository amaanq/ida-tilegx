// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// C++ ABI glue between IDA's processor SDK and the Rust decoder.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include <auto.hpp>
#include <bytes.hpp>
#include <entry.hpp>
#include <frame.hpp>
#include <funcs.hpp>
#include <idp.hpp>
#include <lines.hpp>
#include <nalt.hpp>
#include <name.hpp>
#include <segment.hpp>
#include <typeinf.hpp>
#include <ua.hpp>
#include <xref.hpp>

#include "ffi.hpp"
#include "generated.h" // INSTRUCTIONS[], REG_NAMES[] (from isa/tilegx-gen.nu)

static constexpr int PLFM_TILEGX = 0x8369;
static constexpr int EM_TILEGX = 191;
static constexpr size_t BUNDLE_SIZE = 8;
static constexpr ea_t BUNDLE_MASK = static_cast<ea_t>(BUNDLE_SIZE - 1);
static constexpr size_t CONST_COMMENT_BUFSIZE = 96;
static constexpr size_t STRING_COMMENT_BUFSIZE = 192;
static constexpr size_t STRING_COMMENT_CODEPOINTS = 120;
static constexpr size_t AUTOCMT_BUFSIZE = 128;
static constexpr size_t SPR_NAME_BUFSIZE = 32;
static constexpr size_t PROLOG_SCAN_LIMIT = 0x100;
static constexpr int MNEMONIC_WIDTH = 22;
static constexpr uint16_t SP_REG = 54;
static constexpr size_t STACK_NAME_BUFSIZE = 32;
static constexpr uint64_t TILEGX_RUNTIME_ALIAS_BASE = 0x80000000;
static constexpr int NUM_REGS = static_cast<int>(sizeof(REG_NAMES) / sizeof(REG_NAMES[0]));
static constexpr int NUM_INSTRUCTIONS = static_cast<int>(sizeof(INSTRUCTIONS) / sizeof(INSTRUCTIONS[0]));

static uint64_t abs_magnitude(int64_t value) {
   const auto raw = static_cast<uint64_t>(value);
   return value < 0 ? ~raw + 1 : raw;
}

static const char *const SHORT_NAMES[] = {"tilegx", nullptr};
static const char *const LONG_NAMES[] = {"Tilera Tile-GX", nullptr};

static asm_t gas = {
    ASH_HEXF3 | ASD_DECF0 | ASO_OCTF1 | ASB_BINF3 | AS_N2CHR | AS_LALIGN | AS_1TEXT | AS_ONEDUP | AS_COLON,
    0,
    "GNU assembler",
    0,
    nullptr,
    ".org",
    ".end",
    ";",
    '"',
    '\'',
    "\"'",
    ".ascii",
    ".byte",
    ".short",
    ".long",
    ".quad",
    nullptr,
    ".float",
    ".double",
    nullptr,
    nullptr,
    ".ds.#s(b,w,l,q) #d, #v",
    ".space %s",
    "=",
    nullptr,
    ".",
    nullptr,
    nullptr,
    ".globl",
    nullptr,
    ".extern",
    nullptr,
    nullptr,
    ".align",
    '(',
    ')',
    "%",
    "&",
    "|",
    "^",
    "~",
    "<<",
    ">>",
    nullptr,
    0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
};
static asm_t *const ASSEMBLERS[] = {&gas, nullptr};

static void clear_operand(op_t &op) {
   op.type = o_void;
   op.offb = 0;
   op.offo = 0;
   op.flags = 0;
   op.dtype = dt_void;
   op.reg = 0;
   op.value = 0;
   op.addr = 0;
   op.specval = 0;
   op.specflag1 = 0;
   op.specflag2 = 0;
   op.specflag3 = 0;
   op.specflag4 = 0;
}

static op_dtype_t dtype_for_mem_size(uint8_t size) {
   switch (size) {
      case 1:
         return dt_byte;
      case 2:
         return dt_word;
      case 4:
         return dt_dword;
      default:
         return dt_qword;
   }
}

static const char *slot_name(const TgSlot &slot) {
   if (slot.itype == 0 || slot.itype >= NUM_INSTRUCTIONS) {
      return "";
   }
   return INSTRUCTIONS[slot.itype].name;
}

static bool slot_reg(const TgSlot &slot, int index, uint16_t reg) {
   return index < slot.n_ops && slot.ops[index].kind == TG_OP_REG && slot.ops[index].reg == reg;
}

static bool slot_reg(const TgSlot &slot, int index, uint16_t *reg) {
   if (index >= slot.n_ops || slot.ops[index].kind != TG_OP_REG) {
      return false;
   }
   *reg = slot.ops[index].reg;
   return true;
}

static bool slot_imm(const TgSlot &slot, int index, sval_t *value) {
   if (index >= slot.n_ops || slot.ops[index].kind != TG_OP_IMM) {
      return false;
   }
   *value = static_cast<sval_t>(slot.ops[index].value);
   return true;
}

static bool fill_operand(op_t &op, const TgOp &o) {
   clear_operand(op);
   switch (o.kind) {
      case TG_OP_REG:
         if (o.reg >= NUM_REGS) {
            return false;
         }
         op.type = o_reg;
         op.reg = o.reg;
         op.dtype = dt_qword;
         op.set_shown();
         return true;
      case TG_OP_IMM:
         op.type = o_imm;
         op.value = static_cast<uval_t>(o.value);
         op.dtype = dt_qword;
         op.set_shown();
         return true;
      case TG_OP_NEAR:
         op.type = o_near;
         op.addr = static_cast<ea_t>(o.value);
         op.dtype = dt_code;
         op.set_shown();
         return true;
      case TG_OP_SPR:
         op.type = o_imm;
         op.value = static_cast<uval_t>(o.value);
         op.dtype = dt_word;
         op.specflag1 = TG_OP_SPR;
         op.set_shown();
         return true;
      case TG_OP_MEM:
         if (o.reg >= NUM_REGS) {
            return false;
         }
         op.type = o.value == 0 ? o_phrase : o_displ;
         op.phrase = o.reg;
         op.addr = static_cast<ea_t>(o.value);
         op.dtype = dtype_for_mem_size(o.dtype);
         op.set_shown();
         return true;
      default:
         return false;
   }
}

static bool get_stackvar_displacement(outctx_t *ctx, const op_t *op, qstring *name) {
   sval_t actual = 0;
   int based = OP_SP_BASED;
   tinfo_t frame;
   const ssize_t member_index = ctx->get_stkvar(*op, op->addr, &actual, &based, &frame);
   if (member_index < 0 || frame.empty()) {
      return false;
   }
   udm_t member;
   if (frame.get_udm(&member, static_cast<size_t>(member_index)) < 0) {
      return false;
   }
   *name = member.name;
   return true;
}

static bool decode_bundle_at(ea_t ea, TgBundle &bundle) {
   if ((ea & BUNDLE_MASK) != 0) {
      return false;
   }
   uint8_t bytes[BUNDLE_SIZE];
   if (get_bytes(bytes, BUNDLE_SIZE, ea) != static_cast<ssize_t>(BUNDLE_SIZE)) {
      return false;
   }
   return tg_decode_bundle(bytes, static_cast<uint64_t>(ea), &bundle) != 0;
}

static bool likely_c_string(ea_t ea, ea_t end_ea, size_t *out_len) {
   ssize_t avail = 0;
   for (ea_t cursor = ea; cursor < end_ea && static_cast<size_t>(avail) < TG_STRING_SCAN_BYTES; cursor++) {
      avail++;
   }
   uint8_t bytes[TG_STRING_SCAN_BYTES];
   if (avail == 0 || get_bytes(bytes, avail, ea) != avail) {
      return false;
   }
   return tg_likely_c_string(bytes, static_cast<size_t>(avail), out_len) != 0;
}

static void append_synthetic_comment(ea_t ea, const char *comment) {
   if (comment == nullptr || qstrlen(comment) == 0) {
      return;
   }
   qstring existing;
   if (get_cmt(&existing, ea, false) > 0 && std::strstr(existing.c_str(), comment) != nullptr) {
      return;
   }
   qstring colored;
   colored.sprnt(SCOLOR_ON SCOLOR_AUTOCMT "%s" SCOLOR_OFF SCOLOR_AUTOCMT, comment);
   append_cmt(ea, colored.c_str(), false);
}

class SlotEffects final {
 public:
   static SlotEffects analyze(const TgSlot &slot, TgConstState &state) {
      SlotEffects effects;
      tg_const_state_apply_slot(&slot, &state, effects.comment_, sizeof(effects.comment_), &effects.mem_ref_,
                                &effects.data_ref_);
      return effects;
   }

   void apply_bootstrap(ea_t row_ea) const {
      const bool has_string_ref = append_string_comment(row_ea);
      if (!has_string_ref && comment_[0] != '\0') {
         append_synthetic_comment(row_ea, comment_);
      }
   }

   void apply_emu(const insn_t &insn) const {
      const bool has_string_ref = add_string_ref(insn);
      if (!has_string_ref && comment_[0] != '\0') {
         append_synthetic_comment(insn.ea, comment_);
      }
      add_memory_ref(insn);
   }

 private:
   static bool has_code_from(ea_t ea) { return is_code(get_full_flags(ea)); }

   static ea_t direct_string_ref_target(ea_t ea) {
      const segment_t *seg = getseg(ea);
      if (seg == nullptr) {
         return BADADDR;
      }
      const ea_t head = get_item_head(ea);
      if (head == BADADDR || getseg(head) != seg || !is_strlit(get_full_flags(head))) {
         return BADADDR;
      }
      return head;
   }

   static ea_t segment_offset_string_ref_target(uint64_t offset) {
      for (const segment_t *seg = get_first_seg(); seg != nullptr; seg = get_next_seg(seg->end_ea)) {
         const auto segment_size = static_cast<uint64_t>(seg->end_ea - seg->start_ea);
         if (offset >= segment_size) {
            continue;
         }
         const ea_t target = seg->start_ea + static_cast<ea_t>(offset);
         const ea_t string_target = direct_string_ref_target(target);
         if (string_target != BADADDR) {
            return string_target;
         }
      }
      return BADADDR;
   }

   static ea_t string_ref_target(uint64_t target) {
      const ea_t direct = direct_string_ref_target(static_cast<ea_t>(target));
      if (direct != BADADDR) {
         return direct;
      }

      const ea_t file_offset = segment_offset_string_ref_target(target);
      if (file_offset != BADADDR) {
         return file_offset;
      }

      if (target < TILEGX_RUNTIME_ALIAS_BASE) {
         return BADADDR;
      }
      return segment_offset_string_ref_target(target - TILEGX_RUNTIME_ALIAS_BASE);
   }

   static dref_t user_offset_ref_type() {
      // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange): IDA combines XREF_USER with dref_t values.
      return static_cast<dref_t>(dr_O | XREF_USER);
   }

   static bool format_string_comment(ea_t target, char (&out)[STRING_COMMENT_BUFSIZE]) {
      qstring text;
      size_t max_codepoints = STRING_COMMENT_CODEPOINTS;
      const auto str_type = static_cast<int32>(get_str_type(target));
      const ssize_t len =
          get_strlit_contents(&text, target, get_item_size(target), str_type, &max_codepoints, STRCONV_ESCAPE);
      if (len <= 0) {
         return false;
      }
      qsnprintf(out, sizeof(out), "\"%s\"", text.c_str());
      return true;
   }

   void add_memory_ref(const insn_t &insn) const {
      if (mem_ref_.kind == 0) {
         return;
      }
      const ea_t target = static_cast<ea_t>(mem_ref_.target);
      if (getseg(target) == nullptr) {
         return;
      }
      if (mem_ref_.kind == TG_MEMREF_READ || mem_ref_.kind == TG_MEMREF_READ_WRITE) {
         insn.add_dref(target, 0, dr_R);
      }
      if (mem_ref_.kind == TG_MEMREF_WRITE || mem_ref_.kind == TG_MEMREF_READ_WRITE) {
         insn.add_dref(target, 0, dr_W);
      }
   }

   [[nodiscard]] bool append_string_comment(ea_t from) const {
      if (data_ref_.kind != TG_DATAREF_IMM || !has_code_from(from)) {
         return false;
      }
      const ea_t target = string_ref_target(data_ref_.target);
      if (target == BADADDR) {
         return false;
      }
      char string_comment[STRING_COMMENT_BUFSIZE] = {};
      if (format_string_comment(target, string_comment)) {
         append_synthetic_comment(from, string_comment);
      }
      return true;
   }

   [[nodiscard]] bool add_string_ref(const insn_t &insn) const {
      if (data_ref_.kind != TG_DATAREF_IMM) {
         return false;
      }
      const ea_t target = string_ref_target(data_ref_.target);
      if (target == BADADDR) {
         return false;
      }
      insn.add_dref(target, 0, user_offset_ref_type());
      char string_comment[STRING_COMMENT_BUFSIZE] = {};
      if (format_string_comment(target, string_comment)) {
         append_synthetic_comment(insn.ea, string_comment);
      }
      return true;
   }

   char comment_[CONST_COMMENT_BUFSIZE] = {};
   TgMemRef mem_ref_ = {};
   TgDataRef data_ref_ = {};
};

class DecodedRow final {
 public:
   bool decode(ea_t row_ea) {
      const ea_t row_base = row_ea & ~BUNDLE_MASK;
      if (!decode_bundle_at(row_base, bundle_)) {
         return false;
      }

      TgRowAnalysis decoded = {};
      if (tg_analyze_row(&bundle_, static_cast<uint8_t>(row_ea - row_base), &decoded) == 0) {
         return false;
      }
      offset_ = static_cast<uint8_t>(row_ea - row_base);
      analysis_ = decoded;
      next_ea_ = row_base + decoded.row.next_offset;
      return true;
   }

   [[nodiscard]] const TgRowView &view() const { return analysis_.row; }

   [[nodiscard]] const TgRowAnalysis &analysis() const { return analysis_; }

   [[nodiscard]] const TgSlot &first_slot() const { return analysis_.first_slot; }

   [[nodiscard]] const TgRowRefs &refs() const { return analysis_.refs; }

   [[nodiscard]] const TgSlot &slot(int index) const { return bundle_.slots[view().slots[index]]; }

   [[nodiscard]] ea_t next_ea() const { return next_ea_; }

   [[nodiscard]] uint8_t flags() const { return view().flags; }

   [[nodiscard]] bool falls_through() const { return (flags() & TG_ROW_STOP) == 0; }

   [[nodiscard]] bool ends_basic_block(bool call_stops_block) const {
      return (flags() & (TG_ROW_STOP | TG_ROW_JUMP)) != 0 || (call_stops_block && (flags() & TG_ROW_CALL) != 0);
   }

   [[nodiscard]] sval_t sp_delta() const {
      int64_t delta = 0;
      if (tg_row_sp_delta(&bundle_, offset_, &delta) == 0) {
         return 0;
      }
      return static_cast<sval_t>(delta);
   }

   [[nodiscard]] int may_be_func(int state) const { return tg_row_may_be_func(&bundle_, offset_, state); }

   [[nodiscard]] ssize_t align_size() const { return tg_row_align_size(&bundle_, offset_); }

   [[nodiscard]] bool reg_accesses(TgRegAccesses *accesses) const {
      return accesses != nullptr && tg_row_reg_accesses(&bundle_, offset_, accesses) != 0;
   }

   bool scan_prolog(TgPrologState *state) const {
      return state != nullptr && tg_prolog_scan_row(&bundle_, offset_, state) != 0;
   }

 private:
   TgBundle bundle_ = {};
   TgRowAnalysis analysis_ = {};
   uint8_t offset_ = 0;
   ea_t next_ea_ = BADADDR;
};

static bool has_nonflow_code_xref(ea_t ea) {
   xrefblk_t xb = {};
   return xb.first_to(ea, XREF_NOFLOW | XREF_CODE);
}

class StackAliases final {
 public:
   StackAliases() { reset(); }

   void reset() {
      for (Alias &alias : aliases_) {
         alias = {};
      }
      aliases_[SP_REG] = {true, 0};
   }

   void replay_until(ea_t ea) {
      const func_t *pfn = get_func(ea);
      if (pfn == nullptr) {
         return;
      }

      for (ea_t cursor = pfn->start_ea; cursor < ea;) {
         if (cursor != pfn->start_ea && has_nonflow_code_xref(cursor)) {
            reset();
         }

         DecodedRow row;
         if (!row.decode(cursor)) {
            cursor += 4;
            continue;
         }
         for (int slot_index = 0; slot_index < row.view().n_slots; slot_index++) {
            apply(row.slot(slot_index));
         }
         const ea_t next = row.next_ea();
         cursor = next > cursor ? next : cursor + 4;
      }
   }

   [[nodiscard]] bool stack_offset(const op_t &op, int64_t *offset) const {
      if ((op.type != o_phrase && op.type != o_displ) || op.phrase >= NUM_REGS || !aliases_[op.phrase].valid) {
         return false;
      }
      const int64_t displacement = op.type == o_displ ? static_cast<int64_t>(op.addr) : 0;
      *offset = aliases_[op.phrase].offset + displacement;
      return true;
   }

   void apply(const TgSlot &slot) {
      uint16_t dst = 0;
      if (slot.itype == 0 || slot.itype >= NUM_INSTRUCTIONS || !slot_reg(slot, 0, &dst) || dst >= NUM_REGS) {
         return;
      }

      const char *name = slot_name(slot);
      if (streq(name, "move")) {
         apply_move(slot, dst);
         return;
      }
      if (streq(name, "addi") || streq(name, "addli") || streq(name, "addxi") || streq(name, "addxli")) {
         apply_addi(slot, dst);
         return;
      }
      if ((INSTRUCTIONS[slot.itype].feature & CF_CHG1) != 0) {
         aliases_[dst] = {};
      }
   }

   void apply(const DecodedRow &row) {
      for (int slot_index = 0; slot_index < row.view().n_slots; slot_index++) {
         apply(row.slot(slot_index));
      }
   }

 private:
   struct Alias {
      bool valid = false;
      int64_t offset = 0;
   };

   void apply_move(const TgSlot &slot, uint16_t dst) {
      uint16_t src = 0;
      if (slot_reg(slot, 1, &src) && src < NUM_REGS && aliases_[src].valid) {
         aliases_[dst] = aliases_[src];
      } else {
         aliases_[dst] = {};
      }
   }

   void apply_addi(const TgSlot &slot, uint16_t dst) {
      uint16_t src = 0;
      sval_t delta = 0;
      if (slot_reg(slot, 1, &src) && src < NUM_REGS && aliases_[src].valid && slot_imm(slot, 2, &delta)) {
         aliases_[dst] = {true, aliases_[src].offset + delta};
      } else {
         aliases_[dst] = {};
      }
   }

   Alias aliases_[NUM_REGS] = {};
};

static void apply_const_row(const DecodedRow &row, TgConstState &state) {
   for (int slot_index = 0; slot_index < row.view().n_slots; slot_index++) {
      SlotEffects::analyze(row.slot(slot_index), state);
   }
}

static bool const_reg_value(const TgConstState &state, uint16_t reg, uint64_t *value) {
   if (value == nullptr || reg >= NUM_REGS || (state.valid & (uint64_t{1} << reg)) == 0) {
      return false;
   }
   *value = state.values[reg];
   return true;
}

static void add_indirect_cref(const insn_t &insn, const TgSlot &slot, const TgConstState &state) {
   const char *name = slot_name(slot);
   const bool is_call = streq(name, "jalr") || streq(name, "jalrp");
   if (!is_call && !streq(name, "jr") && !streq(name, "jrp")) {
      return;
   }
   uint16_t reg = 0;
   uint64_t target_value = 0;
   if (!slot_reg(slot, 0, &reg) || !const_reg_value(state, reg, &target_value)) {
      return;
   }
   const ea_t target = static_cast<ea_t>(target_value);
   if (target == BADADDR || getseg(target) == nullptr) {
      return;
   }
   insn.add_cref(target, 0, is_call ? fl_CN : fl_JN);
}

static void emit_const_refs(const insn_t &insn, const DecodedRow &row, TgConstState state) {
   for (int slot_index = 0; slot_index < row.view().n_slots; slot_index++) {
      const TgSlot &slot = row.slot(slot_index);
      add_indirect_cref(insn, slot, state);
      SlotEffects::analyze(slot, state).apply_emu(insn);
   }
}

class ConstReplay final {
 public:
   ConstReplay() { tg_const_state_reset(&state_); }

   void replay_until(ea_t ea) {
      const func_t *pfn = get_func(ea);
      if (pfn == nullptr) {
         return;
      }

      for (ea_t cursor = pfn->start_ea; cursor < ea;) {
         if (cursor != pfn->start_ea && has_nonflow_code_xref(cursor)) {
            tg_const_state_reset(&state_);
         }

         DecodedRow row;
         if (!row.decode(cursor)) {
            cursor += 4;
            continue;
         }
         apply(row);
         const ea_t next = row.next_ea();
         cursor = next > cursor ? next : cursor + 4;
      }
   }

   void emit_refs(const insn_t &insn, const DecodedRow &row) { emit_const_refs(insn, row, state_); }

 private:
   void apply(const DecodedRow &row) { apply_const_row(row, state_); }

   TgConstState state_ = {};
};

struct ReplayRowState {
   ea_t ea = BADADDR;
   StackAliases stack;
   TgConstState consts = {};
};

class FunctionReplayCache final {
 public:
   void clear() {
      valid_ = false;
      start_ea_ = BADADDR;
      end_ea_ = BADADDR;
      rows_.clear();
   }

   const ReplayRowState *state_at(ea_t ea) {
      const func_t *pfn = get_func(ea);
      if (pfn == nullptr) {
         return nullptr;
      }
      if (!matches(*pfn)) {
         build(*pfn);
      }
      const ReplayRowState *state = find(ea);
      if (state == nullptr && matches(*pfn)) {
         build(*pfn);
         state = find(ea);
      }
      return state;
   }

 private:
   struct CachedRow {
      ea_t ea = BADADDR;
      DecodedRow row;
   };

   [[nodiscard]] bool matches(const func_t &pfn) const {
      return valid_ && start_ea_ == pfn.start_ea && end_ea_ == pfn.end_ea;
   }

   [[nodiscard]] const ReplayRowState *find(ea_t ea) const {
      for (const ReplayRowState &row : rows_) {
         if (row.ea == ea) {
            return &row;
         }
      }
      return nullptr;
   }

   [[nodiscard]] static bool contains_ea(const std::vector<ea_t> &eas, ea_t ea) {
      // NOLINTNEXTLINE(readability-use-anyofallof): avoid pulling Boost into the IDA module.
      for (const ea_t candidate : eas) {
         if (candidate == ea) {
            return true;
         }
      }
      return false;
   }

   static void collect_boundary_targets(const DecodedRow &row, const func_t &pfn, std::vector<ea_t> &targets) {
      const TgRowRefs &refs = row.refs();
      for (int index = 0; index < refs.n_refs; index++) {
         const ea_t target = static_cast<ea_t>(refs.refs[index].target);
         if (target > pfn.start_ea && target < pfn.end_ea && !contains_ea(targets, target)) {
            targets.push_back(target);
         }
      }
   }

   void build(const func_t &pfn) {
      valid_ = true;
      start_ea_ = pfn.start_ea;
      end_ea_ = pfn.end_ea;
      rows_.clear();

      std::vector<CachedRow> decoded_rows;
      std::vector<ea_t> boundary_targets;
      for (ea_t cursor = pfn.start_ea; cursor < pfn.end_ea;) {
         DecodedRow row;
         if (!row.decode(cursor)) {
            cursor += 4;
            continue;
         }
         collect_boundary_targets(row, pfn, boundary_targets);
         decoded_rows.push_back({cursor, row});
         const ea_t next = row.next_ea();
         cursor = next > cursor ? next : cursor + 4;
      }

      StackAliases stack;
      TgConstState consts = {};
      tg_const_state_reset(&consts);
      rows_.reserve(decoded_rows.size());
      for (const CachedRow &cached : decoded_rows) {
         if (cached.ea != pfn.start_ea &&
             (contains_ea(boundary_targets, cached.ea) || has_nonflow_code_xref(cached.ea))) {
            stack.reset();
            tg_const_state_reset(&consts);
         }
         rows_.push_back({cached.ea, stack, consts});
         stack.apply(cached.row);
         apply_const_row(cached.row, consts);
      }
   }

   bool valid_ = false;
   ea_t start_ea_ = BADADDR;
   ea_t end_ea_ = BADADDR;
   std::vector<ReplayRowState> rows_;
};

static FunctionReplayCache g_replay_cache;

static void format_stack_name(int64_t offset, char (&out)[STACK_NAME_BUFSIZE]) {
   const uint64_t magnitude = abs_magnitude(offset);
   qsnprintf(out, sizeof(out), "var_%" FMT_64 "x", static_cast<uint64>(magnitude));
}

static void out_stack_alias_operand(outctx_t *ctx, int64_t offset) {
   char name[STACK_NAME_BUFSIZE] = {};
   format_stack_name(offset, name);
   ctx->out_symbol('[');
   ctx->out_register(REG_NAMES[SP_REG]);
   ctx->out_symbol('+');
   ctx->out_line(name, COLOR_DNAME);
   ctx->out_symbol(']');
}

static void out_memory_operand(outctx_t *ctx, const op_t *op, const StackAliases *aliases) {
   int64_t stack_offset = 0;
   if (aliases != nullptr && aliases->stack_offset(*op, &stack_offset)) {
      out_stack_alias_operand(ctx, stack_offset);
      return;
   }

   if (op->phrase >= NUM_REGS) {
      ctx->out_symbol('?');
      return;
   }
   ctx->out_symbol('[');
   ctx->out_register(REG_NAMES[op->phrase]);
   if (op->type == o_phrase && op->phrase == SP_REG) {
      qstring stackvar_name;
      if (get_stackvar_displacement(ctx, op, &stackvar_name)) {
         ctx->out_symbol('+');
         ctx->out_line(stackvar_name.c_str(), COLOR_DNAME);
      }
   } else if (op->type == o_displ && op->addr != 0) {
      const auto disp = static_cast<int64_t>(op->addr);
      qstring stackvar_name;
      const bool has_stackvar = op->phrase == SP_REG && get_stackvar_displacement(ctx, op, &stackvar_name);
      if (has_stackvar) {
         ctx->out_symbol('+');
         ctx->out_line(stackvar_name.c_str(), COLOR_DNAME);
      } else {
         ctx->out_symbol(disp < 0 ? '-' : '+');
         const uint64_t magnitude = abs_magnitude(disp);
         char text[32];
         qsnprintf(text, sizeof(text), "0x%" FMT_64 "x", static_cast<uint64>(magnitude));
         ctx->out_line(text, COLOR_NUMBER);
      }
   }
   ctx->out_symbol(']');
}

struct BootstrapResult {
   ea_t entry_ea = BADADDR;
   ea_t main_ea = BADADDR;
};

struct EaRange {
   ea_t start = BADADDR;
   ea_t end = BADADDR;
};

class SegmentBootstrapper final {
 public:
   explicit SegmentBootstrapper(segment_t &seg) : seg_(&seg) {}

   BootstrapResult run() {
      tg_const_state_reset(&const_state_);
      create_strings();
      create_code_rows();
      return {entry_ea_, main_ea_};
   }

 private:
   segment_t *seg_;
   TgConstState const_state_ = {};
   ea_t entry_ea_ = BADADDR;
   ea_t main_ea_ = BADADDR;
   bool saw_stack_setup_ = false;
   std::vector<uint8_t> visited_;
   std::vector<ea_t> pending_;
   std::vector<ea_t> probable_function_starts_;
   std::vector<EaRange> skipped_data_;

   [[nodiscard]] ea_t first_bundle_ea() const { return (seg_->start_ea + BUNDLE_MASK) & ~BUNDLE_MASK; }

   void enqueue_code(ea_t ea) {
      if (!seg_->contains(ea)) {
         return;
      }
      const auto offset = static_cast<size_t>(ea - seg_->start_ea);
      if (offset >= visited_.size() || visited_[offset] != 0) {
         return;
      }
      visited_[offset] = 1;
      pending_.push_back(ea);
   }

   [[nodiscard]] static bool item_blocks_code(ea_t start, ea_t end) {
      for (ea_t ea = start; ea < end; ea++) {
         const flags64_t f = get_full_flags(ea);
         if (is_code(f)) {
            continue;
         }
         if (is_data(f) || is_tail(f)) {
            return true;
         }
      }
      return false;
   }

   [[nodiscard]] static bool range_is_unknown(ea_t start, ea_t end) {
      for (ea_t ea = start; ea < end; ea++) {
         if (!is_unknown(get_full_flags(ea))) {
            return false;
         }
      }
      return true;
   }

   void create_strings() const {
      for (ea_t ea = seg_->start_ea; ea < seg_->end_ea; ea++) {
         size_t len = 0;
         if (!likely_c_string(ea, seg_->end_ea, &len)) {
            continue;
         }
         const ea_t available = seg_->end_ea - ea;
         const ea_t wanted = static_cast<ea_t>(len) + 1;
         const auto item_len = static_cast<asize_t>(available < wanted ? available : wanted);
         if (item_len > 0 && create_strlit(ea, item_len, STRTYPE_C)) {
            ea += len;
         }
      }
   }

   void apply_slot_effects(ea_t row_ea, const TgBundle &bundle, uint8_t row_offset) {
      TgRowAnalysis analysis = {};
      if (tg_analyze_row(&bundle, row_offset, &analysis) == 0) {
         return;
      }
      for (int slot_index = 0; slot_index < analysis.row.n_slots; slot_index++) {
         const TgSlot &slot = bundle.slots[analysis.row.slots[slot_index]];
         SlotEffects::analyze(slot, const_state_).apply_bootstrap(row_ea);
      }
   }

   static bool stack_setup_slot(const TgSlot &slot) {
      return slot.itype > 0 && slot.n_ops > 0 && slot.ops[0].kind == TG_OP_REG && slot.ops[0].reg == SP_REG;
   }

   void update_entry_hints(ea_t row_ea, const TgRowAnalysis &analysis, const TgBundle &bundle) {
      if (entry_ea_ == BADADDR) {
         entry_ea_ = row_ea;
      }
      for (int slot_index = 0; slot_index < analysis.row.n_slots; slot_index++) {
         if (stack_setup_slot(bundle.slots[analysis.row.slots[slot_index]])) {
            saw_stack_setup_ = true;
         }
      }
      if (!saw_stack_setup_ || main_ea_ != BADADDR) {
         return;
      }
      for (int ref_index = 0; ref_index < analysis.refs.n_refs; ref_index++) {
         const TgCodeRef &ref = analysis.refs.refs[ref_index];
         const ea_t target = static_cast<ea_t>(ref.target);
         if (ref.kind == TG_CREF_CALL && seg_->contains(target)) {
            main_ea_ = target;
            return;
         }
      }
   }

   void create_code_rows() {
      visited_.assign(static_cast<size_t>(seg_->end_ea - seg_->start_ea), 0);
      pending_.clear();
      probable_function_starts_.clear();
      skipped_data_.clear();
      enqueue_code(first_bundle_ea());
      drain_pending_code();
      enqueue_probable_functions();
      drain_pending_code();
      create_skipped_data();
      create_probable_functions();
      refine_main_hint();
      create_jump_gap_data();
   }

   void drain_pending_code() {
      while (!pending_.empty()) {
         const ea_t row_ea = pending_.back();
         pending_.pop_back();
         create_reachable_row(row_ea);
      }
   }

   void create_reachable_row(ea_t row_ea) {
      const ea_t bundle_ea = row_ea & ~BUNDLE_MASK;
      if (bundle_ea < seg_->start_ea || bundle_ea + BUNDLE_SIZE > seg_->end_ea) {
         return;
      }
      if (item_blocks_code(bundle_ea, bundle_ea + BUNDLE_SIZE)) {
         return;
      }

      TgBundle bundle = {};
      if (!decode_bundle_at(bundle_ea, bundle)) {
         return;
      }

      const auto row_offset = static_cast<uint8_t>(row_ea - bundle_ea);
      TgRowAnalysis analysis = {};
      if (tg_analyze_row(&bundle, row_offset, &analysis) == 0) {
         return;
      }

      const bool code_ready = is_code(get_full_flags(row_ea)) || create_insn(row_ea) > 0;
      if (!code_ready) {
         auto_make_code(row_ea);
         return;
      }

      update_entry_hints(row_ea, analysis, bundle);
      apply_slot_effects(row_ea, bundle, row_offset);
      enqueue_row_targets(row_ea, analysis);
      record_skipped_data(row_ea, analysis);
   }

   void enqueue_row_targets(ea_t row_ea, const TgRowAnalysis &analysis) {
      for (int ref_index = 0; ref_index < analysis.refs.n_refs; ref_index++) {
         const ea_t target = static_cast<ea_t>(analysis.refs.refs[ref_index].target);
         enqueue_code(target);
      }
      if ((analysis.row.flags & TG_ROW_STOP) == 0) {
         const ea_t bundle_ea = row_ea & ~BUNDLE_MASK;
         enqueue_code(bundle_ea + analysis.row.next_offset);
      }
   }

   [[nodiscard]] ea_t direct_jump_target(const TgRowAnalysis &analysis) const {
      for (int ref_index = 0; ref_index < analysis.refs.n_refs; ref_index++) {
         const TgCodeRef &ref = analysis.refs.refs[ref_index];
         const ea_t target = static_cast<ea_t>(ref.target);
         if (ref.kind == TG_CREF_JUMP && seg_->contains(target)) {
            return target;
         }
      }
      return BADADDR;
   }

   void refine_main_hint() {
      if (entry_ea_ == BADADDR || main_ea_ != BADADDR) {
         return;
      }

      bool saw_stack_setup = false;
      const ea_t scan_end = qmin(seg_->end_ea, entry_ea_ + PROLOG_SCAN_LIMIT);
      for (ea_t cursor = entry_ea_; cursor < scan_end;) {
         DecodedRow row;
         if (!row.decode(cursor)) {
            break;
         }

         const TgRowAnalysis &analysis = row.analysis();
         for (int slot_index = 0; slot_index < analysis.row.n_slots; slot_index++) {
            if (stack_setup_slot(row.slot(slot_index))) {
               saw_stack_setup = true;
            }
         }
         if (saw_stack_setup) {
            for (int ref_index = 0; ref_index < analysis.refs.n_refs; ref_index++) {
               const TgCodeRef &ref = analysis.refs.refs[ref_index];
               const ea_t target = static_cast<ea_t>(ref.target);
               if (ref.kind == TG_CREF_CALL && seg_->contains(target)) {
                  main_ea_ = target;
                  return;
               }
            }
         }

         if ((analysis.row.flags & TG_ROW_STOP) != 0) {
            const ea_t target = direct_jump_target(analysis);
            if (target == BADADDR || target <= cursor || target >= scan_end) {
               break;
            }
            cursor = target;
            continue;
         }

         const ea_t next = row.next_ea();
         if (next <= cursor) {
            break;
         }
         cursor = next;
      }
   }

   void record_skipped_data(ea_t row_ea, const TgRowAnalysis &analysis) {
      if ((analysis.row.flags & TG_ROW_STOP) == 0 || (analysis.row.flags & TG_ROW_COND_JUMP) != 0) {
         return;
      }

      const ea_t gap_start = row_ea + analysis.row.size;
      ea_t gap_end = BADADDR;
      for (int ref_index = 0; ref_index < analysis.refs.n_refs; ref_index++) {
         const TgCodeRef &ref = analysis.refs.refs[ref_index];
         if (ref.kind != TG_CREF_JUMP) {
            continue;
         }
         const ea_t target = static_cast<ea_t>(ref.target);
         if (target > gap_start && seg_->contains(target) && (gap_end == BADADDR || target < gap_end)) {
            gap_end = target;
         }
      }
      if (gap_end != BADADDR && gap_end > gap_start) {
         skipped_data_.push_back({gap_start, gap_end});
      }
   }

   [[nodiscard]] bool has_strong_prologue(ea_t ea) const {
      DecodedRow entry;
      if (!entry.decode(ea) || entry.may_be_func(0) < 80) {
         return false;
      }

      TgPrologState state = {};
      tg_prolog_state_reset(&state);

      const ea_t scan_end = qmin(seg_->end_ea, ea + PROLOG_SCAN_LIMIT);
      for (ea_t cursor = ea; cursor < scan_end;) {
         const ea_t bundle_ea = cursor & ~BUNDLE_MASK;
         if (bundle_ea < seg_->start_ea || bundle_ea + BUNDLE_SIZE > seg_->end_ea ||
             !range_is_unknown(bundle_ea, bundle_ea + BUNDLE_SIZE)) {
            break;
         }

         DecodedRow row;
         if (!row.decode(cursor)) {
            break;
         }
         row.scan_prolog(&state);
         if (state.saved_link != 0 && (state.frame_size != 0 || state.has_frame_pointer != 0)) {
            return true;
         }
         if ((row.flags() & (TG_ROW_CALL | TG_ROW_RET | TG_ROW_JUMP | TG_ROW_STOP)) != 0) {
            break;
         }

         const ea_t next = row.next_ea();
         if (next <= cursor) {
            break;
         }
         cursor = next;
      }
      return false;
   }

   void enqueue_probable_functions() {
      for (ea_t ea = first_bundle_ea(); ea + BUNDLE_SIZE <= seg_->end_ea; ea += BUNDLE_SIZE) {
         const auto offset = static_cast<size_t>(ea - seg_->start_ea);
         if (offset >= visited_.size() || visited_[offset] != 0 || !range_is_unknown(ea, ea + BUNDLE_SIZE)) {
            continue;
         }
         if (has_strong_prologue(ea)) {
            probable_function_starts_.push_back(ea);
            enqueue_code(ea);
         }
      }
   }

   void create_probable_functions() {
      for (auto it = probable_function_starts_.rbegin(); it != probable_function_starts_.rend(); ++it) {
         const ea_t ea = *it;
         if (!is_code(get_full_flags(ea))) {
            continue;
         }
         const func_t *pfn = get_func(ea);
         if (pfn == nullptr || pfn->start_ea != ea) {
            add_func(ea);
         }
      }
   }

   static void create_data_range(ea_t start, ea_t end) {
      for (ea_t ea = start; ea < end;) {
         if (!is_unknown(get_full_flags(ea))) {
            const asize_t size = get_item_size(ea);
            ea += size > 0 ? size : 1;
            continue;
         }

         ea_t run_end = ea + 1;
         while (run_end < end && is_unknown(get_full_flags(run_end))) {
            run_end++;
         }

         const ea_t qword_start = (ea + BUNDLE_MASK) & ~BUNDLE_MASK;
         if (qword_start > ea) {
            const ea_t byte_end = qmin(qword_start, run_end);
            create_byte(ea, byte_end - ea);
            ea = byte_end;
         } else if (run_end - ea >= static_cast<ea_t>(BUNDLE_SIZE)) {
            const auto len = static_cast<asize_t>((run_end - ea) & ~BUNDLE_MASK);
            create_qword(ea, len);
            ea += len;
         } else {
            create_byte(ea, run_end - ea);
            ea = run_end;
         }
      }
   }

   void create_skipped_data() const {
      for (const EaRange &range : skipped_data_) {
         const ea_t start = qmax(range.start, seg_->start_ea);
         const ea_t end = qmin(range.end, seg_->end_ea);
         if (start < end) {
            create_data_range(start, end);
         }
      }
   }

   void create_jump_gap_data() const {
      for (ea_t ea = seg_->start_ea; ea < seg_->end_ea;) {
         const flags64_t flags = get_full_flags(ea);
         if (!is_code(flags)) {
            const asize_t item_size = get_item_size(ea);
            ea += item_size > 0 ? item_size : 1;
            continue;
         }

         DecodedRow row;
         if (!row.decode(ea) || (row.flags() & TG_ROW_STOP) == 0 || (row.flags() & TG_ROW_COND_JUMP) != 0) {
            if (row.decode(ea) && row.next_ea() > ea) {
               ea = row.next_ea();
            } else {
               const asize_t item_size = get_item_size(ea);
               ea += item_size > 0 ? item_size : 1;
            }
            continue;
         }

         const ea_t gap_start = ea + row.view().size;
         const ea_t target = direct_jump_target(row.analysis());
         if (target > gap_start && seg_->contains(target)) {
            create_data_range(gap_start, target);
         }
         ea = row.next_ea() > ea ? row.next_ea() : ea + 1;
      }
   }
};

static void apply_bootstrap_names(BootstrapResult result) {
   if (result.entry_ea == BADADDR) {
      return;
   }
   add_entry(result.entry_ea, result.entry_ea, "start", false);
   add_func(result.entry_ea);
   if (result.main_ea != BADADDR && result.main_ea != result.entry_ea) {
      create_insn(result.main_ea);
      add_func(result.main_ea);
      set_name(result.main_ea, "main", SN_NOCHECK | SN_FORCE | SN_NOWARN);
   }
}

static BootstrapResult bootstrap_segments() {
   BootstrapResult first_result;
   for (segment_t *seg = get_first_seg(); seg != nullptr; seg = get_next_seg(seg->end_ea)) {
      const BootstrapResult result = SegmentBootstrapper(*seg).run();
      if (first_result.entry_ea == BADADDR) {
         first_result = result;
      }
   }
   return first_result;
}

static ssize_t idaapi tilegx_ana(insn_t *insn) {
   DecodedRow row;
   if (!row.decode(insn->ea)) {
      return 0;
   }

   const TgSlot &slot = row.first_slot();
   insn->itype = slot.itype;
   insn->size = row.view().size;

   for (int i = 0; i < UA_MAXOP; i++) {
      op_t &op = insn->ops[i];
      clear_operand(op);
      if (i >= slot.n_ops) {
         continue;
      }
      if (!fill_operand(op, slot.ops[i])) {
         clear_operand(op);
      }
   }
   return insn->size;
}

static ssize_t tilegx_out_operand(outctx_t *ctx, const op_t *op, const StackAliases *aliases) {
   switch (op->type) {
      case o_reg:
         ctx->out_register(REG_NAMES[op->reg]);
         return 1;
      case o_imm:
         if (op->specflag1 == TG_OP_SPR) {
            char spr_name[SPR_NAME_BUFSIZE];
            if (tg_format_spr(static_cast<uint32_t>(op->value), spr_name, sizeof(spr_name)) != 0) {
               ctx->out_line(spr_name, COLOR_REG);
               return 1;
            }
         }
         ctx->out_value(*op, OOFW_IMM | OOF_SIGNED);
         return 1;
      case o_near:
         if (!ctx->out_name_expr(*op, op->addr)) {
            ctx->out_value(*op, OOF_ADDR | OOFW_64);
         }
         return 1;
      case o_phrase:
      case o_displ:
         out_memory_operand(ctx, op, aliases);
         return 1;
      default:
         return 0;
   }
}

static ssize_t idaapi tilegx_out_operand(outctx_t *ctx, const op_t *op) { return tilegx_out_operand(ctx, op, nullptr); }

static void tilegx_out_slot(outctx_t *ctx, const TgSlot &slot, const StackAliases *aliases) {
   ctx->out_custom_mnem(slot_name(slot), MNEMONIC_WIDTH);
   for (int i = 0; i < slot.n_ops && i < UA_MAXOP; i++) {
      op_t op;
      if (!fill_operand(op, slot.ops[i])) {
         continue;
      }
      if (i > 0) {
         ctx->out_symbol(',');
         ctx->out_char(' ');
      }
      tilegx_out_operand(ctx, &op, aliases);
   }
}

static ssize_t idaapi tilegx_out_insn(outctx_t *ctx) {
   DecodedRow decoded;
   if (!decoded.decode(ctx->insn.ea)) {
      ctx->out_mnemonic();
      ctx->flush_outbuf();
      return 1;
   }

   StackAliases aliases;
   if (const ReplayRowState *state = g_replay_cache.state_at(ctx->insn.ea); state != nullptr) {
      aliases = state->stack;
   } else {
      aliases.replay_until(ctx->insn.ea);
   }
   for (int s = 0; s < decoded.view().n_slots; s++) {
      const TgSlot &slot = decoded.slot(s);
      tilegx_out_slot(ctx, slot, &aliases);
      ctx->flush_outbuf(s == 0 ? -1 : DEFAULT_INDENT);
      aliases.apply(slot);
   }
   return 1;
}

static void trace_stack_pointer(const insn_t *insn, const DecodedRow &row) {
   if (insn == nullptr || !inf_should_trace_sp()) {
      return;
   }

   const sval_t delta = row.sp_delta();
   if (delta == 0) {
      return;
   }

   func_t *pfn = get_func(insn->ea);
   if (pfn != nullptr) {
      add_auto_stkpnt(pfn, insn->ea + insn->size, delta);
   }
}

static bool stack_memory_operand(const op_t &op) {
   return (op.type == o_displ || op.type == o_phrase) && op.phrase == SP_REG;
}

static void create_stack_vars(const insn_t *insn) {
   if (insn == nullptr || !inf_should_create_stkvars()) {
      return;
   }

   func_t *pfn = get_func(insn->ea);
   if (pfn == nullptr) {
      return;
   }
   if ((pfn->flags & FUNC_FRAME) == 0 && !add_frame(pfn, 0, 0, 0)) {
      return;
   }

   const flags64_t flags = get_flags(insn->ea);
   for (const op_t &op : insn->ops) {
      if (!stack_memory_operand(op) || is_defarg(flags, op.n)) {
         continue;
      }
      const auto displacement = static_cast<adiff_t>(op.type == o_phrase ? 0 : op.addr);
      if (insn->create_stkvar(op, displacement, STKVAR_VALID_SIZE | STKVAR_KEEP_EXISTING)) {
         op_stkvar(insn->ea, op.n);
      }
   }
}

static ssize_t idaapi tilegx_emu(const insn_t *insn) {
   DecodedRow row;
   if (!row.decode(insn->ea)) {
      return 0;
   }

   trace_stack_pointer(insn, row);
   create_stack_vars(insn);

   if (const ReplayRowState *state = g_replay_cache.state_at(insn->ea); state != nullptr) {
      emit_const_refs(*insn, row, state->consts);
   } else {
      ConstReplay consts;
      consts.replay_until(insn->ea);
      consts.emit_refs(*insn, row);
   }

   const TgRowRefs &refs = row.refs();
   for (int i = 0; i < refs.n_refs; i++) {
      const ea_t target = static_cast<ea_t>(refs.refs[i].target);
      const cref_t type = refs.refs[i].kind == TG_CREF_CALL ? fl_CN : fl_JN;
      insn->add_cref(target, 0, type);
   }
   if (row.falls_through()) {
      insn->add_cref(row.next_ea(), 0, fl_F);
   }
   return 1;
}

static ssize_t query_insn_flag(const insn_t *insn, uint8_t flag) {
   DecodedRow row;
   if (insn != nullptr && row.decode(insn->ea)) {
      return (row.flags() & flag) != 0 ? 1 : -1;
   }
   return 0;
}

static ssize_t is_indirect_jump(const insn_t *insn) {
   DecodedRow row;
   if (insn != nullptr && row.decode(insn->ea) && (row.flags() & TG_ROW_INDIRECT_JUMP) != 0) {
      return 2;
   }
   return 0;
}

static ssize_t is_sane_insn(const insn_t *insn, int no_crefs) {
   (void)no_crefs;
   DecodedRow row;
   return insn != nullptr && row.decode(insn->ea) ? 1 : -1;
}

static ssize_t tilegx_align_insn_size(ea_t ea) {
   DecodedRow row;
   return row.decode(ea) ? row.align_size() : 0;
}

static ssize_t can_have_type(const op_t *op) {
   if (op == nullptr) {
      return 0;
   }
   if (op->type == o_void || op->type == o_reg || (op->type == o_imm && op->specflag1 == TG_OP_SPR)) {
      return -1;
   }
   return 1;
}

static ssize_t cmp_operands(const op_t *lhs, const op_t *rhs) {
   if (lhs == nullptr || rhs == nullptr) {
      return 0;
   }
   const bool equal = lhs->type == rhs->type && lhs->dtype == rhs->dtype && lhs->reg == rhs->reg &&
                      lhs->phrase == rhs->phrase && lhs->value == rhs->value && lhs->addr == rhs->addr &&
                      lhs->specval == rhs->specval && lhs->specflag1 == rhs->specflag1 &&
                      lhs->specflag2 == rhs->specflag2 && lhs->specflag3 == rhs->specflag3 &&
                      lhs->specflag4 == rhs->specflag4;
   return equal ? 1 : -1;
}

static ssize_t calc_spdelta(sval_t *spdelta, const insn_t *insn) {
   if (spdelta == nullptr || insn == nullptr) {
      return 0;
   }
   DecodedRow row;
   if (!row.decode(insn->ea)) {
      return 0;
   }
   *spdelta = row.sp_delta();
   return 1;
}

static ssize_t may_be_func(const insn_t *insn, int state) {
   DecodedRow row;
   if (insn == nullptr || !row.decode(insn->ea)) {
      return 0;
   }
   return row.may_be_func(state);
}

static access_type_t access_type(uint8_t access) {
   const bool reads = (access & TG_ACCESS_READ) != 0;
   const bool writes = (access & TG_ACCESS_WRITE) != 0;
   if (reads && writes) {
      return RW_ACCESS;
   }
   if (writes) {
      return WRITE_ACCESS;
   }
   if (reads) {
      return READ_ACCESS;
   }
   return NO_ACCESS;
}

static ssize_t get_reg_accesses(reg_accesses_t *accvec, const insn_t *insn) {
   if (accvec == nullptr) {
      return -1;
   }
   if (insn == nullptr) {
      return 0;
   }
   DecodedRow row;
   if (!row.decode(insn->ea)) {
      return 0;
   }

   TgRegAccesses accesses = {};
   if (!row.reg_accesses(&accesses)) {
      return 0;
   }
   accvec->clear();
   for (int i = 0; i < accesses.n_accesses; i++) {
      const TgRegAccess &src = accesses.accesses[i];
      reg_access_t dst;
      dst.regnum = src.reg;
      dst.range.reset();
      dst.access_type = access_type(src.access);
      dst.opnum = src.op_index;
      if (dst.access_type != NO_ACCESS) {
         accvec->push_back(dst);
      }
   }
   return accvec->empty() ? 0 : 1;
}

static bool scan_prolog(ea_t fct_ea, TgPrologState *state) {
   if (state == nullptr) {
      return false;
   }
   tg_prolog_state_reset(state);

   const func_t *pfn = get_func(fct_ea);
   ea_t scan_end = fct_ea + PROLOG_SCAN_LIMIT;
   if (pfn != nullptr && pfn->end_ea < scan_end) {
      scan_end = pfn->end_ea;
   }

   for (ea_t cursor = fct_ea; cursor < scan_end;) {
      DecodedRow row;
      if (!row.decode(cursor)) {
         break;
      }
      row.scan_prolog(state);
      if ((row.flags() & (TG_ROW_CALL | TG_ROW_RET | TG_ROW_JUMP | TG_ROW_STOP)) != 0) {
         break;
      }

      const ea_t next = row.next_ea();
      if (next <= cursor) {
         break;
      }
      cursor = next;
   }
   return state->frame_size != 0 || state->has_frame_pointer != 0 || state->saved_link != 0 || state->saved_regs != 0;
}

static ssize_t analyze_prolog(ea_t fct_ea) {
   func_t *pfn = get_func(fct_ea);
   if (pfn == nullptr) {
      return 0;
   }

   TgPrologState state = {};
   if (!scan_prolog(fct_ea, &state) || state.frame_size == 0) {
      return 0;
   }

   const auto frame_size = static_cast<asize_t>(state.frame_size);
   const auto signed_frame_size = static_cast<sval_t>(state.frame_size);
   const bool ok = pfn->frame == BADNODE
                       ? add_frame(pfn, signed_frame_size, 0, 0)
                       : set_frame_size(pfn, qmax(pfn->frsize, frame_size), pfn->frregs, pfn->argsize);
   if (!ok) {
      return 0;
   }

   if (state.has_frame_pointer != 0) {
      pfn->flags |= FUNC_FRAME;
   }
   pfn->flags |= FUNC_PROLOG_OK;
   update_func(pfn);
   return 1;
}

static ssize_t get_autocmt(qstring *buf, const insn_t *insn) {
   if (buf == nullptr || insn == nullptr) {
      return 0;
   }
   char text[AUTOCMT_BUFSIZE] = {};
   if (tg_autocmt(insn->itype, text, sizeof(text)) == 0) {
      return 0;
   }
   buf->sprnt("%s", text);
   return 1;
}

static ssize_t get_operand_string(qstring *buf, const insn_t *insn, int opnum) {
   if (buf == nullptr || insn == nullptr) {
      return 0;
   }
   const int index = opnum < 0 ? 0 : opnum;
   if (index < 0 || index >= UA_MAXOP) {
      return 0;
   }
   const op_t &op = insn->ops[index];
   switch (op.type) {
      case o_reg:
         if (op.reg >= NUM_REGS) {
            return 0;
         }
         buf->sprnt("%s", REG_NAMES[op.reg]);
         break;
      case o_imm:
         if (op.specflag1 == TG_OP_SPR) {
            char spr_name[SPR_NAME_BUFSIZE] = {};
            if (tg_format_spr(static_cast<uint32_t>(op.value), spr_name, sizeof(spr_name)) == 0) {
               return 0;
            }
            buf->sprnt("%s", spr_name);
         } else {
            buf->sprnt("0x%" FMT_64 "x", static_cast<uint64>(op.value));
         }
         break;
      case o_near:
         buf->sprnt("0x%" FMT_64 "x", static_cast<uint64>(op.addr));
         break;
      case o_phrase:
         if (op.phrase >= NUM_REGS) {
            return 0;
         }
         buf->sprnt("[%s]", REG_NAMES[op.phrase]);
         break;
      case o_displ:
         if (op.phrase >= NUM_REGS) {
            return 0;
         }
         buf->sprnt("[%s%+lld]", REG_NAMES[op.phrase], static_cast<long long>(op.addr));
         break;
      default:
         return 0;
   }
   return static_cast<ssize_t>(qstrlen(buf->c_str()));
}

struct tilegx_t : public procmod_t {
   ssize_t idaapi on_event(ssize_t msgid, va_list va) override;
};

static ssize_t idaapi notify(void *user_data, int msgid, va_list args) {
   (void)user_data;
   (void)args;
   if (msgid == processor_t::ev_get_procmod) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): IDA returns procmod_t through ssize_t here.
      return reinterpret_cast<ssize_t>(new tilegx_t);
   }
   return 0;
}

ssize_t idaapi tilegx_t::on_event(ssize_t msgid, va_list va) {
   switch (msgid) {
      case processor_t::ev_init:
         g_replay_cache.clear();
         if (!tg_abi_layout_matches()) {
            msg("TILE-Gx: Rust/C++ ABI layout mismatch; refusing to initialize processor module\n");
            return -1;
         }
         return 1;
      case processor_t::ev_term:
         g_replay_cache.clear();
         return 0;
      case processor_t::ev_ana_insn:
         return tilegx_ana(va_arg(va, insn_t *));
      case processor_t::ev_emu_insn:
         return tilegx_emu(va_arg(va, const insn_t *));
      case processor_t::ev_out_insn:
         return tilegx_out_insn(va_arg(va, outctx_t *));
      case processor_t::ev_out_operand: {
         outctx_t *ctx = va_arg(va, outctx_t *);
         const op_t *op = va_arg(va, const op_t *);
         return tilegx_out_operand(ctx, op);
      }
      case processor_t::ev_get_autocmt: {
         qstring *buf = va_arg(va, qstring *);
         const insn_t *insn = va_arg(va, const insn_t *);
         return get_autocmt(buf, insn);
      }
      case processor_t::ev_get_operand_string: {
         qstring *buf = va_arg(va, qstring *);
         const insn_t *insn = va_arg(va, const insn_t *);
         const int opnum = va_arg(va, int);
         return get_operand_string(buf, insn, opnum);
      }
      case processor_t::ev_is_cond_insn: {
         const insn_t *insn = va_arg(va, const insn_t *);
         return query_insn_flag(insn, TG_ROW_COND_JUMP);
      }
      case processor_t::ev_is_call_insn: {
         const insn_t *insn = va_arg(va, const insn_t *);
         return query_insn_flag(insn, TG_ROW_CALL);
      }
      case processor_t::ev_is_ret_insn: {
         const insn_t *insn = va_arg(va, const insn_t *);
         va_arg(va, int);
         return query_insn_flag(insn, TG_ROW_RET);
      }
      case processor_t::ev_may_be_func: {
         const insn_t *insn = va_arg(va, const insn_t *);
         const int state = va_arg(va, int);
         return may_be_func(insn, state);
      }
      case processor_t::ev_is_basic_block_end: {
         const insn_t *insn = va_arg(va, const insn_t *);
         const bool call_stops_block = va_arg(va, int) != 0;
         DecodedRow row;
         if (insn != nullptr && row.decode(insn->ea)) {
            return row.ends_basic_block(call_stops_block) ? 1 : -1;
         }
         return 0;
      }
      case processor_t::ev_is_indirect_jump: {
         const insn_t *insn = va_arg(va, const insn_t *);
         return is_indirect_jump(insn);
      }
      case processor_t::ev_is_sane_insn: {
         const insn_t *insn = va_arg(va, const insn_t *);
         const int no_crefs = va_arg(va, int);
         return is_sane_insn(insn, no_crefs);
      }
      case processor_t::ev_is_align_insn:
         return tilegx_align_insn_size(va_arg(va, ea_t));
      case processor_t::ev_can_have_type:
         return can_have_type(va_arg(va, const op_t *));
      case processor_t::ev_cmp_operands: {
         const op_t *lhs = va_arg(va, const op_t *);
         const op_t *rhs = va_arg(va, const op_t *);
         return cmp_operands(lhs, rhs);
      }
      case processor_t::ev_is_sp_based: {
         int *mode = va_arg(va, int *);
         va_arg(va, const insn_t *);
         const op_t *op = va_arg(va, const op_t *);
         if (mode != nullptr && op != nullptr && stack_memory_operand(*op)) {
            *mode = OP_SP_BASED | OP_SP_ADD;
            return 1;
         }
         return 0;
      }
      case processor_t::ev_create_func_frame: {
         func_t *pfn = va_arg(va, func_t *);
         if (pfn == nullptr) {
            return 0;
         }
         return pfn->frame != BADNODE || add_frame(pfn, 0, 0, 0) ? 1 : 0;
      }
      case processor_t::ev_get_frame_retsize: {
         int *retsize = va_arg(va, int *);
         va_arg(va, const func_t *);
         if (retsize != nullptr) {
            *retsize = 0;
            return 1;
         }
         return 0;
      }
      case processor_t::ev_calc_spdelta: {
         sval_t *spdelta = va_arg(va, sval_t *);
         const insn_t *insn = va_arg(va, const insn_t *);
         return calc_spdelta(spdelta, insn);
      }
      case processor_t::ev_get_reg_accesses: {
         reg_accesses_t *accvec = va_arg(va, reg_accesses_t *);
         const insn_t *insn = va_arg(va, const insn_t *);
         va_arg(va, int);
         return get_reg_accesses(accvec, insn);
      }
      case processor_t::ev_analyze_prolog:
         return analyze_prolog(va_arg(va, ea_t));
      case processor_t::ev_newfile: {
         g_replay_cache.clear();
         const BootstrapResult first_result = bootstrap_segments();
         if (get_entry_qty() == 0) {
            apply_bootstrap_names(first_result);
         }
         g_replay_cache.clear();
         return 0;
      }
      case processor_t::ev_oldfile:
         g_replay_cache.clear();
         bootstrap_segments();
         g_replay_cache.clear();
         return 0;
      case processor_t::ev_max_ptr_size:
         return 8;
      case processor_t::ev_str2reg: {
         const char *rn = va_arg(va, const char *);
         const int reg = tg_find_reg(rn);
         if (reg >= 0) {
            return reg + 1; // register index + 1 (0 means "not a register")
         }
         return 0;
      }
      case processor_t::ev_get_reg_info: {
         const char **main_regname = va_arg(va, const char **);
         bitrange_t *bitrange = va_arg(va, bitrange_t *);
         const char *rn = va_arg(va, const char *);
         const int reg = tg_find_reg(rn);
         if (reg >= 0 && main_regname != nullptr) {
            *main_regname = REG_NAMES[reg];
            if (bitrange != nullptr) {
               bitrange->reset();
            }
            return 1;
         }
         if (main_regname != nullptr) {
            *main_regname = nullptr;
         }
         if (bitrange != nullptr) {
            bitrange->reset();
         }
         return 0;
      }
      case processor_t::ev_creating_segm: {
         segment_t *seg = va_arg(va, segment_t *);
         if (seg != nullptr) {
            seg->defsr[0] = seg->sel;
            seg->defsr[1] = seg->sel;
            if (seg->perm == 0) {
               seg->perm = SEGPERM_READ | SEGPERM_EXEC;
            }
         }
         return 0;
      }
      case processor_t::ev_loader_elf_machine: {
         va_arg(va, linput_t *);
         const int machine = va_arg(va, int);
         const char **procname = va_arg(va, const char **);
         if (machine == EM_TILEGX) {
            *procname = "tilegx";
            return machine;
         }
         return 0;
      }
      default:
         return 0;
   }
}

processor_t LPH = {
    IDP_INTERFACE_VERSION,
    PLFM_TILEGX,
    PR_SEGS | PR_NO_SEGMOVE | PR_USE32 | PR_DEFSEG32 | PR_USE64 | PR_DEFSEG64 | PRN_HEX,
    0,
    8,
    8,
    SHORT_NAMES,
    LONG_NAMES,
    ASSEMBLERS,
    &notify,
    REG_NAMES,
    NUM_REGS,
    NUM_REGS - 2,
    NUM_REGS - 1,
    0,
    NUM_REGS - 2,
    NUM_REGS - 1,
    nullptr,
    nullptr,
    0,
    NUM_INSTRUCTIONS,
    INSTRUCTIONS,
};
