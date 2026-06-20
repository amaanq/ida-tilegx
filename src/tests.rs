// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use core::ptr;

use super::*;
use crate::tables::{
   MemKind,
   NO_MEM_OP,
   OpKind,
   OpcodeDef,
   OperandDef,
   PipeEnc,
};

#[test]
fn decode_roundtrips_through_ffi() {
   let bytes = [0_u8; 8];
   let mut out = TgBundle::default();
   // SAFETY: `bytes` is 8 bytes and `out` is a valid local.
   let _ = unsafe { tg_decode_bundle(bytes.as_ptr(), 0, &raw mut out) };
   assert!(usize::from(out.n_slots) <= TG_MAX_SLOTS);
}

#[test]
fn raw_tilegx_score_accepts_dense_code_sample() {
   let bundle = [0x09, 0x18, 0x9B, 0x0D, 0xD3, 0x05, 0xCD, 0x46];
   let mut bytes = [0_u8; TG_RAW_SCORE_MIN_BYTES];
   for chunk in bytes.chunks_exact_mut(8) {
      chunk.copy_from_slice(&bundle);
   }
   // SAFETY: local byte buffer is valid and readable.
   let score = unsafe { tg_raw_tilegx_score(bytes.as_ptr(), bytes.len()) };
   assert_eq!(score, 100);
   // SAFETY: local byte buffer is valid and readable.
   let verdict = unsafe { tg_detect_raw_tilegx(bytes.as_ptr(), bytes.len()) };
   assert_eq!(
      (
         verdict.accepted,
         verdict.score,
         verdict.decoded_bundles,
         verdict.total_bundles,
         verdict.sampled_bytes,
         verdict.runtime_base
      ),
      (
         1,
         100,
         8,
         8,
         u32::try_from(TG_RAW_SCORE_MIN_BYTES).unwrap(),
         0
      )
   );
}

#[test]
fn raw_tilegx_score_rejects_short_buffers() {
   let bytes = [0_u8; TG_RAW_SCORE_MIN_BYTES - 1];
   // SAFETY: local byte buffer is valid and readable.
   let score = unsafe { tg_raw_tilegx_score(bytes.as_ptr(), bytes.len()) };
   assert_eq!(score, 0);
}

#[test]
fn row_mapping_uses_aligned_offsets() {
   let mut bundle = TgBundle {
      n_slots: 3,
      ..TgBundle::default()
   };
   bundle.slots[0].itype = 1;
   bundle.slots[1].itype = 2;
   bundle.slots[2].itype = 3;

   let mut row = TgRowView::default();
   // SAFETY: local values are valid for the FFI call.
   let first_row_status = unsafe { tg_bundle_row(&raw const bundle, 0, &raw mut row) };
   assert_eq!(first_row_status, 1_i32);
   assert_eq!(
      (row.slots[0], row.n_slots, row.size, row.next_offset),
      (0, 1, 4, 4)
   );

   // SAFETY: local values are valid for the FFI call.
   let second_row_status = unsafe { tg_bundle_row(&raw const bundle, 4, &raw mut row) };
   assert_eq!(second_row_status, 1_i32);
   assert_eq!(
      (
         row.slots[0],
         row.slots[1],
         row.n_slots,
         row.size,
         row.next_offset
      ),
      (1, 2, 2, 4, 8)
   );

   // SAFETY: local values are valid for the FFI call.
   let unaligned_row_status = unsafe { tg_bundle_row(&raw const bundle, 2, &raw mut row) };
   assert_eq!(unaligned_row_status, 0_i32);

   let mut code_rows = TgCodeRows::default();
   // SAFETY: local values are valid for the FFI call.
   let code_rows_status = unsafe { tg_bundle_code_rows(&raw const bundle, &raw mut code_rows) };
   assert_eq!(code_rows_status, 1_i32);
   assert_eq!((code_rows.n_rows, code_rows.offsets), (2_u8, [0_u8, 4_u8]));
}

#[test]
fn plain_nop_rows_are_alignment_only() {
   let nop = test_slot("nop", 0, [TgOp::default(); TG_MAX_OPS]);
   let fnop = test_slot("fnop", 0, [TgOp::default(); TG_MAX_OPS]);
   let addi = test_slot("addi", 3, [
      reg_op(1),
      reg_op(1),
      imm_op(1),
      TgOp::default(),
   ]);

   let nop_bundle = single_slot_bundle(nop);
   // SAFETY: local bundle storage is valid for the FFI call.
   let nop_align_size = unsafe { tg_row_align_size(&raw const nop_bundle, 0) };
   assert_eq!(nop_align_size, 8_i32);

   let filler_bundle = single_slot_bundle(fnop);
   // SAFETY: local bundle storage is valid for the FFI call.
   let filler_align_size = unsafe { tg_row_align_size(&raw const filler_bundle, 0) };
   assert_eq!(filler_align_size, 0_i32);

   let mixed_bundle = TgBundle {
      n_slots: 2,
      slots: [nop, addi, TgSlot::default()],
      ..TgBundle::default()
   };
   // SAFETY: local bundle storage is valid for the FFI call.
   let mixed_align_size = unsafe { tg_row_align_size(&raw const mixed_bundle, 0) };
   assert_eq!(mixed_align_size, 0_i32);
}

fn itype(name: &str) -> u16 {
   u16::try_from(generated::NAMES.iter().position(|&n| n == name).unwrap()).unwrap() + 1
}

fn cstr_bytes(buf: &[i8]) -> Vec<u8> {
   buf.iter()
      .take_while(|&&byte| byte != 0)
      .map(|&byte| u8::try_from(byte).unwrap())
      .collect()
}

fn reg_op(reg: u16) -> TgOp {
   TgOp {
      kind: TgOpKind::Reg as u8,
      reg,
      ..TgOp::default()
   }
}

fn imm_op(value: i64) -> TgOp {
   TgOp {
      kind: TgOpKind::Imm as u8,
      value,
      ..TgOp::default()
   }
}

fn spr_op(value: i64) -> TgOp {
   TgOp {
      kind: TgOpKind::Spr as u8,
      value,
      ..TgOp::default()
   }
}

fn mem_op(reg: u16, size: u8, disp: i64) -> TgOp {
   TgOp {
      kind: TgOpKind::Mem as u8,
      dtype: size,
      reg,
      value: disp,
      ..TgOp::default()
   }
}

fn test_slot(name: &str, n_ops: u8, ops: [TgOp; TG_MAX_OPS]) -> TgSlot {
   TgSlot {
      itype: itype(name),
      n_ops,
      ops,
      ..TgSlot::default()
   }
}

fn reg_index(reg: usize) -> u16 {
   u16::try_from(reg).unwrap()
}

fn encode_operand_bits(mut raw: u64, operand_index: u8, value: u64) -> u64 {
   let operand = &generated::OPERANDS[usize::from(operand_index)];
   for pair in operand.bits.chunks_exact(2) {
      if ((value >> pair[1]) & 1) != 0 {
         raw |= 1_u64 << pair[0];
      }
   }
   raw
}

fn encode_first_valid_pipe(name: &str, values: &[u64]) -> u64 {
   let opcode_index = generated::OPCODES
      .iter()
      .position(|op| op.name == name)
      .unwrap();
   encode_opcode_first_valid_pipe(opcode_index, values)
}

fn encode_opcode_first_valid_pipe(opcode_index: usize, values: &[u64]) -> u64 {
   let opcode = &generated::OPCODES[opcode_index];
   let enc = opcode.enc.iter().find(|enc| enc.valid).unwrap();
   encode_opcode_pipe(opcode, enc, values)
}

fn encode_opcode_pipe(opcode: &OpcodeDef, enc: &PipeEnc, values: &[u64]) -> u64 {
   let mut raw = enc.val;
   for (raw_index, &value) in values
      .iter()
      .enumerate()
      .take(usize::from(opcode.num_operands).min(TG_MAX_OPS))
   {
      raw = encode_operand_bits(raw, enc.ops[raw_index], value);
   }
   raw
}

fn sample_operand_value(operand_index: u8, use_negative_disp: bool) -> u64 {
   let operand = &generated::OPERANDS[usize::from(operand_index)];
   match operand.kind {
      OpKind::Reg => u64::from((operand_index % 48) + 8),
      OpKind::Spr => 0x123,
      OpKind::Addr => 0,
      OpKind::Imm if use_negative_disp && operand.signed => (-4_i64).cast_unsigned(),
      OpKind::Imm if use_negative_disp => 4,
      OpKind::Imm => 3,
   }
}

fn decoded_operand_value(operand: &OperandDef, raw_value: u64, pc: u64) -> i64 {
   let mask = if operand.num_bits == 64 {
      u64::MAX
   } else {
      (1_u64 << operand.num_bits) - 1
   };
   let field = raw_value & mask;
   let mut value = i64::try_from(field).unwrap_or(0);
   if operand.signed {
      let shift = 64 - u32::from(operand.num_bits);
      value = (value << shift) >> shift;
   }
   value <<= u32::from(operand.rightshift);
   if operand.pc_rel {
      value += pc.cast_signed();
   }
   value
}

fn single_slot_bundle(slot: TgSlot) -> TgBundle {
   TgBundle {
      n_slots: 1,
      slots: [slot, TgSlot::default(), TgSlot::default()],
      ..TgBundle::default()
   }
}

fn apply_const_slot(slot: &TgSlot, state: &mut TgConstState, buf: &mut [i8]) -> i32 {
   // SAFETY: test-owned slot/state/comment storage is valid for the FFI call.
   unsafe {
      tg_const_state_apply_slot(
         slot,
         state,
         buf.as_mut_ptr(),
         buf.len(),
         ptr::null_mut(),
         ptr::null_mut(),
      )
   }
}

fn apply_const_slot_with_mem(
   slot: &TgSlot,
   state: &mut TgConstState,
   buf: &mut [i8],
) -> (i32, TgMemRef) {
   let mut mem_ref = TgMemRef::default();
   // SAFETY: test-owned slot/state/comment/mem-ref storage is valid for the FFI
   // call.
   let status = unsafe {
      tg_const_state_apply_slot(
         slot,
         state,
         buf.as_mut_ptr(),
         buf.len(),
         &raw mut mem_ref,
         ptr::null_mut(),
      )
   };
   (status, mem_ref)
}

#[test]
fn store_add_decode_keeps_store_reg_and_hides_displacement() {
   let raw = encode_first_valid_pipe("st4_add", &[10, 12, (-4_i64).cast_unsigned()]);
   let bundle = decode_bundle(raw, 0).unwrap();
   let slot = bundle
      .slots
      .iter()
      .find(|slot| slot.itype == itype("st4_add"))
      .unwrap();
   assert_eq!(slot.n_ops, 2);
   assert_eq!(
      (
         slot.ops[0].kind,
         slot.ops[0].reg,
         slot.ops[0].dtype,
         slot.ops[0].value
      ),
      (TgOpKind::Mem as u8, 10, 4, -4)
   );
   assert_eq!(
      (slot.ops[1].kind, slot.ops[1].reg),
      (TgOpKind::Reg as u8, 12)
   );
}

#[test]
fn generated_memory_metadata_decodes_to_visible_memory_operands() {
   const PC: u64 = 0;
   let mut roundtripped = 0_usize;
   for (opcode_index, opcode) in generated::OPCODES.iter().enumerate() {
      if opcode.mem.kind == MemKind::None {
         continue;
      }

      assert!(
         usize::from(opcode.num_operands) <= TG_MAX_OPS,
         "{}",
         opcode.name
      );
      assert_ne!(opcode.mem.base_op, NO_MEM_OP, "{}", opcode.name);
      assert!(opcode.mem.base_op < opcode.num_operands, "{}", opcode.name);
      if opcode.mem.disp_op != NO_MEM_OP {
         assert!(opcode.mem.disp_op < opcode.num_operands, "{}", opcode.name);
         assert_ne!(opcode.mem.disp_op, opcode.mem.base_op, "{}", opcode.name);
      }

      let mut matched = None;
      for enc in opcode.enc.iter().filter(|enc| enc.valid) {
         let mut values = [0_u64; TG_MAX_OPS];
         for (raw_index, value) in values
            .iter_mut()
            .enumerate()
            .take(usize::from(opcode.num_operands))
         {
            *value = sample_operand_value(
               enc.ops[raw_index],
               opcode.mem.disp_op == u8::try_from(raw_index).unwrap(),
            );
         }
         let raw = encode_opcode_pipe(opcode, enc, &values);
         let Some(bundle) = decode_bundle(raw, PC) else {
            continue;
         };
         if let Some(slot) = bundle
            .slots
            .iter()
            .find(|slot| usize::from(slot.itype) == opcode_index + 1)
         {
            matched = Some((enc.ops, values, *slot));
            break;
         }
      }
      let Some((enc_ops, values, slot)) = matched else {
         continue;
      };
      roundtripped += 1;

      let has_disp = opcode.mem.disp_op != NO_MEM_OP;
      assert_eq!(
         slot.n_ops,
         opcode.num_operands - u8::from(has_disp),
         "{}",
         opcode.name
      );

      let visible_mem_index = (0..opcode.mem.base_op)
         .filter(|&raw_index| raw_index != opcode.mem.disp_op)
         .count();
      let mem = slot.ops[visible_mem_index];
      assert_eq!(mem.kind, TgOpKind::Mem as u8, "{}", opcode.name);
      assert_eq!(mem.dtype, opcode.mem.size, "{}", opcode.name);
      assert_eq!(
         u64::from(mem.reg),
         sample_operand_value(enc_ops[usize::from(opcode.mem.base_op)], false),
         "{}",
         opcode.name
      );
      let expected_disp = if has_disp {
         let disp_operand =
            &generated::OPERANDS[usize::from(enc_ops[usize::from(opcode.mem.disp_op)])];
         decoded_operand_value(disp_operand, values[usize::from(opcode.mem.disp_op)], PC)
      } else {
         0
      };
      assert_eq!(mem.value, expected_disp, "{}", opcode.name);
   }
   assert!(roundtripped >= 60, "{roundtripped}");
}

#[test]
fn row_sp_delta_reports_stack_adjustment() {
   let bundle = single_slot_bundle(test_slot("addi", 3, [
      reg_op(reg_index(SP_REG)),
      reg_op(reg_index(SP_REG)),
      imm_op(-0x50),
      TgOp::default(),
   ]));
   let mut delta = 0_i64;
   // SAFETY: local bundle and output storage are valid.
   let status = unsafe { tg_row_sp_delta(&raw const bundle, 0, &raw mut delta) };
   assert_eq!(status, 1_i32);
   assert_eq!(delta, -0x50);
}

#[test]
fn row_may_be_func_scores_frame_pointer_setup() {
   let bundle = single_slot_bundle(test_slot("move", 2, [
      reg_op(reg_index(FP_REG)),
      reg_op(reg_index(SP_REG)),
      TgOp::default(),
      TgOp::default(),
   ]));
   // SAFETY: local bundle is valid.
   let score = unsafe { tg_row_may_be_func(&raw const bundle, 0, 0) };
   assert_eq!(score, 95_i32);
}

#[test]
fn row_reg_accesses_use_operand_metadata() {
   let bundle = single_slot_bundle(test_slot("addi", 3, [
      reg_op(1),
      reg_op(2),
      imm_op(5),
      TgOp::default(),
   ]));
   let mut accesses = TgRegAccesses::default();
   // SAFETY: local bundle and output storage are valid.
   let status = unsafe { tg_row_reg_accesses(&raw const bundle, 0, &raw mut accesses) };
   assert_eq!(status, 1_i32);
   assert_eq!(accesses.n_accesses, 2);
   assert_eq!(
      (accesses.accesses[0].reg, accesses.accesses[0].access),
      (1, TG_ACCESS_WRITE)
   );
   assert_eq!(
      (accesses.accesses[1].reg, accesses.accesses[1].access),
      (2, TG_ACCESS_READ)
   );
}

#[test]
fn row_reg_accesses_mark_store_add_base_writeback() {
   let bundle = single_slot_bundle(test_slot("st4_add", 2, [
      mem_op(10, 4, -4),
      reg_op(12),
      TgOp::default(),
      TgOp::default(),
   ]));
   let mut accesses = TgRegAccesses::default();
   // SAFETY: local bundle and output storage are valid.
   let status = unsafe { tg_row_reg_accesses(&raw const bundle, 0, &raw mut accesses) };
   assert_eq!(status, 1_i32);
   assert_eq!(accesses.n_accesses, 2);
   assert_eq!(
      (accesses.accesses[0].reg, accesses.accesses[0].access),
      (10, TG_ACCESS_READ | TG_ACCESS_WRITE)
   );
   assert_eq!(
      (accesses.accesses[1].reg, accesses.accesses[1].access),
      (12, TG_ACCESS_READ)
   );
}

#[test]
fn row_flags_mark_only_non_return_register_jumps_indirect() {
   let indirect = single_slot_bundle(test_slot("jr", 1, [
      reg_op(10),
      TgOp::default(),
      TgOp::default(),
      TgOp::default(),
   ]));
   let ret = single_slot_bundle(test_slot("jr", 1, [
      reg_op(reg_index(LR_REG)),
      TgOp::default(),
      TgOp::default(),
      TgOp::default(),
   ]));

   let mut row = TgRowView::default();
   // SAFETY: local bundle and output storage are valid.
   let indirect_status = unsafe { tg_bundle_row(&raw const indirect, 0, &raw mut row) };
   assert_eq!(indirect_status, 1_i32);
   assert_ne!(row.flags & TG_ROW_INDIRECT_JUMP, 0);

   // SAFETY: local bundle and output storage are valid.
   let ret_status = unsafe { tg_bundle_row(&raw const ret, 0, &raw mut row) };
   assert_eq!(ret_status, 1_i32);
   assert_eq!(row.flags & TG_ROW_INDIRECT_JUMP, 0);
   assert_ne!(row.flags & TG_ROW_RET, 0);
}

#[test]
fn prolog_scan_tracks_frame_size() {
   let bundle = single_slot_bundle(test_slot("addi", 3, [
      reg_op(reg_index(SP_REG)),
      reg_op(reg_index(SP_REG)),
      imm_op(-0x70),
      TgOp::default(),
   ]));
   let mut state = TgPrologState::default();
   // SAFETY: local state is valid.
   unsafe {
      tg_prolog_state_reset(&raw mut state);
   }
   // SAFETY: local bundle and state are valid.
   let status = unsafe { tg_prolog_scan_row(&raw const bundle, 0, &raw mut state) };
   assert_eq!(status, 1_i32);
   assert_eq!(state.frame_size, 0x70);
   assert_eq!(state.min_sp_delta, -0x70);
}

#[test]
fn prolog_scan_tracks_saved_link_register() {
   let bundle = single_slot_bundle(test_slot("st", 2, [
      mem_op(reg_index(SP_REG), 8, 0),
      reg_op(reg_index(LR_REG)),
      TgOp::default(),
      TgOp::default(),
   ]));
   let mut state = TgPrologState::default();
   // SAFETY: local bundle and state are valid.
   let status = unsafe { tg_prolog_scan_row(&raw const bundle, 0, &raw mut state) };
   assert_eq!(status, 1_i32);
   assert_eq!(state.saved_link, 1);
   assert_ne!(state.saved_regs & (1_u64 << LR_REG), 0);
}

fn apply_const_slot_with_refs(
   slot: &TgSlot,
   state: &mut TgConstState,
   buf: &mut [i8],
) -> (i32, TgMemRef, TgDataRef) {
   let mut mem_ref = TgMemRef::default();
   let mut data_ref = TgDataRef::default();
   // SAFETY: test-owned slot/state/comment/ref storage is valid for the FFI
   // call.
   let status = unsafe {
      tg_const_state_apply_slot(
         slot,
         state,
         buf.as_mut_ptr(),
         buf.len(),
         &raw mut mem_ref,
         &raw mut data_ref,
      )
   };
   (status, mem_ref, data_ref)
}

#[test]
fn row_crefs_classify_calls_and_jumps() {
   let mut bundle = TgBundle {
      n_slots: 2,
      ..TgBundle::default()
   };
   bundle.slots[0] = TgSlot {
      itype: itype("jal"),
      n_ops: 1,
      ops: [
         TgOp {
            kind: TgOpKind::Near as u8,
            value: 0x1234,
            ..TgOp::default()
         },
         TgOp::default(),
         TgOp::default(),
         TgOp::default(),
      ],
      ..TgSlot::default()
   };
   bundle.slots[1] = TgSlot {
      itype: itype("bnez"),
      n_ops: 2,
      ops: [
         TgOp {
            kind: TgOpKind::Reg as u8,
            reg: 1,
            ..TgOp::default()
         },
         TgOp {
            kind: TgOpKind::Near as u8,
            value: 0x5678,
            ..TgOp::default()
         },
         TgOp::default(),
         TgOp::default(),
      ],
      ..TgSlot::default()
   };

   let mut refs = TgRowRefs::default();
   // SAFETY: local values are valid for the FFI call.
   let first_refs_status = unsafe { tg_row_crefs(&raw const bundle, 0, &raw mut refs) };
   assert_eq!(first_refs_status, 1_i32);
   assert_eq!(refs.n_refs, 1_u8);
   assert_eq!(
      (refs.refs[0].kind, refs.refs[0].target),
      (TG_CREF_CALL, 0x1234_u64)
   );

   // SAFETY: local values are valid for the FFI call.
   let second_refs_status = unsafe { tg_row_crefs(&raw const bundle, 4, &raw mut refs) };
   assert_eq!(second_refs_status, 1_i32);
   assert_eq!(refs.n_refs, 1_u8);
   assert_eq!(
      (refs.refs[0].kind, refs.refs[0].target),
      (TG_CREF_JUMP, 0x5678_u64)
   );

   let mut analysis = TgRowAnalysis::default();
   // SAFETY: local values are valid for the FFI call.
   let analysis_status = unsafe { tg_analyze_row(&raw const bundle, 4, &raw mut analysis) };
   assert_eq!(analysis_status, 1_i32);
   assert_eq!(analysis.row.n_slots, 1_u8);
   assert_eq!(analysis.first_slot.itype, itype("bnez"));
   assert_eq!(analysis.refs.n_refs, 1_u8);
   assert_eq!(
      (analysis.refs.refs[0].kind, analysis.refs.refs[0].target),
      (TG_CREF_JUMP, 0x5678_u64)
   );
}

#[test]
fn register_lookup_is_case_insensitive() {
   let lr = b"LR\0";
   let bad = b"user_main\0";
   // SAFETY: byte strings are NUL-terminated.
   let lr_reg = unsafe { tg_find_reg(lr.as_ptr().cast()) };
   assert_eq!(lr_reg, 55_i32);
   // SAFETY: byte string is NUL-terminated.
   let bad_reg = unsafe { tg_find_reg(bad.as_ptr().cast()) };
   assert_eq!(bad_reg, -1_i32);
   // SAFETY: null pointer is explicitly accepted and rejected.
   let null_reg = unsafe { tg_find_reg(ptr::null()) };
   assert_eq!(null_reg, -1_i32);
}

#[test]
fn likely_string_filter_accepts_routerboot_style_strings() {
   let string_bytes = b"boot_panic: BIST hung during training\n\0";
   let mut len = 0;
   // SAFETY: local byte string and output length are valid.
   let status =
      unsafe { tg_likely_c_string(string_bytes.as_ptr(), string_bytes.len(), &raw mut len) };
   assert_eq!(status, 1_i32);
   assert_eq!(len, string_bytes.len() - 1);
}

#[test]
fn likely_string_filter_rejects_short_noise() {
   let string_bytes = [b'j', 0x60, b'i', b'X', b'f', 0];
   let mut len = 0;
   // SAFETY: local byte string and output length are valid.
   let status =
      unsafe { tg_likely_c_string(string_bytes.as_ptr(), string_bytes.len(), &raw mut len) };
   assert_eq!(status, 0_i32);
}

#[test]
fn spr_formatter_writes_known_name() {
   let mut buf = [0_i8; 16];
   // SAFETY: local output storage is valid and writable.
   let status = unsafe { tg_format_spr(0x270B, buf.as_mut_ptr(), buf.len()) };
   assert_eq!(status, 1_i32);
   assert_eq!(cstr_bytes(&buf), b"tile_coord");
}

#[test]
fn spr_formatter_keeps_unknown_fallback_name() {
   let mut buf = [0_i8; 16];
   // SAFETY: local output storage is valid and writable.
   let status = unsafe { tg_format_spr(0x1234, buf.as_mut_ptr(), buf.len()) };
   assert_eq!(status, 1_i32);
   assert_eq!(cstr_bytes(&buf), b"spr_1234");
}

#[test]
fn const_state_comments_on_materialized_values() {
   let mut state = TgConstState::default();
   let moveli = test_slot("moveli", 2, [
      reg_op(41),
      imm_op(0),
      TgOp::default(),
      TgOp::default(),
   ]);
   let insli_hi = test_slot("shl16insli", 3, [
      reg_op(41),
      reg_op(41),
      imm_op(0x18),
      TgOp::default(),
   ]);
   let insli_lo = test_slot("shl16insli", 3, [
      reg_op(41),
      reg_op(41),
      imm_op(0x141),
      TgOp::default(),
   ]);
   let mtspr_780 = test_slot("mtspr", 2, [
      spr_op(0x780),
      reg_op(41),
      TgOp::default(),
      TgOp::default(),
   ]);
   let mtspr_zero = test_slot("mtspr", 2, [
      spr_op(0x782),
      reg_op(63),
      TgOp::default(),
      TgOp::default(),
   ]);
   let mfspr = test_slot("mfspr", 2, [
      reg_op(41),
      spr_op(0x270B),
      TgOp::default(),
      TgOp::default(),
   ]);

   let mut buf = [0_i8; 64];
   let first = apply_const_slot(&moveli, &mut state, &mut buf);
   assert_eq!(first, 0_i32);
   let second = apply_const_slot(&insli_hi, &mut state, &mut buf);
   assert_eq!(second, 0_i32);
   let third = apply_const_slot(&insli_lo, &mut state, &mut buf);
   assert_eq!(third, 0_i32);
   assert!(cstr_bytes(&buf).is_empty());

   buf.fill(0);
   let spr_write = apply_const_slot(&mtspr_780, &mut state, &mut buf);
   assert_eq!(spr_write, 1_i32);
   assert_eq!(cstr_bytes(&buf), b"itlb_current_attr = 0x0000000000180141");

   buf.fill(0);
   let zero_spr_write = apply_const_slot(&mtspr_zero, &mut state, &mut buf);
   assert_eq!(zero_spr_write, 1_i32);
   assert_eq!(cstr_bytes(&buf), b"itlb_current_va = 0x0000000000000000");

   let mfspr_status = apply_const_slot(&mfspr, &mut state, &mut buf);
   assert_eq!(mfspr_status, 0_i32);
   let invalidated_spr_write = apply_const_slot(&mtspr_780, &mut state, &mut buf);
   assert_eq!(invalidated_spr_write, 0_i32);
}

#[test]
fn const_state_reports_memory_refs_from_tracked_bases() {
   let mut state = TgConstState::default();
   let moveli = test_slot("moveli", 2, [
      reg_op(10),
      imm_op(0x1000),
      TgOp::default(),
      TgOp::default(),
   ]);
   let ld = test_slot("ld", 2, [
      reg_op(11),
      mem_op(10, 8, 0),
      TgOp::default(),
      TgOp::default(),
   ]);
   let st4_add = test_slot("st4_add", 2, [
      mem_op(10, 4, -4),
      reg_op(12),
      TgOp::default(),
      TgOp::default(),
   ]);
   let prefetch_add = test_slot("prefetch_add_l1", 2, [
      mem_op(10, 8, 0x20),
      TgOp::default(),
      TgOp::default(),
      TgOp::default(),
   ]);
   let fetchadd4 = test_slot("fetchadd4", 3, [
      reg_op(13),
      mem_op(10, 4, 0),
      reg_op(12),
      TgOp::default(),
   ]);

   let mut buf = [0_i8; 64];
   assert_eq!(apply_const_slot(&moveli, &mut state, &mut buf), 0_i32);

   let (ld_status, ld_ref) = apply_const_slot_with_mem(&ld, &mut state, &mut buf);
   assert_eq!(ld_status, 1_i32);
   assert_eq!(
      (ld_ref.kind, ld_ref.size, ld_ref.target),
      (TG_MEMREF_READ, 8, 0x1000)
   );

   let (st_status, st_ref) = apply_const_slot_with_mem(&st4_add, &mut state, &mut buf);
   assert_eq!(st_status, 1_i32);
   assert_eq!(
      (st_ref.kind, st_ref.size, st_ref.target),
      (TG_MEMREF_WRITE, 4, 0x0FFC)
   );
   assert_eq!(state.get_const(10), Some((0x0FFC, 0)));

   let (prefetch_status, prefetch_ref) =
      apply_const_slot_with_mem(&prefetch_add, &mut state, &mut buf);
   assert_eq!(prefetch_status, 1_i32);
   assert_eq!(
      (prefetch_ref.kind, prefetch_ref.size, prefetch_ref.target),
      (TG_MEMREF_READ, 8, 0x101C)
   );
   assert_eq!(state.get_const(10), Some((0x101C, 0)));

   let (fetchadd_status, fetchadd_ref) =
      apply_const_slot_with_mem(&fetchadd4, &mut state, &mut buf);
   assert_eq!(fetchadd_status, 1_i32);
   assert_eq!(
      (fetchadd_ref.kind, fetchadd_ref.size, fetchadd_ref.target),
      (TG_MEMREF_READ_WRITE, 4, 0x101C)
   );
}

#[test]
fn const_state_reports_materialized_data_ref_candidates() {
   let mut state = TgConstState::default();
   let moveli = test_slot("moveli", 2, [
      reg_op(10),
      imm_op(2),
      TgOp::default(),
      TgOp::default(),
   ]);
   let insli = test_slot("shl16insli", 3, [
      reg_op(10),
      reg_op(10),
      imm_op(0x345),
      TgOp::default(),
   ]);

   let mut buf = [0_i8; 64];
   let (moveli_status, _moveli_mem_ref, moveli_ref) =
      apply_const_slot_with_refs(&moveli, &mut state, &mut buf);
   assert_eq!(moveli_status, 1_i32);
   assert_eq!(
      (moveli_ref.kind, moveli_ref.reg, moveli_ref.target),
      (TG_DATAREF_IMM, 10, 2)
   );

   let (insli_status, _insli_mem_ref, insli_ref) =
      apply_const_slot_with_refs(&insli, &mut state, &mut buf);
   assert_eq!(insli_status, 1_i32);
   assert_eq!(
      (insli_ref.kind, insli_ref.reg, insli_ref.target),
      (TG_DATAREF_IMM, 10, 0x20345)
   );
}

#[test]
fn const_state_clears_bitfield_destinations() {
   let mut state = TgConstState::default();
   let seed = test_slot("moveli", 2, [
      reg_op(10),
      imm_op(0x1234),
      TgOp::default(),
      TgOp::default(),
   ]);
   let bfextu = test_slot("bfextu", 4, [reg_op(10), reg_op(11), imm_op(0), imm_op(7)]);

   let mut buf = [0_i8; 64];
   assert_eq!(apply_const_slot(&seed, &mut state, &mut buf), 0_i32);
   assert_eq!(state.get_const(10), Some((0x1234, 0)));
   assert_eq!(apply_const_slot(&bfextu, &mut state, &mut buf), 0_i32);
   assert_eq!(state.get_const(10), None);
}

#[test]
fn const_state_tracks_shift_and_bitwise_materialization() {
   let mut state = TgConstState::default();
   let seed = test_slot("moveli", 2, [
      reg_op(10),
      imm_op(2),
      TgOp::default(),
      TgOp::default(),
   ]);
   let shli = test_slot("shli", 3, [
      reg_op(10),
      reg_op(10),
      imm_op(12),
      TgOp::default(),
   ]);
   let ori = test_slot("ori", 3, [
      reg_op(10),
      reg_op(10),
      imm_op(0x34),
      TgOp::default(),
   ]);
   let andi = test_slot("andi", 3, [
      reg_op(10),
      reg_op(10),
      imm_op(0x20FF),
      TgOp::default(),
   ]);

   let mut buf = [0_i8; 64];
   let _ = apply_const_slot_with_refs(&seed, &mut state, &mut buf);

   let (shli_status, _shli_mem_ref, shli_ref) =
      apply_const_slot_with_refs(&shli, &mut state, &mut buf);
   assert_eq!(shli_status, 1_i32);
   assert_eq!(
      (shli_ref.kind, shli_ref.reg, shli_ref.target),
      (TG_DATAREF_IMM, 10, 0x2000)
   );

   let (ori_status, _ori_mem_ref, ori_ref) = apply_const_slot_with_refs(&ori, &mut state, &mut buf);
   assert_eq!(ori_status, 1_i32);
   assert_eq!(
      (ori_ref.kind, ori_ref.reg, ori_ref.target),
      (TG_DATAREF_IMM, 10, 0x2034)
   );

   let (andi_status, _andi_mem_ref, andi_ref) =
      apply_const_slot_with_refs(&andi, &mut state, &mut buf);
   assert_eq!(andi_status, 1_i32);
   assert_eq!(
      (andi_ref.kind, andi_ref.reg, andi_ref.target),
      (TG_DATAREF_IMM, 10, 0x2034)
   );
}

#[test]
fn const_state_tracks_register_register_materialization() {
   let mut state = TgConstState::default();
   let lhs = test_slot("moveli", 2, [
      reg_op(10),
      imm_op(0x1200),
      TgOp::default(),
      TgOp::default(),
   ]);
   let rhs = test_slot("moveli", 2, [
      reg_op(11),
      imm_op(0x34),
      TgOp::default(),
      TgOp::default(),
   ]);
   let add = test_slot("add", 3, [
      reg_op(12),
      reg_op(10),
      reg_op(11),
      TgOp::default(),
   ]);
   let xor = test_slot("xor", 3, [
      reg_op(13),
      reg_op(12),
      reg_op(11),
      TgOp::default(),
   ]);

   let mut buf = [0_i8; 64];
   let _ = apply_const_slot_with_refs(&lhs, &mut state, &mut buf);
   let _ = apply_const_slot_with_refs(&rhs, &mut state, &mut buf);

   let (add_status, _add_mem_ref, add_ref) = apply_const_slot_with_refs(&add, &mut state, &mut buf);
   assert_eq!(add_status, 1_i32);
   assert_eq!(
      (add_ref.kind, add_ref.reg, add_ref.target),
      (TG_DATAREF_IMM, 12, 0x1234)
   );

   let (xor_status, _xor_mem_ref, xor_ref) = apply_const_slot_with_refs(&xor, &mut state, &mut buf);
   assert_eq!(xor_status, 1_i32);
   assert_eq!(
      (xor_ref.kind, xor_ref.reg, xor_ref.target),
      (TG_DATAREF_IMM, 13, 0x1200)
   );
}

#[test]
fn const_state_sign_extends_32_bit_x_arithmetic() {
   let mut state = TgConstState::default();
   state.set_const(10, 0x7FFF_FFFF, 0);
   state.set_const(12, 1, 0);
   state.set_const(14, 0xFFFF_FFFF, 0);
   state.set_const(15, 1, 0);

   let addxi = test_slot("addxi", 3, [
      reg_op(11),
      reg_op(10),
      imm_op(1),
      TgOp::default(),
   ]);
   let shlxi = test_slot("shlxi", 3, [
      reg_op(13),
      reg_op(12),
      imm_op(31),
      TgOp::default(),
   ]);
   let addx = test_slot("addx", 3, [
      reg_op(16),
      reg_op(14),
      reg_op(15),
      TgOp::default(),
   ]);

   let mut buf = [0_i8; 64];
   let (addxi_status, _addxi_mem_ref, addxi_ref) =
      apply_const_slot_with_refs(&addxi, &mut state, &mut buf);
   assert_eq!(addxi_status, 1_i32);
   assert_eq!(
      (addxi_ref.kind, addxi_ref.reg, addxi_ref.target),
      (TG_DATAREF_IMM, 11, 0xFFFF_FFFF_8000_0000)
   );

   let (shlxi_status, _shlxi_mem_ref, shlxi_ref) =
      apply_const_slot_with_refs(&shlxi, &mut state, &mut buf);
   assert_eq!(shlxi_status, 1_i32);
   assert_eq!(
      (shlxi_ref.kind, shlxi_ref.reg, shlxi_ref.target),
      (TG_DATAREF_IMM, 13, 0xFFFF_FFFF_8000_0000)
   );

   let zero_add_status = apply_const_slot(&addx, &mut state, &mut buf);
   assert_eq!(zero_add_status, 0_i32);
   assert_eq!(state.get_const(16), Some((0, 0)));
}

#[test]
fn autocmt_uses_manual_instruction_title() {
   let mut buf = [0_i8; 64];
   // SAFETY: local output storage is valid and writable.
   let status = unsafe { tg_autocmt(itype("movei"), buf.as_mut_ptr(), buf.len()) };
   assert_eq!(status, 1_i32);
   assert_eq!(cstr_bytes(&buf), b"Move Immediate Word");
}
