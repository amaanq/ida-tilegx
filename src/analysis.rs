// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
   generated,
   tables::{
      self,
      MemKind,
      NO_MEM_OP,
   },
   types::{
      FP_REG,
      LR_REG,
      SP_REG,
      TG_ACCESS_READ,
      TG_ACCESS_WRITE,
      TG_CREF_CALL,
      TG_CREF_JUMP,
      TG_MAX_CODE_ROWS,
      TG_MAX_CREFS,
      TG_MAX_OPS,
      TG_MAX_REG_ACCESSES,
      TG_MAX_SLOTS,
      TG_MEMREF_READ,
      TG_MEMREF_READ_WRITE,
      TG_MEMREF_WRITE,
      TG_NUM_GPRS,
      TG_ROW_CALL,
      TG_ROW_COND_JUMP,
      TG_ROW_INDIRECT_JUMP,
      TG_ROW_JUMP,
      TG_ROW_RET,
      TG_ROW_STOP,
      TgBundle,
      TgCodeRef,
      TgCodeRows,
      TgConstState,
      TgMemRef,
      TgOpKind,
      TgPrologState,
      TgRegAccess,
      TgRegAccesses,
      TgRowAnalysis,
      TgRowRefs,
      TgRowView,
      TgSlot,
   },
};

fn valid_slot_indices(bundle: &TgBundle) -> ([u8; TG_MAX_SLOTS], usize) {
   let mut out = [0_u8; TG_MAX_SLOTS];
   let mut count = 0;
   for i in 0..usize::from(bundle.n_slots).min(TG_MAX_SLOTS) {
      if bundle.slots[i].itype != 0 {
         out[count] = u8::try_from(i).unwrap_or(0);
         count += 1;
      }
   }
   (out, count)
}

struct BundleLayout<'bundle> {
   bundle:     &'bundle TgBundle,
   indices:    [u8; TG_MAX_SLOTS],
   slot_count: usize,
}

impl<'bundle> BundleLayout<'bundle> {
   fn new(bundle: &'bundle TgBundle) -> Self {
      let (indices, slot_count) = valid_slot_indices(bundle);
      Self {
         bundle,
         indices,
         slot_count,
      }
   }

   fn code_rows(&self) -> TgCodeRows {
      let row_count = row_count(self.slot_count);
      let mut offsets = [0_u8; TG_MAX_CODE_ROWS];
      for (row_index, offset) in offsets.iter_mut().take(row_count).enumerate() {
         *offset = row_offset(row_index, self.slot_count);
      }
      TgCodeRows {
         n_rows: u8::try_from(row_count).unwrap_or(0),
         offsets,
         reserved: 0,
      }
   }

   fn row_at(&self, offset: u8) -> Option<TgRowView> {
      let rows = row_count(self.slot_count);
      for row_index in 0..rows {
         let start = row_offset(row_index, self.slot_count);
         if offset != start {
            continue;
         }
         let end = if row_index + 1 < rows {
            row_offset(row_index + 1, self.slot_count)
         } else {
            8
         };
         let (first, count) = row_slots(self.slot_count, row_index);
         let mut row_indices = [0_u8; TG_MAX_SLOTS];
         row_indices[..count].copy_from_slice(&self.indices[first..first + count]);
         return Some(TgRowView {
            valid:       1,
            n_slots:     u8::try_from(count).unwrap_or(0),
            size:        end - start,
            next_offset: end,
            flags:       row_flags(self.bundle, self.indices, first, count),
            slots:       row_indices,
         });
      }
      None
   }

   fn first_slot(&self, row: TgRowView) -> TgSlot {
      if row.n_slots == 0 {
         TgSlot::default()
      } else {
         self.bundle.slots[usize::from(row.slots[0])]
      }
   }

   fn refs_for(&self, row: TgRowView) -> TgRowRefs {
      let mut refs = TgRowRefs::default();
      for &slot_index in row
         .slots
         .iter()
         .take(usize::from(row.n_slots).min(TG_MAX_SLOTS))
      {
         let slot = &self.bundle.slots[usize::from(slot_index)];
         let kind = if SlotView::new(slot).is_call() {
            TG_CREF_CALL
         } else {
            TG_CREF_JUMP
         };
         for operand_index in 0..usize::from(slot.n_ops).min(TG_MAX_OPS) {
            let op = slot.ops[operand_index];
            if op.kind != TgOpKind::Near as u8 || usize::from(refs.n_refs) >= TG_MAX_CREFS {
               continue;
            }
            refs.refs[usize::from(refs.n_refs)] = TgCodeRef {
               kind,
               target: op.value.cast_unsigned(),
               ..TgCodeRef::default()
            };
            refs.n_refs += 1;
         }
      }
      refs
   }

   fn analysis_at(&self, offset: u8) -> Option<TgRowAnalysis> {
      self.row_at(offset).map(|row| {
         TgRowAnalysis {
            row,
            first_slot: self.first_slot(row),
            refs: self.refs_for(row),
         }
      })
   }
}

const fn row_count(slot_count: usize) -> usize {
   if slot_count == 0 {
      0
   } else if slot_count == 1 {
      1
   } else {
      2
   }
}

const fn row_offset(row: usize, slot_count: usize) -> u8 {
   if slot_count <= 1 || row == 0 { 0 } else { 4 }
}

fn row_slots(slot_count: usize, row: usize) -> (usize, usize) {
   if row == 0 {
      (0, usize::from(slot_count > 0))
   } else {
      (1, slot_count.saturating_sub(1))
   }
}

#[derive(Clone, Copy)]
pub struct SlotView<'slot> {
   slot: &'slot TgSlot,
}

impl<'slot> SlotView<'slot> {
   pub const fn new(slot: &'slot TgSlot) -> Self {
      Self { slot }
   }

   pub fn name(self) -> &'static str {
      if self.slot.itype == 0 {
         ""
      } else {
         generated::NAMES[usize::from(self.slot.itype - 1)]
      }
   }

   fn opcode(self) -> Option<&'static tables::OpcodeDef> {
      let index = self.slot.itype.checked_sub(1)?;
      generated::OPCODES.get(usize::from(index))
   }

   fn operand_def(self, visible_index: usize) -> Option<&'static tables::OperandDef> {
      let opcode = self.opcode()?;
      let raw_index = visible_to_raw_op_index(opcode, visible_index)?;
      let enc = opcode.enc.iter().find(|enc| enc.valid)?;
      generated::OPERANDS.get(usize::from(enc.ops[raw_index]))
   }

   pub fn reg(self, index: usize) -> Option<usize> {
      let op = self.slot.ops.get(index).copied()?;
      (op.kind == TgOpKind::Reg as u8 && usize::from(op.reg) < TG_NUM_GPRS)
         .then_some(usize::from(op.reg))
   }

   pub fn imm(self, index: usize) -> Option<i64> {
      let op = self.slot.ops.get(index).copied()?;
      (op.kind == TgOpKind::Imm as u8 || op.kind == TgOpKind::Spr as u8).then_some(op.value)
   }

   fn is_call(self) -> bool {
      matches!(self.name(), "jal" | "jalr" | "jalrp")
   }

   fn is_cond_jump(self) -> bool {
      matches!(
         self.name(),
         "beqz"
            | "beqzt"
            | "bgez"
            | "bgezt"
            | "bgtz"
            | "bgtzt"
            | "blbc"
            | "blbct"
            | "blbs"
            | "blbst"
            | "blez"
            | "blezt"
            | "bltz"
            | "bltzt"
            | "bnez"
            | "bnezt"
      )
   }

   fn is_stop(self) -> bool {
      matches!(self.name(), "iret" | "j" | "jr" | "jrp")
   }

   fn is_indirect_jump(self) -> bool {
      matches!(self.name(), "jr" | "jrp") && !self.is_ret()
   }

   fn is_ret(self) -> bool {
      self.name() == "iret"
         || (matches!(self.name(), "jr" | "jrp")
            && self.slot.n_ops > 0
            && self.slot.ops[0].kind == TgOpKind::Reg as u8
            && usize::from(self.slot.ops[0].reg) == LR_REG)
   }

   fn is_plain_nop(self) -> bool {
      self.name() == "nop"
   }

   pub fn writes_first_register(self) -> bool {
      if self.reg(0).is_none() {
         return false;
      }
      self.operand_def(0).is_some_and(|def| def.dest)
   }

   pub fn memory_writeback(self) -> Option<(usize, i64)> {
      for operand_index in 0..usize::from(self.slot.n_ops).min(TG_MAX_OPS) {
         let op = self.slot.ops[operand_index];
         if op.kind != TgOpKind::Mem as u8 {
            continue;
         }
         let def = self.operand_def(operand_index)?;
         if def.dest && usize::from(op.reg) < TG_NUM_GPRS {
            return Some((usize::from(op.reg), op.value));
         }
      }
      None
   }

   fn sp_delta(self) -> Option<i64> {
      let (dst, src, delta) = matches!(self.name(), "addi" | "addli" | "addxi" | "addxli")
         .then(|| (self.reg(0), self.reg(1), self.imm(2)))?;
      (dst == Some(SP_REG) && src == Some(SP_REG)).then_some(delta?)
   }

   fn moves_frame_pointer(self) -> bool {
      self.name() == "move" && self.reg(0) == Some(FP_REG) && self.reg(1) == Some(SP_REG)
   }

   fn stores_link_to_stack(self) -> bool {
      self.name().starts_with("st")
         && self
            .slot
            .ops
            .iter()
            .take(usize::from(self.slot.n_ops))
            .any(|op| op.kind == TgOpKind::Mem as u8 && usize::from(op.reg) == SP_REG)
         && self
            .slot
            .ops
            .iter()
            .take(usize::from(self.slot.n_ops))
            .any(|op| op.kind == TgOpKind::Reg as u8 && usize::from(op.reg) == LR_REG)
   }

   fn stack_store_reg(self) -> Option<usize> {
      if !self.name().starts_with("st") {
         return None;
      }
      let has_stack_mem = self
         .slot
         .ops
         .iter()
         .take(usize::from(self.slot.n_ops))
         .any(|op| op.kind == TgOpKind::Mem as u8 && usize::from(op.reg) == SP_REG);
      if !has_stack_mem {
         return None;
      }
      self
         .slot
         .ops
         .iter()
         .take(usize::from(self.slot.n_ops))
         .find_map(|op| {
            (op.kind == TgOpKind::Reg as u8 && usize::from(op.reg) < TG_NUM_GPRS)
               .then_some(usize::from(op.reg))
         })
   }

   fn function_start_score(self) -> i32 {
      if self.is_ret() || (self.is_stop() && !self.is_call()) || self.is_cond_jump() {
         return 0;
      }
      if self.moves_frame_pointer() {
         return 95;
      }
      if self.sp_delta().is_some_and(|delta| delta < 0) {
         return 85;
      }
      if self.stores_link_to_stack() {
         return 80;
      }
      0
   }

   fn reg_accesses(self, out: &mut RegAccessBuilder) {
      for operand_index in 0..usize::from(self.slot.n_ops).min(TG_MAX_OPS) {
         let op = self.slot.ops[operand_index];
         if op.kind == TgOpKind::Mem as u8 {
            let access = self
               .operand_def(operand_index)
               .map_or(TG_ACCESS_READ, |def| {
                  (u8::from(def.src) * TG_ACCESS_READ) | (u8::from(def.dest) * TG_ACCESS_WRITE)
               });
            out.add(usize::from(op.reg), operand_index, access);
            continue;
         }
         if op.kind != TgOpKind::Reg as u8 {
            continue;
         }

         let mut access = self.operand_def(operand_index).map_or(0, |def| {
            (u8::from(def.src) * TG_ACCESS_READ) | (u8::from(def.dest) * TG_ACCESS_WRITE)
         });
         if access == 0 {
            access = if operand_index == 0 && self.writes_first_register() {
               TG_ACCESS_WRITE
            } else {
               TG_ACCESS_READ
            };
         }
         out.add(usize::from(op.reg), operand_index, access);
      }
      if self.is_call() {
         out.add(LR_REG, usize::from(u8::MAX), TG_ACCESS_WRITE);
      }
   }

   pub fn memory_ref(self, state: &TgConstState) -> Option<TgMemRef> {
      let kind = match self.opcode()?.mem.kind {
         MemKind::None => return None,
         MemKind::Read => TG_MEMREF_READ,
         MemKind::Write => TG_MEMREF_WRITE,
         MemKind::ReadWrite => TG_MEMREF_READ_WRITE,
      };
      let mem = self
         .slot
         .ops
         .iter()
         .take(usize::from(self.slot.n_ops))
         .find(|op| op.kind == TgOpKind::Mem as u8)?;
      let (base_value, _depth) = state.get_const(usize::from(mem.reg))?;
      Some(TgMemRef {
         kind,
         size: mem.dtype,
         reserved: [0; 6],
         target: base_value.wrapping_add(mem.value.cast_unsigned()),
      })
   }
}

impl TgPrologState {
   fn observe_slot(&mut self, slot: SlotView<'_>) {
      if slot.moves_frame_pointer() {
         self.has_frame_pointer = 1;
      }
      if slot.stores_link_to_stack() {
         self.saved_link = 1;
      }
      if let Some(reg) = slot.stack_store_reg() {
         self.saved_regs |= 1_u64 << reg;
      }
      if let Some(delta) = slot.sp_delta() {
         self.current_sp_delta = self.current_sp_delta.saturating_add(delta);
         self.min_sp_delta = self.min_sp_delta.min(self.current_sp_delta);
         self.frame_size = u32::try_from(self.min_sp_delta.saturating_neg()).unwrap_or(u32::MAX);
      }
   }

   pub const fn has_evidence(self) -> bool {
      self.frame_size != 0
         || self.has_frame_pointer != 0
         || self.saved_link != 0
         || self.saved_regs != 0
   }
}

fn visible_to_raw_op_index(opcode: &tables::OpcodeDef, visible_index: usize) -> Option<usize> {
   let mut visible = 0_usize;
   for raw_index in 0..usize::from(opcode.num_operands).min(TG_MAX_OPS) {
      if opcode.mem.disp_op != NO_MEM_OP && raw_index == usize::from(opcode.mem.disp_op) {
         continue;
      }
      if visible == visible_index {
         return Some(raw_index);
      }
      visible += 1;
   }
   None
}

struct RegAccessBuilder {
   accesses: TgRegAccesses,
}

impl RegAccessBuilder {
   const fn new() -> Self {
      Self {
         accesses: TgRegAccesses {
            n_accesses: 0,
            reserved:   [0; 7],
            accesses:   [TgRegAccess {
               reg:      0,
               op_index: 0,
               access:   0,
            }; TG_MAX_REG_ACCESSES],
         },
      }
   }

   fn add(&mut self, reg: usize, op_index: usize, access: u8) {
      if reg >= TG_NUM_GPRS || access == 0 {
         return;
      }
      let reg_u16 = u16::try_from(reg).unwrap_or(0);
      let op_index_u8 = u8::try_from(op_index).unwrap_or(u8::MAX);
      for existing in self
         .accesses
         .accesses
         .iter_mut()
         .take(usize::from(self.accesses.n_accesses))
      {
         if existing.reg == reg_u16 && existing.op_index == op_index_u8 {
            existing.access |= access;
            return;
         }
      }
      if usize::from(self.accesses.n_accesses) >= TG_MAX_REG_ACCESSES {
         return;
      }
      self.accesses.accesses[usize::from(self.accesses.n_accesses)] = TgRegAccess {
         reg: reg_u16,
         op_index: op_index_u8,
         access,
      };
      self.accesses.n_accesses += 1;
   }

   const fn finish(self) -> TgRegAccesses {
      self.accesses
   }
}

fn row_flags(bundle: &TgBundle, indices: [u8; TG_MAX_SLOTS], first: usize, count: usize) -> u8 {
   let mut flags = 0;
   for &slot_index in indices.iter().skip(first).take(count) {
      let slot = SlotView::new(&bundle.slots[usize::from(slot_index)]);
      if slot.is_call() {
         flags |= TG_ROW_CALL;
      }
      if slot.is_ret() {
         flags |= TG_ROW_RET;
      }
      if slot.is_cond_jump() {
         flags |= TG_ROW_COND_JUMP | TG_ROW_JUMP;
      }
      if slot.is_indirect_jump() {
         flags |= TG_ROW_INDIRECT_JUMP | TG_ROW_JUMP;
      }
      if slot.is_stop() {
         flags |= TG_ROW_STOP | TG_ROW_JUMP;
      }
   }
   flags
}

pub fn bundle_row(bundle: &TgBundle, offset: u8) -> Option<TgRowView> {
   BundleLayout::new(bundle).row_at(offset)
}

pub fn row_crefs(bundle: &TgBundle, row: TgRowView) -> TgRowRefs {
   BundleLayout::new(bundle).refs_for(row)
}

pub fn analyze_row(bundle: &TgBundle, offset: u8) -> Option<TgRowAnalysis> {
   BundleLayout::new(bundle).analysis_at(offset)
}

pub fn bundle_code_rows(bundle: &TgBundle) -> TgCodeRows {
   BundleLayout::new(bundle).code_rows()
}

pub fn row_align_size(bundle: &TgBundle, row: TgRowView) -> u8 {
   let (indices, count) = valid_slot_indices(bundle);
   if row.valid == 0 || count == 0 {
      return 0;
   }
   let all_plain_nops = indices
      .iter()
      .take(count)
      .all(|&slot_index| SlotView::new(&bundle.slots[usize::from(slot_index)]).is_plain_nop());
   if all_plain_nops { row.size } else { 0 }
}

pub fn row_sp_delta(bundle: &TgBundle, row: TgRowView) -> i64 {
   let mut delta = 0_i64;
   for &slot_index in row
      .slots
      .iter()
      .take(usize::from(row.n_slots).min(TG_MAX_SLOTS))
   {
      let slot = SlotView::new(&bundle.slots[usize::from(slot_index)]);
      if let Some(slot_delta) = slot.sp_delta() {
         delta += slot_delta;
      }
   }
   delta
}

pub fn row_may_be_func(bundle: &TgBundle, row: TgRowView) -> i32 {
   row.slots
      .iter()
      .take(usize::from(row.n_slots).min(TG_MAX_SLOTS))
      .map(|&slot_index| {
         SlotView::new(&bundle.slots[usize::from(slot_index)]).function_start_score()
      })
      .max()
      .unwrap_or(0)
}

pub fn row_reg_accesses(bundle: &TgBundle, row: TgRowView) -> TgRegAccesses {
   let mut builder = RegAccessBuilder::new();
   for &slot_index in row
      .slots
      .iter()
      .take(usize::from(row.n_slots).min(TG_MAX_SLOTS))
   {
      SlotView::new(&bundle.slots[usize::from(slot_index)]).reg_accesses(&mut builder);
   }
   builder.finish()
}

pub fn scan_prolog_row(bundle: &TgBundle, row: TgRowView, state: &mut TgPrologState) {
   state.rows = state.rows.saturating_add(1);
   for &slot_index in row
      .slots
      .iter()
      .take(usize::from(row.n_slots).min(TG_MAX_SLOTS))
   {
      state.observe_slot(SlotView::new(&bundle.slots[usize::from(slot_index)]));
   }
}
