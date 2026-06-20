// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
   analysis::SlotView,
   types::{
      TG_DATAREF_IMM,
      TgConstState,
      TgDataRef,
      TgMemRef,
   },
};

#[derive(Clone, Copy)]
pub enum ConstEffect {
   RegConst { reg: usize, value: u64 },
   SprWrite { spr: u32, value: u64 },
}

pub struct SlotEffects {
   pub const_effect: Option<ConstEffect>,
   pub mem_ref:      Option<TgMemRef>,
   pub data_ref:     Option<TgDataRef>,
}

pub struct ConstTracker<'state> {
   state: &'state mut TgConstState,
}

fn sign_extend_32(value: u64) -> u64 {
   let low = u32::try_from(value & u64::from(u32::MAX)).unwrap_or(0);
   i64::from(low.cast_signed()).cast_unsigned()
}

impl<'state> ConstTracker<'state> {
   pub const fn new(state: &'state mut TgConstState) -> Self {
      Self { state }
   }

   pub fn analyze_slot(&mut self, slot: SlotView<'_>) -> SlotEffects {
      let mem_ref = slot.memory_ref(self.state);
      let const_effect = self.step(slot);
      SlotEffects {
         const_effect,
         mem_ref,
         data_ref: constant_data_ref(slot, const_effect),
      }
   }

   fn step(&mut self, slot: SlotView<'_>) -> Option<ConstEffect> {
      let result = match slot.name() {
         "move" => self.set_move_const(slot),
         "movei" | "moveli" => self.set_imm_const(slot),
         "addi" | "addli" | "addxi" | "addxli" => self.set_addi_const(slot),
         "shl16insli" => self.set_shl16insli_const(slot),
         "shli" | "shlxi" => self.set_shli_const(slot),
         "andi" | "ori" | "xori" => self.set_bitimm_const(slot),
         "add" | "addx" | "and" | "or" | "xor" => self.set_bitreg_const(slot),
         "mtspr" => return self.set_mtspr_comment(slot),
         _ => None,
      };
      if result.is_none() {
         self.apply_untracked_writes(slot);
      }
      result.map(|(reg, value, _depth)| ConstEffect::RegConst { reg, value })
   }

   fn apply_untracked_writes(&mut self, slot: SlotView<'_>) {
      if slot.writes_first_register()
         && let Some(dst) = slot.reg(0)
      {
         self.state.clear_const(dst);
      }
      if let Some((base, delta)) = slot.memory_writeback() {
         if let Some((value, depth)) = self.state.get_const(base) {
            self
               .state
               .set_const(base, value.wrapping_add(delta.cast_unsigned()), depth);
         } else {
            self.state.clear_const(base);
         }
      }
   }

   fn set_move_const(&mut self, slot: SlotView<'_>) -> Option<(usize, u64, u8)> {
      let dst = slot.reg(0)?;
      let src = slot.reg(1)?;
      let (value, depth) = self.state.get_const(src)?;
      self.state.set_const(dst, value, depth);
      Some((dst, value, depth))
   }

   fn set_imm_const(&mut self, slot: SlotView<'_>) -> Option<(usize, u64, u8)> {
      let dst = slot.reg(0)?;
      let value = slot.imm(1)?.cast_unsigned();
      self.state.set_const(dst, value, 0);
      Some((dst, value, 0))
   }

   fn set_addi_const(&mut self, slot: SlotView<'_>) -> Option<(usize, u64, u8)> {
      let dst = slot.reg(0)?;
      let src = slot.reg(1)?;
      let imm = slot.imm(2)?;
      let (base, depth) = self.state.get_const(src)?;
      let value = if matches!(slot.name(), "addxi" | "addxli") {
         sign_extend_32(base.wrapping_add(imm.cast_unsigned()))
      } else {
         base.wrapping_add(imm.cast_unsigned())
      };
      self.state.set_const(dst, value, depth);
      Some((dst, value, depth))
   }

   fn set_shl16insli_const(&mut self, slot: SlotView<'_>) -> Option<(usize, u64, u8)> {
      let dst = slot.reg(0)?;
      let src = slot.reg(1)?;
      let imm = slot.imm(2)?.cast_unsigned() & 0xFFFF;
      let (base, depth) = self.state.get_const(src)?;
      let next_depth = depth.saturating_add(1);
      let value = (base << 16_u32) | imm;
      self.state.set_const(dst, value, next_depth);
      Some((dst, value, next_depth))
   }

   fn set_shli_const(&mut self, slot: SlotView<'_>) -> Option<(usize, u64, u8)> {
      let dst = slot.reg(0)?;
      let src = slot.reg(1)?;
      let shift = u32::try_from(slot.imm(2)?).ok()?.min(63);
      let (base, depth) = self.state.get_const(src)?;
      let next_depth = depth.saturating_add(1);
      let value = if slot.name() == "shlxi" {
         let low = u32::try_from(base & u64::from(u32::MAX)).unwrap_or(0);
         sign_extend_32(u64::from(low.wrapping_shl(shift.min(31))))
      } else {
         base.wrapping_shl(shift)
      };
      self.state.set_const(dst, value, next_depth);
      Some((dst, value, next_depth))
   }

   fn set_bitimm_const(&mut self, slot: SlotView<'_>) -> Option<(usize, u64, u8)> {
      let dst = slot.reg(0)?;
      let src = slot.reg(1)?;
      let rhs = slot.imm(2)?.cast_unsigned();
      let (base, depth) = self.state.get_const(src)?;
      let value = match slot.name() {
         "andi" => base & rhs,
         "ori" => base | rhs,
         "xori" => base ^ rhs,
         _ => return None,
      };
      self.state.set_const(dst, value, depth);
      Some((dst, value, depth))
   }

   fn set_bitreg_const(&mut self, slot: SlotView<'_>) -> Option<(usize, u64, u8)> {
      let dst = slot.reg(0)?;
      let lhs = slot.reg(1)?;
      let rhs = slot.reg(2)?;
      let (left, left_depth) = self.state.get_const(lhs)?;
      let (right, right_depth) = self.state.get_const(rhs)?;
      let value = match slot.name() {
         "add" => left.wrapping_add(right),
         "addx" => sign_extend_32(left.wrapping_add(right)),
         "and" => left & right,
         "or" => left | right,
         "xor" => left ^ right,
         _ => return None,
      };
      let depth = left_depth.max(right_depth);
      self.state.set_const(dst, value, depth);
      Some((dst, value, depth))
   }

   fn set_mtspr_comment(&self, slot: SlotView<'_>) -> Option<ConstEffect> {
      let spr = u32::try_from(slot.imm(0)?).ok()?;
      let src = slot.reg(1)?;
      let (value, _depth) = self.state.get_const(src)?;
      Some(ConstEffect::SprWrite { spr, value })
   }
}

fn constant_data_ref(slot: SlotView<'_>, effect: Option<ConstEffect>) -> Option<TgDataRef> {
   let ConstEffect::RegConst { reg, value, .. } = effect? else {
      return None;
   };
   if value == 0 {
      return None;
   }
   match slot.name() {
      "movei" | "moveli" | "addi" | "addli" | "addxi" | "addxli" | "shl16insli" | "shli"
      | "shlxi" | "andi" | "ori" | "xori" | "add" | "addx" | "and" | "or" | "xor" => {},
      _ => return None,
   }
   Some(TgDataRef {
      kind:     TG_DATAREF_IMM,
      reg:      u8::try_from(reg).ok()?,
      reserved: [0; 6],
      target:   value,
   })
}
