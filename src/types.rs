// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub const TG_MAX_OPS: usize = 4;
pub const TG_MAX_SLOTS: usize = 3;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TgOpKind {
   None = 0,
   Reg  = 1,
   Imm  = 2,
   Near = 3,
   Spr  = 4,
   Mem  = 5,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[expect(clippy::pub_underscore_fields, reason = "explicit C-ABI padding")]
pub struct TgOp {
   pub kind:      u8,
   pub dtype:     u8,
   pub reg:       u16,
   pub _reserved: u32,
   pub value:     i64,
}

impl Default for TgOp {
   fn default() -> Self {
      Self {
         kind:      TgOpKind::None as u8,
         dtype:     0,
         reg:       0,
         _reserved: 0,
         value:     0,
      }
   }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[expect(clippy::pub_underscore_fields, reason = "explicit C-ABI padding")]
pub struct TgSlot {
   pub itype:     u16,
   pub n_ops:     u8,
   pub _reserved: u8,
   pub ops:       [TgOp; TG_MAX_OPS],
}

impl Default for TgSlot {
   fn default() -> Self {
      Self {
         itype:     0,
         n_ops:     0,
         _reserved: 0,
         ops:       [TgOp::default(); TG_MAX_OPS],
      }
   }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[expect(clippy::pub_underscore_fields, reason = "explicit C-ABI padding")]
pub struct TgBundle {
   pub n_slots:   u8,
   pub _reserved: [u8; 7],
   pub slots:     [TgSlot; TG_MAX_SLOTS],
}

impl Default for TgBundle {
   fn default() -> Self {
      Self {
         n_slots:   0,
         _reserved: [0; 7],
         slots:     [TgSlot::default(); TG_MAX_SLOTS],
      }
   }
}

pub const TG_ROW_CALL: u8 = 1 << 0;
pub const TG_ROW_RET: u8 = 1 << 1;
pub const TG_ROW_COND_JUMP: u8 = 1 << 2;
pub const TG_ROW_STOP: u8 = 1 << 3;
pub const TG_ROW_JUMP: u8 = 1 << 4;
pub const TG_ROW_INDIRECT_JUMP: u8 = 1 << 5;
pub const TG_CREF_JUMP: u8 = 0;
pub const TG_CREF_CALL: u8 = 1;
pub const TG_MEMREF_NONE: u8 = 0;
pub const TG_MEMREF_READ: u8 = 1;
pub const TG_MEMREF_WRITE: u8 = 2;
pub const TG_MEMREF_READ_WRITE: u8 = 3;
pub const TG_DATAREF_NONE: u8 = 0;
pub const TG_DATAREF_IMM: u8 = 1;
pub const TG_ACCESS_READ: u8 = 1;
pub const TG_ACCESS_WRITE: u8 = 2;
pub const TG_NUM_GPRS: usize = 64;
pub const TG_MAX_CREFS: usize = TG_MAX_SLOTS * TG_MAX_OPS;
pub const TG_MAX_CODE_ROWS: usize = 2;
pub const TG_MAX_REG_ACCESSES: usize = 16;
pub const TG_STRING_MAX_BYTES: usize = 512;
pub const TG_STRING_SCAN_BYTES: usize = TG_STRING_MAX_BYTES + 1;
pub const TG_RAW_BASE_SCAN_MAX_BYTES: usize = 256 * 1024;
pub const TG_RAW_RUNTIME_ALIAS_BASE: u64 = 0x8000_0000;
pub const TG_RAW_SCORE_MAX_BYTES: usize = 4096;
pub const TG_RAW_SCORE_MIN_BYTES: usize = 64;
pub const TG_RAW_TILEGX_ACCEPT_SCORE: u32 = 75;
pub const TG_ABI_LAYOUT_MAGIC: u32 = 0x5447_5841;
pub const TG_ABI_LAYOUT_VERSION: u32 = 3;
pub const SP_REG: usize = 54;
pub const LR_REG: usize = 55;
pub const FP_REG: usize = 29;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TgRowView {
   pub valid:       u8,
   pub n_slots:     u8,
   pub size:        u8,
   pub next_offset: u8,
   pub flags:       u8,
   pub slots:       [u8; TG_MAX_SLOTS],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TgCodeRef {
   pub kind:     u8,
   pub reserved: [u8; 7],
   pub target:   u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TgRowRefs {
   pub n_refs:   u8,
   pub reserved: [u8; 7],
   pub refs:     [TgCodeRef; TG_MAX_CREFS],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TgMemRef {
   pub kind:     u8,
   pub size:     u8,
   pub reserved: [u8; 6],
   pub target:   u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TgDataRef {
   pub kind:     u8,
   pub reg:      u8,
   pub reserved: [u8; 6],
   pub target:   u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TgRegAccess {
   pub reg:      u16,
   pub op_index: u8,
   pub access:   u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TgRegAccesses {
   pub n_accesses: u8,
   pub reserved:   [u8; 7],
   pub accesses:   [TgRegAccess; TG_MAX_REG_ACCESSES],
}

impl Default for TgRegAccesses {
   fn default() -> Self {
      Self {
         n_accesses: 0,
         reserved:   [0; 7],
         accesses:   [TgRegAccess::default(); TG_MAX_REG_ACCESSES],
      }
   }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TgPrologState {
   pub saved_regs:        u64,
   pub current_sp_delta:  i64,
   pub min_sp_delta:      i64,
   pub frame_size:        u32,
   pub rows:              u8,
   pub has_frame_pointer: u8,
   pub saved_link:        u8,
   pub reserved:          [u8; 5],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TgRawFileVerdict {
   pub accepted:        u8,
   pub reserved:        [u8; 3],
   pub score:           u32,
   pub decoded_bundles: u32,
   pub total_bundles:   u32,
   pub sampled_bytes:   u32,
   pub runtime_base:    u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TgRowAnalysis {
   pub row:        TgRowView,
   pub first_slot: TgSlot,
   pub refs:       TgRowRefs,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TgCodeRows {
   pub n_rows:   u8,
   pub offsets:  [u8; TG_MAX_CODE_ROWS],
   pub reserved: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TgConstState {
   pub valid:  u64,
   pub values: [u64; TG_NUM_GPRS],
   pub depths: [u8; TG_NUM_GPRS],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TgAbiLayout {
   pub magic:                 u32,
   pub version:               u32,
   pub tg_op_size:            usize,
   pub tg_op_align:           usize,
   pub tg_slot_size:          usize,
   pub tg_slot_align:         usize,
   pub tg_bundle_size:        usize,
   pub tg_bundle_align:       usize,
   pub tg_row_view_size:      usize,
   pub tg_row_view_align:     usize,
   pub tg_code_ref_size:      usize,
   pub tg_code_ref_align:     usize,
   pub tg_row_refs_size:      usize,
   pub tg_row_refs_align:     usize,
   pub tg_mem_ref_size:       usize,
   pub tg_mem_ref_align:      usize,
   pub tg_data_ref_size:      usize,
   pub tg_data_ref_align:     usize,
   pub tg_reg_access_size:    usize,
   pub tg_reg_access_align:   usize,
   pub tg_reg_accesses_size:  usize,
   pub tg_reg_accesses_align: usize,
   pub tg_prolog_state_size:  usize,
   pub tg_prolog_state_align: usize,
   pub tg_raw_verdict_size:   usize,
   pub tg_raw_verdict_align:  usize,
   pub tg_row_analysis_size:  usize,
   pub tg_row_analysis_align: usize,
   pub tg_code_rows_size:     usize,
   pub tg_code_rows_align:    usize,
   pub tg_const_state_size:   usize,
   pub tg_const_state_align:  usize,
   pub string_max_bytes:      usize,
   pub string_scan_bytes:     usize,
}

impl Default for TgConstState {
   fn default() -> Self {
      let mut state = Self {
         valid:  0,
         values: [0; TG_NUM_GPRS],
         depths: [0; TG_NUM_GPRS],
      };
      state.set_const(63, 0, 0);
      state
   }
}

impl TgConstState {
   pub(crate) const fn get_const(&self, reg: usize) -> Option<(u64, u8)> {
      if reg >= TG_NUM_GPRS || (self.valid & (1_u64 << reg)) == 0 {
         None
      } else {
         Some((self.values[reg], self.depths[reg]))
      }
   }

   pub(crate) const fn set_const(&mut self, reg: usize, value: u64, depth: u8) {
      if reg >= TG_NUM_GPRS {
         return;
      }
      self.valid |= 1_u64 << reg;
      self.values[reg] = value;
      self.depths[reg] = depth;
   }

   pub(crate) const fn clear_const(&mut self, reg: usize) {
      if reg >= TG_NUM_GPRS || reg == 63 {
         return;
      }
      self.valid &= !(1_u64 << reg);
      self.values[reg] = 0;
      self.depths[reg] = 0;
   }
}

#[cfg(test)]
#[expect(
   clippy::inline_modules,
   reason = "layout assertions stay next to FFI types"
)]
mod layout_tests {
   use core::mem::{
      align_of,
      size_of,
   };

   use super::*;

   #[test]
   fn op_layout_is_compact_and_aligned() {
      assert_eq!(size_of::<TgOp>(), 16);
      assert_eq!(align_of::<TgOp>(), 8);
   }

   #[test]
   fn slot_and_bundle_sizes() {
      assert_eq!(size_of::<TgSlot>(), 8 + size_of::<TgOp>() * TG_MAX_OPS);
      assert_eq!(align_of::<TgSlot>(), 8);
      assert_eq!(
         size_of::<TgBundle>(),
         8 + size_of::<TgSlot>() * TG_MAX_SLOTS
      );
   }

   #[test]
   fn row_ref_layout_is_compact_and_aligned() {
      assert_eq!(size_of::<TgCodeRef>(), 16);
      assert_eq!(align_of::<TgCodeRef>(), 8);
      assert_eq!(size_of::<TgMemRef>(), 16);
      assert_eq!(align_of::<TgMemRef>(), 8);
      assert_eq!(size_of::<TgDataRef>(), 16);
      assert_eq!(align_of::<TgDataRef>(), 8);
      assert_eq!(size_of::<TgRegAccess>(), 4);
      assert_eq!(align_of::<TgRegAccess>(), 2);
      assert_eq!(
         size_of::<TgRegAccesses>(),
         8 + size_of::<TgRegAccess>() * TG_MAX_REG_ACCESSES
      );
      assert_eq!(align_of::<TgRegAccesses>(), 2);
      assert_eq!(size_of::<TgPrologState>(), 40);
      assert_eq!(align_of::<TgPrologState>(), 8);
      assert_eq!(size_of::<TgRawFileVerdict>(), 32);
      assert_eq!(align_of::<TgRawFileVerdict>(), 8);
      assert_eq!(
         size_of::<TgRowRefs>(),
         8 + size_of::<TgCodeRef>() * TG_MAX_CREFS
      );
      assert_eq!(align_of::<TgRowRefs>(), 8);
      assert_eq!(
         size_of::<TgRowAnalysis>(),
         size_of::<TgRowView>() + size_of::<TgSlot>() + size_of::<TgRowRefs>()
      );
      assert_eq!(align_of::<TgRowAnalysis>(), 8);
      assert_eq!(size_of::<TgCodeRows>(), 4);
      assert_eq!(align_of::<TgCodeRows>(), 1);
      assert_eq!(
         (TG_STRING_MAX_BYTES, TG_STRING_SCAN_BYTES),
         (512, TG_STRING_MAX_BYTES + 1)
      );
      assert_eq!(size_of::<TgAbiLayout>(), 264);
      assert_eq!(align_of::<TgAbiLayout>(), align_of::<usize>());
   }
}
