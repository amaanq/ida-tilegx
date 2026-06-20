// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! TILE-Gx bundle decoder using generated masks and operand gather tables.
//!
//! X bundles use pipes X0/X1. Y bundles use Y0/Y1/Y2.

use crate::{
   TgBundle,
   TgOp,
   TgOpKind,
   TgSlot,
   generated::{
      OPCODES,
      OPERANDS,
   },
   tables::{
      MemDef,
      MemKind,
      NO_MEM_OP,
      OpKind,
      OperandDef,
   },
};

const MODE_MASK: u64 = 3_u64 << 62;

/// Decode one 64-bit bundle located at `pc`.
pub fn decode_bundle(raw: u64, pc: u64) -> Option<TgBundle> {
   let pipes: &[usize] = if raw & MODE_MASK == 0 {
      &[0, 1]
   } else {
      &[2, 3, 4]
   };
   let mut bundle = TgBundle::default();
   let mut any = false;
   for (n, &pipe) in pipes.iter().enumerate() {
      let slot = decode_pipe(raw, pc, pipe);
      any |= slot.itype != 0;
      bundle.slots[n] = slot;
   }
   bundle.n_slots = u8::try_from(pipes.len()).unwrap_or(0);
   // No pipe in the bundle matched: report failure so the FFI returns 0.
   any.then_some(bundle)
}

/// Most-specific match wins by fixed bit count.
fn decode_pipe(raw: u64, pc: u64, pipe: usize) -> TgSlot {
   let mut best = Option::<usize>::None;
   let mut best_pop = 0_u32;
   for (i, op) in OPCODES.iter().enumerate() {
      let enc = &op.enc[pipe];
      if enc.valid && (raw & enc.mask) == enc.val {
         let pop = enc.mask.count_ones();
         if best.is_none() || pop > best_pop {
            best = Some(i);
            best_pop = pop;
         }
      }
   }

   let Some(idx) = best else {
      return TgSlot::default();
   };
   let op = &OPCODES[idx];
   let enc = &op.enc[pipe];
   let mut raw_ops = [TgOp::default(); 4];
   for i in 0..usize::from(op.num_operands) {
      raw_ops[i] = extract_operand(raw, pc, &OPERANDS[usize::from(enc.ops[i])]);
   }
   let ops = visible_operands(&raw_ops, op.num_operands, op.mem);
   TgSlot {
      itype:     u16::try_from(idx).unwrap_or(0) + 1,
      n_ops:     ops.0,
      _reserved: 0,
      ops:       ops.1,
   }
}

fn visible_operands(raw_ops: &[TgOp; 4], num_operands: u8, mem: MemDef) -> (u8, [TgOp; 4]) {
   let mut out = [TgOp::default(); 4];
   let mut count = 0_usize;
   for i in 0..usize::from(num_operands) {
      if mem.disp_op != NO_MEM_OP && i == usize::from(mem.disp_op) {
         continue;
      }
      let op = if i == usize::from(mem.base_op) && mem.kind != MemKind::None {
         memory_operand(raw_ops, mem).unwrap_or_default()
      } else {
         raw_ops[i]
      };
      out[count] = op;
      count += 1;
   }
   (u8::try_from(count).unwrap_or(0), out)
}

fn memory_operand(raw_ops: &[TgOp; 4], mem: MemDef) -> Option<TgOp> {
   let base = raw_ops.get(usize::from(mem.base_op)).copied()?;
   if base.kind != TgOpKind::Reg as u8 {
      return None;
   }
   let disp = if mem.disp_op == NO_MEM_OP {
      0
   } else {
      raw_ops.get(usize::from(mem.disp_op)).copied()?.value
   };
   Some(TgOp {
      kind: TgOpKind::Mem as u8,
      dtype: mem.size,
      reg: base.reg,
      value: disp,
      ..TgOp::default()
   })
}

fn extract_operand(raw: u64, pc: u64, od: &OperandDef) -> TgOp {
   // Gather the raw field from its (input_bit, output_bit) pairs.
   let mut field = 0;
   for pair in od.bits.chunks_exact(2) {
      field |= ((raw >> pair[0]) & 1) << pair[1];
   }

   // Sign-extend the num_bits-wide field when signed, matching binutils.
   let mut val = i64::try_from(field).unwrap_or(0);
   if od.signed {
      let shift = 64 - u32::from(od.num_bits);
      val = (val << shift) >> shift;
   }

   // Scale by the operand's encoded shift, then anchor to pc when relative.
   let mut value = val << u32::from(od.rightshift);
   if od.pc_rel {
      value += pc.cast_signed();
   }

   match od.kind {
      OpKind::Reg => {
         TgOp {
            kind: TgOpKind::Reg as u8,
            reg: u16::try_from(field & 0x3F).unwrap_or(0),
            ..Default::default()
         }
      },
      OpKind::Addr => {
         TgOp {
            kind: TgOpKind::Near as u8,
            value,
            ..Default::default()
         }
      },
      OpKind::Imm => {
         TgOp {
            kind: TgOpKind::Imm as u8,
            value,
            ..Default::default()
         }
      },
      OpKind::Spr => {
         TgOp {
            kind: TgOpKind::Spr as u8,
            value,
            ..Default::default()
         }
      },
   }
}

#[cfg(test)]
#[expect(
   clippy::inline_modules,
   reason = "decoder smoke tests stay next to decode"
)]
mod tests {
   use super::*;
   use crate::generated::NAMES;

   fn mnems(raw: u64, pc: u64) -> Vec<&'static str> {
      let bundle = decode_bundle(raw, pc).unwrap();
      (0..bundle.n_slots as usize)
         .map(|i| {
            let it = bundle.slots[i].itype;
            if it == 0 {
               "<invalid>"
            } else {
               NAMES[(it - 1) as usize]
            }
         })
         .collect()
   }

   #[test]
   fn entry_bundle_decodes() {
      // Expected: { addxi r9, r32, -79 ; addi r38, r46, -96 ; ld2u r25, [r25] }.
      let raw = u64::from_le_bytes([0x09, 0x18, 0x9B, 0x0D, 0xD3, 0x05, 0xCD, 0x46]);
      let pc = 0xFFFF_FFFC_0003_B0F8_u64;
      assert_eq!(mnems(raw, pc), vec!["addxi", "addi", "ld2u"]);
      let bundle = decode_bundle(raw, pc).unwrap();
      let slot = bundle.slots[2];
      assert_eq!(slot.ops[1].kind, crate::TgOpKind::Mem as u8);
      assert_eq!(
         (slot.ops[1].reg, slot.ops[1].dtype, slot.ops[1].value),
         (25, 2, 0)
      );
   }

   #[test]
   fn spr_operands_stay_distinct_from_immediates() {
      // Expected: { shl16insli r41, r41, 0x141 ; mfspr r42, 0x270b }.
      let raw = u64::from_le_bytes([0x69, 0x1A, 0x14, 0x70, 0x75, 0xE1, 0xB4, 0x18]);
      let bundle = decode_bundle(raw, 0x260).unwrap();
      let slot = bundle.slots[1];

      assert_eq!(NAMES[usize::from(slot.itype - 1)], "mfspr");
      assert_eq!(slot.ops[1].kind, crate::TgOpKind::Spr as u8);
      assert_eq!(slot.ops[1].value, 0x270B_i64);
   }
}
