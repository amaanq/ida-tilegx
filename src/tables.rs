// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Runtime types for generated decode tables.

/// Decoded operand class.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OpKind {
   Reg,
   Imm,
   Addr,
   Spr,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MemKind {
   None,
   Read,
   Write,
   ReadWrite,
}

pub const NO_MEM_OP: u8 = u8::MAX;

#[derive(Clone, Copy)]
pub struct MemDef {
   pub kind:    MemKind,
   pub size:    u8,
   pub base_op: u8,
   pub disp_op: u8,
}

/// How one operand is packed into the bundle and interpreted.
#[expect(
   clippy::struct_excessive_bools,
   reason = "this mirrors the ISA operand spec"
)]
pub struct OperandDef {
   pub kind:       OpKind,
   pub num_bits:   u8,
   pub signed:     bool,
   pub src:        bool,
   pub dest:       bool,
   pub pc_rel:     bool,
   pub rightshift: u8,
   /// Flattened `[input_bit, output_bit, ...]` pairs recovered from binutils'
   /// `extract()`. Read two at a time.
   pub bits:       &'static [u8],
}

/// How one opcode is encoded in a single pipe.
pub struct PipeEnc {
   pub valid: bool,
   pub mask:  u64,
   pub val:   u64,
   /// Indices into `OPERANDS` for this pipe's operands (padded with 0).
   pub ops:   [u8; 4],
}

/// Instruction metadata and per-pipe encodings (X0, X1, Y0, Y1, Y2).
#[expect(
   dead_code,
   reason = "name/pipes are kept for generated metadata and tooling"
)]
pub struct OpcodeDef {
   pub name:         &'static str,
   pub pipes:        u8,
   pub num_operands: u8,
   pub mem:          MemDef,
   pub enc:          [PipeEnc; 5],
}
