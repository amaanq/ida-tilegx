# Generates the Rust/C++ tables from the ISA spec in this directory.
# Run via `nix run .#gen` or directly with `nu isa/tilegx-gen.nu`.

const PIPE_INDEX = { X0: 0, X1: 1, Y0: 2, Y1: 3, Y2: 4 }
const KIND = { reg: "Reg", imm: "Imm", addr: "Addr", spr: "Spr" }

# 64 architectural register names, then IDA's fake segment registers.
const REGS = [
   r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19
   r20 r21 r22 r23 r24 r25 r26 r27 r28 r29 r30 r31 r32 r33 r34 r35 r36 r37 r38 r39
   r40 r41 r42 r43 r44 r45 r46 r47 r48 r49 r50 r51 r52
   tp sp lr sn idn0 idn1 udn0 udn1 udn2 udn3 zero
]

# Control-flow class inferred from mnemonic and address operands.
# The "jal" prefix covers the indirect forms jalr/jalrp as well.
def cflow [name: string, has_addr: bool] {
   if ($name | str starts-with "jal") {
      "call"
   } else if $name == "j" {
      "jump"
   } else if $name in [jr jrp] {
      "ijump"
   } else if $name == "iret" {
      "ret"
   } else if $has_addr {
      "cbranch"
   } else {
      "normal"
   }
}

def cf_flags [cf: string] {
   match $cf {
      "call" => ["CF_CALL"]
      "jump" => ["CF_JUMP" "CF_STOP"]
      "ijump" => ["CF_JUMP" "CF_STOP"]
      "cbranch" => ["CF_JUMP"]
      "ret" => ["CF_STOP"]
      _ => []
   }
}

def mem-kind [name: string] {
   if ($name | str starts-with "ld") {
      "read"
   } else if ($name | str starts-with "st") {
      "write"
   } else if ($name | str starts-with "prefetch") or ($name in [dtlbpr finv flush icoh inv wh64]) {
      "read"
   } else if ($name | str starts-with "fetch") or ($name in [cmpexch cmpexch4 exch exch4]) {
      "read-write"
   } else {
      "none"
   }
}

def mem-size [name: string] {
   if ($name | str starts-with "ld1") or ($name | str starts-with "st1") or ($name | str starts-with "ldnt1") or ($name | str starts-with "stnt1") {
      1
   } else if ($name | str starts-with "ld2") or ($name | str starts-with "st2") or ($name | str starts-with "ldnt2") or ($name | str starts-with "stnt2") {
      2
   } else if ($name | str starts-with "ld4") or ($name | str starts-with "st4") or ($name | str starts-with "ldnt4") or ($name | str starts-with "stnt4") or ($name in [cmpexch4 exch4 fetchadd4 fetchaddgez4 fetchand4 fetchor4]) {
      4
   } else {
      8
   }
}

def has-mem-displacement [name: string] {
   ($name | str contains "_add") or ($name | str ends-with "_tls")
}

def mem-def [name: string] {
   let kind = (mem-kind $name)
   if $kind == "none" {
      {kind: "MemKind::None", size: "0", base_op: "NO_MEM_OP", disp_op: "NO_MEM_OP"}
   } else {
      let base_op = (if ($name | str starts-with "ld") or ($name | str starts-with "fetch") or ($name in [cmpexch cmpexch4 exch exch4]) { 1 } else { 0 })
      let store_add = (($name | str starts-with "st") and ($name | str contains "_add"))
      let disp_op = if (has-mem-displacement $name) {
         if $store_add { "2" } else if $base_op == 1 { "2" } else { "1" }
      } else {
         "NO_MEM_OP"
      }
      let rust_kind = match $kind {
         "read" => "MemKind::Read"
         "write" => "MemKind::Write"
         "read-write" => "MemKind::ReadWrite"
         _ => "MemKind::None"
      }
      {
         kind: $rust_kind
         size: $"(mem-size $name)"
         base_op: $"($base_op)"
         disp_op: $disp_op
      }
   }
}

def visible-operands [op: record, ops_defs: list] {
   let mem = (mem-def $op.name)
   if $mem.kind == "MemKind::None" {
      0..<($op.num_operands) | each {|i| {kind: "normal", index: $i, def: ($ops_defs | get $i)} }
   } else {
      let base_op = ($mem.base_op | into int)
      let disp_op = if $mem.disp_op == "NO_MEM_OP" { -1 } else { $mem.disp_op | into int }
      0..<($op.num_operands)
      | where {|i| $i != $disp_op }
      | each {|i|
         if $i == $base_op {
            {kind: "mem", index: $i, access: (mem-kind $op.name)}
         } else {
            {kind: "normal", index: $i, def: ($ops_defs | get $i)}
         }
      }
   }
}

# Widest rendered cell in a column, for aligning the generated tables.
def col_width [rows: list, col: string] {
   $rows | each {|r| ($r | get $col | str length) } | math max
}

# Greedily pack comma-suffixed tokens into indented lines under a width budget,
# so a long flat array (names, operand bit pairs) reads as even-length rows.
def wrap_tokens [tokens: list<string>, indent: string, budget: int] {
   mut lines = []
   mut cur = ""
   for t in $tokens {
      let cand = (if ($cur | is-empty) { $t } else { $cur + " " + $t })
      if (($cand | str length) > $budget and ($cur | is-not-empty)) {
         $lines = ($lines | append ($indent + $cur))
         $cur = $t
      } else {
         $cur = $cand
      }
   }
   if ($cur | is-not-empty) {
      $lines = ($lines | append ($indent + $cur))
   }
   $lines | str join "\n"
}

def main [] {
   let isa_dir = $env.FILE_PWD
   let repo_dir = ($isa_dir | path dirname)
   let generated_rs = ($repo_dir | path join src generated.rs)
   let generated_h = ($repo_dir | path join src generated.h)
   let spec = open ($isa_dir | path join tilegx.nuon)
   let autocmts = open ($isa_dir | path join tilegx-autocmt.nuon)
   let n_ops = ($spec.operands | length)
   let n_opc = ($spec.opcodes | length)
   let mpl = (
      "// This Source Code Form is subject to the terms of the Mozilla Public\n" +
      "// License, v. 2.0. If a copy of the MPL was not distributed with this\n" +
      "// file, You can obtain one at https://mozilla.org/MPL/2.0/.\n"
   )

   # Rust decoder tables.
   mut s = $mpl + "\n// @generated by isa/tilegx-gen.nu from isa/tilegx.nuon -- do not edit.\n\n"
   $s += "#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]\n\n"
   $s += "use crate::tables::{MemDef, MemKind, NO_MEM_OP, OperandDef, OpKind, OpcodeDef, PipeEnc};\n\n"
   let op_rows = (
      $spec.operands | each {|op|
         let items = ($op.bits | each {|b| [$"($b.0)_u8" $"($b.1)_u8"] } | flatten)
         {
            kind:       $"OpKind::(($KIND | get $op.type)),"
            num_bits:   $"($op.num_bits),"
            signed:     $"($op.signed),"
            src:        $"($op.src),"
            dest:       $"($op.dest),"
            pc_rel:     $"($op.pc_rel),"
            rightshift: $"($op.rightshift),"
            chunks:     ($items | chunks 16 | each {|c| $c | str join ", " })
         }
      }
   )
   let ow = {
      kind:       (col_width $op_rows kind)
      num_bits:   (col_width $op_rows num_bits)
      signed:     (col_width $op_rows signed)
      src:        (col_width $op_rows src)
      dest:       (col_width $op_rows dest)
      pc_rel:     (col_width $op_rows pc_rel)
      rightshift: (col_width $op_rows rightshift)
   }
   $s += $"pub static OPERANDS: [OperandDef; ($n_ops)] = [\n"
   for r in $op_rows {
      $s += "   OperandDef {\n"
      $s += ("      "
         + "kind: " + ($r.kind | fill -w $ow.kind) + " "
         + "num_bits: " + ($r.num_bits | fill -w $ow.num_bits) + " "
         + "signed: " + ($r.signed | fill -w $ow.signed) + " "
         + "src: " + ($r.src | fill -w $ow.src) + " "
         + "dest: " + ($r.dest | fill -w $ow.dest) + " "
         + "pc_rel: " + ($r.pc_rel | fill -w $ow.pc_rel) + " "
         + "rightshift: " + $r.rightshift + "\n")
      if (($r.chunks | length) <= 1) {
         $s += ("      bits: &[" + ($r.chunks | get 0? | default "") + "],\n")
      } else {
         $s += "      bits: &[\n"
         for c in $r.chunks {
            $s += ("         " + $c + ",\n")
         }
         $s += "      ],\n"
      }
      $s += "   },\n"
   }
   $s += "];\n\n"

   # One {valid, mask, val, ops} cell per pipe (X0, X1, Y0, Y1, Y2).
   let enc_cells = (
      $spec.opcodes | each {|op|
         0..4 | each {|pi|
            let m = ($op.enc | where {|e| ($PIPE_INDEX | get $e.pipe) == $pi })
            if ($m | is-empty) {
               { valid: "false," mask: "0," val: "0," ops: "[0_u8; 4]" }
            } else {
               let e = ($m | first)
               let ops = ($e.ops | append [0 0 0 0] | first 4 | each {|x| $"($x)_u8" } | str join ", ")
               { valid: "true," mask: $"($e.mask)_u64," val: $"($e.val)_u64," ops: $"[($ops)]" }
            }
         }
      }
   )
   # Align the PipeEnc columns across every pipe of every opcode.
   let flat = ($enc_cells | flatten)
   let pw = {
      valid: (col_width $flat valid)
      mask:  (col_width $flat mask)
      val:   (col_width $flat val)
   }
   let hdr_rows = (
      $spec.opcodes | each {|op|
         let mem = (mem-def $op.name)
         {
            name:         $"\"($op.name)\","
            pipes:        $"($op.pipes),"
            num_operands: $"($op.num_operands),"
            mem:          $"MemDef { kind: ($mem.kind), size: ($mem.size), base_op: ($mem.base_op), disp_op: ($mem.disp_op) },"
         }
      }
   )
   let cw = {
      name:         (col_width $hdr_rows name)
      pipes:        (col_width $hdr_rows pipes)
      num_operands: (col_width $hdr_rows num_operands)
      mem:          (col_width $hdr_rows mem)
   }
   $s += $"pub static OPCODES: [OpcodeDef; ($n_opc)] = [\n"
   for i in 0..<($n_opc) {
      let h = ($hdr_rows | get $i)
      $s += ("   OpcodeDef { "
         + "name: " + ($h.name | fill -w $cw.name) + " "
         + "pipes: " + ($h.pipes | fill -w $cw.pipes) + " "
         + "num_operands: " + ($h.num_operands | fill -w $cw.num_operands) + " "
         + "mem: " + ($h.mem | fill -w $cw.mem) + " "
         + "enc: [\n")
      for c in ($enc_cells | get $i) {
         $s += ("      PipeEnc { "
            + "valid: " + ($c.valid | fill -w $pw.valid) + " "
            + "mask: " + ($c.mask | fill -w $pw.mask) + " "
            + "val: " + ($c.val | fill -w $pw.val) + " "
            + "ops: " + $c.ops + " },\n")
      }
      $s += "   ] },\n"
   }
   $s += "];\n\n"
   let name_tokens = ($spec.opcodes | each {|o| $"\"($o.name)\"," })
   $s += $"pub static NAMES: [&str; ($n_opc)] = [\n"
   $s += ((wrap_tokens $name_tokens "   " 96) + "\n];\n")
   let autocmt_tokens = (
      $spec.opcodes | each {|o|
         let text = ($autocmts | get -o $o.name)
         if $text == null {
            error make {msg: $"missing auto-comment for ($o.name)"}
         }
         $"\"($text)\","
      }
   )
   $s += $"\n\npub static AUTOCMTS: [&str; ($n_opc)] = [\n"
   $s += ((wrap_tokens $autocmt_tokens "   " 96) + "\n];\n")
   let rust_reg_tokens = (($REGS ++ [cs ds]) | each {|r| $"\"($r)\"," })
   $s += $"\n\npub static REG_NAMES: [&str; (($REGS | length) + 2)] = [\n"
   $s += ((wrap_tokens $rust_reg_tokens "   " 96) + "\n];\n")
   $s | save -f $generated_rs

   # C++ IDA tables.
   mut h = $mpl + "\n// @generated by isa/tilegx-gen.nu from isa/tilegx.nuon -- do not edit.\n"
   $h += "// Included by processor.cpp after <idp.hpp>.\n\n"
   $h += "static const instruc_t INSTRUCTIONS[] = {\n"
   $h += "    { \"\", 0 },\n"  # itype 0 = could not decode
   for op in $spec.opcodes {
      let first_pipe = ($op.enc | first)
      let ops_defs = ($first_pipe.ops | each {|i| $spec.operands | get $i })
      let has_addr = ($ops_defs | any {|o| $o.type == "addr"})
      let cf = (cflow $op.name $has_addr)
      mut flags = []
      for v in (visible-operands $op $ops_defs | enumerate) {
         let ida_op = ($v.index + 1)
         if $v.item.kind == "mem" {
            if $v.item.access == "read-write" {
               $flags = ($flags | append [$"CF_USE($ida_op)" $"CF_CHG($ida_op)"])
            } else if $v.item.access == "write" {
               $flags = ($flags | append $"CF_CHG($ida_op)")
            } else {
               $flags = ($flags | append $"CF_USE($ida_op)")
            }
         } else {
            let od = $v.item.def
            if $od.dest { $flags = ($flags | append $"CF_CHG($ida_op)") }
            if ($od.src or $od.type == "addr") { $flags = ($flags | append $"CF_USE($ida_op)") }
         }
      }
      $flags = ($flags | append (cf_flags $cf))
      let feat = (if ($flags | is-empty) { "0" } else { $flags | str join " | " })
      $h += $"    { \"($op.name)\", ($feat) },\n"
   }
   $h += "};\n\n"
   let regnames = (($REGS ++ [cs ds]) | each {|r| $"\"($r)\"" } | str join ", ")
   $h += $"static const char *const REG_NAMES[] = { ($regnames) };\n"
   $h | ^clang-format --assume-filename=($generated_h) | save -f $generated_h

   print $"wrote src/generated.rs and src/generated.h with ($n_ops) operands, ($n_opc) opcodes, (($REGS | length)) registers"
}
