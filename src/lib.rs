// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// no_std staticlib. Tests use std.
#![cfg_attr(not(test), no_std)]

//! Native TILE-Gx decoder exported to IDA through local `#[repr(C)]` FFI types.

mod analysis;
mod constprop;
mod decode;
mod raw;
mod spr;
mod strings;
mod tables;
mod types;

mod generated;

use core::{
   ffi::{
      CStr,
      c_char,
   },
   fmt::{
      self,
      Write,
   },
   mem::{
      align_of,
      size_of,
   },
   slice,
};

use constprop::{
   ConstEffect,
   ConstTracker,
};
pub use decode::decode_bundle;
pub use types::*;

// IDA links libc's abort. panic = "abort" leaves no unwinding to handle.
#[cfg(not(test))]
#[panic_handler]
#[expect(
   clippy::cfg_not_test,
   reason = "the panic handler is only needed in the no_std build"
)]
#[expect(
   clippy::undocumented_unsafe_blocks,
   reason = "panic path calls libc abort directly"
)]
fn panic(_info: &core::panic::PanicInfo) -> ! {
   unsafe extern "C" {
      fn abort() -> !;
   }
   // SAFETY `abort` is resolved from libc at link time and never returns.
   unsafe { abort() }
}

// panic = "abort" never unwinds, but the object still references the
// personality routine. rustc would supply it when linking, however, the C++
// driver that links this staticlib does not, so define a no-op to keep IDA's
// dlopen from failing.
#[cfg(not(test))]
#[unsafe(no_mangle)]
#[expect(clippy::cfg_not_test, reason = "only the no_std build references it")]
const extern "C" fn rust_eh_personality() {}

/// Mnemonic for an `itype` (0 = could not decode). For tests and tooling.
pub const fn opcode_name(itype: u16) -> &'static str {
   if itype == 0 {
      "<invalid>"
   } else {
      generated::NAMES[(itype - 1) as usize]
   }
}

pub fn opcode_autocmt(itype: u16) -> &'static str {
   itype
      .checked_sub(1)
      .and_then(|index| generated::AUTOCMTS.get(usize::from(index)).copied())
      .unwrap_or("")
}

/// Return the IDA row that starts at the given bundle offset.
///
/// # Safety
///
/// The input bundle pointer must point to readable bundle storage and the
/// output pointer must point to writable row storage. Either pointer may be
/// null, in which case the function returns 0 and writes nothing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tg_bundle_row(
   bundle_ptr: *const TgBundle,
   offset: u8,
   out_ptr: *mut TgRowView,
) -> i32 {
   if bundle_ptr.is_null() || out_ptr.is_null() {
      return 0;
   }
   // SAFETY: null was checked above; the caller guarantees a readable bundle.
   let bundle = unsafe { &*bundle_ptr };
   if let Some(row) = analysis::bundle_row(bundle, offset) {
      // SAFETY: null was checked above; the caller guarantees writable storage.
      unsafe {
         *out_ptr = row;
      }
      return 1_i32;
   }
   // SAFETY: null was checked above; the caller guarantees writable storage.
   unsafe {
      *out_ptr = TgRowView::default();
   }
   0_i32
}

/// Return all direct code references emitted by the row at the given offset.
///
/// # Safety
///
/// The input bundle pointer must point to readable bundle storage and the
/// output pointer must point to writable reference storage. Either pointer may
/// be null, in which case the function returns 0 and writes nothing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tg_row_crefs(
   bundle_ptr: *const TgBundle,
   offset: u8,
   out_ptr: *mut TgRowRefs,
) -> i32 {
   if bundle_ptr.is_null() || out_ptr.is_null() {
      return 0;
   }
   // SAFETY: null was checked above; the caller guarantees a readable bundle.
   let bundle = unsafe { &*bundle_ptr };
   if let Some(row) = analysis::bundle_row(bundle, offset) {
      // SAFETY: null was checked above; the caller guarantees writable storage.
      unsafe {
         *out_ptr = analysis::row_crefs(bundle, row);
      }
      return 1_i32;
   }
   // SAFETY: null was checked above; the caller guarantees writable storage.
   unsafe {
      *out_ptr = TgRowRefs::default();
   }
   0_i32
}

/// Return the consolidated analysis for one decoded row.
///
/// # Safety
///
/// The input bundle pointer must point to readable bundle storage and the
/// output pointer must point to writable analysis storage. Either pointer may
/// be null, in which case the function returns 0 and writes nothing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tg_analyze_row(
   bundle_ptr: *const TgBundle,
   offset: u8,
   out_ptr: *mut TgRowAnalysis,
) -> i32 {
   if bundle_ptr.is_null() || out_ptr.is_null() {
      return 0;
   }
   // SAFETY: null was checked above; the caller guarantees a readable bundle.
   let bundle = unsafe { &*bundle_ptr };
   if let Some(analysis) = analysis::analyze_row(bundle, offset) {
      // SAFETY: null was checked above; the caller guarantees writable storage.
      unsafe {
         *out_ptr = analysis;
      }
      return 1_i32;
   }
   // SAFETY: null was checked above; the caller guarantees writable storage.
   unsafe {
      *out_ptr = TgRowAnalysis::default();
   }
   0_i32
}

/// Return the row start offsets that should be turned into IDA code items.
///
/// # Safety
///
/// The input bundle pointer must point to readable bundle storage and the
/// output pointer must point to writable row-offset storage. Either pointer may
/// be null, in which case the function returns 0 and writes nothing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tg_bundle_code_rows(
   bundle_ptr: *const TgBundle,
   out_ptr: *mut TgCodeRows,
) -> i32 {
   if bundle_ptr.is_null() || out_ptr.is_null() {
      return 0;
   }
   // SAFETY: null was checked above; the caller guarantees a readable bundle.
   let bundle = unsafe { &*bundle_ptr };
   let rows = analysis::bundle_code_rows(bundle);
   // SAFETY: null was checked above; the caller guarantees writable storage.
   unsafe {
      *out_ptr = rows;
   }
   i32::from(rows.n_rows != 0)
}

/// Return the row size if it is a plain alignment NOP row.
///
/// # Safety
///
/// The input bundle pointer must point to readable bundle storage, or be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tg_row_align_size(bundle_ptr: *const TgBundle, offset: u8) -> i32 {
   if bundle_ptr.is_null() {
      return 0;
   }
   // SAFETY: null was checked above; the caller guarantees a readable bundle.
   let bundle = unsafe { &*bundle_ptr };
   let Some(row) = analysis::bundle_row(bundle, offset) else {
      return 0;
   };
   i32::from(analysis::row_align_size(bundle, row))
}

/// Return the cumulative stack-pointer delta for a decoded row.
///
/// # Safety
///
/// The input bundle pointer must point to readable bundle storage and the
/// output pointer must point to writable delta storage. Either pointer may be
/// null, in which case the function returns 0 and writes nothing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tg_row_sp_delta(
   bundle_ptr: *const TgBundle,
   offset: u8,
   out_ptr: *mut i64,
) -> i32 {
   if bundle_ptr.is_null() || out_ptr.is_null() {
      return 0;
   }
   // SAFETY: null was checked above; the caller guarantees a readable bundle.
   let bundle = unsafe { &*bundle_ptr };
   let Some(row) = analysis::bundle_row(bundle, offset) else {
      return 0;
   };
   // SAFETY: null was checked above; the caller guarantees writable storage.
   unsafe {
      *out_ptr = analysis::row_sp_delta(bundle, row);
   }
   1
}

/// Score whether the row looks like a function start.
///
/// # Safety
///
/// The input bundle pointer must point to readable bundle storage. A null
/// pointer or non-row offset returns 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tg_row_may_be_func(
   bundle_ptr: *const TgBundle,
   offset: u8,
   _state: i32,
) -> i32 {
   if bundle_ptr.is_null() {
      return 0;
   }
   // SAFETY: null was checked above; the caller guarantees a readable bundle.
   let bundle = unsafe { &*bundle_ptr };
   analysis::bundle_row(bundle, offset).map_or(0, |row| analysis::row_may_be_func(bundle, row))
}

/// Return full-register read/write information for a decoded row.
///
/// # Safety
///
/// The input bundle pointer must point to readable bundle storage and the
/// output pointer must point to writable access storage. Either pointer may be
/// null, in which case the function returns 0 and writes nothing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tg_row_reg_accesses(
   bundle_ptr: *const TgBundle,
   offset: u8,
   out_ptr: *mut TgRegAccesses,
) -> i32 {
   if bundle_ptr.is_null() || out_ptr.is_null() {
      return 0;
   }
   // SAFETY: null was checked above; the caller guarantees a readable bundle.
   let bundle = unsafe { &*bundle_ptr };
   let Some(row) = analysis::bundle_row(bundle, offset) else {
      return 0;
   };
   // SAFETY: null was checked above; the caller guarantees writable storage.
   unsafe {
      *out_ptr = analysis::row_reg_accesses(bundle, row);
   }
   1
}

/// Reset prologue scanning state.
///
/// # Safety
///
/// The state pointer must be null or point to writable state storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tg_prolog_state_reset(state_ptr: *mut TgPrologState) {
   if state_ptr.is_null() {
      return;
   }
   // SAFETY: null was checked above; the caller guarantees writable storage.
   unsafe {
      *state_ptr = TgPrologState::default();
   }
}

/// Apply one decoded row to prologue scanning state.
///
/// # Safety
///
/// The bundle pointer must point to readable bundle storage and the state
/// pointer must point to writable state storage. Either pointer may be null, in
/// which case the function returns 0 and writes nothing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tg_prolog_scan_row(
   bundle_ptr: *const TgBundle,
   offset: u8,
   state_ptr: *mut TgPrologState,
) -> i32 {
   if bundle_ptr.is_null() || state_ptr.is_null() {
      return 0;
   }
   // SAFETY: null was checked above; the caller guarantees a readable bundle.
   let bundle = unsafe { &*bundle_ptr };
   let Some(row) = analysis::bundle_row(bundle, offset) else {
      return 0;
   };
   // SAFETY: null was checked above; the caller guarantees writable storage.
   let state = unsafe { &mut *state_ptr };
   analysis::scan_prolog_row(bundle, row, state);
   i32::from(state.has_evidence())
}

/// Find a TILE-Gx register by C-string name, ignoring ASCII case.
///
/// # Safety
///
/// The input pointer must be null or point to a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tg_find_reg(name_ptr: *const c_char) -> i32 {
   if name_ptr.is_null() {
      return -1;
   }
   // SAFETY: null was checked above; the caller guarantees a C string.
   let name = unsafe { CStr::from_ptr(name_ptr) }.to_bytes();
   for (i, reg) in generated::REG_NAMES.iter().enumerate() {
      if name.eq_ignore_ascii_case(reg.as_bytes()) {
         return i32::try_from(i).unwrap_or(-1);
      }
   }
   -1
}

/// Write the short instruction auto-comment for an IDA instruction type.
///
/// # Safety
///
/// The output pointer must point to `out_len` writable bytes. A null pointer,
/// zero length, invalid instruction type, or empty auto-comment returns 0 and
/// writes nothing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tg_autocmt(itype: u16, out_ptr: *mut c_char, out_len: usize) -> i32 {
   if out_ptr.is_null() || out_len == 0 {
      return 0;
   }
   let text = opcode_autocmt(itype);
   if text.is_empty() {
      return 0;
   }
   let mut out = CStrBuf::new(out_ptr, out_len);
   if out.write_str(text).is_err() {
      // SAFETY: null/zero length was checked above.
      unsafe {
         *out_ptr = 0;
      }
      return 0;
   }
   out.finish();
   1
}

/// Reset register-constant tracking state.
///
/// # Safety
///
/// The state pointer must be null or point to writable state storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tg_const_state_reset(state_ptr: *mut TgConstState) {
   if state_ptr.is_null() {
      return;
   }
   // SAFETY: null was checked above; the caller guarantees writable storage.
   unsafe {
      *state_ptr = TgConstState::default();
   }
}

struct CStrBuf {
   ptr: *mut c_char,
   cap: usize,
   len: usize,
}

impl CStrBuf {
   const fn new(ptr: *mut c_char, cap: usize) -> Self {
      Self { ptr, cap, len: 0 }
   }

   fn finish(&mut self) {
      // SAFETY: callers construct this only with non-null storage and cap > 0.
      let end = unsafe { self.ptr.add(self.len) };
      // SAFETY: the pointer above is within the caller-provided output buffer.
      unsafe {
         *end = 0;
      }
   }
}

impl Write for CStrBuf {
   fn write_str(&mut self, s: &str) -> fmt::Result {
      if self.len + s.len() >= self.cap {
         return Err(fmt::Error);
      }
      for &byte in s.as_bytes() {
         // SAFETY: the capacity check above leaves room for this byte and the
         // final nul terminator.
         let out = unsafe { self.ptr.add(self.len) };
         // SAFETY: out points into the caller-provided output buffer.
         unsafe {
            *out = byte.cast_signed();
         }
         self.len += 1;
      }
      Ok(())
   }
}

/// Format a TILE-Gx SPR operand into caller-provided C-string storage.
///
/// # Safety
///
/// The output pointer must point to `out_len` writable bytes. A null pointer
/// or zero length returns 0 and writes nothing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tg_format_spr(spr: u32, out_ptr: *mut c_char, out_len: usize) -> i32 {
   if out_ptr.is_null() || out_len == 0 {
      return 0;
   }
   let mut out = CStrBuf::new(out_ptr, out_len);
   if spr::write_spr_name(&mut out, spr).is_err() {
      // SAFETY: null/zero length was checked above.
      unsafe {
         *out_ptr = 0;
      }
      return 0;
   }
   out.finish();
   1
}

/// Apply one decoded slot to register-constant state and optionally emit a
/// ready-to-append IDA comment.
///
/// # Safety
///
/// The slot pointer must point to readable slot storage, the state pointer to
/// writable tracking state, and the output pointer to the requested writable
/// byte count. A null output pointer or zero length suppresses comment text but
/// still updates state. A null memory-reference pointer suppresses memory-ref
/// output.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tg_const_state_apply_slot(
   slot_ptr: *const TgSlot,
   state_ptr: *mut TgConstState,
   out_ptr: *mut c_char,
   out_len: usize,
   mem_ref_ptr: *mut TgMemRef,
   data_ref_ptr: *mut TgDataRef,
) -> i32 {
   if slot_ptr.is_null() || state_ptr.is_null() {
      return 0;
   }
   // SAFETY: null was checked above; the caller guarantees a readable slot.
   let raw_slot = unsafe { &*slot_ptr };
   // SAFETY: null was checked above; the caller guarantees writable state.
   let state = unsafe { &mut *state_ptr };
   let slot = analysis::SlotView::new(raw_slot);
   let effects = ConstTracker::new(state).analyze_slot(slot);
   let mem_ref = effects.mem_ref;
   if !mem_ref_ptr.is_null() {
      // SAFETY: null was checked above; the caller guarantees writable storage.
      unsafe {
         *mem_ref_ptr = mem_ref.unwrap_or_default();
      }
   }
   let data_ref = effects.data_ref;
   if !data_ref_ptr.is_null() {
      // SAFETY: null was checked above; the caller guarantees writable storage.
      unsafe {
         *data_ref_ptr = data_ref.unwrap_or_default();
      }
   }

   let has_mem_ref = mem_ref.is_some();
   let has_data_ref = data_ref.is_some() && !data_ref_ptr.is_null();
   let Some(effect) = effects.const_effect else {
      return i32::from(has_mem_ref || has_data_ref);
   };
   if out_ptr.is_null() || out_len == 0 {
      return i32::from(has_mem_ref || has_data_ref);
   }

   let mut out = CStrBuf::new(out_ptr, out_len);
   let status = match effect {
      ConstEffect::SprWrite { spr, value } => {
         spr::write_spr_name(&mut out, spr).and_then(|()| write!(&mut out, " = 0x{value:016x}"))
      },
      ConstEffect::RegConst { .. } => return i32::from(has_mem_ref || has_data_ref),
   };
   if status.is_err() {
      // SAFETY: null/zero length was checked above.
      unsafe {
         *out_ptr = 0;
      }
      return i32::from(has_mem_ref || has_data_ref);
   }
   out.finish();
   1
}

/// Apply the raw TILE-Gx file heuristic to a byte buffer.
///
/// # Safety
///
/// The byte pointer must point to the requested readable byte range, or be
/// null. Null and too-short buffers return a rejected verdict.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tg_detect_raw_tilegx(
   bytes_ptr: *const u8,
   len: usize,
) -> TgRawFileVerdict {
   if bytes_ptr.is_null() {
      return TgRawFileVerdict::default();
   }
   // SAFETY: null was checked above; the caller guarantees len readable bytes.
   let bytes = unsafe { slice::from_raw_parts(bytes_ptr, len) };
   raw::detect_raw_tilegx(bytes)
}

/// Score whether a byte buffer looks like raw little-endian TILE-Gx code.
///
/// # Safety
///
/// The byte pointer must point to the requested readable byte range, or be
/// null. Null and too-short buffers score 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tg_raw_tilegx_score(bytes_ptr: *const u8, len: usize) -> u32 {
   if bytes_ptr.is_null() {
      return 0;
   }
   // SAFETY: null was checked above; the caller guarantees len readable bytes.
   let bytes = unsafe { slice::from_raw_parts(bytes_ptr, len) };
   raw::raw_tilegx_score(bytes)
}

/// Detect a likely C string in a byte buffer.
///
/// # Safety
///
/// The byte pointer must point to the requested readable byte range and the
/// output pointer must point to writable length storage. Either pointer may be
/// null, in which case the function returns 0 and writes nothing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tg_likely_c_string(
   bytes_ptr: *const u8,
   len: usize,
   out_len_ptr: *mut usize,
) -> i32 {
   if bytes_ptr.is_null() || out_len_ptr.is_null() {
      return 0;
   }
   // SAFETY: null was checked above; the caller guarantees len readable bytes.
   let bytes = unsafe { slice::from_raw_parts(bytes_ptr, len) };
   strings::likely_c_string(bytes).map_or(0_i32, |str_len| {
      // SAFETY: null was checked above; the caller guarantees writable storage.
      unsafe {
         *out_len_ptr = str_len;
      }
      1_i32
   })
}

#[unsafe(no_mangle)]
pub const extern "C" fn tg_abi_layout() -> TgAbiLayout {
   TgAbiLayout {
      magic:                 TG_ABI_LAYOUT_MAGIC,
      version:               TG_ABI_LAYOUT_VERSION,
      tg_op_size:            size_of::<TgOp>(),
      tg_op_align:           align_of::<TgOp>(),
      tg_slot_size:          size_of::<TgSlot>(),
      tg_slot_align:         align_of::<TgSlot>(),
      tg_bundle_size:        size_of::<TgBundle>(),
      tg_bundle_align:       align_of::<TgBundle>(),
      tg_row_view_size:      size_of::<TgRowView>(),
      tg_row_view_align:     align_of::<TgRowView>(),
      tg_code_ref_size:      size_of::<TgCodeRef>(),
      tg_code_ref_align:     align_of::<TgCodeRef>(),
      tg_row_refs_size:      size_of::<TgRowRefs>(),
      tg_row_refs_align:     align_of::<TgRowRefs>(),
      tg_mem_ref_size:       size_of::<TgMemRef>(),
      tg_mem_ref_align:      align_of::<TgMemRef>(),
      tg_data_ref_size:      size_of::<TgDataRef>(),
      tg_data_ref_align:     align_of::<TgDataRef>(),
      tg_reg_access_size:    size_of::<TgRegAccess>(),
      tg_reg_access_align:   align_of::<TgRegAccess>(),
      tg_reg_accesses_size:  size_of::<TgRegAccesses>(),
      tg_reg_accesses_align: align_of::<TgRegAccesses>(),
      tg_prolog_state_size:  size_of::<TgPrologState>(),
      tg_prolog_state_align: align_of::<TgPrologState>(),
      tg_raw_verdict_size:   size_of::<TgRawFileVerdict>(),
      tg_raw_verdict_align:  align_of::<TgRawFileVerdict>(),
      tg_row_analysis_size:  size_of::<TgRowAnalysis>(),
      tg_row_analysis_align: align_of::<TgRowAnalysis>(),
      tg_code_rows_size:     size_of::<TgCodeRows>(),
      tg_code_rows_align:    align_of::<TgCodeRows>(),
      tg_const_state_size:   size_of::<TgConstState>(),
      tg_const_state_align:  align_of::<TgConstState>(),
      string_max_bytes:      TG_STRING_MAX_BYTES,
      string_scan_bytes:     TG_STRING_SCAN_BYTES,
   }
}

/// Decode an 8-byte little-endian bundle located at `pc`.
///
/// # Safety
///
/// `bytes` must point to 8 readable bytes and `out` to a writable [`TgBundle`].
/// Returns 1 on success, 0 if the bundle could not be decoded.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tg_decode_bundle(bytes: *const u8, pc: u64, out: *mut TgBundle) -> i32 {
   if bytes.is_null() || out.is_null() {
      return 0;
   }
   // SAFETY: `bytes` points to 8 readable bytes per the contract. A byte array
   // has alignment 1 so the read is always well aligned.
   let raw = u64::from_le_bytes(unsafe { *bytes.cast::<[u8; 8]>() });
   if let Some(bundle) = decode_bundle(raw, pc) {
      // SAFETY: `out` is a valid writable pointer per the contract.
      unsafe {
         *out = bundle;
      }
      1
   } else {
      // SAFETY: same contract as above.
      unsafe {
         *out = TgBundle::default();
      }
      0
   }
}

#[cfg(test)] mod tests;
