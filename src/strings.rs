// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::types::TG_STRING_MAX_BYTES;

const fn is_strlit_char(byte: u8) -> bool {
   (byte >= 0x20 && byte <= 0x7E) || byte == b'\n' || byte == b'\r' || byte == b'\t'
}

const COMMON_STRLIT_PUNCT: &[u8] = b" \t\r\n_%:;,.+-/()[]<>=\'\"!?#&";

fn is_common_strlit_char(byte: u8) -> bool {
   byte.is_ascii_alphanumeric() || COMMON_STRLIT_PUNCT.contains(&byte)
}

pub fn likely_c_string(bytes: &[u8]) -> Option<usize> {
   let mut len = 0_usize;
   let mut letters = 0_usize;
   let mut common = 0_usize;
   for &byte in bytes.iter().take(TG_STRING_MAX_BYTES) {
      if byte == 0 {
         break;
      }
      if !is_strlit_char(byte) {
         return None;
      }
      if byte.is_ascii_alphabetic() {
         letters += 1_usize;
      }
      if is_common_strlit_char(byte) {
         common += 1_usize;
      }
      len += 1_usize;
   }
   if len < 8_usize || len >= bytes.len() || bytes[len] != 0 {
      return None;
   }
   if letters < 4_usize || common * 100_usize < len * 85_usize {
      return None;
   }
   Some(len)
}
