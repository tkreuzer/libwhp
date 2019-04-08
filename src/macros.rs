// Copyright 2018 Cloudbase Solutions Srl
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// Based on https://github.com/retep998/winapi-rs/blob/becb23f4522bec535fdc3417e7c15b390851f2de/src/macros.rs#L308-L326
macro_rules! bitfield {
    ($base:ident $field:ident: $fieldtype:ty [
        $($thing:ident $set_thing:ident[$r:expr],)+
    ]) => {
        impl $base {$(
            #[inline]
            #[allow(non_snake_case)]
            pub fn $thing(&self) -> $fieldtype {
                let size = $crate::std::mem::size_of::<$fieldtype>() * 8;;
                self.$field << (size - $r.end) >> (size - $r.end + $r.start)
            }
            #[inline]
            #[allow(non_snake_case)]
            pub fn $set_thing(&mut self, val: $fieldtype) {
                let mask = ((1 << ($r.end - $r.start)) - 1) << $r.start;
                self.$field &= !mask;
                self.$field |= (val << $r.start) & mask;
            }
        )+}

        impl std::fmt::Display for $base {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                writeln!(f, "{}:", stringify!($base)).unwrap();
                $(
                writeln!(f, "    {}: 0x{:x?}", stringify!($thing),
                         self.$thing()).unwrap();
                )+
                Ok(())
            }
        }
    }
}


// Assumes that WHV_UINT128 is used.
macro_rules! bitfield128 {
    ($base:ident $field:ident: $fieldtype:ty [
        $($thing:ident $set_thing:ident[$r:expr],)+
    ]) => {
        impl $base {$(
            #[inline]
            #[allow(non_snake_case)]
            pub fn $thing(&self) -> $fieldtype {
                // We assume that $r.start < $r.end and both are
                // either smaller or greater than 64.
                if $r.start < 64 {
                    self.$field.Low64 <<
                        (64 - $r.end) >> (64 - $r.end + $r.start)
                }
                else {
                    self.$field.High64 <<
                        (128 - $r.end) >> (64 - $r.end + $r.start)
                }
            }
            #[inline]
            #[allow(non_snake_case)]
            pub fn $set_thing(&mut self, val: $fieldtype) {
                let mask = ((1 << ($r.end - $r.start)) - 1) << ($r.start % 64);
                if $r.start < 64 {
                    self.$field.Low64 &= !mask;
                    self.$field.Low64 |= (val << ($r.start % 64) & mask);
                }
                else {
                    self.$field.High64 &= !mask;
                    self.$field.High64 |= (val << ($r.start % 64) & mask);
                }
            }
        )+}

        impl std::fmt::Display for $base {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                writeln!(f, "{}:", stringify!($base)).unwrap();
                $(
                writeln!(f, "    {}: 0x{:x?}", stringify!($thing),
                         self.$thing()).unwrap();
                )+
                Ok(())
            }
        }
    }
}

