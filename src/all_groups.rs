// Code largely taken from https://github.com/nix-rust/nix/pull/1820
//
// The MIT License (MIT)
//
// Copyright (c) 2015 Carl Lerche + nix-rust Authors
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use libc;
use nix::{errno, unistd, Result};
use std::{mem, ptr};

#[derive(Debug)]
pub struct AllGroups;

impl Iterator for AllGroups {
    type Item = Result<unistd::Group>;

    #[cfg(target_env = "gnu")]
    fn next(&mut self) -> Option<Self::Item> {
        let mut grp = mem::MaybeUninit::<libc::group>::uninit();
        let str_buf_size = match unistd::sysconf(unistd::SysconfVar::GETGR_R_SIZE_MAX) {
            Ok(Some(n)) => n as usize,
            Err(_) | Ok(None) => 4096,
        };

        let mut str_buf = Vec::with_capacity(str_buf_size);
        let mut res: *mut libc::group = ptr::null_mut();
        let ret = unsafe {
            libc::getgrent_r(
                grp.as_mut_ptr(),
                str_buf.as_mut_ptr(),
                str_buf_size,
                &mut res as *mut *mut libc::group,
            )
        };

        if ret != 0 && ret != libc::ENOENT && res.is_null() {
            return Some(Err(errno::Errno::from_i32(ret)));
        }

        if res.is_null() {
            None
        } else {
            let grp = unsafe { grp.assume_init() };
            Some(Ok(unistd::Group::from(&grp)))
        }
    }

    #[cfg(not(target_env = "gnu"))]
    fn next(&mut self) -> Option<Self::Item> {
        errno::Errno::clear();

        let grp = unsafe { libc::getgrent() };
        if grp.is_null() {
            if errno::Errno::last() == errno::Errno::from_i32(0) {
                None
            } else {
                Some(Err(errno::Errno::last()))
            }
        } else {
            Some(Ok(unistd::Group::from(unsafe { &*grp })))
        }
    }
}

impl Drop for AllGroups {
    fn drop(&mut self) {
        unsafe { libc::endgrent() };
    }
}
