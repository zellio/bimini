use nix::{errno, unistd, Result};

#[cfg(target_env = "gnu")]
use std::{mem, ptr};

#[derive(Debug)]
pub struct GroupsIter;

impl Iterator for GroupsIter {
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

impl Drop for GroupsIter {
    fn drop(&mut self) {
        unsafe { libc::endgrent() };
    }
}
