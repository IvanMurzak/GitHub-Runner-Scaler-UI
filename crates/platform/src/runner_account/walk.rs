//! A walk over a directory tree that never follows a link, at any depth.
//!
//! The daemon changes owners and modes as `root` inside trees that runner
//! accounts write to, while their jobs may still run. A walk by path can be
//! turned anywhere: swap a directory for a link between the walk's look at it
//! and its use of it, and every later path goes through the link. Here each
//! directory is opened relative to its parent's descriptor with `O_NOFOLLOW`,
//! and each entry is changed by name relative to that descriptor, also without
//! following a link. What replaces an entry mid-walk is still inside the tree
//! the walk was asked to visit, so the worst a swap does is make the walk skip
//! or change something that tree already held.

use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

/// What [`walk`] shows its visitor.
pub(super) enum Node<'a> {
    /// A directory, open: changes go through its descriptor.
    Directory {
        fd: &'a OwnedFd,
        stat: &'a libc::stat,
    },
    /// Anything else, by name in its open parent.
    Entry {
        parent: RawFd,
        name: &'a CStr,
        stat: &'a libc::stat,
    },
}

impl Node<'_> {
    pub(super) const fn stat(&self) -> &libc::stat {
        match self {
            Self::Directory { stat, .. } | Self::Entry { stat, .. } => stat,
        }
    }

    /// Changes the owner and group (`u32::MAX` keeps one).
    pub(super) fn chown(&self, uid: u32, gid: u32) -> io::Result<()> {
        // SAFETY: the descriptors are open for the call and `name` is
        // NUL-terminated.
        check(unsafe {
            match self {
                Self::Directory { fd, .. } => libc::fchown(fd.as_raw_fd(), uid, gid),
                Self::Entry { parent, name, .. } => {
                    libc::fchownat(*parent, name.as_ptr(), uid, gid, libc::AT_SYMLINK_NOFOLLOW)
                }
            }
        })
    }

    /// Changes the mode. A link has none of its own and is left alone.
    pub(super) fn chmod(&self, mode: u32) -> io::Result<()> {
        if is_link(self.stat()) {
            return Ok(());
        }
        let mode = libc::mode_t::try_from(mode).map_err(|_| io::ErrorKind::InvalidInput)?;
        // SAFETY: as for `chown`.
        let status = unsafe {
            match self {
                Self::Directory { fd, .. } => libc::fchmod(fd.as_raw_fd(), mode),
                Self::Entry { parent, name, .. } => {
                    libc::fchmodat(*parent, name.as_ptr(), mode, libc::AT_SYMLINK_NOFOLLOW)
                }
            }
        };
        match check(status) {
            // Swapped for a link since it was looked at: nothing to change.
            Err(error) if error.raw_os_error() == Some(libc::EOPNOTSUPP) => Ok(()),
            other => other,
        }
    }
}

/// Visits `root` and everything under it. `visit` returns whether to enter a
/// directory it was shown; an entry that vanishes mid-walk is skipped.
///
/// # Errors
///
/// The first error met, after which the rest of the tree is not visited.
pub(super) fn walk(
    root: &Path,
    visit: &mut dyn FnMut(&Node<'_>) -> io::Result<bool>,
) -> io::Result<()> {
    let path = CString::new(root.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    match open_directory(libc::AT_FDCWD, &path) {
        Ok(fd) => {
            let stat = fstat(&fd)?;
            if visit(&Node::Directory {
                fd: &fd,
                stat: &stat,
            })? {
                walk_below(&fd, visit)?;
            }
            Ok(())
        }
        Err(error) if matches!(error.raw_os_error(), Some(libc::ENOTDIR | libc::ELOOP)) => {
            let stat = lstat_at(libc::AT_FDCWD, &path)?;
            visit(&Node::Entry {
                parent: libc::AT_FDCWD,
                name: &path,
                stat: &stat,
            })
            .map(|_| ())
        }
        Err(error) => Err(error),
    }
}

fn walk_below(
    directory: &OwnedFd,
    visit: &mut dyn FnMut(&Node<'_>) -> io::Result<bool>,
) -> io::Result<()> {
    for name in names(directory)? {
        let parent = directory.as_raw_fd();
        let stat = match lstat_at(parent, &name) {
            Ok(stat) => stat,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
            visit(&Node::Entry {
                parent,
                name: &name,
                stat: &stat,
            })?;
            continue;
        }
        let child = match open_directory(parent, &name) {
            Ok(child) => child,
            // Gone, or no longer a directory: nothing here to enter.
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP)
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        let stat = fstat(&child)?;
        if visit(&Node::Directory {
            fd: &child,
            stat: &stat,
        })? {
            walk_below(&child, visit)?;
        }
    }
    Ok(())
}

pub(super) const fn is_link(stat: &libc::stat) -> bool {
    stat.st_mode & libc::S_IFMT == libc::S_IFLNK
}

fn check(status: libc::c_int) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn open_directory(parent: RawFd, name: &CStr) -> io::Result<OwnedFd> {
    // SAFETY: `name` is NUL-terminated; a descriptor `openat` returns is
    // owned by nothing else.
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: see above.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn fstat(fd: &OwnedFd) -> io::Result<libc::stat> {
    // SAFETY: `stat` is plain data the call fills in.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: the descriptor is open and `stat` is writable.
    check(unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) })?;
    Ok(stat)
}

fn lstat_at(parent: RawFd, name: &CStr) -> io::Result<libc::stat> {
    // SAFETY: as for `fstat`.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `name` is NUL-terminated and `stat` is writable.
    check(unsafe { libc::fstatat(parent, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) })?;
    Ok(stat)
}

/// The names in `directory`, read through its descriptor.
fn names(directory: &OwnedFd) -> io::Result<Vec<CString>> {
    // `fdopendir` takes the descriptor over, so it gets a duplicate.
    // SAFETY: duplicating an open descriptor.
    let duplicate = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `duplicate` is an open directory descriptor nothing else owns.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: `fdopendir` failed, so the descriptor is still ours.
        unsafe { libc::close(duplicate) };
        return Err(error);
    }
    let mut names = Vec::new();
    loop {
        // SAFETY: `stream` is open until `closedir` below.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        // SAFETY: `d_name` is a NUL-terminated name valid until the next
        // `readdir` on this stream.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if !matches!(name.to_bytes(), b"." | b"..") {
            names.push(name.to_owned());
        }
    }
    // SAFETY: closes the stream and the duplicate it owns.
    unsafe { libc::closedir(stream) };
    Ok(names)
}

/// Sets the extended attribute `name` on the open directory `fd`.
#[cfg(target_os = "linux")]
pub(super) fn set_attribute(fd: &OwnedFd, name: &CStr, value: &[u8]) -> io::Result<()> {
    // SAFETY: the descriptor is open, `name` is NUL-terminated and `value`
    // is valid for its length.
    check(unsafe {
        libc::fsetxattr(
            fd.as_raw_fd(),
            name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    })
}

/// Reads the extended attribute `name` of the open directory `fd` into
/// `value`, returning its length.
#[cfg(target_os = "linux")]
pub(super) fn attribute(fd: &OwnedFd, name: &CStr, value: &mut [u8]) -> io::Result<usize> {
    // SAFETY: the descriptor is open, `name` is NUL-terminated and `value`
    // is writable for its length.
    let length = unsafe {
        libc::fgetxattr(
            fd.as_raw_fd(),
            name.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    usize::try_from(length).map_err(|_| io::Error::last_os_error())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_swapped_in_anywhere_is_never_followed() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), b"x").unwrap();
        let tree = root.path().join("tree");
        std::fs::create_dir_all(tree.join("a/b")).unwrap();
        std::fs::write(tree.join("a/b/file"), b"x").unwrap();
        std::os::unix::fs::symlink(outside.path(), tree.join("a/link")).unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("root-link")).unwrap();
        let mut seen = Vec::new();
        walk(&tree, &mut |node| {
            seen.push((matches!(node, Node::Directory { .. }), is_link(node.stat())));
            node.chmod(0o750)?;
            Ok(true)
        })
        .unwrap();
        // tree, a, b, file, link: the link is shown, never entered.
        assert_eq!(seen.len(), 5);
        assert_eq!(seen.iter().filter(|(_, link)| *link).count(), 1);
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&tree.join("a/b/file")), 0o750);
        assert_ne!(mode(&outside.path().join("secret")), 0o750);
        // A root that is itself a link is shown as one and not entered.
        let mut entered = false;
        walk(&root.path().join("root-link"), &mut |node| {
            entered |= matches!(node, Node::Directory { .. });
            Ok(true)
        })
        .unwrap();
        assert!(!entered);
    }
}
