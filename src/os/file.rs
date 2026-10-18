//! Whole-file helpers.
//!
//! Advisory locking is available on [`std::fs::File`] itself (`lock`, `try_lock`, ...).

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;

use crate::core::{Error, ErrorKind, Result};

/// Reads a whole file, refusing files larger than `limit` bytes.
pub fn read_limited(path: impl AsRef<Path>, limit: u64) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    let size = file.metadata()?.len();
    if size > limit {
        return Err(Error::new(
            ErrorKind::TooLarge,
            format!("file is {size} bytes, limit is {limit}"),
        ));
    }
    let mut data = Vec::with_capacity(size as usize);
    // `take` guards against the file growing after the size check.
    file.take(limit + 1).read_to_end(&mut data)?;
    if data.len() as u64 > limit {
        return Err(Error::new(ErrorKind::TooLarge, "file grew past the limit"));
    }
    Ok(data)
}

/// Replaces `path` with `data` atomically: readers see either the old or the new contents,
/// never a mix, even if the process dies midway.
pub fn write_atomic(path: impl AsRef<Path>, data: &[u8]) -> io::Result<()> {
    let path = path.as_ref();
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let mut temp_name = std::ffi::OsString::from(".");
    temp_name.push(name);
    temp_name.push(format!(".{}.tmp", std::process::id()));
    let temp = path.with_file_name(temp_name);

    let result = (|| {
        let mut file = File::create(&temp)?;
        file.write_all(data)?;
        file.sync_all()?;
        fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_then_limited_read() {
        let dir = std::env::temp_dir().join(format!("weft-file-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("data.txt");

        write_atomic(&path, b"first").unwrap();
        write_atomic(&path, b"second").unwrap();
        assert_eq!(read_limited(&path, 6).unwrap(), b"second");
        let err = read_limited(&path, 5).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::TooLarge);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1, "no temp file left");

        fs::remove_dir_all(&dir).unwrap();
    }
}
