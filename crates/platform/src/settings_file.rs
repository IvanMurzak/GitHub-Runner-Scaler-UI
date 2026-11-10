//! Small operator settings kept as one JSON file each.

use std::io;
use std::path::Path;

use serde::Serialize;
use serde::de::DeserializeOwned;

/// The settings at `path`, or the defaults when there is no file.
///
/// # Errors
///
/// When the file cannot be read or does not parse.
pub fn load<T: Default + DeserializeOwned>(path: &Path) -> io::Result<T> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(T::default()),
        Err(error) => Err(error),
    }
}

/// Writes `value` to `path` atomically, so a crash never leaves a truncated
/// file that every later load would refuse.
///
/// # Errors
///
/// When the file cannot be written.
pub fn save(path: &Path, value: &impl Serialize) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(io::Error::other)?;
    crate::host_fitness::write_atomically(path, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Example {
        value: u8,
    }

    #[test]
    fn a_missing_file_is_the_defaults_and_a_saved_one_reads_back() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("nested").join("example.json");
        assert_eq!(load::<Example>(&path).unwrap(), Example::default());
        save(&path, &Example { value: 7 }).unwrap();
        assert_eq!(load::<Example>(&path).unwrap(), Example { value: 7 });
        std::fs::write(&path, b"{").unwrap();
        assert!(load::<Example>(&path).is_err());
    }
}
