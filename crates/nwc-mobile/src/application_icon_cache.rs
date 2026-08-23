use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use nostr::hashes::{sha256, Hash};

use crate::nwa::validated_public_icon_url;

const ICON_DIRECTORY: &str = "nwc_icons";
const STALE_TEMPORARY_FILE_AGE: Duration = Duration::from_secs(60);
static TEMPORARY_FILE_NONCE: AtomicU64 = AtomicU64::new(0);

/// Maximum normalized icon size accepted by the shared cache.
pub const MAX_APPLICATION_ICON_BYTES: usize = 5 * 1024 * 1024;

/// A bounded public HTTPS URL suitable for an application's display icon.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ApplicationIconUrl(String);

impl ApplicationIconUrl {
    /// Parses and canonicalizes a public HTTPS application icon URL.
    pub fn parse(value: &str) -> Result<Self, ApplicationIconCacheError> {
        validated_public_icon_url(value)
            .map(Self)
            .ok_or(ApplicationIconCacheError::InvalidUrl)
    }

    /// Returns the canonical public URL.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ApplicationIconUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApplicationIconUrl([redacted])")
    }
}

/// Filesystem-backed cache for normalized application icons.
#[derive(Clone, Debug)]
pub struct ApplicationIconCache {
    directory: PathBuf,
}

impl ApplicationIconCache {
    /// Creates a cache rooted beneath the host's non-sensitive cache directory.
    #[must_use]
    pub fn new(cache_directory: impl AsRef<Path>) -> Self {
        Self {
            directory: cache_directory.as_ref().join(ICON_DIRECTORY),
        }
    }

    /// Creates the cache directory and removes interrupted temporary writes.
    pub fn prepare(&self) -> Result<(), ApplicationIconCacheError> {
        fs::create_dir_all(&self.directory)?;
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let is_temporary = entry
                .path()
                .extension()
                .and_then(|extension| extension.to_str())
                == Some("tmp");
            let is_stale = entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .and_then(|modified| modified.elapsed().map_err(io::Error::other))
                .is_ok_and(|age| age >= STALE_TEMPORARY_FILE_AGE);
            if is_temporary && is_stale {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }

    /// Returns a versioned local file URL when the normalized icon is cached.
    pub fn cached_file_url(
        &self,
        remote_url: &ApplicationIconUrl,
    ) -> Result<Option<String>, ApplicationIconCacheError> {
        let path = self.icon_path(remote_url);
        let metadata = match path.metadata() {
            Ok(metadata) if metadata.is_file() => metadata,
            Ok(_) => return Ok(None),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if metadata.len() == 0 || metadata.len() > MAX_APPLICATION_ICON_BYTES as u64 {
            return Err(ApplicationIconCacheError::InvalidBytes);
        }
        let content = fs::read(&path)?;
        let version = sha256::Hash::hash(&content);
        let mut file_url =
            url::Url::from_file_path(&path).map_err(|()| ApplicationIconCacheError::InvalidPath)?;
        file_url
            .query_pairs_mut()
            .append_pair("v", &version.to_string());
        Ok(Some(file_url.into()))
    }

    /// Atomically stores host-normalized icon bytes and returns their local file URL.
    pub fn store(
        &self,
        remote_url: &ApplicationIconUrl,
        normalized_bytes: &[u8],
    ) -> Result<String, ApplicationIconCacheError> {
        if normalized_bytes.is_empty() || normalized_bytes.len() > MAX_APPLICATION_ICON_BYTES {
            return Err(ApplicationIconCacheError::InvalidBytes);
        }
        fs::create_dir_all(&self.directory)?;
        let destination = self.icon_path(remote_url);
        let nonce = TEMPORARY_FILE_NONCE.fetch_add(1, Ordering::Relaxed);
        let temporary = destination.with_extension(format!("{nonce}.tmp"));
        fs::write(&temporary, normalized_bytes)?;
        if let Err(error) = fs::rename(&temporary, &destination) {
            let _ = fs::remove_file(&temporary);
            return Err(error.into());
        }
        self.cached_file_url(remote_url)?
            .ok_or(ApplicationIconCacheError::InvalidPath)
    }

    fn icon_path(&self, remote_url: &ApplicationIconUrl) -> PathBuf {
        let digest = sha256::Hash::hash(remote_url.as_str().as_bytes());
        self.directory.join(digest.to_string())
    }
}

/// Stable application icon cache failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum ApplicationIconCacheError {
    /// The remote URL is not a bounded public HTTPS URL.
    InvalidUrl,
    /// Normalized bytes are empty or exceed the cache bound.
    InvalidBytes,
    /// The platform path cannot be represented as a local file URL.
    InvalidPath,
    /// A cache filesystem operation failed.
    Io(io::Error),
}

impl fmt::Display for ApplicationIconCacheError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidUrl => "application icon URL is invalid",
            Self::InvalidBytes => "application icon bytes are invalid",
            Self::InvalidPath => "application icon cache path is invalid",
            Self::Io(_) => "application icon cache is unavailable",
        })
    }
}

impl std::error::Error for ApplicationIconCacheError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidUrl | Self::InvalidBytes | Self::InvalidPath => None,
        }
    }
}

impl From<io::Error> for ApplicationIconCacheError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_directory() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "nwc-mobile-icon-cache-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn icon_urls_require_public_https_targets() {
        assert!(ApplicationIconUrl::parse("https://app.example/icon.png").is_ok());
        for invalid in [
            "http://app.example/icon.png",
            "https://localhost/icon.png",
            "https://127.0.0.1/icon.png",
            "https://app.example:8443/icon.png",
            "https://app.example/icon.png#fragment",
        ] {
            assert!(matches!(
                ApplicationIconUrl::parse(invalid),
                Err(ApplicationIconCacheError::InvalidUrl)
            ));
        }
    }

    #[test]
    fn cache_stores_normalized_bytes_under_a_versioned_file_url() {
        let directory = test_directory();
        let cache = ApplicationIconCache::new(&directory);
        let remote = ApplicationIconUrl::parse("https://app.example/icon.png").expect("URL");

        cache.prepare().expect("prepare cache");
        assert_eq!(cache.cached_file_url(&remote).expect("lookup"), None);
        let local = cache.store(&remote, b"normalized-icon").expect("store");

        assert!(local.starts_with("file://"));
        assert!(local.contains("?v="));
        assert_eq!(
            cache.cached_file_url(&remote).expect("lookup").as_deref(),
            Some(local.as_str())
        );
        let replaced = cache
            .store(&remote, b"different-normalized-icon")
            .expect("replace");
        assert_ne!(replaced, local);
        fs::remove_dir_all(directory).expect("remove test cache");
    }

    #[test]
    fn cache_rejects_empty_and_oversized_bytes() {
        let cache = ApplicationIconCache::new(test_directory());
        let remote = ApplicationIconUrl::parse("https://app.example/icon.png").expect("URL");

        assert!(matches!(
            cache.store(&remote, &[]),
            Err(ApplicationIconCacheError::InvalidBytes)
        ));
        assert!(matches!(
            cache.store(&remote, &vec![0; MAX_APPLICATION_ICON_BYTES + 1]),
            Err(ApplicationIconCacheError::InvalidBytes)
        ));
    }
}
