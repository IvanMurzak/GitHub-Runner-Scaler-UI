//! Non-secret execution configuration and immutable attempt allocation.
//!
//! Provider selection never treats `Auto` as permission to start a native
//! process. The only executable provider in this release is native.

use serde::de::Error as _;
use serde::{Deserialize, Serialize};

use crate::model::TargetScope;
use crate::workspace::WorkspacePolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    Auto,
    Oci,
    WindowsHyperVContainer,
    VirtualMachine,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageReference {
    reference: String,
}

impl ImageReference {
    /// A pinned, provider-specific reference. No mutable tag or credential is
    /// accepted as an image identity.
    pub fn new(reference: impl Into<String>) -> Result<Self, ExecutionError> {
        let reference = reference.into();
        let valid = !reference.is_empty()
            && reference.len() <= 512
            && reference.trim() == reference
            && !reference.chars().any(char::is_whitespace)
            && !reference.contains('@') // OCI digest syntax is checked below.
            && (reference.starts_with("sha256:") || reference.starts_with("vm-version:"));
        // OCI references may include a registry and repository before a digest,
        // but no userinfo or mutable tag is allowed.
        let oci = reference
            .rsplit_once("@sha256:")
            .is_some_and(|(name, digest)| {
                !name.is_empty()
                    && !name.contains('@')
                    && !name.contains("://")
                    && !name.chars().any(char::is_whitespace)
                    && oci_name_is_safe(name)
                    && digest.len() == 64
                    && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            });
        let digest = reference.strip_prefix("sha256:").is_some_and(|digest| {
            digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        });
        let version = reference
            .strip_prefix("vm-version:")
            .is_some_and(|version| {
                !version.is_empty()
                    && version.len() <= 128
                    && version
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            });
        if !(oci || (valid && (digest || version))) {
            return Err(ExecutionError::InvalidImage);
        }
        Ok(Self { reference })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.reference
    }
}

/// A colon is only legal as a numeric port in the registry component. This
/// excludes userinfo-looking references and mutable tags before the digest.
fn oci_name_is_safe(name: &str) -> bool {
    let mut segments = name.split('/');
    let Some(registry_or_image) = segments.next() else {
        return false;
    };
    let has_path = name.contains('/');
    let first = if let Some((host, port)) = registry_or_image.rsplit_once(':') {
        has_path
            && !host.is_empty()
            && !port.is_empty()
            && port.bytes().all(|byte| byte.is_ascii_digit())
            && safe_oci_segment(host)
    } else {
        safe_oci_segment(registry_or_image)
    };
    first && segments.all(safe_oci_segment)
}

fn safe_oci_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    pub cpu_millis: u32,
    pub memory_mib: u32,
    pub disk_mib: u32,
}

impl ResourceLimits {
    pub fn validate(self) -> Result<Self, ExecutionError> {
        if self.cpu_millis < 100 || self.memory_mib < 256 || self.disk_mib < 1024 {
            return Err(ExecutionError::InvalidResources);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ExecutionPolicy {
    Native,
    Isolated {
        backend: Backend,
        image: ImageReference,
        resources: ResourceLimits,
    },
}

impl<'de> Deserialize<'de> for ExecutionPolicy {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        let object = value
            .as_object()
            .ok_or_else(|| D::Error::custom("invalid execution policy shape"))?;
        match object.get("mode").and_then(serde_json::Value::as_str) {
            Some("native") if object.len() == 1 => Ok(Self::Native),
            Some("isolated")
                if object.len() == 4
                    && object.contains_key("backend")
                    && object.contains_key("image")
                    && object.contains_key("resources") =>
            {
                let backend = serde_json::from_value(object["backend"].clone())
                    .map_err(|_| D::Error::custom("invalid execution backend"))?;
                let image = serde_json::from_value(object["image"].clone())
                    .map_err(|_| D::Error::custom("invalid execution image shape"))?;
                let resources = serde_json::from_value(object["resources"].clone())
                    .map_err(|_| D::Error::custom("invalid execution resource shape"))?;
                Ok(Self::Isolated {
                    backend,
                    image,
                    resources,
                })
            }
            _ => Err(D::Error::custom("invalid execution policy shape")),
        }
    }
}

impl ExecutionPolicy {
    pub fn validate(
        &self,
        scope: TargetScope,
        workspace: &WorkspacePolicy,
    ) -> Result<(), ExecutionError> {
        if let Self::Isolated {
            backend,
            image,
            resources,
        } = self
        {
            if scope != TargetScope::Repository {
                return Err(ExecutionError::IsolatedRequiresRepository);
            }
            if workspace.is_persistent() {
                return Err(ExecutionError::IsolatedRequiresEphemeral);
            }
            resources.validate()?;
            ImageReference::new(image.as_str())?;
            if matches!(backend, Backend::Oci | Backend::WindowsHyperVContainer)
                && !image.as_str().contains("sha256:")
            {
                return Err(ExecutionError::BackendImageMismatch);
            }
        }
        Ok(())
    }

    #[must_use]
    pub const fn is_native(&self) -> bool {
        matches!(self, Self::Native)
    }
}

/// The execution identity belongs to exactly one provider kind. The native
/// start token is retained in the existing durable runtime sidecar; the
/// process ID here matches the journal's legacy `process_id` column.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AttemptExecution {
    Native {
        process_id: Option<u32>,
    },
    Isolated {
        provider_kind: Backend,
        environment_id: Option<String>,
        resolved_image: ImageReference,
        generation: String,
    },
}

impl<'de> Deserialize<'de> for AttemptExecution {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        let object = value
            .as_object()
            .ok_or_else(|| D::Error::custom("invalid attempt execution shape"))?;
        match object.get("kind").and_then(serde_json::Value::as_str) {
            Some("native") if object.len() == 2 && object.contains_key("process_id") => {
                let process_id = serde_json::from_value(object["process_id"].clone())
                    .map_err(|_| D::Error::custom("invalid native process identity"))?;
                Ok(Self::Native { process_id })
            }
            Some("isolated")
                if object.len() == 5
                    && object.contains_key("provider_kind")
                    && object.contains_key("environment_id")
                    && object.contains_key("resolved_image")
                    && object.contains_key("generation") =>
            {
                let provider_kind = serde_json::from_value(object["provider_kind"].clone())
                    .map_err(|_| D::Error::custom("invalid provider kind"))?;
                let environment_id = serde_json::from_value(object["environment_id"].clone())
                    .map_err(|_| D::Error::custom("invalid environment identity"))?;
                let resolved_image = serde_json::from_value(object["resolved_image"].clone())
                    .map_err(|_| D::Error::custom("invalid resolved image shape"))?;
                let generation = serde_json::from_value(object["generation"].clone())
                    .map_err(|_| D::Error::custom("invalid generation"))?;
                Ok(Self::Isolated {
                    provider_kind,
                    environment_id,
                    resolved_image,
                    generation,
                })
            }
            _ => Err(D::Error::custom("invalid attempt execution shape")),
        }
    }
}

impl AttemptExecution {
    /// The provider allocation and generation cannot change after the first
    /// journal write. Native PID and isolated environment ID may be filled
    /// once, then only repeated with the same value.
    #[must_use]
    pub fn can_advance_to(&self, next: &Self) -> bool {
        match (self, next) {
            (Self::Native { process_id: old }, Self::Native { process_id: new }) => {
                old.is_none() || old == new
            }
            (
                Self::Isolated {
                    provider_kind: old_provider,
                    environment_id: old_id,
                    resolved_image: old_image,
                    generation: old_generation,
                },
                Self::Isolated {
                    provider_kind: new_provider,
                    environment_id: new_id,
                    resolved_image: new_image,
                    generation: new_generation,
                },
            ) => {
                old_provider == new_provider
                    && old_image == new_image
                    && old_generation == new_generation
                    && (old_id.is_none() || old_id == new_id)
            }
            _ => false,
        }
    }

    pub fn validate(&self) -> Result<(), ExecutionError> {
        if let Self::Isolated {
            provider_kind,
            environment_id,
            resolved_image,
            generation,
        } = self
        {
            if matches!(provider_kind, Backend::Auto) {
                return Err(ExecutionError::UnresolvedProvider);
            }
            ImageReference::new(resolved_image.as_str())?;
            if matches!(
                provider_kind,
                Backend::Oci | Backend::WindowsHyperVContainer
            ) && !resolved_image.as_str().contains("sha256:")
            {
                return Err(ExecutionError::BackendImageMismatch);
            }
            if !non_secret_id(generation)
                || environment_id
                    .as_deref()
                    .is_some_and(|id| !non_secret_id(id))
            {
                return Err(ExecutionError::InvalidEnvironmentIdentity);
            }
        }
        Ok(())
    }

    #[must_use]
    pub const fn is_native(&self) -> bool {
        matches!(self, Self::Native { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pinned_oci() -> ImageReference {
        ImageReference::new(format!("registry.example/runner@sha256:{}", "a".repeat(64)))
            .expect("pinned image")
    }

    fn isolated() -> ExecutionPolicy {
        ExecutionPolicy::Isolated {
            backend: Backend::Oci,
            image: pinned_oci(),
            resources: ResourceLimits {
                cpu_millis: 1000,
                memory_mib: 1024,
                disk_mib: 4096,
            },
        }
    }

    #[test]
    fn isolated_configuration_rejects_persistent_and_non_repository_workspaces() {
        let policy = isolated();
        assert_eq!(
            policy.validate(TargetScope::Organization, &WorkspacePolicy::Ephemeral),
            Err(ExecutionError::IsolatedRequiresRepository)
        );
        let persistent = WorkspacePolicy::Persistent {
            root: crate::path::LocalAbsolutePath::new(if cfg!(windows) {
                "C:\\runner-work"
            } else {
                "/runner-work"
            })
            .expect("valid path"),
        };
        assert_eq!(
            policy.validate(TargetScope::Repository, &persistent),
            Err(ExecutionError::IsolatedRequiresEphemeral)
        );
        assert!(
            policy
                .validate(TargetScope::Repository, &WorkspacePolicy::Ephemeral)
                .is_ok()
        );
    }

    #[test]
    fn mutable_credentials_and_unknown_provider_shapes_fail_closed() {
        for reference in [
            "runner:latest",
            "https://user:token@registry.example/runner",
            "registry.example/runner@sha256:short",
            "registry.example/runner @sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert_eq!(
                ImageReference::new(reference),
                Err(ExecutionError::InvalidImage)
            );
        }
        let digest = "a".repeat(64);
        for reference in [
            format!("user:password@sha256:{digest}"),
            format!("registry.example/runner:latest@sha256:{digest}"),
            format!("user:password/runner@sha256:{digest}"),
        ] {
            assert_eq!(
                ImageReference::new(reference),
                Err(ExecutionError::InvalidImage)
            );
        }
        assert!(
            ImageReference::new(format!("registry.example:5000/runner@sha256:{digest}")).is_ok()
        );
        assert!(serde_json::from_str::<ExecutionPolicy>(
            r#"{"mode":"isolated","backend":"unknown","image":{"reference":"x"},"resources":{"cpu_millis":1000,"memory_mib":1024,"disk_mib":4096}}"#
        ).is_err());
        assert!(
            serde_json::from_str::<ExecutionPolicy>(r#"{"mode":"native","backend":"oci"}"#)
                .is_err()
        );
        let malformed: ExecutionPolicy = serde_json::from_str(
            r#"{"mode":"isolated","backend":"oci","image":{"reference":"runner:latest"},"resources":{"cpu_millis":1000,"memory_mib":1024,"disk_mib":4096}}"#
        ).expect("raw shape parses; validation rejects the image");
        assert_eq!(
            malformed.validate(TargetScope::Repository, &WorkspacePolicy::Ephemeral),
            Err(ExecutionError::InvalidImage)
        );
    }

    #[test]
    fn isolated_attempt_identity_is_non_secret_and_concrete() {
        let valid = AttemptExecution::Isolated {
            provider_kind: Backend::Oci,
            environment_id: Some("env-123".into()),
            resolved_image: pinned_oci(),
            generation: "gen-123".into(),
        };
        assert!(valid.validate().is_ok());
        let unknown = AttemptExecution::Isolated {
            provider_kind: Backend::Auto,
            environment_id: Some("env-123".into()),
            resolved_image: pinned_oci(),
            generation: "gen-123".into(),
        };
        assert_eq!(unknown.validate(), Err(ExecutionError::UnresolvedProvider));
    }

    #[test]
    fn container_backends_require_digest_images_for_policy_and_journal() {
        let version = ImageReference::new("vm-version:macos-15.0").expect("pinned VM version");
        for backend in [Backend::Oci, Backend::WindowsHyperVContainer] {
            let policy = ExecutionPolicy::Isolated {
                backend,
                image: version.clone(),
                resources: ResourceLimits {
                    cpu_millis: 1000,
                    memory_mib: 1024,
                    disk_mib: 4096,
                },
            };
            assert_eq!(
                policy.validate(TargetScope::Repository, &WorkspacePolicy::Ephemeral),
                Err(ExecutionError::BackendImageMismatch)
            );
            let attempt = AttemptExecution::Isolated {
                provider_kind: backend,
                environment_id: None,
                resolved_image: version.clone(),
                generation: "gen-123".into(),
            };
            assert_eq!(
                attempt.validate(),
                Err(ExecutionError::BackendImageMismatch)
            );
        }
        let vm = ExecutionPolicy::Isolated {
            backend: Backend::VirtualMachine,
            image: version,
            resources: ResourceLimits {
                cpu_millis: 1000,
                memory_mib: 1024,
                disk_mib: 4096,
            },
        };
        assert!(
            vm.validate(TargetScope::Repository, &WorkspacePolicy::Ephemeral)
                .is_ok()
        );
    }
}

fn non_secret_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExecutionError {
    #[error("isolated execution requires a repository profile")]
    IsolatedRequiresRepository,
    #[error("isolated execution requires an ephemeral workspace")]
    IsolatedRequiresEphemeral,
    #[error("the image must be a pinned, credential-free digest or version")]
    InvalidImage,
    #[error("the image identity is incompatible with the selected backend")]
    BackendImageMismatch,
    #[error("isolated CPU, memory and disk limits are below the required floor")]
    InvalidResources,
    #[error("an attempt must record a concrete provider, not auto")]
    UnresolvedProvider,
    #[error("the environment identity or generation is malformed")]
    InvalidEnvironmentIdentity,
    #[error("the attempt execution identity does not match its recorded process ID")]
    AttemptIdentityMismatch,
    #[error("an isolated environment cannot be cleaned without provider absence proof")]
    IsolatedCleanupUnproven,
}
