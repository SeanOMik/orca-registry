use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Constants for common media types described in [OCI spec](https://github.com/opencontainers/image-spec/blob/main/media-types.md#oci-image-media-types).
#[allow(dead_code)]
pub mod media_types {
    pub const DESCRIPTOR: &'static str = "application/vnd.oci.descriptor.v1+json";
    pub const OCI_LAYOUT: &'static str = "application/vnd.oci.layout.header.v1+json";
    pub const IMAGE_INDEX: &'static str = "application/vnd.oci.image.index.v1+json";
    pub const IMAGE_MANIFEST: &'static str = "application/vnd.oci.image.manifest.v1+json";
    pub const IMAGE_CONFIG: &'static str = "application/vnd.oci.image.config.v1+json";
    pub const LAYER_TAR: &'static str = "application/vnd.oci.image.layer.v1.tar";
    pub const LAYER_TAR_GZIP: &'static str = "application/vnd.oci.image.layer.v1.tar+gzip";
    pub const LAYER_TAR_ZSTD: &'static str = "application/vnd.oci.image.layer.v1.tar+zstd";
    pub const OCI_EMPTY: &'static str = "application/vnd.oci.empty.v1+json";
}

/* #[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerConfig {
    pub media_type: String,
    pub size: Option<u32>,
    pub digest: String
} */

/// Describes the disposition of the targeted content.
/// https://github.com/opencontainers/image-spec/blob/main/descriptor.md
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    pub media_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    pub size: u32,
    pub digest: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub annotations: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageManifest {
    pub schema_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    pub config: Descriptor,
    pub layers: Vec<Descriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<Descriptor>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub annotations: HashMap<String, String>,
}

impl<'de> Deserialize<'de> for ImageManifest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Create a Raw struct so that I can do cross field validation for the struct
        // I'm implementing Deserialize with.
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        pub struct Raw {
            pub schema_version: u32,
            pub media_type: Option<String>,
            pub artifact_type: Option<String>,
            pub config: Descriptor,
            pub layers: Vec<Descriptor>,
            pub subject: Option<Descriptor>,
            pub annotations: HashMap<String, String>,
        }

        let raw = Raw::deserialize(deserializer)?;

        // artifactType MUST be set when config.mediaType is NOT set
        if raw.artifact_type.is_none() && raw.config.media_type.is_empty() {
            return Err(serde::de::Error::custom("artifactType MUST be set when config.mediaType is NOT set"));
        }

        Ok(Self {
            schema_version: raw.schema_version,
            media_type: raw.media_type,
            artifact_type: raw.artifact_type,
            config: raw.config,
            layers: raw.layers,
            subject: raw.subject,
            annotations: raw.annotations,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Platform {
    pub architecture: String,
    pub os: String,
    #[serde(rename = "os.version", skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    #[serde(rename = "os.features", default, skip_serializing_if = "Vec::is_empty")]
    pub os_features: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexItem {
    #[serde(flatten)]
    pub descriptor: Descriptor,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageIndex {
    pub schema_version: u32,
    pub media_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    // This field must always be present, even when the array is empty.
    pub manifests: Vec<IndexItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<Descriptor>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub annotations: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Manifest {
    Image(ImageManifest),
    /// Multiple manifests
    Index(ImageIndex)
}

/// A referrer.
/// 
/// This struct is mostly just a Descriptor, but has an extra field, `namespace` for seeing where
/// the referrer is from. This makes it easier to filter when listing referrers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Referrer {
    #[serde(flatten)]
    pub descriptor: Descriptor,
    pub namespace: String,
}

impl std::ops::Deref for Referrer {
    type Target = Descriptor;

    fn deref(&self) -> &Self::Target {
        &self.descriptor
    }
}

impl std::ops::DerefMut for Referrer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.descriptor
    }
}

impl Referrer {
    pub fn from_image_manifest(namespace: &str, digest: &str, image: &ImageManifest) -> Self {
        let layers_size = image.layers.iter().map(|l| l.size).sum();
        
        // per the spec, if artifactType is missing, it must be set to mediaType if the manifest
        // is an image manifest. If its an index, omit it.
        let artifact_type = image.artifact_type.clone()
            .unwrap_or_else(|| image.config.media_type.clone());

        let d = Descriptor {
            media_type: image.media_type.clone().unwrap(),
            artifact_type: Some(artifact_type),
            size: layers_size,
            digest: digest.into(),
            urls: vec![],
            annotations: image.annotations.clone(),
            data: None,
            platform: None,
        };
        
        Referrer {
            descriptor: d,
            namespace: namespace.into(),
        }
    }

    pub fn from_index_manifest(namespace: &str, digest: &str, index: &ImageIndex) -> Self {
        let manifests_size = index.manifests.iter().map(|m| m.descriptor.size).sum();

        let d = Descriptor {
            media_type: index.media_type.clone(),
            artifact_type: index.artifact_type.clone(),
            size: manifests_size,
            digest: digest.into(),
            urls: vec![],
            annotations: index.annotations.clone(),
            data: None,
            platform: None,
        };

        Referrer {
            descriptor: d,
            namespace: namespace.into(),
        }
    }
}

/// A list of referrers.
/// 
/// https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-referrers
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReferrersList {
    pub schema_version: u32,
    pub media_type: String,
    pub referrers: Vec<Referrer>,
}