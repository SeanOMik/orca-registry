use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerConfig {
    pub media_type: String,
    pub size: Option<u32>,
    pub digest: String
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Layer {
    pub media_type: String,
    pub size: u32,
    pub digest: String,
    pub urls: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageManifest {
    pub schema_version: u32,
    pub media_type: String,
    pub config: ContainerConfig,
    pub layers: Vec<Layer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Platform {
    pub architecture: String,
    pub os: String,
    #[serde(rename = "os.version")]
    pub os_version: Option<String>,
    #[serde(rename = "os.features")]
    pub os_features: Option<Vec<String>>,
    pub variant: Option<String>,
    pub features: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestListItem {
    pub media_type: String,
    pub size: u32,
    pub digest: String,
    pub platform: Platform,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestList {
    pub schema_version: u32,
    pub media_type: String,
    pub manifests: Vec<ManifestListItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Manifest {
    Image(ImageManifest),
    List(ManifestList)
}