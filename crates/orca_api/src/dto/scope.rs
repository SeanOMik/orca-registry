use serde::{Deserialize, Serialize};
use thiserror::Error;

use std::fmt;

#[derive(Default, Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScopeType {
    #[default]
    Unknown,
    #[serde(rename = "repository")]
    Repository,
}

impl fmt::Display for ScopeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ScopeType::Unknown => write!(f, ""),
            ScopeType::Repository => write!(f, "repository"),
        }
    }
}

#[derive(Default, Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Action {
    #[default]
    None,
    #[serde(rename = "push")]
    Push,
    #[serde(rename = "pull")]
    Pull,
    #[serde(rename = "delete")]
    Delete,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Action::None => write!(f, ""),
            Action::Push => write!(f, "push"),
            Action::Pull => write!(f, "pull"),
            Action::Delete => write!(f, "delete"),
        }
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Scope {
    #[serde(rename = "type")]
    pub scope_type: ScopeType,
    pub name: String,
    pub actions: Vec<Action>,
}

impl Scope {
    pub fn new(scope_type: ScopeType, path: String, actions: &[Action]) -> Self {
        Self {
            scope_type,
            name: path,
            actions: actions.to_vec(),
        }
    }

    pub fn to_error_details(&self) -> Vec<ScopeDetail> {
        let mut details = vec![];

        for action in &self.actions {
            details.push(ScopeDetail {
                scope_type: self.scope_type,
                name: self.name.clone(),
                action: *action,
            })
        }

        details
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let actions = self.actions
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<String>>()
            .join(",");

        write!(f, "{}:{}:{}", self.scope_type, self.name, actions)
    }
}

#[derive(Debug, Error)]
pub enum ScopeParseError {
    #[error("Invalid scope type: '{0}'")]
    InvalidScopeType(String),
    #[error("Invalid action: '{0}'")]
    InvalidAction(String),
    #[error("Malformed scope string, unable to parse")]
    Malformed
}

impl TryFrom<&str> for Scope {
    type Error = ScopeParseError;

    fn try_from(val: &str) -> Result<Self, Self::Error> {
        let splits: Vec<&str> = val.split(":").collect();
        if splits.len() == 3 {
            let scope_type = match splits[0] {
                "repository" => ScopeType::Repository,
                _ => {
                    return Err(ScopeParseError::InvalidScopeType(splits[0].into()));
                }
            };

            let path = splits[1];

            let actions: Result<Vec<Action>, _> = splits[2]
                .split(",")
                .map(|a| match a {
                    "pull" => Ok(Action::Pull),
                    "push" => Ok(Action::Push),
                    "delete" => Ok(Action::Delete),
                    _ => Err(ScopeParseError::InvalidAction(a.into())),
                }).collect();
            let actions = actions?;

            Ok(Scope {
                scope_type,
                name: String::from(path),
                actions
            })
        } else {
            Err(ScopeParseError::Malformed)
        }
    }
}


#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScopeDetail {
    #[serde(rename = "type")]
    pub scope_type: ScopeType,
    pub name: String,
    pub action: Action,
}