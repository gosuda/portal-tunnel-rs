//! ECH / inner routing hostname carriage (R13).

use compact_str::CompactString;
use serde::{Deserialize, Serialize};

/// Short hostname carried on the first `Control` frame when ECH-aware.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutedHostname(pub CompactString);
