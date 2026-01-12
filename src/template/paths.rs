//! Platform-specific path resolution for template directories

use std::path::PathBuf;

#[derive(Debug)]
/// Utility for resolving template paths
pub struct PathResolver;

impl PathResolver {
    /// Get system-wide template directory
    pub fn system_template_dir() -> PathBuf {
        #[cfg(unix)]
        {
            PathBuf::from("/usr/local/share/cert-x-gen/templates")
        }
        
        #[cfg(windows)]
        {
            let program_data = env::var("ProgramData")
                .unwrap_or_else(|_| "C:\\ProgramData".to_string());
            PathBuf::from(program_data)
                .join("cert-x-gen")
                .join("templates")
        }
    }
    
    /// Get user-specific template directory
    pub fn user_template_dir() -> PathBuf {
        dirs::home_dir()
            .map(|h| h.join(".cert-x-gen/templates"))
            .unwrap_or_else(|| PathBuf::from("~/.cert-x-gen/templates"))
    }
    
    /// Get local project template directory
    pub fn local_template_dir() -> PathBuf {
        PathBuf::from("./templates")
    }
    
    /// Get user config directory
    pub fn user_config_dir() -> PathBuf {
        dirs::home_dir()
            .map(|h| h.join(".cert-x-gen"))
            .unwrap_or_else(|| PathBuf::from("~/.cert-x-gen"))
    }
    
    /// Get template cache directory
    pub fn cache_dir() -> PathBuf {
        Self::user_config_dir().join("cache")
    }
    
    /// Get all template directories in priority order (highest first)
    pub fn all_template_dirs() -> Vec<PathBuf> {
        vec![
            Self::local_template_dir(),   // Priority 3 (highest)
            Self::user_template_dir(),    // Priority 2
            Self::system_template_dir(),  // Priority 1 (lowest)
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_path_resolution() {
        let system = PathResolver::system_template_dir();
        let user = PathResolver::user_template_dir();
        let local = PathResolver::local_template_dir();
        
        assert!(system.is_absolute());
        assert!(user.to_str().unwrap().contains(".cert-x-gen"));
        assert_eq!(local, PathBuf::from("./templates"));
    }
}
