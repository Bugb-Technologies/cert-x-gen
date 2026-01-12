//! Git client wrapper for template repository management

use crate::error::{Error, Result};
use git2::{
    build::CheckoutBuilder,
    Repository as GitRepository, 
    FetchOptions, 
    RemoteCallbacks,
    AnnotatedCommit,
};
use std::path::Path;
use std::process::Command;
use tracing::{info, debug, warn};

/// Git client for repository operations
#[derive(Debug)]
pub struct GitClient;

impl GitClient {
    /// Clone a repository to local path
    pub fn clone(url: &str, path: &Path, branch: &str) -> Result<()> {
        info!("Cloning repository {} to {}", url, path.display());
        
        // Check if path already exists
        if path.exists() {
            return Err(Error::config(format!(
                "Path already exists: {}",
                path.display()
            )));
        }
        
        // Create parent directory
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::config(format!(
                    "Failed to create parent directory: {}", e
                )))?;
        }
        
        // For public HTTPS GitHub repos, use system git command (more reliable on macOS)
        if url.starts_with("https://github.com") {
            return Self::clone_with_system_git(url, path, branch);
        }
        
        // For other repos, use git2 library with proper callbacks
        let mut callbacks = RemoteCallbacks::new();
        
        // Set up credentials callback for non-GitHub or SSH repos
        callbacks.credentials(|_url, username_from_url, allowed_types| {
            if allowed_types.is_ssh_key() {
                let username = username_from_url.unwrap_or("git");
                git2::Cred::ssh_key_from_agent(username)
            } else if allowed_types.is_default() {
                git2::Cred::default()
            } else {
                Err(git2::Error::from_str("unsupported authentication type"))
            }
        });
        
        callbacks.transfer_progress(|stats| {
            if stats.received_objects() == stats.total_objects() {
                debug!("Resolving deltas {}/{}", 
                    stats.indexed_deltas(), 
                    stats.total_deltas()
                );
            } else {
                debug!("Received {}/{} objects ({} bytes)", 
                    stats.received_objects(), 
                    stats.total_objects(),
                    stats.received_bytes()
                );
            }
            true
        });
        
        let mut fetch_opts = FetchOptions::new();
        fetch_opts.remote_callbacks(callbacks);
        
        let mut builder = git2::build::RepoBuilder::new();
        builder.fetch_options(fetch_opts);
        builder.branch(branch);
        
        builder.clone(url, path)
            .map_err(|e| Error::config(format!("Failed to clone repository: {}", e)))?;
        
        info!("Successfully cloned repository to {}", path.display());
        Ok(())
    }
    
    /// Clone using system git command (more reliable for public HTTPS repos on macOS)
    fn clone_with_system_git(url: &str, path: &Path, branch: &str) -> Result<()> {
        info!("Using system git command to clone public repository");
        
        // Check if git is available
        let git_check = Command::new("git")
            .arg("--version")
            .output();
        
        if git_check.is_err() {
            warn!("System git not available, falling back to git2 library");
            return Self::clone_with_git2_anonymous(url, path, branch);
        }
        
        // Clone with system git, disabling credential helper for public repos
        // This prevents macOS keychain from asking for credentials
        let output = Command::new("git")
            .env("GIT_TERMINAL_PROMPT", "0")  // Disable terminal prompts
            .args(&[
                "-c", "credential.helper=",  // Temporarily disable credential helper
                "clone", 
                "-b", branch, 
                url, 
                path.to_str().unwrap()
            ])
            .output()
            .map_err(|e| Error::config(format!("Failed to run git clone: {}", e)))?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let _stdout = String::from_utf8_lossy(&output.stdout);
            
            // If system git fails, try the git2 fallback
            warn!("System git clone failed: {}, falling back to git2", stderr);
            return Self::clone_with_git2_anonymous(url, path, branch);
        }
        
        info!("Successfully cloned repository using system git");
        Ok(())
    }
    
    /// Fallback clone method using git2 with anonymous access
    fn clone_with_git2_anonymous(url: &str, path: &Path, branch: &str) -> Result<()> {
        info!("Using git2 with anonymous access for public repository");
        
        // For public HTTPS repos, we don't need authentication
        // But we need to handle the callback being invoked
        let mut callbacks = RemoteCallbacks::new();
        
        // Simple callback that always returns anonymous credentials
        callbacks.credentials(|_url, _username, _allowed| {
            // For public repos, we just need to return something
            // Empty credentials work for anonymous HTTPS access
            git2::Cred::default()
        });
        
        let mut fetch_opts = FetchOptions::new();
        fetch_opts.remote_callbacks(callbacks);
        
        let mut builder = git2::build::RepoBuilder::new();
        builder.fetch_options(fetch_opts);
        builder.branch(branch);
        
        builder.clone(url, path)
            .map_err(|e| Error::config(format!("Failed to clone repository: {}", e)))?;
        
        info!("Successfully cloned repository using git2");
        Ok(())
    }
    
    /// Pull latest changes for an existing repository
    pub fn pull(path: &Path, branch: &str) -> Result<()> {
        info!("Pulling updates for {} (branch: {})", path.display(), branch);
        
        if !path.exists() {
            return Err(Error::config(format!(
                "Repository path does not exist: {}",
                path.display()
            )));
        }
        
        // Check if we're dealing with a GitHub repo
        let repo = GitRepository::open(path)
            .map_err(|e| Error::config(format!("Failed to open repository: {}", e)))?;
        
        let mut remote = repo.find_remote("origin")
            .map_err(|e| Error::config(format!("Failed to find remote 'origin': {}", e)))?;
        
        let remote_url = remote.url().unwrap_or("");
        
        // For public GitHub HTTPS repos, use system git
        if remote_url.starts_with("https://github.com") {
            drop(remote);
            drop(repo);
            return Self::pull_with_system_git(path, branch);
        }
        
        // For other repos, use git2 with callbacks
        let mut callbacks = RemoteCallbacks::new();
        
        callbacks.credentials(|_url, username_from_url, allowed_types| {
            if allowed_types.is_ssh_key() {
                let username = username_from_url.unwrap_or("git");
                git2::Cred::ssh_key_from_agent(username)
            } else if allowed_types.is_default() {
                git2::Cred::default()
            } else {
                Err(git2::Error::from_str("unsupported authentication type"))
            }
        });
        
        callbacks.transfer_progress(|stats| {
            debug!("Fetching: {}/{} objects", 
                stats.received_objects(), 
                stats.total_objects()
            );
            true
        });
        
        let mut fetch_opts = FetchOptions::new();
        fetch_opts.remote_callbacks(callbacks);
        
        // Fetch the branch
        let refspec = format!("refs/heads/{}", branch);
        remote.fetch(&[&refspec], Some(&mut fetch_opts), None)
            .map_err(|e| Error::config(format!("Failed to fetch updates: {}", e)))?;
        
        // Get FETCH_HEAD to merge
        let fetch_head = repo.find_reference("FETCH_HEAD")
            .map_err(|e| Error::config(format!("Failed to find FETCH_HEAD: {}", e)))?;
        let fetch_commit = repo.reference_to_annotated_commit(&fetch_head)
            .map_err(|e| Error::config(format!("Failed to get fetch commit: {}", e)))?;
        
        // Perform fast-forward merge
        Self::fast_forward(&repo, &fetch_commit)?;
        
        info!("Successfully pulled updates for {}", path.display());
        Ok(())
    }
    
    /// Pull using system git command
    fn pull_with_system_git(path: &Path, branch: &str) -> Result<()> {
        info!("Using system git command to pull updates");
        
        // First, fetch updates
        let fetch_output = Command::new("git")
            .current_dir(path)
            .args(&["fetch", "origin", branch])
            .output()
            .map_err(|e| Error::config(format!("Failed to run git fetch: {}", e)))?;
        
        if !fetch_output.status.success() {
            let stderr = String::from_utf8_lossy(&fetch_output.stderr);
            return Err(Error::config(format!("Git fetch failed: {}", stderr)));
        }
        
        // Then, merge with fast-forward only
        let merge_output = Command::new("git")
            .current_dir(path)
            .args(&["merge", "--ff-only", &format!("origin/{}", branch)])
            .output()
            .map_err(|e| Error::config(format!("Failed to run git merge: {}", e)))?;
        
        if !merge_output.status.success() {
            let stderr = String::from_utf8_lossy(&merge_output.stderr);
            let stdout = String::from_utf8_lossy(&merge_output.stdout);
            
            // Check if we're already up to date
            if stdout.contains("Already up to date") || stderr.contains("Already up to date") {
                info!("Repository is already up to date");
                return Ok(());
            }
            
            return Err(Error::config(format!("Git merge failed: {}", stderr)));
        }
        
        info!("Successfully pulled updates using system git");
        Ok(())
    }
    
    /// Get current commit hash
    pub fn get_current_commit(path: &Path) -> Result<String> {
        let repo = GitRepository::open(path)
            .map_err(|e| Error::config(format!("Failed to open repository: {}", e)))?;
        
        let head = repo.head()
            .map_err(|e| Error::config(format!("Failed to get HEAD: {}", e)))?;
        
        let commit = head.peel_to_commit()
            .map_err(|e| Error::config(format!("Failed to get commit: {}", e)))?;
        
        Ok(commit.id().to_string())
    }
    
    /// Check if repository is clean (no uncommitted changes)
    pub fn is_clean(path: &Path) -> Result<bool> {
        let repo = GitRepository::open(path)
            .map_err(|e| Error::config(format!("Failed to open repository: {}", e)))?;
        
        let statuses = repo.statuses(None)
            .map_err(|e| Error::config(format!("Failed to get status: {}", e)))?;
        
        Ok(statuses.is_empty())
    }
    
    /// Check if a path is a valid git repository
    pub fn is_repository(path: &Path) -> bool {
        path.join(".git").exists()
    }
    
    /// Fast-forward merge
    fn fast_forward(
        repo: &GitRepository,
        fetch_commit: &AnnotatedCommit<'_>,
    ) -> Result<()> {
        let head_ref = repo.head()
            .map_err(|e| Error::config(format!("Failed to get HEAD: {}", e)))?;
        
        let _head_commit = head_ref.peel_to_commit()
            .map_err(|e| Error::config(format!("Failed to get HEAD commit: {}", e)))?;
        
        // Check if fast-forward is possible
        let (analysis, _) = repo.merge_analysis(&[fetch_commit])
            .map_err(|e| Error::config(format!("Failed to analyze merge: {}", e)))?;
        
        if analysis.is_fast_forward() {
            let refname = head_ref.name()
                .ok_or_else(|| Error::config("Invalid reference name".to_string()))?;
            
            let mut reference = repo.find_reference(refname)
                .map_err(|e| Error::config(format!("Failed to find reference: {}", e)))?;
            
            reference.set_target(fetch_commit.id(), "Fast-forward merge")
                .map_err(|e| Error::config(format!("Failed to set target: {}", e)))?;
            
            repo.checkout_head(Some(CheckoutBuilder::default().force()))
                .map_err(|e| Error::config(format!("Failed to checkout HEAD: {}", e)))?;
            
            info!("Fast-forward merge completed");
            Ok(())
        } else if analysis.is_up_to_date() {
            info!("Repository is already up to date");
            Ok(())
        } else {
            Err(Error::config(
                "Cannot fast-forward. Repository has diverged. Please resolve conflicts manually.".to_string()
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_is_repository() {
        let temp_dir = TempDir::new().unwrap();
        
        // Not a repository yet
        assert!(!GitClient::is_repository(temp_dir.path()));
        
        // Initialize a repository
        GitRepository::init(temp_dir.path()).unwrap();
        
        // Now it should be a repository
        assert!(GitClient::is_repository(temp_dir.path()));
    }
    
    #[test]
    fn test_is_clean_empty_repo() {
        let temp_dir = TempDir::new().unwrap();
        GitRepository::init(temp_dir.path()).unwrap();
        
        // New repository should be clean (though empty)
        let result = GitClient::is_clean(temp_dir.path());
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_clone_to_existing_path() {
        let temp_dir = TempDir::new().unwrap();
        
        // Create a directory
        std::fs::create_dir_all(temp_dir.path()).unwrap();
        
        // Try to clone to existing path should fail
        let result = GitClient::clone(
            "https://github.com/example/repo.git",
            temp_dir.path(),
            "main"
        );
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }
    
    #[test]
    fn test_pull_nonexistent_repo() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path().join("nonexistent");
        
        let result = GitClient::pull(&repo_path, "main");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not exist"));
    }
    
    #[test]
    fn test_get_current_commit_no_repo() {
        let temp_dir = TempDir::new().unwrap();
        
        let result = GitClient::get_current_commit(temp_dir.path());
        assert!(result.is_err());
    }
}