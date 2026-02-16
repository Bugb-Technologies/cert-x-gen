//! MCP (Model Context Protocol) server for CERT-X-GEN
//!
//! Exposes cxg capabilities as MCP tools for AI agent integration.
//! Run with: `cxg mcp` (stdio transport)

pub mod server;

pub use server::CxgMcpServer;

use crate::error::Result;

/// Run the MCP server over stdio transport
pub async fn run_mcp() -> Result<()> {
    use rmcp::ServiceExt;
    use tokio::io::{stdin, stdout};

    // Suppress all non-MCP output (banner, progress, logs go to stderr)
    eprintln!("CERT-X-GEN MCP server starting...");

    let server = CxgMcpServer::new();
    let transport = (stdin(), stdout());

    let service = server
        .serve(transport)
        .await
        .map_err(|e| crate::error::Error::config(format!("MCP server failed to start: {}", e)))?;

    eprintln!("CERT-X-GEN MCP server running (stdio)");

    // Wait for the service to complete
    let _quit_reason = service
        .waiting()
        .await
        .map_err(|e| crate::error::Error::config(format!("MCP server error: {}", e)))?;

    eprintln!("CERT-X-GEN MCP server stopped");
    Ok(())
}
