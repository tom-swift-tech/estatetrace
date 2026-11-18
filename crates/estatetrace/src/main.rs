mod api;
mod backup;
mod profile;
mod scan;
mod state;
mod static_files;
mod theme;

use anyhow::Result;
use clap::{Parser, Subcommand};
use state::AppState;
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "estatetrace", about = "EstateTrace local Azure operations dashboard")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the local web service (default).
    Serve {
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: String,
        #[arg(long)]
        open: bool,
    },
    /// Run a manual inventory scan using the shared collector.
    Scan,
    /// Create a consistent backup archive.
    Backup {
        #[arg(long)]
        out: Option<std::path::PathBuf>,
    },
    /// Restore a backup into a profile directory (secrets must be reconnected).
    Restore {
        #[arg(long)]
        archive: std::path::PathBuf,
        #[arg(long)]
        profile: Option<std::path::PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("estatetrace=info".parse()?))
        .init();

    let cli = Cli::parse();
    match cli.command.unwrap_or(Commands::Serve {
        bind: "127.0.0.1:8787".into(),
        open: true,
    }) {
        Commands::Serve { bind, open } => {
            let state = AppState::bootstrap().await?;
            let app = api::router(state.clone());
            let addr: SocketAddr = bind.parse()?;
            tracing::info!("EstateTrace listening on http://{addr}");
            if open {
                let url = format!("http://{addr}/");
                let _ = open::that(&url);
            }
            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(listener, app).await?;
        }
        Commands::Scan => {
            let state = AppState::bootstrap().await?;
            scan::run_scan(&state).await?;
        }
        Commands::Backup { out } => {
            let profile = profile::profile_dir()?;
            let dest = out.unwrap_or_else(|| {
                profile.join(format!(
                    "backups/estatetrace-backup-{}.zip",
                    chrono::Utc::now().format("%Y%m%dT%H%M%SZ")
                ))
            });
            backup::create_backup(&profile, &dest)?;
            println!("backup written to {}", dest.display());
        }
        Commands::Restore { archive, profile } => {
            let dest = match profile {
                Some(p) => p,
                None => profile::profile_dir()?,
            };
            backup::restore_backup(&archive, &dest)?;
            println!(
                "restored into {}. Reconnect ServiceNow and chat credentials.",
                dest.display()
            );
        }
    }
    Ok(())
}

/// Minimal opener without extra crate dependency issues on Windows.
mod open {
    pub fn that(url: &str) -> std::io::Result<()> {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .spawn()
            .map(|_| ())
    }
}