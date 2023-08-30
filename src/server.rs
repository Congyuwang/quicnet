use std::{num::NonZeroUsize, sync::atomic::AtomicBool, time::Duration};

use crate::config::{quic::default_config, ServerConfig};
use quinn::Endpoint;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tracing_subscriber::EnvFilter;

const NET_LOG: &str = "quicnet";
const MAX_WORKER_THREADS: usize = 256;
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

pub enum ServerCommand {
    // TODO
    Abort,
}

pub struct Server {
    cmd_sender: UnboundedSender<ServerCommand>,

    // use has_joined to fence the join_handle,
    // both should only be accessed by the `join` method.
    has_joined: AtomicBool,
    join_handle: Option<std::thread::JoinHandle<()>>,
}

impl Server {
    pub fn init(n_threads: usize, config: ServerConfig) -> std::io::Result<Self> {
        Server::init_logger();
        let (cmd_sender, cmd_receiver) = Server::make_cmd_channel();
        let endpoint = Server::make_endpoint(config)?;
        let runtime = Server::make_runtime(n_threads)?;
        let join_handle = Some(std::thread::spawn(move || {
            let handle = runtime.handle();
            runtime.block_on(Server::main(cmd_receiver));
            tracing::info!("shutting down server");
            runtime.shutdown_timeout(SHUTDOWN_TIMEOUT);
            tracing::info!("server stopped");
        }));
        Ok(Server {
            cmd_sender,
            has_joined: AtomicBool::new(false),
            join_handle,
        })
    }

    /// main loop
    async fn main(mut cmd_receiver: UnboundedReceiver<ServerCommand>) {
        while let Some(cmd) = cmd_receiver.recv().await {
            match cmd {
                ServerCommand::Abort => {
                    unimplemented!();
                }
            }
        }
    }

    fn make_endpoint(config: ServerConfig) -> std::io::Result<Endpoint> {
        let (server_config, client_config) = default_config(&config)?;
        let mut endpoint = Endpoint::server(server_config, config.addr)?;
        endpoint.set_default_client_config(client_config);
        Ok(endpoint)
    }

    fn init_logger() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::builder().with_env_var(NET_LOG).from_env_lossy())
            .try_init();
    }

    fn make_cmd_channel() -> (
        UnboundedSender<ServerCommand>,
        UnboundedReceiver<ServerCommand>,
    ) {
        unbounded_channel()
    }

    fn make_runtime(n_threads: usize) -> std::io::Result<tokio::runtime::Runtime> {
        let n_thread = n_threads.min(MAX_WORKER_THREADS);
        match n_thread {
            0 => {
                let n_cpu =
                    std::thread::available_parallelism().unwrap_or(NonZeroUsize::new(1).unwrap());
                tracing::info!("socket manager started runtime with {n_cpu} threads");
                tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .worker_threads(n_cpu.get())
                    .build()
            }
            1 => {
                tracing::info!("socket manager started runtime with single thread");
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
            }
            n => {
                tracing::info!("socket manager started runtime with {n} threads");
                tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .worker_threads(n)
                    .build()
            }
        }
    }
}
