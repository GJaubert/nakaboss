//! Stand-alone light-client daemon. Runs the light-client as a background process.
#![deny(missing_docs, unsafe_code)]

use std::net;
use std::path::PathBuf;

pub use nakamoto_client::{Client, Config, Error, Network};
pub use nakamoto_client::{Domain, LoadingHandler};
pub use nakamoto_common::bitcoin::p2p::ServiceFlags;

pub mod logger;

/// The network reactor we're going to use.
type Reactor = nakamoto_net_poll::Reactor<net::TcpStream>;

/// Run the light-client. Takes an initial list of peers to connect to, a list of listen addresses,
/// the client root and the Bitcoin network to connect to.
pub fn run(
    connect: &[net::SocketAddr],
    listen: &[net::SocketAddr],
    root: Option<PathBuf>,
    domains: &[Domain],
    network: Network,
    p2p_v2: bool
) -> Result<(), Error> {
    let mut cfg = Config {
        network,
        connect: connect.to_vec(),
        domains: domains.to_vec(),
        listen: if listen.is_empty() {
            vec![([0, 0, 0, 0], 0).into()]
        } else {
            listen.to_vec()
        },
        p2p_v2,
        ..Config::default()
    };
    if let Some(path) = root {
        cfg.root = path;
    }
    if !connect.is_empty() {
        cfg.limits.max_outbound_peers = connect.len();
    }
    if p2p_v2 {
        cfg.services = cfg.services | ServiceFlags::P2P_V2;
    }

    Client::<Reactor>::new()?.run(cfg)
}
