/// This crate contains the main link for lighthouse to rust-libp2p. It therefore re-exports
/// all required libp2p functionality.
///
/// This crate builds and manages the libp2p services required by the beacon node.
#[macro_use]
extern crate lazy_static;

pub mod behaviour;
mod config;
mod discovery;
mod metrics;
pub mod rpc;
mod service;
pub mod types;

// shift this type into discv5
pub type Enr = libp2p::discv5::enr::Enr<libp2p::discv5::enr::CombinedKey>;

pub use crate::types::{error, GossipTopic, NetworkGlobals, PeerInfo, PubsubMessage};
pub use config::Config as NetworkConfig;
pub use libp2p::gossipsub::{MessageId, Topic, TopicHash};
pub use libp2p::{multiaddr, Multiaddr};
pub use libp2p::{PeerId, Swarm};
pub use rpc::RPCEvent;
pub use service::{Libp2pEvent, Service};
