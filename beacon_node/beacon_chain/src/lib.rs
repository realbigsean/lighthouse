#![recursion_limit = "128"]

pub use parking_lot;

pub use attestation_verification::Error as AttestationError;
pub use beacon_fork_choice_store::{BeaconForkChoiceStore, Error as ForkChoiceStoreError};
pub use block_verification::{BlockError, GossipVerifiedBlock};
pub use eth1_chain::{Eth1Chain, Eth1ChainBackend};
pub use events::ServerSentEventHandler;
pub use metrics::scrape_for_metrics;
pub use slot_clock;
pub use state_processing::per_block_processing::errors::{
    AttestationValidationError, AttesterSlashingValidationError, DepositValidationError,
    ExitValidationError, ProposerSlashingValidationError,
};
pub use store;
pub use types;

pub use self::beacon_chain::{
    AttestationProcessingOutcome, BeaconChain, BeaconChainTypes, BeaconStore, ChainSegmentResult,
    ForkChoiceError, StateSkipConfig, MAXIMUM_GOSSIP_CLOCK_DISPARITY,
};
pub use self::beacon_snapshot::BeaconSnapshot;
pub use self::chain_config::ChainConfig;
pub use self::errors::{BeaconChainError, BlockProductionError};

// For lazy-static
pub mod attestation_verification;
mod beacon_chain;
mod beacon_fork_choice_store;
mod beacon_proposer_cache;
mod beacon_snapshot;
mod block_verification;
pub mod builder;
pub mod chain_config;
mod errors;
pub mod eth1_chain;
pub mod events;
mod head_tracker;
mod metrics;
pub mod migrate;
mod naive_aggregation_pool;
mod observed_attestations;
mod observed_attesters;
mod observed_block_producers;
pub mod observed_operations;
mod persisted_beacon_chain;
mod persisted_fork_choice;
pub mod schema_change;
mod shuffling_cache;
mod snapshot_cache;
pub mod state_advance_timer;
pub mod test_utils;
mod timeout_rw_lock;
pub mod validator_monitor;
mod validator_pubkey_cache;
