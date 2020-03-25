//! This service keeps track of which shard subnet the beacon node should be subscribed to at any
//! given time. It schedules subscriptions to shard subnets, requests peer discoveries and
//! determines whether attestations should be aggregated and/or passed to the beacon node.

use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::{types::GossipKind, NetworkGlobals};
use futures::prelude::*;
use hashmap_delay::HashSetDelay;
use rand::seq::SliceRandom;
use rest_types::ValidatorSubscription;
use slog::{crit, debug, error, o, warn};
use slot_clock::SlotClock;
use std::boxed::Box;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use types::{Attestation, SubnetId};
use types::{EthSpec, Slot};

/// The minimum number of slots ahead that we attempt to discover peers for a subscription. If the
/// slot is less than this number, skip the peer discovery process.
const MIN_PEER_DISCOVERY_SLOT_LOOK_AHEAD: u64 = 1;
/// The number of slots ahead that we attempt to discover peers for a subscription. If the slot to
/// attest to is greater than this, we queue a discovery request for this many slots prior to
/// subscribing.
const TARGET_PEER_DISCOVERY_SLOT_LOOK_AHEAD: u64 = 6;
/// The time (in slots) before a last seen validator is considered absent and we unsubscribe from the random
/// gossip topics that we subscribed to due to the validator connection.
const LAST_SEEN_VALIDATOR_TIMEOUT: u32 = 150; // 30 mins at a 12s slot time
/// The fraction of a slot that we subscribe to a subnet before the required slot.
///
/// Note: The time is calculated as `time = milliseconds_per_slot / ADVANCE_SUBSCRIPTION_TIME`
const ADVANCE_SUBSCRIBE_TIME: u32 = 3;

const DEFAULT_EXPIRATION_TIMEOUT: u32 = 3; // 36s at 12s slot time

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum AttServiceMessage {
    /// Subscribe to the specified subnet id.
    Subscribe(SubnetId),
    /// Unsubscribe to the specified subnet id.
    Unsubscribe(SubnetId),
    /// Add the `SubnetId` to the ENR bitfield.
    EnrAdd(SubnetId),
    /// Remove the `SubnetId` from the ENR bitfield.
    EnrRemove(SubnetId),
    /// Discover peers for a particular subnet.
    DiscoverPeers(SubnetId),
}

pub struct AttestationService<T: BeaconChainTypes> {
    /// Queued events to return to the driving service.
    events: VecDeque<AttServiceMessage>,

    /// A collection of public network variables.
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,

    /// A reference to the beacon chain to process received attestations.
    beacon_chain: Arc<BeaconChain<T>>,

    /// The collection of currently subscribed random subnets mapped to their expiry deadline.
    random_subnets: HashSetDelay<SubnetId>,

    /// A collection of timeouts for when to start searching for peers for a particular shard.
    discover_peers: HashSetDelay<(SubnetId, Slot)>,

    /// A collection of timeouts for when to subscribe to a shard subnet.
    subscriptions: HashSetDelay<(SubnetId, Slot)>,

    /// A collection of timeouts for when to unsubscribe from a shard subnet.
    unsubscriptions: HashSetDelay<(SubnetId, Slot)>,

    /// A collection of seen validators. These dictate how many random subnets we should be
    /// subscribed to. As these time out, we unsubscribe for the required random subnets and update
    /// our ENR.
    /// This is a set of validator indices.
    known_validators: HashSetDelay<u64>,

    /// The logger for the attestation service.
    log: slog::Logger,
}

impl<T: BeaconChainTypes> AttestationService<T> {
    /* Public functions */

    pub fn new(
        beacon_chain: Arc<BeaconChain<T>>,
        network_globals: Arc<NetworkGlobals<T::EthSpec>>,
        log: &slog::Logger,
    ) -> Self {
        let log = log.new(o!("service" => "attestation_service"));

        // calculate the random subnet duration from the spec constants
        let spec = &beacon_chain.spec;
        let slot_duration = beacon_chain.slot_clock.slot_duration();
        let random_subnet_duration_millis = spec
            .epochs_per_random_subnet_subscription
            .saturating_mul(T::EthSpec::slots_per_epoch())
            .saturating_mul(slot_duration.as_millis() as u64);

        // Panics on overflow. Ensure LAST_SEEN_VALIDATOR_TIMEOUT is not too large.
        let last_seen_val_timeout = slot_duration
            .checked_mul(LAST_SEEN_VALIDATOR_TIMEOUT)
            .expect("LAST_SEEN_VALIDATOR_TIMEOUT must not be ridiculously large");
        let default_timeout = slot_duration.checked_mul(DEFAULT_EXPIRATION_TIMEOUT)
            .expect("DEFAULT_EXPIRATION_TIMEOUT must not be ridiculoustly large");

        AttestationService {
            events: VecDeque::with_capacity(10),
            network_globals,
            beacon_chain,
            random_subnets: HashSetDelay::new(Duration::from_millis(random_subnet_duration_millis)),
            discover_peers: HashSetDelay::new(default_timeout),
            subscriptions: HashSetDelay::new(default_timeout),
            unsubscriptions: HashSetDelay::new(default_timeout),
            known_validators: HashSetDelay::new(last_seen_val_timeout),
            log,
        }
    }

    /// Processes a list of validator subscriptions.
    ///
    /// This will:
    /// - Register new validators as being known.
    /// - Subscribe to the required number of random subnets.
    /// - Update the local ENR for new random subnets due to seeing new validators.
    /// - Search for peers for required subnets.
    /// - Request subscriptions for subnets on specific slots when required.
    /// - Build the timeouts for each of these events.
    ///
    /// This returns a result simply for the ergonomics of using ?. The result can be
    /// safely dropped.
    pub fn validator_subscriptions(
        &mut self,
        subscriptions: Vec<ValidatorSubscription>,
    ) -> Result<(), ()> {
        for subscription in subscriptions {
            //NOTE: We assume all subscriptions have been verified before reaching this service

            // Registers the validator with the attestation service.
            // This will subscribe to long-lived random subnets if required.
            self.add_known_validator(subscription.validator_index);

            let subnet_id = SubnetId::new(
                subscription.attestation_committee_index
                    % self.beacon_chain.spec.attestation_subnet_count,
            );
            // determine if we should run a discovery lookup request and request it if required
            if let Err(e) = self.discover_peers_request(subnet_id, subscription.slot) {
                warn!(self.log, "Discovery lookup request error"; "error" => e);
            }

            // set the subscription timer to subscribe to the next subnet if required
            if let Err(e) = self.subscribe_to_subnet(subnet_id, subscription.slot) {
                warn!(self.log, "Subscription to subnet error"; "error" => e);
            }
        }
        Ok(())
    }

    pub fn handle_attestation(
        &mut self,
        subnet: SubnetId,
        attestation: Box<Attestation<T::EthSpec>>,
    ) {}

    /* Internal private functions */

    /// Checks if there are currently queued discovery requests and the time required to make the
    /// request.
    ///
    /// If there is sufficient time and no other request exists, queues a peer discovery request
    /// for the required subnet.
    fn discover_peers_request(
        &mut self,
        subnet_id: SubnetId,
        subscription_slot: Slot,
    ) -> Result<(), &'static str> {
        let current_slot = self
            .beacon_chain
            .slot_clock
            .now()
            .ok_or_else(|| "Could not get the current slot")?;
        let slot_duration = self.beacon_chain.slot_clock.slot_duration();

        // if there is enough time to perform a discovery lookup
        if subscription_slot >= current_slot.saturating_add(MIN_PEER_DISCOVERY_SLOT_LOOK_AHEAD) {
            // check if a discovery request already exists
            if self
                .discover_peers
                .get(&(subnet_id, subscription_slot))
                .is_some()
            {
                // already a request queued, end
                return Ok(());
            }

            // check current event log to see if there is a discovery event queued
            if self
                .events
                .iter()
                .find(|event| event == &&AttServiceMessage::DiscoverPeers(subnet_id))
                .is_some()
            {
                // already queued a discovery event
                return Ok(());
            }

            // if the slot is more than epoch away, add an event to start looking for peers
            if subscription_slot
                < current_slot.saturating_add(TARGET_PEER_DISCOVERY_SLOT_LOOK_AHEAD)
            {
                // then instantly add a discovery request
                self.events
                    .push_back(AttServiceMessage::DiscoverPeers(subnet_id));
            } else {
                // Queue the discovery event to be executed for
                // TARGET_PEER_DISCOVERY_SLOT_LOOK_AHEAD

                let duration_to_discover = {
                    let duration_to_next_slot = self
                        .beacon_chain
                        .slot_clock
                        .duration_to_next_slot()
                        .ok_or_else(|| "Unable to determine duration to next slot")?;
                    // The -1 is done here to exclude the current slot duration, as we will use
                    // `duration_to_next_slot`.
                    let slots_until_discover = subscription_slot
                        .saturating_sub(current_slot)
                        .saturating_sub(1u64)
                        .saturating_sub(TARGET_PEER_DISCOVERY_SLOT_LOOK_AHEAD);

                    duration_to_next_slot + slot_duration * (slots_until_discover.as_u64() as u32)
                };

                self.discover_peers
                    .insert_at((subnet_id, subscription_slot), duration_to_discover);
            }
        }
        Ok(())
    }

    /// Checks the current random subnets and subscriptions to determine if a new subscription for this
    /// subnet is required for the given slot.
    ///
    /// If required, adds a subscription event and an associated unsubscription event.
    fn subscribe_to_subnet(
        &mut self,
        subnet_id: SubnetId,
        subscription_slot: Slot,
    ) -> Result<(), &'static str> {
        // initialise timing variables
        let current_slot = self
            .beacon_chain
            .slot_clock
            .now()
            .ok_or_else(|| "Could not get the current slot")?;

        // Ignore a subscription to the current slot.
        if current_slot >= subscription_slot {
            return Err("Could not subscribe to current slot, insufficient time");
        }

        let slot_duration = self.beacon_chain.slot_clock.slot_duration();
        let advance_subscription_duration = slot_duration
            .checked_div(ADVANCE_SUBSCRIBE_TIME)
            .expect("ADVANCE_SUBSCRIPTION_TIME cannot be too large");
        let duration_to_next_slot = self
            .beacon_chain
            .slot_clock
            .duration_to_next_slot()
            .ok_or_else(|| "Unable to determine duration to next slot")?;

        // calculate the time to subscribe to the subnet
        let duration_to_subscribe = {
            // The -1 is done here to exclude the current slot duration, as we will use
            // `duration_to_next_slot`.
            let slots_until_subscribe = subscription_slot
                .saturating_sub(current_slot)
                .saturating_sub(1u64);

            duration_to_next_slot
                .checked_add(slot_duration)
                .ok_or_else(|| "Overflow in adding slot_duration attestation time")?
                .checked_mul(slots_until_subscribe.as_u64() as u32)
                .ok_or_else(|| "Overflow in multiplying number of slots in attestation time")?
                .checked_sub(advance_subscription_duration)
                .unwrap_or_else(|| Duration::from_secs(0))
        };
        // the duration until we no longer need this subscription. We assume a single slot is
        // sufficient.
        let expected_end_subscription_duration = duration_to_subscribe
            + slot_duration
            + std::cmp::min(advance_subscription_duration, duration_to_next_slot);

        // Checks on current subscriptions
        // Note: We may be connected to a long-lived random subnet. In this case we still add the
        // subscription timeout and check this case when the timeout fires. This is because a
        // long-lived random subnet can be unsubscribed at any time when a validator becomes
        // in-active. This case is checked on the subscription event (see `handle_subscriptions`).

        // Return if we already have a subscription for this subnet_id and slot
        if self.subscriptions.contains(&(subnet_id, subscription_slot)) {
            return Ok(());
        }

        // We are not currently subscribed and have no waiting subscription, create one
        self.subscriptions
            .insert_at((subnet_id, subscription_slot), duration_to_subscribe);

        // if there is an unsubscription event for the slot prior, we remove it to prevent
        // unsubscriptions immediately after the subscription. We also want to minimize
        // subscription churn and maintain a consecutive subnet subscriptions.
        self.unsubscriptions
            .remove(&(subnet_id, subscription_slot.saturating_sub(1u64)));
        // add an unsubscription event to remove ourselves from the subnet once completed
        self.unsubscriptions.insert_at(
            (subnet_id, subscription_slot),
            expected_end_subscription_duration,
        );
        Ok(())
    }

    /// Updates the `known_validators` mapping and subscribes to a set of random subnets if required.
    ///
    /// This also updates the ENR to indicate our long-lived subscription to the subnet
    fn add_known_validator(&mut self, validator_index: u64) {
        if self.known_validators.get(&validator_index).is_none() {
            // New validator has subscribed
            // Subscribe to random topics and update the ENR if needed.

            let spec = &self.beacon_chain.spec;

            if self.random_subnets.len() < spec.attestation_subnet_count as usize {
                // Still room for subscriptions
                self.subscribe_to_random_subnets(
                    self.beacon_chain.spec.random_subnets_per_validator as usize,
                );
            }
        }
        // add the new validator or update the current timeout for a known validator
        self.known_validators.insert(validator_index);
    }

    /// Subscribe to long-lived random subnets and update the local ENR bitfield.
    fn subscribe_to_random_subnets(&mut self, no_subnets_to_subscribe: usize) {
        let subnet_count = self.beacon_chain.spec.attestation_subnet_count;

        // Build a list of random subnets that we are not currently subscribed to.
        let available_subnets = (0..subnet_count)
            .map(SubnetId::new)
            .filter(|subnet_id| self.random_subnets.get(subnet_id).is_none())
            .collect::<Vec<_>>();

        let to_subscribe_subnets = {
            if available_subnets.len() < no_subnets_to_subscribe {
                debug!(self.log, "Reached maximum random subnet subscriptions");
                available_subnets
            } else {
                // select a random sample of available subnets
                available_subnets
                    .choose_multiple(&mut rand::thread_rng(), no_subnets_to_subscribe)
                    .cloned()
                    .collect::<Vec<_>>()
            }
        };

        for subnet_id in to_subscribe_subnets {
            // remove this subnet from any immediate subscription/un-subscription events
            self.subscriptions
                .retain(|(map_subnet_id, _)| map_subnet_id != &subnet_id);
            self.unsubscriptions
                .retain(|(map_subnet_id, _)| map_subnet_id != &subnet_id);

            // insert a new random subnet
            self.random_subnets.insert(subnet_id);

            // if we are not already subscribed, then subscribe
            let topic_kind = &GossipKind::CommitteeIndex(subnet_id);

            if let None = self
                .network_globals
                .gossipsub_subscriptions
                .read()
                .iter()
                .find(|topic| topic.kind() == topic_kind)
            {
                // not already subscribed to the topic
                self.events
                    .push_back(AttServiceMessage::Subscribe(subnet_id));
            }
            // add the subnet to the ENR bitfield
            self.events.push_back(AttServiceMessage::EnrAdd(subnet_id));
        }
    }

    /* A collection of functions that handle the various timeouts */

    /// Request a discovery query to find peers for a particular subnet.
    fn handle_discover_peers(&mut self, subnet_id: SubnetId, target_slot: Slot) {
        debug!(self.log, "Searching for peers for subnet"; "subnet" => *subnet_id, "target_slot" => target_slot);
        self.events
            .push_back(AttServiceMessage::DiscoverPeers(subnet_id));
    }

    /// A queued subscription is ready.
    ///
    /// We add subscriptions events even if we are already subscribed to a random subnet (as these
    /// can be unsubscribed at any time by inactive validators). If we are
    /// still subscribed at the time the event fires, we don't re-subscribe.
    fn handle_subscriptions(&mut self, subnet_id: SubnetId, target_slot: Slot) {
        // Check if the subnet currently exists as a long-lasting random subnet
        if let Some(expiry) = self.random_subnets.get(&subnet_id) {
            // we are subscribed via a random subnet, if this is to expire during the time we need
            // to be subscribed, just extend the expiry
            let slot_duration = self.beacon_chain.slot_clock.slot_duration();
            let advance_subscription_duration = slot_duration
                .checked_div(ADVANCE_SUBSCRIBE_TIME)
                .expect("ADVANCE_SUBSCRIPTION_TIME cannot be too large");
            // we require the subnet subscription for at least a slot on top of the initial
            // subscription time
            let expected_end_subscription_duration = slot_duration + advance_subscription_duration;

            if expiry < &(Instant::now() + expected_end_subscription_duration) {
                self.random_subnets
                    .update_timeout(&subnet_id, expected_end_subscription_duration);
            }
        } else {
            // we are also not un-subscribing from a subnet if the next slot requires us to be
            // subscribed. Therefore there could be the case that we are already still subscribed
            // to the required subnet. In which case we do not issue another subscription request.
            let topic_kind = &GossipKind::CommitteeIndex(subnet_id);
            if self
                .network_globals
                .gossipsub_subscriptions
                .read()
                .iter()
                .find(|topic| topic.kind() == topic_kind)
                .is_none()
            {
                // we are not already subscribed
                debug!(self.log, "Subscribing to subnet"; "subnet" => *subnet_id, "target_slot" => target_slot.as_u64());
                self.events
                    .push_back(AttServiceMessage::Subscribe(subnet_id));
            }
        }
    }

    /// A queued unsubscription is ready.
    ///
    /// Unsubscription events are added, even if we are subscribed to long-lived random subnets. If
    /// a random subnet is present, we do not unsubscribe from it.
    fn handle_unsubscriptions(&mut self, subnet_id: SubnetId, target_slot: Slot) {
        // Check if the subnet currently exists as a long-lasting random subnet
        if self.random_subnets.contains(&subnet_id) {
            return;
        }

        debug!(self.log, "Unsubscribing from subnet"; "subnet" => *subnet_id, "processed_slot" => target_slot.as_u64());

        // various logic checks
        if self.subscriptions.contains(&(subnet_id, target_slot)) {
            crit!(self.log, "Unsubscribing from a subnet in subscriptions");
        }
        self.events
            .push_back(AttServiceMessage::Unsubscribe(subnet_id));
    }

    /// A random subnet has expired.
    ///
    /// This function selects a new subnet to join, or extends the expiry if there are no more
    /// available subnets to choose from.
    fn handle_random_subnet_expiry(&mut self, subnet_id: SubnetId) {
        let subnet_count = self.beacon_chain.spec.attestation_subnet_count;
        if self.random_subnets.len() == (subnet_count - 1) as usize {
            // We are at capacity, simply increase the timeout of the current subnet
            self.random_subnets.insert(subnet_id);
            return;
        }

        // we are not at capacity, unsubscribe from the current subnet, remove the ENR bitfield bit and choose a new random one
        // from the available subnets
        // Note: This should not occur during a required subnet as subscriptions update the timeout
        // to last as long as they are needed.

        debug!(self.log, "Unsubscribing from random subnet"; "subnet_id" => *subnet_id);
        self.events
            .push_back(AttServiceMessage::Unsubscribe(subnet_id));
        self.events
            .push_back(AttServiceMessage::EnrRemove(subnet_id));
        self.subscribe_to_random_subnets(1);
    }

    /// A known validator has not sent a subscription in a while. They are considered offline and the
    /// beacon node no longer needs to be subscribed to the allocated random subnets.
    ///
    /// We don't keep track of a specific validator to random subnet, rather the ratio of active
    /// validators to random subnets. So when a validator goes offline, we can simply remove the
    /// allocated amount of random subnets.
    fn handle_known_validator_expiry(&mut self) -> Result<(), ()> {
        let spec = &self.beacon_chain.spec;
        let subnet_count = spec.attestation_subnet_count;
        let random_subnets_per_validator = spec.random_subnets_per_validator;
        if self.known_validators.len() as u64 * random_subnets_per_validator >= subnet_count {
            // have too many validators, ignore
            return Ok(());
        }

        let subscribed_subnets = self.random_subnets.keys_vec();
        let to_remove_subnets = subscribed_subnets.choose_multiple(
            &mut rand::thread_rng(),
            random_subnets_per_validator as usize,
        );
        let current_slot = self.beacon_chain.slot_clock.now().ok_or_else(|| {
            warn!(self.log, "Could not get the current slot");
        })?;

        for subnet_id in to_remove_subnets {
            // If a subscription is queued for two slots in the future, it's associated unsubscription
            // will unsubscribe from the expired subnet.
            // If there is no subscription for this subnet,slot it is safe to add one, without
            // unsubscribing early from a required subnet
            if self
                .subscriptions
                .get(&(**subnet_id, current_slot + 2))
                .is_none()
            {
                // set an unsubscribe event
                let duration_to_next_slot = self
                    .beacon_chain
                    .slot_clock
                    .duration_to_next_slot()
                    .ok_or_else(|| {
                        warn!(self.log, "Unable to determine duration to next slot");
                    })?;
                let slot_duration =
                    self.beacon_chain.slot_clock.slot_duration();
                // Set the unsubscription timeout
                let unsubscription_duration = duration_to_next_slot + slot_duration * 2;
                self.unsubscriptions
                    .insert_at((**subnet_id, current_slot + 2), unsubscription_duration);
            }

            // as the long lasting subnet subscription is being removed, remove the subnet_id from
            // the ENR bitfield
            self.events
                .push_back(AttServiceMessage::EnrRemove(**subnet_id));
        }
        Ok(())
    }
}

impl<T: BeaconChainTypes> Stream for AttestationService<T> {
    type Item = AttServiceMessage;
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        // process any peer discovery events
        while let Async::Ready(Some((subnet_id, target_slot))) =
                    self.discover_peers.poll().map_err(|e| {
                        error!(self.log, "Failed to check for peer discovery requests"; "error"=> format!("{}", e));
                    })?
                {
                    self.handle_discover_peers(subnet_id, target_slot);
                }

        // process any subscription events
        while let Async::Ready(Some((subnet_id, target_slot))) = self.subscriptions.poll().map_err(|e| {
                        error!(self.log, "Failed to check for subnet subscription times"; "error"=> format!("{}", e));
                    })?
                {
                    self.handle_subscriptions(subnet_id, target_slot);
                }

        // process any un-subscription events
        while let Async::Ready(Some((subnet_id, target_slot))) = self.unsubscriptions.poll().map_err(|e| {
                        error!(self.log, "Failed to check for subnet unsubscription times"; "error"=> format!("{}", e));
                    })?
                {
                    self.handle_unsubscriptions(subnet_id, target_slot);
                }

        // process any random subnet expiries
        while let Async::Ready(Some(subnet)) = self.random_subnets.poll().map_err(|e| {
                        error!(self.log, "Failed to check for random subnet cycles"; "error"=> format!("{}", e));
                    })?
                {
                    self.handle_random_subnet_expiry(subnet);
                }

        // process any known validator expiries
        while let Async::Ready(Some(_validator_index)) = self.known_validators.poll().map_err(|e| {
                        error!(self.log, "Failed to check for random subnet cycles"; "error"=> format!("{}", e));
                    })?
                {
                    let _ = self.handle_known_validator_expiry();
                }

        // process any generated events
        if let Some(event) = self.events.pop_front() {
            return Ok(Async::Ready(Some(event)));
        }

        Ok(Async::NotReady)
    }
}

#[cfg(test)]
mod tests {
    extern crate rand;
    extern crate tokio_timer;
    extern crate futures;


    use super::*;
    use futures::{future, Stream};
    use tokio::runtime::Runtime;
    use tokio_timer::*;
    use beacon_chain::builder::{BeaconChainBuilder, Witness};
    use eth2_libp2p::{NetworkGlobals, PeerId};
    use genesis::{generate_deterministic_keypairs, interop_genesis_state, recent_genesis_time};
    use store::migrate::NullMigrator;
    use store::MemoryStore;
    use types::{EthSpec, MinimalEthSpec};
    use bls::{Signature, Keypair};
    use slog::{Logger, info};
    use sloggers::{terminal::TerminalLoggerBuilder, types::Severity, Build};
    use slot_clock::SystemTimeSlotClock;
    use beacon_chain::eth1_chain::CachingEth1Backend;
    use beacon_chain::events::NullEventHandler;
    use sloggers::null::NullLoggerBuilder;
    use tempfile::tempdir;
    use matches::assert_matches;
    use std::time::UNIX_EPOCH;

    pub type TestBeaconChainType = Witness<
        MemoryStore<MinimalEthSpec>,
        NullMigrator,
        SystemTimeSlotClock,
        CachingEth1Backend<MinimalEthSpec, MemoryStore<MinimalEthSpec>>,
        MinimalEthSpec,
        NullEventHandler<MinimalEthSpec>,
    >;

    pub struct TestBeaconChain {
        chain: BeaconChain<TestBeaconChainType>
    }

    impl TestBeaconChain {
        pub fn new_with_system_clock(keypairs: Vec<Keypair>, slot_duration: Duration) -> Self {
            let data_dir = tempdir().expect("should create temporary data_dir");
            let spec = MinimalEthSpec::default_spec();
            let genesis_time = recent_genesis_time(0);

            let log = get_logger();
            info!(log, "genesis time: {:?}", genesis_time);

            let chain = BeaconChainBuilder::new(MinimalEthSpec)
                .logger(log.clone())
                .custom_spec(spec.clone())
                .store(Arc::new(MemoryStore::open()))
                .store_migrator(NullMigrator)
                .data_dir(data_dir.path().to_path_buf())
                .genesis_state(
                    interop_genesis_state::<MinimalEthSpec>(&keypairs, genesis_time, &spec)
                        .expect("should generate interop state"),
                )
                .expect("should build state using recent genesis")
                .dummy_eth1_backend()
                .expect("should build dummy backend")
                .null_event_handler()
                .slot_clock(
                    SystemTimeSlotClock::new(
                        Slot::new(0),
                        Duration::from_secs(genesis_time),
                        slot_duration))
                .reduced_tree_fork_choice()
                .expect("should add fork choice to builder")
                .build()
                .expect("should build");

            Self {
                chain
            }
        }
    }

    fn get_logger() -> Logger {
        TerminalLoggerBuilder::new()
            .level(Severity::Debug)
            .build()
            .expect("logger should build")
    }

    fn get_sig() -> Signature {
        let keypair = Keypair::random();
        Signature::new(&[42, 42], &keypair.sk)
    }

    // hardcode validator count to 1 and slot duration to 1 second for now
    fn get_beacon_chain(slot_duration: u64) -> TestBeaconChain {
        let key_pairs: Vec<Keypair> = generate_deterministic_keypairs(1);
        TestBeaconChain::new_with_system_clock(key_pairs, Duration::from_secs(slot_duration))
    }

    fn get_attestation_service(slot_duration: u64) -> AttestationService<TestBeaconChainType> {
        let peer_id = PeerId::random();
        let network_globals: NetworkGlobals<MinimalEthSpec> =
            NetworkGlobals::new(peer_id, 0, 0);
        let beacon_chain = get_beacon_chain(slot_duration);
        let log = get_logger();
        AttestationService::new(Arc::new(beacon_chain.chain), Arc::new(network_globals), &log)
    }

    fn get_subscription(validator_index: u64, committee_index: u64, slot: Slot) -> ValidatorSubscription {
        ValidatorSubscription::new(
            validator_index,
            committee_index,
            slot,
            get_sig())
    }

    fn get_subscriptions(validator_count: u64, subscription_slot: u64) -> Vec<ValidatorSubscription> {
        let mut subscriptions: Vec<ValidatorSubscription> = Vec::new();
        for validator_index in 0..validator_count {
            subscriptions.push(ValidatorSubscription::new(
                validator_index,
                validator_index,
                Slot::new(subscription_slot),
                get_sig()));
        }
        subscriptions
    }

    fn run_one<F>(f: F) -> Result<F::Item, F::Error>
        where
            F: IntoFuture,
            F::Future: Send + 'static,
            F::Item: Send + 'static,
            F::Error: Send + 'static,
    {
        let mut runtime = Runtime::new().expect("Unable to create a runtime");
        runtime.block_on_all(f.into_future())
    }

    fn run_one_with_delay<F>(f: F, delay: u64) -> Result<F::Item, F::Error>
        where
            F: IntoFuture,
            F::Future: Send + 'static,
            F::Item: Send + 'static,
            F::Error: Send + 'static,
    {
        let mut runtime = Runtime::new().expect("Unable to create a runtime");
        runtime.block_on(
            Delay::new(Instant::now() + Duration::from_millis(delay))).unwrap();
        runtime.block_on_all(f.into_future())
    }

    fn is_subscription_event(_event: AttServiceMessage, subnet_id: SubnetId) -> bool {
        _event.eq(&AttServiceMessage::Subscribe(subnet_id)) ||
            _event.eq(&AttServiceMessage::EnrAdd(subnet_id)) ||
            _event.eq(&AttServiceMessage::Unsubscribe(subnet_id)) ||
            _event.eq(&AttServiceMessage::DiscoverPeers(subnet_id))
    }

    #[test]
    fn test_subscribe_current_slot() {
        // subscription config
        let validator_index = 1;
        let committee_index = 1;
        let subscription_subnet_id = SubnetId::new(committee_index);
        let subscription_slot = 0;

        // other test config
        let slot_duration_secs = 5;
        let initial_delay_millis = 500;


        // create the attestation service and subscriptions
        let mut attestation_service = get_attestation_service(slot_duration_secs);
        let current_slot = attestation_service.beacon_chain.slot_clock.now().expect("Could not get current slot");
        let subscriptions = vec![get_subscription(validator_index, committee_index, current_slot + Slot::new(subscription_slot)), ];

        // submit the subscriptions
        attestation_service.validator_subscriptions(subscriptions).unwrap();

        let test_closure = future::poll_fn( move || -> Poll<(Vec<AttServiceMessage>, Vec<AttServiceMessage>), ()>{
            let mut subscription_events = Vec::new();
            let mut random_subnet_events = Vec::new();

            // poll for the produced events
            while let Ok(Async::Ready(Some(_event))) = attestation_service.poll()
            {
                if is_subscription_event(_event, subscription_subnet_id){
                    subscription_events.push(_event);
                } else {
                    random_subnet_events.push(_event)
                }
                info!(attestation_service.log, "event: {:?}", _event);
            };
            Ok(Async::Ready((subscription_events, random_subnet_events)))
        });

        // run the test after an initial delay and collect produced events
        let actual = run_one_with_delay(test_closure, initial_delay_millis).unwrap();

        // expected events
        let expected = vec![];

        // assert the submitted subscriptions match exactly, and random subnet subscriptions match message type and count
        assert_eq!(actual.0, expected);
        assert_matches!(actual.1[..], [AttServiceMessage::Subscribe(_any1), AttServiceMessage::EnrAdd(_any2)]);
    }

    #[test]
    fn test_subscribe_one_slot_ahead() {
        // subscription config
        let validator_index = 1;
        let committee_index = 1;
        let subscription_subnet_id = SubnetId::new(committee_index);
        let subscription_slot = 1;

        // other test config
        let slot_duration_secs = 5;
        let initial_delay_millis = 500;


        // create the attestation service and subscriptions
        let mut attestation_service = get_attestation_service(slot_duration_secs);
        let current_slot = attestation_service.beacon_chain.slot_clock.now().expect("Could not get current slot");
        let subscriptions = vec![get_subscription(validator_index, committee_index, current_slot + Slot::new(subscription_slot)), ];

        // submit the subscriptions
        attestation_service.validator_subscriptions(subscriptions).unwrap();

        let test_closure = future::poll_fn( move || -> Poll<(Vec<AttServiceMessage>, Vec<AttServiceMessage>), ()>{
            let mut subscription_events = Vec::new();
            let mut random_subnet_events = Vec::new();

            // poll for the produced events
            while let Ok(Async::Ready(Some(_event))) = attestation_service.poll()
            {
                if is_subscription_event(_event, subscription_subnet_id){
                    subscription_events.push(_event);
                } else {
                    random_subnet_events.push(_event)
                }
                info!(attestation_service.log, "event: {:?}", _event);
            };
            Ok(Async::Ready((subscription_events, random_subnet_events)))
        });

        // run the test after an initial delay and collect produced events
        let actual = run_one_with_delay(test_closure, initial_delay_millis).unwrap();

        // expected events
        let expected = vec![AttServiceMessage::DiscoverPeers(subscription_subnet_id), AttServiceMessage::Subscribe(subscription_subnet_id)];

        // assert the submitted subscriptions match exactly, and random subnet subscriptions match message type and count
        assert_eq!(actual.0, expected);
        assert_matches!(actual.1[..], [AttServiceMessage::Subscribe(_any1), AttServiceMessage::EnrAdd(_any2)]);
    }

    #[test]
    fn test_subscribe_two_slots_ahead() {
        // subscription config
        let validator_index = 2;
        let committee_index = 2;
        let subscription_subnet_id = SubnetId::new(committee_index);
        let subscription_slot = 2;

        // other test config
        let slot_duration_secs = 5;
        let initial_delay_millis = 500;


        // create the attestation service and subscriptions
        let mut attestation_service = get_attestation_service(slot_duration_secs);
        let current_slot = attestation_service.beacon_chain.slot_clock.now().expect("Could not get current slot");
        let subscriptions = vec![get_subscription(validator_index, committee_index, current_slot + Slot::new(subscription_slot)), ];

        // submit the subscriptions
        attestation_service.validator_subscriptions(subscriptions).unwrap();

        let test_closure = future::poll_fn( move || -> Poll<(Vec<AttServiceMessage>, Vec<AttServiceMessage>), ()>{
            let mut subscription_events = Vec::new();
            let mut random_subnet_events = Vec::new();

            // poll for the produced events
            while let Ok(Async::Ready(Some(_event))) = attestation_service.poll()
            {
                if is_subscription_event(_event, subscription_subnet_id){
                    subscription_events.push(_event);
                } else {
                    random_subnet_events.push(_event)
                }
                info!(attestation_service.log, "event: {:?}", _event);
            };
            Ok(Async::Ready((subscription_events, random_subnet_events)))
        });

        // run the test after an initial delay and collect produced events
        let actual = run_one_with_delay(test_closure, initial_delay_millis).unwrap();

        // expected events
        let expected = vec![AttServiceMessage::DiscoverPeers(subscription_subnet_id)];

        // assert the submitted subscriptions match exactly, and random subnet subscriptions match message type and count
        assert_eq!(actual.0, expected);
        assert_matches!(actual.1[..], [AttServiceMessage::Subscribe(_any1), AttServiceMessage::EnrAdd(_any2)]);
    }

    #[test]
    fn test_subscribe_two_slots_ahead_wait_one_slot() {
        // subscription config
        let validator_index = 2;
        let committee_index = 2;
        let subscription_subnet_id = SubnetId::new(committee_index);
        let subscription_slot = 2;

        // other test config
        let slot_duration_secs = 5;
        let initial_delay_millis = 8000;


        // create the attestation service and subscriptions
        let mut attestation_service = get_attestation_service(slot_duration_secs);
        let current_slot = attestation_service.beacon_chain.slot_clock.now().expect("Could not get current slot");
        let subscriptions = vec![get_subscription(validator_index, committee_index, current_slot + Slot::new(subscription_slot)), ];

        // submit the subscriptions
        attestation_service.validator_subscriptions(subscriptions).unwrap();

        let test_closure = future::poll_fn( move || -> Poll<(Vec<AttServiceMessage>, Vec<AttServiceMessage>), ()>{
            let mut subscription_events = Vec::new();
            let mut random_subnet_events = Vec::new();

            // poll for the produced events
            while let Ok(Async::Ready(Some(_event))) = attestation_service.poll()
            {
                if is_subscription_event(_event, subscription_subnet_id){
                    subscription_events.push(_event);
                } else {
                    random_subnet_events.push(_event)
                }
                info!(attestation_service.log, "event: {:?}", _event);
            };
            Ok(Async::Ready((subscription_events, random_subnet_events)))
        });

        // run the test after an initial delay and collect produced events
        let actual = run_one_with_delay(test_closure, initial_delay_millis).unwrap();

        // expected events
        let expected = vec![AttServiceMessage::DiscoverPeers(subscription_subnet_id), AttServiceMessage::Subscribe(subscription_subnet_id)];

        // assert the submitted subscriptions match exactly, and random subnet subscriptions match message type and count
        assert_eq!(actual.0, expected);
        assert_matches!(actual.1[..], [AttServiceMessage::Subscribe(_any1), AttServiceMessage::EnrAdd(_any2)]);
    }

    #[test]
    fn test_subscribe_wait_for_unsubscribe() {
        // subscription config
        let validator_index = 1;
        let committee_index = 1;
        let subscription_subnet_id = SubnetId::new(committee_index);
        let subscription_slot = 2;

        // other test config
        let slot_duration_secs = 1;
        let initial_delay_millis = 5000;


        // create the attestation service and subscriptions
        let mut attestation_service = get_attestation_service(slot_duration_secs);
        let current_slot = attestation_service.beacon_chain.slot_clock.now().expect("Could not get current slot");
        let subscriptions = vec![get_subscription(validator_index, committee_index, current_slot + Slot::new(subscription_slot)), ];

        // submit the subscriptions
        attestation_service.validator_subscriptions(subscriptions).unwrap();

        let test_closure = future::poll_fn( move || -> Poll<(Vec<AttServiceMessage>, Vec<AttServiceMessage>), ()>{
            let mut subscription_events = Vec::new();
            let mut random_subnet_events = Vec::new();

            // poll for the produced events
            while let Ok(Async::Ready(Some(_event))) = attestation_service.poll()
            {
                if is_subscription_event(_event, subscription_subnet_id){
                    subscription_events.push(_event);
                } else {
                    random_subnet_events.push(_event)
                }
                info!(attestation_service.log, "event: {:?}", _event);
            };
            Ok(Async::Ready((subscription_events, random_subnet_events)))
        });

        // run the test after an initial delay and collect produced events
        let actual = run_one_with_delay(test_closure, initial_delay_millis).unwrap();

        // expected events
        let expected = vec![AttServiceMessage::DiscoverPeers(subscription_subnet_id), AttServiceMessage::Subscribe(subscription_subnet_id), AttServiceMessage::Unsubscribe(subscription_subnet_id)];

        // assert the submitted subscriptions match exactly, and random subnet subscriptions match message type and count
        assert_eq!(actual.0, expected);
        assert_matches!(actual.1[..], [AttServiceMessage::Subscribe(_any1), AttServiceMessage::EnrAdd(_any2)]);
    }
}




