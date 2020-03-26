#[cfg(test)]
mod tests {
    use super::super::*;
    use beacon_chain::builder::{BeaconChainBuilder, Witness};
    use beacon_chain::eth1_chain::CachingEth1Backend;
    use beacon_chain::events::NullEventHandler;
    use bls::{Keypair, Signature};
    use eth2_libp2p::{NetworkGlobals, PeerId};
    use futures::Stream;
    use genesis::{generate_deterministic_keypairs, interop_genesis_state, recent_genesis_time};
    use lazy_static::lazy_static;
    use matches::assert_matches;
    use slog::{info, Logger};
    use sloggers::{terminal::TerminalLoggerBuilder, types::Severity, Build};
    use slot_clock::SystemTimeSlotClock;
    use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
    use store::migrate::NullMigrator;
    use store::MemoryStore;
    use tempfile::tempdir;
    use tokio::prelude::*;
    use types::{EthSpec, MinimalEthSpec};

    const SLOT_DURATION_MILLIS: u64 = 200;

    type TestBeaconChainType = Witness<
        MemoryStore<MinimalEthSpec>,
        NullMigrator,
        SystemTimeSlotClock,
        CachingEth1Backend<MinimalEthSpec, MemoryStore<MinimalEthSpec>>,
        MinimalEthSpec,
        NullEventHandler<MinimalEthSpec>,
    >;

    pub struct TestBeaconChain {
        chain: Arc<BeaconChain<TestBeaconChainType>>,
    }

    impl TestBeaconChain {
        pub fn new_with_system_clock() -> Self {
            let data_dir = tempdir().expect("should create temporary data_dir");
            let spec = MinimalEthSpec::default_spec();
            let genesis_time = recent_genesis_time(0);

            let keypairs = generate_deterministic_keypairs(1);

            let log = get_logger();
            info!(log, "genesis time: {:?}", genesis_time);

            let chain = Arc::new(
                BeaconChainBuilder::new(MinimalEthSpec)
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
                    .slot_clock(SystemTimeSlotClock::new(
                        Slot::new(0),
                        Duration::from_secs(genesis_time),
                        Duration::from_millis(SLOT_DURATION_MILLIS),
                    ))
                    .reduced_tree_fork_choice()
                    .expect("should add fork choice to builder")
                    .build()
                    .expect("should build"),
            );

            Self { chain }
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

    lazy_static! {
        static ref CHAIN: TestBeaconChain = { TestBeaconChain::new_with_system_clock() };
    }

    fn get_attestation_service() -> AttestationService<TestBeaconChainType> {
        let peer_id = PeerId::random();
        let network_globals: NetworkGlobals<MinimalEthSpec> = NetworkGlobals::new(peer_id, 0, 0);
        let beacon_chain = CHAIN.chain.clone();

        let log = get_logger();
        AttestationService::new(beacon_chain, Arc::new(network_globals), &log)
    }

    fn get_subscription(
        validator_index: u64,
        committee_index: u64,
        slot: Slot,
    ) -> ValidatorSubscription {
        ValidatorSubscription::new(validator_index, committee_index, slot, get_sig())
    }

    fn _get_subscriptions(
        validator_count: u64,
        subscription_slot: u64,
    ) -> Vec<ValidatorSubscription> {
        let mut subscriptions: Vec<ValidatorSubscription> = Vec::new();
        for validator_index in 0..validator_count {
            subscriptions.push(ValidatorSubscription::new(
                validator_index,
                validator_index,
                Slot::new(subscription_slot),
                get_sig(),
            ));
        }
        subscriptions
    }

    fn _is_subscription_event(_event: AttServiceMessage, subnet_id: SubnetId) -> bool {
        _event.eq(&AttServiceMessage::Subscribe(subnet_id))
            || _event.eq(&AttServiceMessage::EnrAdd(subnet_id))
            || _event.eq(&AttServiceMessage::Unsubscribe(subnet_id))
            || _event.eq(&AttServiceMessage::DiscoverPeers(subnet_id))
    }

    // gets a number of events from the subscription service, or returns none if it times out after a number
    // of slots
    fn get_events<S: Stream<Item = AttServiceMessage, Error = ()>>(
        stream: S,
        no_events: u64,
        no_slots_before_timeout: u32,
    ) -> impl Future<Item = Vec<AttServiceMessage>, Error = ()> {
        stream
            .take(no_events)
            .collect()
            .timeout(Duration::from_millis(SLOT_DURATION_MILLIS) * no_slots_before_timeout)
            .map_err(|_| ())
    }

    #[test]
    fn test_subscribe_current_slot() {
        // subscription config
        let validator_index = 1;
        let committee_index = 1;
        let subscription_slot = 0;

        // create the attestation service and subscriptions
        let mut attestation_service = get_attestation_service();
        let current_slot = attestation_service
            .beacon_chain
            .slot_clock
            .now()
            .expect("Could not get current slot");
        let subscriptions = vec![get_subscription(
            validator_index,
            committee_index,
            current_slot + Slot::new(subscription_slot),
        )];

        // submit the subscriptions
        attestation_service
            .validator_subscriptions(subscriptions)
            .unwrap();

        let test_result = Arc::new(AtomicBool::new(false));
        let thread_result = test_result.clone();
        tokio::run(
            get_events(attestation_service, 2, 3)
                .map(move |events| {
                    dbg!(&events);
                    // currently two events, but will be three in the latest commits
                    assert_eq!(events.len(), 3);
                    // test completed successfully
                    thread_result.store(true, Relaxed);
                })
                // this doesn't need to be here, but helps with debugging
                .map_err(|_| panic!("Did not receive desired events in the given time frame")),
        );
        assert!(test_result.load(Relaxed))
    }

    #[test]
    fn test_subscribe_five_slots_ahead() {
        // subscription config
        let validator_index = 1;
        let committee_index = 1;
        let subscription_subnet_id = SubnetId::new(committee_index);
        let subscription_slot = 5;

        // create the attestation service and subscriptions
        let mut attestation_service = get_attestation_service();
        let current_slot = attestation_service
            .beacon_chain
            .slot_clock
            .now()
            .expect("Could not get current slot");
        let subscriptions = vec![get_subscription(
            validator_index,
            committee_index,
            current_slot + Slot::new(subscription_slot),
        )];

        // submit the subscriptions
        attestation_service
            .validator_subscriptions(subscriptions)
            .unwrap();

        let test_result = Arc::new(AtomicBool::new(false));
        let thread_result = test_result.clone();

        // expected events
        let expected = vec![
            AttServiceMessage::DiscoverPeers(subscription_subnet_id),
            AttServiceMessage::Subscribe(subscription_subnet_id),
        ];

        tokio::run(
            get_events(attestation_service, 4, 10)
                .map(move |events| {
                    dbg!(&events);
                    // currently two events, but will be three in the latest commits
                    assert_eq!(expected[..], events[2..]);
                    assert_matches!(
                        events[..2],
                        [
                            AttServiceMessage::Subscribe(_any1),
                            AttServiceMessage::EnrAdd(_any2)
                        ]
                    );
                    // test completed successfully
                    thread_result.store(true, Relaxed);
                })
                // this doesn't need to be here, but helps with debugging
                .map_err(|_| panic!("Did not receive desired events in the given time frame")),
        );
        assert!(test_result.load(Relaxed))
    }
}
