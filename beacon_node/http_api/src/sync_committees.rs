//! Contains the handlers for sync committee endpoints.
use beacon_chain::sync_committee_verification::VerifiedSyncSignature;
use beacon_chain::{
    BeaconChain, BeaconChainError, BeaconChainTypes, StateSkipConfig,
    MAXIMUM_GOSSIP_CLOCK_DISPARITY,
};
use eth2::types::{self as api_types};
use slog::{error, Logger};
use slot_clock::SlotClock;
use types::{BeaconStateError, Epoch, EthSpec, SyncCommitteeSignature, SyncDuty};

/// The struct that is returned to the requesting HTTP client.
type SyncDuties = api_types::GenericResponse<Vec<SyncDuty>>;

/// Handles a request from the HTTP API for sync committee duties.
pub fn sync_committee_duties<T: BeaconChainTypes>(
    request_epoch: Epoch,
    request_indices: &[u64],
    chain: &BeaconChain<T>,
) -> Result<SyncDuties, warp::reject::Rejection> {
    // Try using the head's sync committees to satisfy the request. This should be sufficient for
    // the vast majority of requests. Rather than checking if we think the request will succeed in a
    // way prone to data races, we attempt the request immediately and check the error code.
    match chain.sync_committee_duties_from_head(request_epoch, request_indices) {
        Ok(duties) => return Ok(convert_to_response(duties)),
        Err(BeaconChainError::SyncDutiesError(BeaconStateError::SyncCommitteeNotKnown {
            ..
        })) => (),
        Err(e) => return Err(warp_utils::reject::beacon_chain_error(e)),
    }

    let duties = duties_from_state_load(request_epoch, request_indices, chain)
        .map_err(warp_utils::reject::beacon_chain_error)?;
    Ok(convert_to_response(duties))
}

/// Slow path for duties: load a state and use it to compute the duties.
fn duties_from_state_load<T: BeaconChainTypes>(
    request_epoch: Epoch,
    request_indices: &[u64],
    chain: &BeaconChain<T>,
) -> Result<Vec<Option<SyncDuty>>, BeaconChainError> {
    // Determine what the current epoch would be if we fast-forward our system clock by
    // `MAXIMUM_GOSSIP_CLOCK_DISPARITY`.
    //
    // Most of the time, `tolerant_current_epoch` will be equal to `current_epoch`. However, during
    // the first `MAXIMUM_GOSSIP_CLOCK_DISPARITY` duration of the epoch `tolerant_current_epoch`
    // will equal `current_epoch + 1`
    let current_epoch = chain.epoch()?;

    let tolerant_current_epoch = chain
        .slot_clock
        .now_with_future_tolerance(MAXIMUM_GOSSIP_CLOCK_DISPARITY)
        .ok_or_else(|| BeaconChainError::UnableToReadSlot)?
        .epoch(T::EthSpec::slots_per_epoch());

    let max_sync_committee_period = tolerant_current_epoch.sync_committee_period(&chain.spec)? + 1;
    let sync_committee_period = request_epoch.sync_committee_period(&chain.spec)?;

    if sync_committee_period <= max_sync_committee_period {
        // Load the state at the start of the *previous* sync committee period.
        // This is sufficient for historical duties, and efficient in the case where the head
        // is lagging the current epoch and we need duties for the next period (because we only
        // have to transition the head to start of the current period).
        let load_slot = Epoch::new(
            sync_committee_period.saturating_sub(1)
                * chain.spec.epochs_per_sync_committee_period.as_u64(),
        )
        .start_slot(T::EthSpec::slots_per_epoch());

        let state = chain.state_at_slot(load_slot, StateSkipConfig::WithoutStateRoots)?;

        state
            .get_sync_committee_duties(request_epoch, request_indices, &chain.spec)
            .map_err(BeaconChainError::SyncDutiesError)
    } else {
        Err(BeaconChainError::SyncDutiesError(
            BeaconStateError::SyncCommitteeNotKnown {
                current_epoch,
                epoch: request_epoch,
            },
        ))
    }
}

fn convert_to_response(duties: Vec<Option<SyncDuty>>) -> SyncDuties {
    api_types::GenericResponse::from(
        duties
            .into_iter()
            .filter_map(|maybe_duty| maybe_duty)
            .collect::<Vec<_>>(),
    )
}

/// Receive sync committee duties, storing them in the pools & broadcasting them.
pub fn process_sync_committee_signatures<T: BeaconChainTypes>(
    sync_committee_signatures: Vec<SyncCommitteeSignature>,
    chain: &BeaconChain<T>,
    log: Logger,
) -> Result<(), warp::reject::Rejection> {
    let mut failures = vec![];

    for (i, sync_committee_signature) in sync_committee_signatures.iter().enumerate() {
        let verified =
            match VerifiedSyncSignature::verify(sync_committee_signature.clone(), None, chain) {
                Ok(verified) => verified,
                Err(e) => {
                    error!(
                        log,
                        "Failure verifying sync committee signature for gossip";
                        "error" => ?e,
                        "request_index" => i,
                        "slot" => sync_committee_signature.slot,
                        "validator_index" => sync_committee_signature.validator_index,
                    );
                    failures.push(api_types::Failure::new(i, format!("Verification: {:?}", e)));
                    continue;
                }
            };

        if let Err(e) = chain.add_to_naive_sync_aggregation_pool(verified) {
            error!(
                log,
                "Unable to add sync committee signature to pool";
                "error" => ?e,
                "slot" => sync_committee_signature.slot,
                "validator_index" => sync_committee_signature.validator_index,
            );
        }

        // FIXME(sproul): publish on gossip
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(warp_utils::reject::indexed_bad_request(
            "error processing sync committee signatures".to_string(),
            failures,
        ))
    }
}
