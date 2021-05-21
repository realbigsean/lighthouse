use crate::beacon_node_fallback::{BeaconNodeFallback, RequireSynced};
use crate::{duties_service::DutiesService, validator_store::ValidatorStore};
use environment::RuntimeContext;
use eth2::types::BlockId;
use futures::future::FutureExt;
use slog::{crit, debug, error, info, trace};
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;
use tokio::time::{sleep, sleep_until, Duration, Instant};
use types::{
    ChainSpec, EthSpec, Hash256, PublicKeyBytes, Slot, SyncContributionData, SyncDuty,
    SyncSelectionProof,
};

pub struct SyncCommitteeService<T: SlotClock + 'static, E: EthSpec> {
    inner: Arc<Inner<T, E>>,
}

impl<T: SlotClock + 'static, E: EthSpec> Clone for SyncCommitteeService<T, E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T: SlotClock + 'static, E: EthSpec> Deref for SyncCommitteeService<T, E> {
    type Target = Inner<T, E>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

pub struct Inner<T: SlotClock + 'static, E: EthSpec> {
    duties_service: Arc<DutiesService<T, E>>,
    validator_store: ValidatorStore<T, E>,
    slot_clock: T,
    beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
    context: RuntimeContext<E>,
}

impl<T: SlotClock + 'static, E: EthSpec> SyncCommitteeService<T, E> {
    pub fn new(
        duties_service: Arc<DutiesService<T, E>>,
        validator_store: ValidatorStore<T, E>,
        slot_clock: T,
        beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
        context: RuntimeContext<E>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                duties_service,
                validator_store,
                slot_clock,
                beacon_nodes,
                context,
            }),
        }
    }

    pub fn start_update_service(self, spec: &ChainSpec) -> Result<(), String> {
        let log = self.context.log().clone();
        let slot_duration = Duration::from_secs(spec.seconds_per_slot);
        let duration_to_next_slot = self
            .slot_clock
            .duration_to_next_slot()
            .ok_or("Unable to determine duration to next slot")?;

        info!(
            log,
            "Sync committee service started";
            "next_update_millis" => duration_to_next_slot.as_millis()
        );

        let executor = self.context.executor.clone();

        let interval_fut = async move {
            loop {
                if let Some(duration_to_next_slot) = self.slot_clock.duration_to_next_slot() {
                    sleep(duration_to_next_slot + slot_duration / 3).await;
                    let log = self.context.log();

                    if let Err(e) = self.spawn_contribution_tasks(slot_duration).await {
                        crit!(
                            log,
                            "Failed to spawn attestation tasks";
                            "error" => e
                        )
                    } else {
                        trace!(
                            log,
                            "Spawned attestation tasks";
                        )
                    }
                } else {
                    error!(log, "Failed to read slot clock");
                    // If we can't read the slot clock, just wait another slot.
                    sleep(slot_duration).await;
                }
            }
        };

        executor.spawn(interval_fut, "sync_committee_service");
        Ok(())
    }

    async fn spawn_contribution_tasks(&self, slot_duration: Duration) -> Result<(), String> {
        let log = self.context.log().clone();
        let slot = self.slot_clock.now().ok_or("Failed to read slot clock")?;
        let duration_to_next_slot = self
            .slot_clock
            .duration_to_next_slot()
            .ok_or("Unable to determine duration to next slot")?;

        // If a validator needs to publish a sync aggregate, they must do so at 2/3
        // through the slot. This delay triggers at this time
        let aggregate_production_instant = Instant::now()
            + duration_to_next_slot
                .checked_sub(slot_duration / 3)
                .unwrap_or_else(|| Duration::from_secs(0));

        let slot_duties = self
            .duties_service
            .sync_duties
            .get_duties_for_slot::<E>(slot, &self.duties_service.spec)
            .ok_or_else(|| format!("Error fetching duties for slot {}", slot))?;

        if slot_duties.duties.is_empty() {
            debug!(
                log,
                "No local validators in current sync committee";
                "slot" => slot,
            );
            return Ok(());
        }

        // Fetch block root for `SyncCommitteeContribution`.
        let block_root = self
            .beacon_nodes
            .first_success(RequireSynced::Yes, |beacon_node| async move {
                beacon_node
                    .get_beacon_blocks_root(BlockId::Slot(slot))
                    .await
            })
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("No block root found for slot {}", slot))?
            .data
            .root;

        // Spawn one task to publish all of the sync committee signatures.
        let validator_duties = slot_duties.duties;
        self.inner.context.executor.spawn(
            self.clone()
                .publish_sync_committee_signatures(slot, block_root, validator_duties)
                .map(|_| ()),
            "sync_committee_signature_publish",
        );

        let aggregators = slot_duties.aggregators;
        self.inner.context.executor.spawn(
            self.clone()
                .publish_sync_committee_aggregates(
                    slot,
                    block_root,
                    aggregators,
                    aggregate_production_instant,
                )
                .map(|_| ()),
            "sync_committee_aggregate_publish",
        );

        Ok(())
    }

    /// Publish sync committee signatures.
    async fn publish_sync_committee_signatures(
        self,
        slot: Slot,
        beacon_block_root: Hash256,
        validator_duties: Vec<SyncDuty>,
    ) -> Result<(), ()> {
        let log = self.context.log().clone();

        let committee_signatures = validator_duties
            .iter()
            .filter_map(|duty| {
                self.validator_store
                    .produce_sync_committee_signature(
                        slot,
                        beacon_block_root,
                        duty.validator_index,
                        &duty.pubkey,
                    )
                    .or_else(|| {
                        crit!(
                            log,
                            "Failed to sign sync committee signature";
                            "validator_index" => duty.validator_index,
                            "slot" => slot,
                        );
                        None
                    })
            })
            .collect::<Vec<_>>();

        let signatures_slice = &committee_signatures;

        self.beacon_nodes
            .first_success(RequireSynced::No, |beacon_node| async move {
                beacon_node
                    .post_beacon_pool_sync_committee_signatures(signatures_slice)
                    .await
            })
            .await
            .map_err(|e| {
                error!(
                    log,
                    "Unable to publish sync committee signatures";
                    "slot" => slot,
                    "error" => %e,
                );
            })?;

        info!(
            log,
            "Successfully published sync committee signatures";
            "count" => committee_signatures.len(),
            "head_block" => ?beacon_block_root,
            "slot" => slot,
        );

        Ok(())
    }

    async fn publish_sync_committee_aggregates(
        self,
        slot: Slot,
        beacon_block_root: Hash256,
        aggregators: HashMap<u64, Vec<(u64, PublicKeyBytes, SyncSelectionProof)>>,
        aggregate_instant: Instant,
    ) {
        for (subnet_id, subnet_aggregators) in aggregators {
            let service = self.clone();
            self.inner.context.executor.spawn(
                service
                    .publish_sync_committee_aggregate_for_subnet(
                        slot,
                        beacon_block_root,
                        subnet_id,
                        subnet_aggregators,
                        aggregate_instant,
                    )
                    .map(|_| ()),
                "sync_committee_aggregate_publish_subnet",
            );
        }
    }

    async fn publish_sync_committee_aggregate_for_subnet(
        self,
        slot: Slot,
        beacon_block_root: Hash256,
        subnet_id: u64,
        subnet_aggregators: Vec<(u64, PublicKeyBytes, SyncSelectionProof)>,
        aggregate_instant: Instant,
    ) -> Result<(), ()> {
        sleep_until(aggregate_instant).await;

        let log = self.context.log();

        let contribution = self
            .beacon_nodes
            .first_success(RequireSynced::No, |beacon_node| async move {
                let sync_contribution_data = SyncContributionData {
                    slot,
                    beacon_block_root,
                    subcommittee_index: subnet_id,
                };

                beacon_node
                    .get_validator_sync_committee_contribution::<E>(&sync_contribution_data)
                    .await
            })
            .await
            .map_err(|e| {
                crit!(
                    log,
                    "Failed to produce sync contribution";
                    "slot" => slot,
                    "beacon_block_root" => ?beacon_block_root,
                    "error" => %e,
                )
            })?
            .ok_or_else(|| {
                crit!(
                    log,
                    "No aggregate contribution found";
                    "slot" => slot,
                    "beacon_block_root" => ?beacon_block_root,
                );
            })?
            .data;

        // Make `SignedContributionAndProof`s
        let signed_contributions = subnet_aggregators
            .into_iter()
            .filter_map(|(aggregator_index, aggregator_pk, selection_proof)| {
                self.validator_store
                    .produce_signed_contribution_and_proof(
                        aggregator_index,
                        &aggregator_pk,
                        contribution.clone(),
                        selection_proof,
                    )
                    .or_else(|| {
                        crit!(
                            log,
                            "Unable to sign sync committee contribution";
                            "slot" => slot,
                        );
                        None
                    })
            })
            .collect::<Vec<_>>();

        // Publish to the beacon node.
        let signed_contributions_slice = &signed_contributions;
        self.beacon_nodes
            .first_success(RequireSynced::Yes, |beacon_node| async move {
                beacon_node
                    .post_validator_contribution_and_proofs(signed_contributions_slice)
                    .await
            })
            .await
            .map_err(|e| {
                error!(
                    log,
                    "Unable to publish sync committee signatures";
                    "slot" => slot,
                    "error" => %e,
                );
            })?;

        info!(
            log,
            "Publishing signed contribution and proof";
            "contribution" => ?contribution,
            "slot" => slot,
        );

        Ok(())
    }
}
