use crate::block_verification::PayloadVerificationHandle;
use crate::block_verification_types::AsBlock;
use crate::{
    block_verification_types::BlockImportData,
    data_availability_checker::{AvailabilityCheckError, STATE_LRU_CAPACITY_NON_ZERO},
    eth1_finalization_cache::Eth1FinalizationData,
    BeaconChainTypes, BeaconStore, ExecutionPendingBlock,
};
use lru::LruCache;
use parking_lot::RwLock;
use ssz_derive::{Decode, Encode};
use state_processing::{BlockReplayer, ConsensusContext, StateProcessingStrategy};
use std::sync::Arc;
use types::{ssz_tagged_signed_beacon_block, ssz_tagged_signed_beacon_block_arc};
use types::{BeaconState, BlindedPayload, ChainSpec, Epoch, EthSpec, Hash256, SignedBeaconBlock};

/// This mirrors everything in the `AvailabilityPendingExecutedBlock`, except
/// that it is much smaller because it contains only a state root instead of
/// a full `BeaconState`.
#[derive(Encode, Decode)]
pub struct DietAvailabilityPendingExecutedBlock<E: EthSpec> {
    #[ssz(with = "ssz_tagged_signed_beacon_block_arc")]
    block: Arc<SignedBeaconBlock<E>>,
    state_root: Hash256,
    #[ssz(with = "ssz_tagged_signed_beacon_block")]
    parent_block: SignedBeaconBlock<E, BlindedPayload<E>>,
    parent_eth1_finalization_data: Eth1FinalizationData,
    confirmed_state_roots: Vec<Hash256>,
    consensus_context: ConsensusContext<E>,
    //TODO(sean) db migration?
    #[ssz(skip_serializing, skip_deserializing)]
    payload_verification_handle: Option<PayloadVerificationHandle<E>>,
}

impl<E: EthSpec> Clone for DietAvailabilityPendingExecutedBlock<E> {
    fn clone(&self) -> Self {
        todo!()
    }
}

/// just implementing the same methods as `AvailabilityPendingExecutedBlock`
impl<E: EthSpec> DietAvailabilityPendingExecutedBlock<E> {
    pub fn as_block(&self) -> &SignedBeaconBlock<E> {
        &self.block
    }

    pub fn num_blobs_expected(&self) -> usize {
        self.block
            .message()
            .body()
            .blob_kzg_commitments()
            .map_or(0, |commitments| commitments.len())
    }
}

/// This LRU cache holds BeaconStates used for block import. If the cache overflows,
/// the least recently used state will be dropped. If the dropped state is needed
/// later on, it will be recovered from the parent state and replaying the block.
///
/// WARNING: This cache assumes the parent block of any `AvailabilityPendingExecutedBlock`
/// has already been imported into ForkChoice. If this is not the case, the cache
/// will fail to recover the state when the cache overflows because it can't load
/// the parent state!
pub struct StateLRUCache<T: BeaconChainTypes> {
    states: RwLock<LruCache<Hash256, BeaconState<T::EthSpec>>>,
    store: BeaconStore<T>,
    spec: ChainSpec,
}

impl<T: BeaconChainTypes> StateLRUCache<T> {
    pub fn new(store: BeaconStore<T>, spec: ChainSpec) -> Self {
        Self {
            states: RwLock::new(LruCache::new(STATE_LRU_CAPACITY_NON_ZERO)),
            store,
            spec,
        }
    }

    /// This will store the state in the LRU cache and return a
    /// `DietAvailabilityPendingExecutedBlock` which is much cheaper to
    /// keep around in memory.
    pub fn register_pending_executed_block(
        &self,
        executed_block: ExecutionPendingBlock<T>,
    ) -> DietAvailabilityPendingExecutedBlock<T::EthSpec> {
        let state = executed_block.import_data.state;
        let state_root = executed_block.block.state_root();
        self.states.write().put(state_root, state);

        DietAvailabilityPendingExecutedBlock {
            block: executed_block.block,
            state_root,
            parent_block: executed_block.import_data.parent_block,
            parent_eth1_finalization_data: executed_block.import_data.parent_eth1_finalization_data,
            confirmed_state_roots: executed_block.import_data.confirmed_state_roots,
            consensus_context: executed_block.import_data.consensus_context,
            payload_verification_handle: Some(executed_block.payload_verification_handle),
        }
    }

    /// Recover the `AvailabilityPendingExecutedBlock` from the diet version.
    /// This method will first check the cache and if the state is not found
    /// it will reconstruct the state by loading the parent state from disk and
    /// replaying the block.
    pub fn recover_pending_executed_block(
        &self,
        diet_executed_block: DietAvailabilityPendingExecutedBlock<T::EthSpec>,
    ) -> Result<ExecutionPendingBlock<T>, AvailabilityCheckError> {
        let maybe_state = self.states.write().pop(&diet_executed_block.state_root);
        if let Some(state) = maybe_state {
            let block_root = diet_executed_block.block.canonical_root();
            Ok(ExecutionPendingBlock {
                block: diet_executed_block.block,
                import_data: BlockImportData {
                    block_root,
                    state,
                    parent_block: diet_executed_block.parent_block,
                    parent_eth1_finalization_data: diet_executed_block
                        .parent_eth1_finalization_data,
                    confirmed_state_roots: diet_executed_block.confirmed_state_roots,
                    consensus_context: diet_executed_block.consensus_context,
                },
                payload_verification_handle: todo!(),
            })
        } else {
            self.reconstruct_pending_executed_block(diet_executed_block)
        }
    }

    /// Reconstruct the `AvailabilityPendingExecutedBlock` by loading the parent
    /// state from disk and replaying the block. This function does NOT check the
    /// LRU cache.
    pub fn reconstruct_pending_executed_block(
        &self,
        diet_executed_block: DietAvailabilityPendingExecutedBlock<T::EthSpec>,
    ) -> Result<ExecutionPendingBlock<T>, AvailabilityCheckError> {
        let block_root = diet_executed_block.block.canonical_root();
        let state = self.reconstruct_state(&diet_executed_block)?;
        Ok(ExecutionPendingBlock {
            block: diet_executed_block.block,
            import_data: BlockImportData {
                block_root,
                state,
                parent_block: diet_executed_block.parent_block,
                parent_eth1_finalization_data: diet_executed_block.parent_eth1_finalization_data,
                confirmed_state_roots: diet_executed_block.confirmed_state_roots,
                consensus_context: diet_executed_block.consensus_context,
            },
            //TODO(sean) spawn a new handle
            // payload_verification_handle: diet_executed_block.payload_verification_handle,
            payload_verification_handle: todo!(),
        })
    }

    /// Reconstruct the state by loading the parent state from disk and replaying
    /// the block.
    fn reconstruct_state(
        &self,
        diet_executed_block: &DietAvailabilityPendingExecutedBlock<T::EthSpec>,
    ) -> Result<BeaconState<T::EthSpec>, AvailabilityCheckError> {
        let parent_block_root = diet_executed_block.parent_block.canonical_root();
        let parent_block_state_root = diet_executed_block.parent_block.state_root();
        let (parent_state_root, parent_state) = self
            .store
            .get_advanced_hot_state(
                parent_block_root,
                diet_executed_block.parent_block.slot(),
                parent_block_state_root,
            )
            .map_err(AvailabilityCheckError::StoreError)?
            .ok_or(AvailabilityCheckError::ParentStateMissing(
                parent_block_state_root,
            ))?;

        let state_roots = vec![
            Ok((parent_state_root, diet_executed_block.parent_block.slot())),
            Ok((
                diet_executed_block.state_root,
                diet_executed_block.block.slot(),
            )),
        ];

        let block_replayer: BlockReplayer<'_, T::EthSpec, AvailabilityCheckError, _> =
            BlockReplayer::new(parent_state, &self.spec)
                .no_signature_verification()
                .state_processing_strategy(StateProcessingStrategy::Accurate)
                .state_root_iter(state_roots.into_iter())
                .minimal_block_root_verification();

        block_replayer
            .apply_blocks(vec![diet_executed_block.block.clone_as_blinded()], None)
            .map(|block_replayer| block_replayer.into_state())
            .and_then(|mut state| {
                state
                    .build_exit_cache(&self.spec)
                    .map_err(AvailabilityCheckError::RebuildingStateCaches)?;
                state
                    .update_tree_hash_cache()
                    .map_err(AvailabilityCheckError::RebuildingStateCaches)?;
                Ok(state)
            })
    }

    /// returns the state cache for inspection
    pub fn lru_cache(&self) -> &RwLock<LruCache<Hash256, BeaconState<T::EthSpec>>> {
        &self.states
    }

    /// remove any states from the cache from before the given epoch
    pub fn do_maintenance(&self, cutoff_epoch: Epoch) {
        let mut write_lock = self.states.write();
        while let Some((_, state)) = write_lock.peek_lru() {
            if state.slot().epoch(T::EthSpec::slots_per_epoch()) < cutoff_epoch {
                write_lock.pop_lru();
            } else {
                break;
            }
        }
    }
}

/// This can only be used during testing. The intended way to
/// obtain a `DietAvailabilityPendingExecutedBlock` is to call
/// `register_pending_executed_block` on the `StateLRUCache`.
#[cfg(test)]
impl<T: BeaconChainTypes> From<ExecutionPendingBlock<T>>
    for DietAvailabilityPendingExecutedBlock<T::EthSpec>
{
    fn from(value: ExecutionPendingBlock<T>) -> Self {
        Self {
            block: value.block,
            state_root: value.import_data.state.canonical_root(),
            parent_block: value.import_data.parent_block,
            parent_eth1_finalization_data: value.import_data.parent_eth1_finalization_data,
            confirmed_state_roots: value.import_data.confirmed_state_roots,
            consensus_context: value.import_data.consensus_context,
            payload_verification_handle: value.payload_verification_outcome,
        }
    }
}
