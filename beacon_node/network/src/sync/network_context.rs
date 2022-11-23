//! Provides network functionality for the Syncing thread. This fundamentally wraps a network
//! channel and stores a global RPC ID to perform requests.

use super::manager::{
    BlockTy, Id, RequestId as SyncRequestId, SeansBlob, SeansBlock, SeansBlockBlob,
};
use super::range_sync::{BatchId, ChainId, ExpectedBatchTy};
use crate::beacon_processor::WorkEvent;
use crate::service::{NetworkMessage, RequestId};
use crate::status::ToStatusMessage;
use beacon_chain::{BeaconChainTypes, EngineState};
use fnv::FnvHashMap;
use lighthouse_network::rpc::methods::BlobsByRangeRequest;
use lighthouse_network::rpc::{BlocksByRangeRequest, BlocksByRootRequest, GoodbyeReason};
use lighthouse_network::{Client, NetworkGlobals, PeerAction, PeerId, ReportSource, Request};
use slog::{debug, trace, warn};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::mpsc;
use types::{BlobsSidecar, SignedBeaconBlock, SignedBeaconBlockAndBlobsSidecar};

#[derive(Debug, Default)]
struct BlockBlobRequestInfo {
    /// Blocks we have received awaiting for their corresponding blob
    accumulated_blocks: VecDeque<SeansBlock>,
    /// Blobs we have received awaiting for their corresponding block
    accumulated_blobs: VecDeque<SeansBlob>,
    /// Whether the individual RPC request for blocks is finished or not.
    // Not sure if this is needed
    is_blocks_rpc_finished: bool,
    /// Whether the individual RPC request for blobs is finished or not
    // Not sure if this is needed
    is_blobs_rpc_finished: bool,
}

/// Wraps a Network channel to employ various RPC related network functionality for the Sync manager. This includes management of a global RPC request Id.
pub struct SyncNetworkContext<T: BeaconChainTypes> {
    /// The network channel to relay messages to the Network service.
    network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,

    /// Access to the network global vars.
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,

    /// A sequential ID for all RPC requests.
    request_id: Id,

    /// BlocksByRange requests made by the range syncing algorithm.
    range_requests: FnvHashMap<Id, (ChainId, BatchId)>,

    /// BlocksByRange requests made by backfill syncing.
    backfill_requests: FnvHashMap<Id, BatchId>,

    block_blob_requests: FnvHashMap<Id, (ChainId, BatchId, BlockBlobRequestInfo)>,

    /// Whether the ee is online. If it's not, we don't allow access to the
    /// `beacon_processor_send`.
    execution_engine_state: EngineState,

    /// Channel to send work to the beacon processor.
    beacon_processor_send: mpsc::Sender<WorkEvent<T>>,

    /// Logger for the `SyncNetworkContext`.
    log: slog::Logger,
}

impl<T: BeaconChainTypes> SyncNetworkContext<T> {
    pub fn new(
        network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
        network_globals: Arc<NetworkGlobals<T::EthSpec>>,
        beacon_processor_send: mpsc::Sender<WorkEvent<T>>,
        log: slog::Logger,
    ) -> Self {
        Self {
            network_send,
            execution_engine_state: EngineState::Online, // always assume `Online` at the start
            network_globals,
            request_id: 1,
            range_requests: FnvHashMap::default(),
            backfill_requests: FnvHashMap::default(),
            beacon_processor_send,
            block_blob_requests: Default::default(),
            log,
        }
    }

    /// Returns the Client type of the peer if known
    pub fn client_type(&self, peer_id: &PeerId) -> Client {
        self.network_globals
            .peers
            .read()
            .peer_info(peer_id)
            .map(|info| info.client().clone())
            .unwrap_or_default()
    }

    pub fn status_peers<C: ToStatusMessage>(
        &mut self,
        chain: &C,
        peers: impl Iterator<Item = PeerId>,
    ) {
        let status_message = chain.status_message();
        for peer_id in peers {
            debug!(
                self.log,
                "Sending Status Request";
                "peer" => %peer_id,
                "fork_digest" => ?status_message.fork_digest,
                "finalized_root" => ?status_message.finalized_root,
                "finalized_epoch" => ?status_message.finalized_epoch,
                "head_root" => %status_message.head_root,
                "head_slot" => %status_message.head_slot,
            );

            let request = Request::Status(status_message.clone());
            let request_id = RequestId::Router;
            let _ = self.send_network_msg(NetworkMessage::SendRequest {
                peer_id,
                request,
                request_id,
            });
        }
    }

    /// A blocks by range request for the range sync algorithm.
    pub fn blocks_by_range_request(
        &mut self,
        peer_id: PeerId,
        batch_type: ExpectedBatchTy,
        request: BlocksByRangeRequest,
        chain_id: ChainId,
        batch_id: BatchId,
    ) -> Result<Id, &'static str> {
        trace!(
            self.log,
            "Sending BlocksByRange Request";
            "method" => "BlocksByRange",
            "count" => request.count,
            "peer" => %peer_id,
        );
        let request = Request::BlocksByRange(request);
        let id = self.next_id();
        let request_id = RequestId::Sync(SyncRequestId::RangeSync { id });
        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request,
            request_id,
        })?;
        self.range_requests.insert(id, (chain_id, batch_id));
        Ok(id)
    }

    /// A blocks-blob by range request for the range sync algorithm.
    pub fn blocks_blobs_by_range_request(
        &mut self,
        peer_id: PeerId,
        request: BlocksByRangeRequest, // for now this is enough to get both requests.
        chain_id: ChainId,
        batch_id: BatchId,
    ) -> Result<Id, &'static str> {
        debug!(
            self.log,
            "Sending BlockBlock by range request";
            "method" => "BlocksByRangeAndBlobsOrSomething",
            "count" => request.count,
            "peer" => %peer_id,
        );

        // create the shared request id. This is fine since the rpc handles substream ids.
        let id = self.next_id();
        let request_id = RequestId::Sync(SyncRequestId::RangeBlockBlob { id });

        // Create the blob request based on the blob request.
        let blobs_request = Request::BlobsByRange(BlobsByRangeRequest {
            start_slot: request.start_slot,
            count: request.count,
        });
        let blocks_request = Request::BlocksByRange(request);

        // Send both requests. Make sure both can be sent.
        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request: blocks_request,
            request_id,
        })
        .and_then(|_| {
            self.send_network_msg(NetworkMessage::SendRequest {
                peer_id,
                request: blobs_request,
                request_id,
            })
        })?;
        let block_blob_info = BlockBlobRequestInfo::default();
        self.block_blob_requests
            .insert(id, (chain_id, batch_id, block_blob_info));
        Ok(id)
    }

    /// A blocks by range request sent by the backfill sync algorithm
    pub fn backfill_blocks_by_range_request(
        &mut self,
        peer_id: PeerId,
        batch_type: ExpectedBatchTy,
        request: BlocksByRangeRequest,
        batch_id: BatchId,
    ) -> Result<Id, &'static str> {
        trace!(
            self.log,
            "Sending backfill BlocksByRange Request";
            "method" => "BlocksByRange",
            "count" => request.count,
            "peer" => %peer_id,
        );
        let request = Request::BlocksByRange(request);
        let id = self.next_id();
        let request_id = RequestId::Sync(SyncRequestId::BackFillSync { id });
        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request,
            request_id,
        })?;
        self.backfill_requests.insert(id, batch_id);
        Ok(id)
    }

    /// Received a blocks by range response.
    pub fn range_sync_block_response(
        &mut self,
        request_id: Id,
        blob: Option<Arc<SignedBeaconBlock<T::EthSpec>>>,
        batch_type: ExpectedBatchTy,
    ) -> Option<(ChainId, BatchId, Option<BlockTy<T::EthSpec>>)> {
        unimplemented!()
    }

    pub fn range_sync_blob_response(
        &mut self,
        request_id: Id,
        block_ty: Option<BlobsSidecar<T::EthSpec>>,
    ) -> Option<(ChainId, BatchId, Option<BlockTy<T::EthSpec>>)> {
        unimplemented!()
    }

    pub fn range_sync_request_failed(
        &mut self,
        request_id: Id,
        batch_type: ExpectedBatchTy,
    ) -> Option<(ChainId, BatchId)> {
        unimplemented!()
    }

    pub fn backfill_request_failed(
        &mut self,
        request_id: Id,
        batch_type: ExpectedBatchTy,
    ) -> Option<BatchId> {
        unimplemented!()
    }

    /// Received a blocks by range response.
    pub fn backfill_sync_block_response(
        &mut self,
        request_id: Id,
        block_ty: Option<Arc<SignedBeaconBlock<T::EthSpec>>>,
        batch_type: ExpectedBatchTy,
    ) -> Option<(BatchId, Option<BlockTy<T::EthSpec>>)> {
        unimplemented!()
    }

    pub fn backfill_sync_blob_response(
        &mut self,
        request_id: Id,
        block_ty: Option<Arc<BlobsSidecar<T::EthSpec>>>,
    ) -> Option<(BatchId, Option<BlockTy<T::EthSpec>>)> {
        unimplemented!()
    }

    /// Sends a blocks by root request for a single block lookup.
    pub fn single_block_lookup_request(
        &mut self,
        peer_id: PeerId,
        request: BlocksByRootRequest,
    ) -> Result<Id, &'static str> {
        //FIXME(sean) add prune depth logic here?
        // D: YES

        trace!(
            self.log,
            "Sending BlocksByRoot Request";
            "method" => "BlocksByRoot",
            "count" => request.block_roots.len(),
            "peer" => %peer_id
        );
        let request = Request::BlocksByRoot(request);
        let id = self.next_id();
        let request_id = RequestId::Sync(SyncRequestId::SingleBlock { id });
        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request,
            request_id,
        })?;
        Ok(id)
    }

    /// Sends a blocks by root request for a parent request.
    pub fn parent_lookup_request(
        &mut self,
        peer_id: PeerId,
        request: BlocksByRootRequest,
    ) -> Result<Id, &'static str> {
        trace!(
            self.log,
            "Sending BlocksByRoot Request";
            "method" => "BlocksByRoot",
            "count" => request.block_roots.len(),
            "peer" => %peer_id
        );
        let request = Request::BlocksByRoot(request);
        let id = self.next_id();
        let request_id = RequestId::Sync(SyncRequestId::ParentLookup { id });
        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request,
            request_id,
        })?;
        Ok(id)
    }

    pub fn is_execution_engine_online(&self) -> bool {
        self.execution_engine_state == EngineState::Online
    }

    pub fn update_execution_engine_state(&mut self, engine_state: EngineState) {
        debug!(self.log, "Sync's view on execution engine state updated";
            "past_state" => ?self.execution_engine_state, "new_state" => ?engine_state);
        self.execution_engine_state = engine_state;
    }

    /// Terminates the connection with the peer and bans them.
    pub fn goodbye_peer(&mut self, peer_id: PeerId, reason: GoodbyeReason) {
        self.network_send
            .send(NetworkMessage::GoodbyePeer {
                peer_id,
                reason,
                source: ReportSource::SyncService,
            })
            .unwrap_or_else(|_| {
                warn!(self.log, "Could not report peer, channel failed");
            });
    }

    /// Reports to the scoring algorithm the behaviour of a peer.
    pub fn report_peer(&mut self, peer_id: PeerId, action: PeerAction, msg: &'static str) {
        debug!(self.log, "Sync reporting peer"; "peer_id" => %peer_id, "action" => %action);
        self.network_send
            .send(NetworkMessage::ReportPeer {
                peer_id,
                action,
                source: ReportSource::SyncService,
                msg,
            })
            .unwrap_or_else(|e| {
                warn!(self.log, "Could not report peer, channel failed"; "error"=> %e);
            });
    }

    /// Subscribes to core topics.
    pub fn subscribe_core_topics(&mut self) {
        self.network_send
            .send(NetworkMessage::SubscribeCoreTopics)
            .unwrap_or_else(|e| {
                warn!(self.log, "Could not subscribe to core topics."; "error" => %e);
            });
    }

    /// Sends an arbitrary network message.
    fn send_network_msg(&mut self, msg: NetworkMessage<T::EthSpec>) -> Result<(), &'static str> {
        self.network_send.send(msg).map_err(|_| {
            debug!(self.log, "Could not send message to the network service");
            "Network channel send Failed"
        })
    }

    pub fn processor_channel_if_enabled(&self) -> Option<&mpsc::Sender<WorkEvent<T>>> {
        self.is_execution_engine_online()
            .then_some(&self.beacon_processor_send)
    }

    pub fn processor_channel(&self) -> &mpsc::Sender<WorkEvent<T>> {
        &self.beacon_processor_send
    }

    fn next_id(&mut self) -> Id {
        let id = self.request_id;
        self.request_id += 1;
        id
    }

    pub fn batch_type(&self, epoch: types::Epoch) -> ExpectedBatchTy {
        // Keep tests only for blocks.
        #[cfg(test)]
        {
            return ExpectedBatchTy::OnlyBlock;
        }
        #[cfg(not(test))]
        {
            use super::range_sync::EPOCHS_PER_BATCH;
            assert_eq!(
                EPOCHS_PER_BATCH, 1,
                "If this is not one, everything will fail horribly"
            );
            warn!(
            self.log,
            "Missing fork boundary and prunning boundary comparison to decide request type. EVERYTHING IS A BLOB, BOB."
        );
            // Here we need access to the beacon chain, check the fork boundary, the current epoch, the
            // blob period to serve and check with that if the batch is a blob batch or not.
            // NOTE: This would carelessly assume batch sizes are always 1 epoch, to avoid needing to
            // align with the batch boundary.
            ExpectedBatchTy::OnlyBlockBlobs
        }
    }
}
