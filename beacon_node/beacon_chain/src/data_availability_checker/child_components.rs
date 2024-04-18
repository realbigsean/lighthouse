use crate::block_verification_types::RpcBlock;
use bls::Hash256;
use std::sync::Arc;
use types::blob_sidecar::FixedBlobSidecarList;
use types::{BlobSidecar, EthSpec, SignedBeaconBlock};

/// For requests triggered by an `UnknownBlockParent` or `UnknownBlobParent`, this struct
/// is used to cache components as they are sent to the network service. We can't use the
/// data availability cache currently because any blocks or blobs without parents
/// won't pass validation and therefore won't make it into the cache.
pub struct ChildComponents<E: EthSpec> {
    pub block_root: Hash256,
    pub downloaded_block: Option<Arc<SignedBeaconBlock<E>>>,
    pub downloaded_blobs: FixedBlobSidecarList<E>,
}

impl<E: EthSpec> ChildComponents<E> {
    pub fn empty(block_root: Hash256) -> Self {
        Self {
            block_root,
            downloaded_block: None,
            downloaded_blobs: <_>::default(),
        }
    }

    pub fn new(
        block_root: Hash256,
        block: Option<Arc<SignedBeaconBlock<E>>>,
        blobs: Option<Vec<Arc<BlobSidecar<E>>>>,
    ) -> Result<Self, String> {
        let mut cache = Self::empty(block_root);
        if let Some(block) = block {
            cache.merge_block(block);
        }
        if let Some(blobs) = blobs {
            cache.merge_blobs(blobs)?;
        }
        Ok(cache)
    }

    pub fn new_from_rpc_block(value: RpcBlock<E>) -> Result<Self, String> {
        let (block_root, block, blobs) = value.deconstruct();
        // Safe to unwrap because we are constructing the struct from a valid RpcBlock
        Self::new(block_root, Some(block), blobs.map(Into::into))
    }

    pub fn merge_block(&mut self, block: Arc<SignedBeaconBlock<E>>) {
        self.downloaded_block = Some(block);
    }

    pub fn merge_blob(&mut self, blob: Arc<BlobSidecar<E>>) -> Result<(), String> {
        if blob.index >= E::max_blobs_per_block() as u64 {
            return Err(format!("Blob index {} is out of range", blob.index));
        }
        self.merge_blob_unchecked(blob);
        Ok(())
    }

    pub fn merge_blobs(&mut self, blobs: Vec<Arc<BlobSidecar<E>>>) -> Result<(), String> {
        for blob in blobs.into_iter() {
            self.merge_blob(blob)?;
        }
        Ok(())
    }

    pub fn merge_blob_unchecked(&mut self, blob: Arc<BlobSidecar<E>>) {
        if let Some(blob_ref) = self.downloaded_blobs.get_mut(blob.index as usize) {
            *blob_ref = Some(blob);
        }
    }

    pub fn merge_blobs_unchecked(&mut self, blobs: Vec<Arc<BlobSidecar<E>>>) {
        for blob in blobs.into_iter() {
            self.merge_blob_unchecked(blob);
        }
    }

    pub fn clear_blobs(&mut self) {
        self.downloaded_blobs = FixedBlobSidecarList::default();
    }
}
