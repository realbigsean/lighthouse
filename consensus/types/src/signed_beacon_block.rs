use crate::beacon_block_body::format_kzg_commitments;
use crate::*;
use bls::Signature;
use derivative::Derivative;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use std::fmt;
use superstruct::superstruct;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

#[derive(arbitrary::Arbitrary, PartialEq, Eq, Hash, Clone, Copy)]
pub struct SignedBeaconBlockHash(Hash256);

impl fmt::Debug for SignedBeaconBlockHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SignedBeaconBlockHash({:?})", self.0)
    }
}

impl fmt::Display for SignedBeaconBlockHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Hash256> for SignedBeaconBlockHash {
    fn from(hash: Hash256) -> SignedBeaconBlockHash {
        SignedBeaconBlockHash(hash)
    }
}

impl From<SignedBeaconBlockHash> for Hash256 {
    fn from(signed_beacon_block_hash: SignedBeaconBlockHash) -> Hash256 {
        signed_beacon_block_hash.0
    }
}

/// A `BeaconBlock` and a signature from its proposer.
#[superstruct(
    meta_variants(Blinded, Full),
    variants(Base, Altair, Merge, Capella, Deneb),
    variant_attributes(
        derive(
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash,
            Derivative,
            arbitrary::Arbitrary
        ),
        derivative(PartialEq, Hash(bound = "E: EthSpec")),
        serde(bound = "E: EthSpec"),
        arbitrary(bound = "E: EthSpec"),
    ),
    map_into(BeaconBlock),
    map_ref_into(BeaconBlockRef),
    map_ref_mut_into(BeaconBlockRefMut)
)]
#[derive(
    Debug, Clone, Serialize, Deserialize, Encode, TreeHash, Derivative, arbitrary::Arbitrary,
)]
#[derivative(PartialEq, Hash(bound = "E: EthSpec"))]
#[serde(untagged)]
#[serde(bound = "E: EthSpec")]
#[arbitrary(bound = "E: EthSpec")]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
pub struct SignedBeaconBlock<E: EthSpec> {
    #[superstruct(flatten)]
    pub message: BeaconBlock<E>,
    pub signature: Signature,
}

pub type SignedBlindedBeaconBlock<E> = SignedBeaconBlockBlinded<E>;

impl<E: EthSpec> SignedBeaconBlock<E> {
    /// Returns the name of the fork pertaining to `self`.
    ///
    /// Will return an `Err` if `self` has been instantiated to a variant conflicting with the fork
    /// dictated by `self.slot()`.
    pub fn fork_name(&self, spec: &ChainSpec) -> Result<ForkName, InconsistentFork> {
        self.message().fork_name(spec)
    }

    /// Returns the name of the fork pertaining to `self`
    /// Does not check that the fork is consistent with the slot.
    pub fn fork_name_unchecked(&self) -> ForkName {
        self.message().fork_name_unchecked()
    }

    /// SSZ decode with fork variant determined by slot.
    pub fn from_ssz_bytes(bytes: &[u8], spec: &ChainSpec) -> Result<Self, ssz::DecodeError> {
        Self::from_ssz_bytes_with(bytes, |bytes| BeaconBlock::from_ssz_bytes(bytes, spec))
    }

    /// SSZ decode with explicit fork variant.
    pub fn from_ssz_bytes_for_fork(
        bytes: &[u8],
        fork_name: ForkName,
    ) -> Result<Self, ssz::DecodeError> {
        Self::from_ssz_bytes_with(bytes, |bytes| {
            BeaconBlock::from_ssz_bytes_for_fork(bytes, fork_name)
        })
    }

    /// SSZ decode which attempts to decode all variants (slow).
    pub fn any_from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Self::from_ssz_bytes_with(bytes, BeaconBlock::any_from_ssz_bytes)
    }

    /// SSZ decode with custom decode function.
    pub fn from_ssz_bytes_with(
        bytes: &[u8],
        block_decoder: impl FnOnce(&[u8]) -> Result<BeaconBlock<E>, ssz::DecodeError>,
    ) -> Result<Self, ssz::DecodeError> {
        // We need the customer decoder for `BeaconBlock`, which doesn't compose with the other
        // SSZ utils, so we duplicate some parts of `ssz_derive` here.
        let mut builder = ssz::SszDecoderBuilder::new(bytes);

        builder.register_anonymous_variable_length_item()?;
        builder.register_type::<Signature>()?;

        let mut decoder = builder.build()?;

        // Read the first item as a `BeaconBlock`.
        let message = decoder.decode_next_with(block_decoder)?;
        let signature = decoder.decode_next()?;

        Ok(Self::from_block(message, signature))
    }

    /// Create a new `SignedBeaconBlock` from a `BeaconBlock` and `Signature`.
    pub fn from_block(block: BeaconBlock<E>, signature: Signature) -> Self {
        match block {
            BeaconBlock::Blinded(BeaconBlockBlinded::Base(message)) => SignedBeaconBlock::Blinded(
                SignedBeaconBlockBlinded::Base(SignedBeaconBlockBlindedBase { message, signature }),
            ),
            BeaconBlock::Blinded(BeaconBlockBlinded::Altair(message)) => {
                SignedBeaconBlock::Blinded(SignedBeaconBlockBlinded::Altair(
                    SignedBeaconBlockBlindedAltair { message, signature },
                ))
            }
            BeaconBlock::Blinded(BeaconBlockBlinded::Merge(message)) => {
                SignedBeaconBlock::Blinded(SignedBeaconBlockBlinded::Merge(
                    SignedBeaconBlockBlindedMerge { message, signature },
                ))
            }
            BeaconBlock::Blinded(BeaconBlockBlinded::Capella(message)) => {
                SignedBeaconBlock::Blinded(SignedBeaconBlockBlinded::Capella(
                    SignedBeaconBlockBlindedCapella { message, signature },
                ))
            }
            BeaconBlock::Blinded(BeaconBlockBlinded::Deneb(message)) => {
                SignedBeaconBlock::Blinded(SignedBeaconBlockBlinded::Deneb(
                    SignedBeaconBlockBlindedDeneb { message, signature },
                ))
            }
            BeaconBlock::Full(BeaconBlockFull::Base(message)) => {
                SignedBeaconBlock::Full(SignedBeaconBlockFull::Base(SignedBeaconBlockFullBase {
                    message,
                    signature,
                }))
            }
            BeaconBlock::Full(BeaconBlockFull::Altair(message)) => SignedBeaconBlock::Full(
                SignedBeaconBlockFull::Altair(SignedBeaconBlockFullAltair { message, signature }),
            ),
            BeaconBlock::Full(BeaconBlockFull::Merge(message)) => {
                SignedBeaconBlock::Full(SignedBeaconBlockFull::Merge(SignedBeaconBlockFullMerge {
                    message,
                    signature,
                }))
            }
            BeaconBlock::Full(BeaconBlockFull::Capella(message)) => SignedBeaconBlock::Full(
                SignedBeaconBlockFull::Capella(SignedBeaconBlockFullCapella { message, signature }),
            ),
            BeaconBlock::Full(BeaconBlockFull::Deneb(message)) => {
                SignedBeaconBlock::Full(SignedBeaconBlockFull::Deneb(SignedBeaconBlockFullDeneb {
                    message,
                    signature,
                }))
            }
        }
    }

    /// Deconstruct the `SignedBeaconBlock` into a `BeaconBlock` and `Signature`.
    ///
    /// This is necessary to get a `&BeaconBlock` from a `SignedBeaconBlock` because
    /// `SignedBeaconBlock` only contains a `BeaconBlock` _variant_.
    pub fn deconstruct(self) -> (BeaconBlock<E>, Signature) {
        map_signed_beacon_block_into_beacon_block!(self, |block, beacon_block_cons| {
            (beacon_block_cons(block.message), block.signature)
        })
    }

    /// Accessor for the block's `message` field as a ref.
    pub fn message<'a>(&'a self) -> BeaconBlockRef<'a, E> {
        map_signed_beacon_block_ref_into_beacon_block_ref!(
            &'a _,
            self.to_ref(),
            |inner, cons| cons(&inner.message)
        )
    }

    /// Accessor for the block's `message` as a mutable reference (for testing only).
    pub fn message_mut<'a>(&'a mut self) -> BeaconBlockRefMut<'a, E> {
        map_signed_beacon_block_ref_mut_into_beacon_block_ref_mut!(
            &'a _,
            self.to_mut(),
            |inner, cons| cons(inner.message_mut())
        )
    }

    /// Verify `self.signature`.
    ///
    /// If the root of `block.message` is already known it can be passed in via `object_root_opt`.
    /// Otherwise, it will be computed locally.
    pub fn verify_signature(
        &self,
        object_root_opt: Option<Hash256>,
        pubkey: &PublicKey,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> bool {
        // Refuse to verify the signature of a block if its structure does not match the fork at
        // `self.slot()`.
        if self.fork_name(spec).is_err() {
            return false;
        }

        let domain = spec.get_domain(
            self.epoch(),
            Domain::BeaconProposer,
            fork,
            genesis_validators_root,
        );

        let message = if let Some(object_root) = object_root_opt {
            SigningData {
                object_root,
                domain,
            }
            .tree_hash_root()
        } else {
            self.message().signing_root(domain)
        };

        self.signature().verify(pubkey, message)
    }

    /// Produce a signed beacon block header corresponding to this block.
    pub fn signed_block_header(&self) -> SignedBeaconBlockHeader {
        SignedBeaconBlockHeader {
            message: self.message().block_header(),
            signature: self.signature().clone(),
        }
    }

    /// Convenience accessor for the block's slot.
    pub fn slot(&self) -> Slot {
        self.message().slot()
    }

    /// Convenience accessor for the block's epoch.
    pub fn epoch(&self) -> Epoch {
        self.message().slot().epoch(E::slots_per_epoch())
    }

    /// Convenience accessor for the block's parent root.
    pub fn parent_root(&self) -> Hash256 {
        self.message().parent_root()
    }

    /// Convenience accessor for the block's state root.
    pub fn state_root(&self) -> Hash256 {
        self.message().state_root()
    }

    /// Returns the `tree_hash_root` of the block.
    pub fn canonical_root(&self) -> Hash256 {
        self.message().tree_hash_root()
    }

    pub fn num_expected_blobs(&self) -> usize {
        self.message()
            .body()
            .blob_kzg_commitments()
            .map(|c| c.len())
            .unwrap_or(0)
    }

    /// Used for displaying commitments in logs.
    pub fn commitments_formatted(&self) -> String {
        let Ok(commitments) = self.message().body().blob_kzg_commitments() else {
            return "[]".to_string();
        };

        format_kzg_commitments(commitments.as_ref())
    }
}

// We can convert pre-Bellatrix blocks without payloads into blocks with payloads.
impl<E: EthSpec> From<SignedBeaconBlockBlindedBase<E>> for SignedBeaconBlockFullBase<E> {
    fn from(signed_block: SignedBeaconBlockBlindedBase<E>) -> Self {
        let SignedBeaconBlockBlindedBase { message, signature } = signed_block;
        SignedBeaconBlockFullBase {
            message: message.into(),
            signature,
        }
    }
}

impl<E: EthSpec> From<SignedBeaconBlockBlindedAltair<E>> for SignedBeaconBlockFullAltair<E> {
    fn from(signed_block: SignedBeaconBlockBlindedAltair<E>) -> Self {
        let SignedBeaconBlockBlindedAltair { message, signature } = signed_block;
        SignedBeaconBlockFullAltair {
            message: message.into(),
            signature,
        }
    }
}

// Post-Bellatrix blocks can be "unblinded" by adding the full payload.
// NOTE: It might be nice to come up with a `superstruct` pattern to abstract over this before
// the first fork after Bellatrix.
impl<E: EthSpec> SignedBeaconBlockBlindedMerge<E> {
    pub fn into_full_block(
        self,
        execution_payload: ExecutionPayloadMerge<E>,
    ) -> SignedBeaconBlockFullMerge<E> {
        let SignedBeaconBlockBlindedMerge {
            message:
                BeaconBlockBlindedMerge {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root,
                    body:
                        BeaconBlockBodyBlindedMerge {
                            randao_reveal,
                            eth1_data,
                            graffiti,
                            proposer_slashings,
                            attester_slashings,
                            attestations,
                            deposits,
                            voluntary_exits,
                            sync_aggregate,
                            execution_payload_header: _,
                        },
                },
            signature,
        } = self;
        SignedBeaconBlockFullMerge {
            message: BeaconBlockFullMerge {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body: BeaconBlockBodyFullMerge {
                    randao_reveal,
                    eth1_data,
                    graffiti,
                    proposer_slashings,
                    attester_slashings,
                    attestations,
                    deposits,
                    voluntary_exits,
                    sync_aggregate,
                    execution_payload,
                },
            },
            signature,
        }
    }
}

impl<E: EthSpec> SignedBeaconBlockBlindedCapella<E> {
    pub fn into_full_block(
        self,
        execution_payload: ExecutionPayloadCapella<E>,
    ) -> SignedBeaconBlockFullCapella<E> {
        let SignedBeaconBlockBlindedCapella {
            message:
                BeaconBlockBlindedCapella {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root,
                    body:
                        BeaconBlockBodyBlindedCapella {
                            randao_reveal,
                            eth1_data,
                            graffiti,
                            proposer_slashings,
                            attester_slashings,
                            attestations,
                            deposits,
                            voluntary_exits,
                            sync_aggregate,
                            execution_payload_header: _,
                            bls_to_execution_changes,
                        },
                },
            signature,
        } = self;
        SignedBeaconBlockFullCapella {
            message: BeaconBlockFullCapella {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body: BeaconBlockBodyFullCapella {
                    randao_reveal,
                    eth1_data,
                    graffiti,
                    proposer_slashings,
                    attester_slashings,
                    attestations,
                    deposits,
                    voluntary_exits,
                    sync_aggregate,
                    execution_payload,
                    bls_to_execution_changes,
                },
            },
            signature,
        }
    }
}

impl<E: EthSpec> SignedBeaconBlockBlindedDeneb<E> {
    pub fn into_full_block(
        self,
        execution_payload: ExecutionPayloadDeneb<E>,
    ) -> SignedBeaconBlockFullDeneb<E> {
        let SignedBeaconBlockBlindedDeneb {
            message:
                BeaconBlockBlindedDeneb {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root,
                    body:
                        BeaconBlockBodyBlindedDeneb {
                            randao_reveal,
                            eth1_data,
                            graffiti,
                            proposer_slashings,
                            attester_slashings,
                            attestations,
                            deposits,
                            voluntary_exits,
                            sync_aggregate,
                            execution_payload_header: _,
                            bls_to_execution_changes,
                            blob_kzg_commitments,
                        },
                },
            signature,
        } = self;
        SignedBeaconBlockFullDeneb {
            message: BeaconBlockFullDeneb {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body: BeaconBlockBodyFullDeneb {
                    randao_reveal,
                    eth1_data,
                    graffiti,
                    proposer_slashings,
                    attester_slashings,
                    attestations,
                    deposits,
                    voluntary_exits,
                    sync_aggregate,
                    execution_payload,
                    bls_to_execution_changes,
                    blob_kzg_commitments,
                },
            },
            signature,
        }
    }
}

impl<E: EthSpec> SignedBeaconBlockBlinded<E> {
    pub fn try_into_full_block(
        self,
        execution_payload: Option<ExecutionPayload<E>>,
    ) -> Option<SignedBeaconBlockFull<E>> {
        todo!()
        // let full_block = match (self, execution_payload) {
        //     (SignedBeaconBlock::Base(block), _) => SignedBeaconBlock::Base(block.into()),
        //     (SignedBeaconBlock::Altair(block), _) => SignedBeaconBlock::Altair(block.into()),
        //     (SignedBeaconBlock::Merge(block), Some(ExecutionPayload::Merge(payload))) => {
        //         SignedBeaconBlock::Merge(block.into_full_block(payload))
        //     }
        //     (SignedBeaconBlock::Capella(block), Some(ExecutionPayload::Capella(payload))) => {
        //         SignedBeaconBlock::Capella(block.into_full_block(payload))
        //     }
        //     (SignedBeaconBlock::Deneb(block), Some(ExecutionPayload::Deneb(payload))) => {
        //         SignedBeaconBlock::Deneb(block.into_full_block(payload))
        //     }
        //     // avoid wildcard matching forks so that compiler will
        //     // direct us here when a new fork has been added
        //     (SignedBeaconBlock::Merge(_), _) => return None,
        //     (SignedBeaconBlock::Capella(_), _) => return None,
        //     (SignedBeaconBlock::Deneb(_), _) => return None,
        // };
        // Some(full_block)
    }
}

// We can blind blocks with payloads by converting the payload into a header.
//
// We can optionally keep the header, or discard it.
impl<E: EthSpec> From<SignedBeaconBlock<E>>
    for (SignedBlindedBeaconBlock<E>, Option<ExecutionPayload<E>>)
{
    fn from(signed_block: SignedBeaconBlock<E>) -> Self {
        let (block, signature) = signed_block.deconstruct();
        let (blinded_block, payload) = block.into();
        (
            SignedBeaconBlockBlinded::from_block(blinded_block, signature),
            payload,
        )
    }
}

impl<E: EthSpec> From<SignedBeaconBlock<E>> for SignedBlindedBeaconBlock<E> {
    fn from(signed_block: SignedBeaconBlock<E>) -> Self {
        let (blinded_block, _) = signed_block.into();
        blinded_block
    }
}

// We can blind borrowed blocks with payloads by converting the payload into a header (without
// cloning the payload contents).
impl<E: EthSpec> SignedBeaconBlock<E> {
    pub fn clone_as_blinded(&self) -> SignedBlindedBeaconBlock<E> {
        SignedBeaconBlockBlinded::from_block(self.message().into(), self.signature().clone())
    }
}

impl<E: EthSpec> ForkVersionDeserialize for SignedBeaconBlockFull<E> {
    fn deserialize_by_fork<'de, D: serde::Deserializer<'de>>(
        value: serde_json::value::Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error> {
        Ok(map_fork_name!(
            fork_name,
            Self,
            serde_json::from_value(value).map_err(|e| serde::de::Error::custom(format!(
                "SignedBeaconBlock failed to deserialize: {:?}",
                e
            )))?
        ))
    }
}

/// This module can be used to encode and decode a `SignedBeaconBlock` the same way it
/// would be done if we had tagged the superstruct enum with
/// `#[ssz(enum_behaviour = "union")]`
/// This should _only_ be used *some* cases when storing these objects in the database
/// and _NEVER_ for encoding / decoding blocks sent over the network!
pub mod ssz_tagged_signed_beacon_block {
    use super::*;
    pub mod encode {
        use super::*;
        #[allow(unused_imports)]
        use ssz::*;

        pub fn is_ssz_fixed_len() -> bool {
            false
        }

        pub fn ssz_fixed_len() -> usize {
            BYTES_PER_LENGTH_OFFSET
        }

        pub fn ssz_bytes_len<E: EthSpec>(block: &SignedBeaconBlockFull<E>) -> usize {
            block
                .ssz_bytes_len()
                .checked_add(1)
                .expect("encoded length must be less than usize::max")
        }

        pub fn ssz_append<E: EthSpec>(block: &SignedBeaconBlockFull<E>, buf: &mut Vec<u8>) {
            let fork_name = block.fork_name_unchecked();
            fork_name.ssz_append(buf);
            block.ssz_append(buf);
        }

        pub fn as_ssz_bytes<E: EthSpec>(block: &SignedBeaconBlockFull<E>) -> Vec<u8> {
            let mut buf = vec![];
            ssz_append(block, &mut buf);

            buf
        }
    }

    pub mod decode {
        use super::*;
        #[allow(unused_imports)]
        use ssz::*;

        pub fn is_ssz_fixed_len() -> bool {
            false
        }

        pub fn ssz_fixed_len() -> usize {
            BYTES_PER_LENGTH_OFFSET
        }

        pub fn from_ssz_bytes<E: EthSpec>(
            bytes: &[u8],
        ) -> Result<SignedBeaconBlockFull<E>, DecodeError> {
            let fork_byte = bytes
                .first()
                .copied()
                .ok_or(DecodeError::OutOfBoundsByte { i: 0 })?;
            let body = bytes
                .get(1..)
                .ok_or(DecodeError::OutOfBoundsByte { i: 1 })?;

            match ForkName::from_ssz_bytes(&[fork_byte])? {
                ForkName::Base => Ok(SignedBeaconBlockFull::Base(
                    SignedBeaconBlockFullBase::from_ssz_bytes(body)?,
                )),
                ForkName::Altair => Ok(SignedBeaconBlockFull::Altair(
                    SignedBeaconBlockFullAltair::from_ssz_bytes(body)?,
                )),
                ForkName::Merge => Ok(SignedBeaconBlockFull::Merge(
                    SignedBeaconBlockFullMerge::from_ssz_bytes(body)?,
                )),
                ForkName::Capella => Ok(SignedBeaconBlockFull::Capella(
                    SignedBeaconBlockFullCapella::from_ssz_bytes(body)?,
                )),
                ForkName::Deneb => Ok(SignedBeaconBlockFull::Deneb(
                    SignedBeaconBlockFullDeneb::from_ssz_bytes(body)?,
                )),
            }
        }
    }
}

pub mod ssz_tagged_signed_beacon_block_arc {
    use super::*;
    pub mod encode {
        pub use super::ssz_tagged_signed_beacon_block::encode::*;
    }

    pub mod decode {
        pub use super::ssz_tagged_signed_beacon_block::decode::{is_ssz_fixed_len, ssz_fixed_len};
        use super::*;
        #[allow(unused_imports)]
        use ssz::*;
        use std::sync::Arc;

        pub fn from_ssz_bytes<E: EthSpec>(
            bytes: &[u8],
        ) -> Result<Arc<SignedBeaconBlockFull<E>>, DecodeError> {
            ssz_tagged_signed_beacon_block::decode::from_ssz_bytes(bytes).map(Arc::new)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn add_remove_payload_roundtrip() {
        type E = MainnetEthSpec;

        let spec = &E::default_spec();
        let sig = Signature::empty();
        let blocks = vec![
            SignedBeaconBlock::<E>::from_block(
                BeaconBlock::Base(BeaconBlockBase::empty(spec)),
                sig.clone(),
            ),
            SignedBeaconBlock::from_block(
                BeaconBlock::Altair(BeaconBlockAltair::empty(spec)),
                sig.clone(),
            ),
            SignedBeaconBlock::from_block(BeaconBlock::Merge(BeaconBlockMerge::empty(spec)), sig),
        ];

        for block in blocks {
            let (blinded_block, payload): (SignedBlindedBeaconBlock<E>, _) = block.clone().into();
            assert_eq!(blinded_block.tree_hash_root(), block.tree_hash_root());

            if let Some(payload) = &payload {
                assert_eq!(
                    payload.tree_hash_root(),
                    block
                        .message()
                        .execution_payload()
                        .unwrap()
                        .tree_hash_root()
                );
            }

            let reconstructed = blinded_block.try_into_full_block(payload).unwrap();
            assert_eq!(reconstructed, block);
        }
    }

    #[test]
    fn test_ssz_tagged_signed_beacon_block() {
        type E = MainnetEthSpec;

        let spec = &E::default_spec();
        let sig = Signature::empty();
        let blocks = vec![
            SignedBeaconBlock::<E>::from_block(
                BeaconBlock::Base(BeaconBlockBase::empty(spec)),
                sig.clone(),
            ),
            SignedBeaconBlock::from_block(
                BeaconBlock::Altair(BeaconBlockAltair::empty(spec)),
                sig.clone(),
            ),
            SignedBeaconBlock::from_block(
                BeaconBlock::Merge(BeaconBlockMerge::empty(spec)),
                sig.clone(),
            ),
            SignedBeaconBlock::from_block(
                BeaconBlock::Capella(BeaconBlockCapella::empty(spec)),
                sig.clone(),
            ),
            SignedBeaconBlock::from_block(BeaconBlock::Deneb(BeaconBlockDeneb::empty(spec)), sig),
        ];

        for block in blocks {
            let encoded = ssz_tagged_signed_beacon_block::encode::as_ssz_bytes(&block);
            let decoded = ssz_tagged_signed_beacon_block::decode::from_ssz_bytes::<E, _>(&encoded)
                .expect("should decode");
            assert_eq!(decoded, block);
        }
    }
}
