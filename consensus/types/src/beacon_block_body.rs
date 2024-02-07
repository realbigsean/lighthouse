use crate::test_utils::TestRandom;
use crate::*;
use derivative::Derivative;
use merkle_proof::{MerkleTree, MerkleTreeError};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use std::marker::PhantomData;
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash::{TreeHash, BYTES_PER_CHUNK};
use tree_hash_derive::TreeHash;

pub type KzgCommitments<T> =
    VariableList<KzgCommitment, <T as EthSpec>::MaxBlobCommitmentsPerBlock>;
pub type KzgCommitmentOpts<T> =
    FixedVector<Option<KzgCommitment>, <T as EthSpec>::MaxBlobsPerBlock>;

/// Index of the `blob_kzg_commitments` leaf in the `BeaconBlockBody` tree post-deneb.
pub const BLOB_KZG_COMMITMENTS_INDEX: usize = 11;

/// The body of a `BeaconChain` block, containing operations.
///
/// This *superstruct* abstracts over the hard-fork.
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
            TestRandom,
            Derivative,
            arbitrary::Arbitrary
        ),
        derivative(PartialEq, Hash(bound = "T: EthSpec")),
        serde(bound = "T: EthSpec", deny_unknown_fields),
        arbitrary(bound = "T: EthSpec"),
    ),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Debug, Clone, Serialize, Deserialize, Derivative, arbitrary::Arbitrary)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[serde(untagged)]
#[serde(bound = "T: EthSpec")]
#[arbitrary(bound = "T: EthSpec")]
pub struct BeaconBlockBody<T: EthSpec> {
    pub randao_reveal: Signature,
    pub eth1_data: Eth1Data,
    pub graffiti: Graffiti,
    pub proposer_slashings: VariableList<ProposerSlashing, T::MaxProposerSlashings>,
    pub attester_slashings: VariableList<AttesterSlashing<T>, T::MaxAttesterSlashings>,
    pub attestations: VariableList<Attestation<T>, T::MaxAttestations>,
    pub deposits: VariableList<Deposit, T::MaxDeposits>,
    pub voluntary_exits: VariableList<SignedVoluntaryExit, T::MaxVoluntaryExits>,
    #[superstruct(only(Altair, Merge, Capella, Deneb))]
    pub sync_aggregate: SyncAggregate<T>,
    #[superstruct(flatten(Merge, Capella, Deneb), meta_only(Full))]
    pub execution_payload: ExecutionPayload<T>,
    #[superstruct(flatten(Merge, Capella, Deneb), meta_only(Blinded))]
    pub execution_payload_header: ExecutionPayloadHeader<T>,
    #[superstruct(only(Capella, Deneb))]
    pub bls_to_execution_changes:
        VariableList<SignedBlsToExecutionChange, T::MaxBlsToExecutionChanges>,
    #[superstruct(only(Deneb))]
    pub blob_kzg_commitments: KzgCommitments<T>,
}

impl<T: EthSpec> BeaconBlockBody<T> {
    pub fn execution_payload(&self) -> Result<ExecutionPayloadRef<'_, T>, Error> {
        self.to_ref().execution_payload()
    }
}

impl<'a, T: EthSpec> BeaconBlockBodyRef<'a, T> {
    pub fn execution_payload(&self) -> Result<ExecutionPayloadRef<'a, T>, Error> {
        match self {
            Self::Blinded(body) => Err(Error::PayloadConversionLogicFlaw),
            Self::Full(body) => match body {
                BeaconBlockBodyFull::Base(_) | BeaconBlockBodyFull::Altair(_) => {
                    Err(Error::IncorrectStateVariant)
                }
                BeaconBlockBodyFull::Merge(body) => {
                    Ok(ExecutionPayloadRef::from(&body.execution_payload))
                }
                BeaconBlockBodyFull::Capella(body) => {
                    Ok(ExecutionPayloadRef::from(&body.execution_payload))
                }
                BeaconBlockBodyFull::Deneb(body) => {
                    Ok(ExecutionPayloadRef::from(&body.execution_payload))
                }
            },
        }
    }

    pub fn execution_payload_header(&self) -> Result<ExecutionPayloadHeaderRef<'a, T>, Error> {
        match self {
            Self::Blinded(body) => match body {
                BeaconBlockBodyBlinded::Base(_) | BeaconBlockBodyBlinded::Altair(_) => {
                    Err(Error::IncorrectStateVariant)
                }
                BeaconBlockBodyBlinded::Merge(body) => Ok(ExecutionPayloadHeaderRef::from(
                    &body.execution_payload_header,
                )),
                BeaconBlockBodyBlinded::Capella(body) => Ok(ExecutionPayloadHeaderRef::from(
                    &body.execution_payload_header,
                )),
                BeaconBlockBodyBlinded::Deneb(body) => Ok(ExecutionPayloadHeaderRef::from(
                    &body.execution_payload_header,
                )),
            },
            Self::Full(body) => Err(Error::PayloadConversionLogicFlaw),
        }
    }

    /// Produces the proof of inclusion for a `KzgCommitment` in `self.blob_kzg_commitments`
    /// at `index`.
    pub fn kzg_commitment_merkle_proof(
        &self,
        index: usize,
    ) -> Result<FixedVector<Hash256, T::KzgCommitmentInclusionProofDepth>, Error> {
        todo!()
        // match self {
        //     Self::Base(_) | Self::Altair(_) | Self::Merge(_) | Self::Capella(_) => {
        //         Err(Error::IncorrectStateVariant)
        //     }
        //     Self::Deneb(body) => {
        //         // We compute the branches by generating 2 merkle trees:
        //         // 1. Merkle tree for the `blob_kzg_commitments` List object
        //         // 2. Merkle tree for the `BeaconBlockBody` container
        //         // We then merge the branches for both the trees all the way up to the root.

        //         // Part1 (Branches for the subtree rooted at `blob_kzg_commitments`)
        //         //
        //         // Branches for `blob_kzg_commitments` without length mix-in
        //         let depth = T::max_blob_commitments_per_block()
        //             .next_power_of_two()
        //             .ilog2();
        //         let leaves: Vec<_> = body
        //             .blob_kzg_commitments
        //             .iter()
        //             .map(|commitment| commitment.tree_hash_root())
        //             .collect();
        //         let tree = MerkleTree::create(&leaves, depth as usize);
        //         let (_, mut proof) = tree
        //             .generate_proof(index, depth as usize)
        //             .map_err(Error::MerkleTreeError)?;

        //         // Add the branch corresponding to the length mix-in.
        //         let length = body.blob_kzg_commitments.len();
        //         let usize_len = std::mem::size_of::<usize>();
        //         let mut length_bytes = [0; BYTES_PER_CHUNK];
        //         length_bytes
        //             .get_mut(0..usize_len)
        //             .ok_or(Error::MerkleTreeError(MerkleTreeError::PleaseNotifyTheDevs))?
        //             .copy_from_slice(&length.to_le_bytes());
        //         let length_root = Hash256::from_slice(length_bytes.as_slice());
        //         proof.push(length_root);

        //         // Part 2
        //         // Branches for `BeaconBlockBody` container
        //         let leaves = [
        //             body.randao_reveal.tree_hash_root(),
        //             body.eth1_data.tree_hash_root(),
        //             body.graffiti.tree_hash_root(),
        //             body.proposer_slashings.tree_hash_root(),
        //             body.attester_slashings.tree_hash_root(),
        //             body.attestations.tree_hash_root(),
        //             body.deposits.tree_hash_root(),
        //             body.voluntary_exits.tree_hash_root(),
        //             body.sync_aggregate.tree_hash_root(),
        //             body.execution_payload.tree_hash_root(),
        //             body.bls_to_execution_changes.tree_hash_root(),
        //             body.blob_kzg_commitments.tree_hash_root(),
        //         ];
        //         let beacon_block_body_depth = leaves.len().next_power_of_two().ilog2() as usize;
        //         let tree = MerkleTree::create(&leaves, beacon_block_body_depth);
        //         let (_, mut proof_body) = tree
        //             .generate_proof(BLOB_KZG_COMMITMENTS_INDEX, beacon_block_body_depth)
        //             .map_err(Error::MerkleTreeError)?;
        //         // Join the proofs for the subtree and the main tree
        //         proof.append(&mut proof_body);

        //         debug_assert_eq!(proof.len(), T::kzg_proof_inclusion_proof_depth());
        //         Ok(proof.into())
        //     }
        //}
    }
}

impl<'a, T: EthSpec> BeaconBlockBodyRef<'a, T> {
    /// Get the fork_name of this object
    pub fn fork_name(self) -> ForkName {
        match self {
            BeaconBlockBodyRef::Blinded(BeaconBlockBodyBlinded::Base(_)) => ForkName::Base,
            BeaconBlockBodyRef::Blinded(BeaconBlockBodyBlinded::Altair(_)) => ForkName::Altair,
            BeaconBlockBodyRef::Blinded(BeaconBlockBodyBlinded::Merge(_)) => ForkName::Merge,
            BeaconBlockBodyRef::Blinded(BeaconBlockBodyBlinded::Capella(_)) => ForkName::Capella,
            BeaconBlockBodyRef::Blinded(BeaconBlockBodyBlinded::Deneb(_)) => ForkName::Deneb,
            BeaconBlockBodyRef::Full(BeaconBlockBodyFull::Base(_)) => ForkName::Base,
            BeaconBlockBodyRef::Full(BeaconBlockBodyFull::Altair(_)) => ForkName::Altair,
            BeaconBlockBodyRef::Full(BeaconBlockBodyFull::Merge(_)) => ForkName::Merge,
            BeaconBlockBodyRef::Full(BeaconBlockBodyFull::Capella(_)) => ForkName::Capella,
            BeaconBlockBodyRef::Full(BeaconBlockBodyFull::Deneb(_)) => ForkName::Deneb,
        }
    }
}

// We can convert pre-Bellatrix block bodies without payloads into block bodies "with" payloads.
impl<E: EthSpec> From<BeaconBlockBodyBlindedBase<E>> for BeaconBlockBodyFullBase<E> {
    fn from(body: BeaconBlockBodyBlindedBase<E>) -> Self {
        let BeaconBlockBodyBlindedBase {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
        } = body;

        BeaconBlockBodyFullBase {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
        }
    }
}

impl<E: EthSpec> From<BeaconBlockBodyBlindedAltair<E>> for BeaconBlockBodyFullAltair<E> {
    fn from(body: BeaconBlockBodyBlindedAltair<E>) -> Self {
        let BeaconBlockBodyBlindedAltair {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
        } = body;

        BeaconBlockBodyFullAltair {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
        }
    }
}

// Likewise bodies with payloads can be transformed into bodies without.
impl<E: EthSpec> From<BeaconBlockBodyFullBase<E>>
    for (BeaconBlockBodyBlindedBase<E>, Option<ExecutionPayload<E>>)
{
    fn from(body: BeaconBlockBodyFullBase<E>) -> Self {
        let BeaconBlockBodyFullBase {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
        } = body;

        (
            BeaconBlockBodyBlindedBase {
                randao_reveal,
                eth1_data,
                graffiti,
                proposer_slashings,
                attester_slashings,
                attestations,
                deposits,
                voluntary_exits,
            },
            None,
        )
    }
}

impl<E: EthSpec> From<BeaconBlockBodyFullAltair<E>>
    for (BeaconBlockBodyBlindedAltair<E>, Option<ExecutionPayload<E>>)
{
    fn from(body: BeaconBlockBodyFullAltair<E>) -> Self {
        let BeaconBlockBodyFullAltair {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
        } = body;

        (
            BeaconBlockBodyBlindedAltair {
                randao_reveal,
                eth1_data,
                graffiti,
                proposer_slashings,
                attester_slashings,
                attestations,
                deposits,
                voluntary_exits,
                sync_aggregate,
            },
            None,
        )
    }
}

impl<E: EthSpec> From<BeaconBlockBodyFullMerge<E>>
    for (
        BeaconBlockBodyBlindedMerge<E>,
        Option<ExecutionPayloadMerge<E>>,
    )
{
    fn from(body: BeaconBlockBodyFullMerge<E>) -> Self {
        let BeaconBlockBodyFullMerge {
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
        } = body;

        (
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
                execution_payload_header: From::from(&execution_payload),
            },
            Some(execution_payload),
        )
    }
}

impl<E: EthSpec> From<BeaconBlockBodyFullCapella<E>>
    for (
        BeaconBlockBodyBlindedCapella<E>,
        Option<ExecutionPayloadCapella<E>>,
    )
{
    fn from(body: BeaconBlockBodyFullCapella<E>) -> Self {
        let BeaconBlockBodyFullCapella {
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
        } = body;

        (
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
                execution_payload_header: From::from(&execution_payload),
                bls_to_execution_changes,
            },
            Some(execution_payload),
        )
    }
}

impl<E: EthSpec> From<BeaconBlockBodyFullDeneb<E>>
    for (
        BeaconBlockBodyBlindedDeneb<E>,
        Option<ExecutionPayloadDeneb<E>>,
    )
{
    fn from(body: BeaconBlockBodyFullDeneb<E>) -> Self {
        let BeaconBlockBodyFullDeneb {
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
        } = body;

        (
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
                execution_payload_header: From::from(&execution_payload),
                bls_to_execution_changes,
                blob_kzg_commitments,
            },
            Some(execution_payload),
        )
    }
}

// We can clone a full block into a blinded block, without cloning the payload.
impl<E: EthSpec> BeaconBlockBodyFullBase<E> {
    pub fn clone_as_blinded(&self) -> BeaconBlockBodyBlindedBase<E> {
        let (block_body, _payload) = self.clone().into();
        block_body
    }
}

impl<E: EthSpec> BeaconBlockBodyFullAltair<E> {
    pub fn clone_as_blinded(&self) -> BeaconBlockBodyBlindedAltair<E> {
        let (block_body, _payload) = self.clone().into();
        block_body
    }
}

impl<E: EthSpec> BeaconBlockBodyFullMerge<E> {
    pub fn clone_as_blinded(&self) -> BeaconBlockBodyBlindedMerge<E> {
        let BeaconBlockBodyFullMerge {
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
        } = self;

        BeaconBlockBodyBlindedMerge {
            randao_reveal: randao_reveal.clone(),
            eth1_data: eth1_data.clone(),
            graffiti: *graffiti,
            proposer_slashings: proposer_slashings.clone(),
            attester_slashings: attester_slashings.clone(),
            attestations: attestations.clone(),
            deposits: deposits.clone(),
            voluntary_exits: voluntary_exits.clone(),
            sync_aggregate: sync_aggregate.clone(),
            execution_payload_header: execution_payload.into(),
        }
    }
}

impl<E: EthSpec> BeaconBlockBodyFullCapella<E> {
    pub fn clone_as_blinded(&self) -> BeaconBlockBodyBlindedCapella<E> {
        let BeaconBlockBodyFullCapella {
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
        } = self;

        BeaconBlockBodyBlindedCapella {
            randao_reveal: randao_reveal.clone(),
            eth1_data: eth1_data.clone(),
            graffiti: *graffiti,
            proposer_slashings: proposer_slashings.clone(),
            attester_slashings: attester_slashings.clone(),
            attestations: attestations.clone(),
            deposits: deposits.clone(),
            voluntary_exits: voluntary_exits.clone(),
            sync_aggregate: sync_aggregate.clone(),
            execution_payload_header: execution_payload.into(),
            bls_to_execution_changes: bls_to_execution_changes.clone(),
        }
    }
}

impl<E: EthSpec> BeaconBlockBodyFullDeneb<E> {
    pub fn clone_as_blinded(&self) -> BeaconBlockBodyBlindedDeneb<E> {
        let BeaconBlockBodyFullDeneb {
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
        } = self;

        BeaconBlockBodyBlindedDeneb {
            randao_reveal: randao_reveal.clone(),
            eth1_data: eth1_data.clone(),
            graffiti: *graffiti,
            proposer_slashings: proposer_slashings.clone(),
            attester_slashings: attester_slashings.clone(),
            attestations: attestations.clone(),
            deposits: deposits.clone(),
            voluntary_exits: voluntary_exits.clone(),
            sync_aggregate: sync_aggregate.clone(),
            execution_payload_header: execution_payload.into(),
            bls_to_execution_changes: bls_to_execution_changes.clone(),
            blob_kzg_commitments: blob_kzg_commitments.clone(),
        }
    }
}

impl<E: EthSpec> From<BeaconBlockBodyFull<E>>
    for (BeaconBlockBodyBlinded<E>, Option<ExecutionPayload<E>>)
{
    fn from(body: BeaconBlockBodyFull<E>) -> Self {
        map_beacon_block_body_full!(body, |inner, cons| {
            let (block, payload) = inner.into();
            (cons(block), payload.map(Into::into))
        })
    }
}

/// Util method helpful for logging.
pub fn format_kzg_commitments(commitments: &[KzgCommitment]) -> String {
    let commitment_strings: Vec<String> = commitments.iter().map(|x| x.to_string()).collect();
    let commitments_joined = commitment_strings.join(", ");
    let surrounded_commitments = format!("[{}]", commitments_joined);
    surrounded_commitments
}

#[cfg(test)]
mod tests {
    mod base {
        use super::super::*;
        ssz_and_tree_hash_tests!(BeaconBlockBodyBase<MainnetEthSpec>);
    }
    mod altair {
        use super::super::*;
        ssz_and_tree_hash_tests!(BeaconBlockBodyAltair<MainnetEthSpec>);
    }
}
