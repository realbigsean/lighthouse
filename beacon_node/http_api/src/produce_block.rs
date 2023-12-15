use bytes::Bytes;
use std::sync::Arc;
use types::{payload::BlockProductionVersion, *};

use beacon_chain::{BeaconBlockResponse, BeaconChain, BeaconChainTypes, ProduceBlockVerification};
use eth2::types::{self as api_types, EndpointVersion, SkipRandaoVerification};
use ssz::Encode;
use warp::{
    hyper::{Body, Response},
    Reply,
};

use crate::version::{
    add_consensus_block_value_header, add_consensus_version_header,
    add_execution_payload_blinded_header, add_execution_payload_value_header,
    fork_versioned_response, inconsistent_fork_rejection,
};

pub fn get_randao_verification(
    query: &api_types::ValidatorBlocksQuery,
    randao_reveal_infinity: bool,
) -> Result<ProduceBlockVerification, warp::Rejection> {
    let randao_verification = if query.skip_randao_verification == SkipRandaoVerification::Yes {
        if !randao_reveal_infinity {
            return Err(warp_utils::reject::custom_bad_request(
                "randao_reveal must be point-at-infinity if verification is skipped".into(),
            ));
        }
        ProduceBlockVerification::NoVerification
    } else {
        ProduceBlockVerification::VerifyRandao
    };

    Ok(randao_verification)
}

pub async fn produce_block_v3<T: BeaconChainTypes>(
    endpoint_version: EndpointVersion,
    accept_header: Option<api_types::Accept>,
    chain: Arc<BeaconChain<T>>,
    slot: Slot,
    query: api_types::ValidatorBlocksQuery,
) -> Result<Response<Body>, warp::Rejection> {
    let randao_reveal = query.randao_reveal.decompress().map_err(|e| {
        warp_utils::reject::custom_bad_request(format!(
            "randao reveal is not a valid BLS signature: {:?}",
            e
        ))
    })?;

    let randao_verification = get_randao_verification(&query, randao_reveal.is_infinity())?;

    let block_response_type = chain
        .produce_block_with_verification(
            randao_reveal,
            slot,
            query.graffiti.map(Into::into),
            randao_verification,
            BlockProductionVersion::V3,
        )
        .await
        .map_err(|e| {
            warp_utils::reject::custom_bad_request(format!("failed to fetch a block: {:?}", e))
        })?;

    build_response_v3(chain, block_response_type, endpoint_version, accept_header)
}

pub fn build_response_v3<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block_response: BeaconBlockResponse<T::EthSpec>,
    endpoint_version: EndpointVersion,
    accept_header: Option<api_types::Accept>,
) -> Result<Response<Body>, warp::Rejection> {
    let BeaconBlockResponse {
        block,
        state,
        execution_payload_value,
        consensus_block_value,
    } = block_response;

    let execution_payload_blinded = true;

    let fork_name = ForkName::Base;

    match accept_header {
        Some(api_types::Accept::Ssz) => Response::builder()
            .status(200)
            .header("Content-Type", "application/ssz")
            .body(block.as_ssz_bytes().into())
            .map(|res: Response<Body>| add_consensus_version_header(res, fork_name))
            .map(|res| add_execution_payload_blinded_header(res, execution_payload_blinded))
            .map(|res: Response<Body>| {
                add_execution_payload_value_header(res, execution_payload_value)
            })
            .map(|res| add_consensus_block_value_header(res, consensus_block_value))
            .map_err(|e| -> warp::Rejection {
                warp_utils::reject::custom_server_error(format!("failed to create response: {}", e))
            }),
        _ => fork_versioned_response(endpoint_version, fork_name, block)
            .map(|response| warp::reply::json(&response).into_response())
            .map(|res| add_consensus_version_header(res, fork_name))
            .map(|res| add_execution_payload_blinded_header(res, execution_payload_blinded))
            .map(|res| add_execution_payload_value_header(res, execution_payload_value))
            .map(|res| add_consensus_block_value_header(res, consensus_block_value)),
    }
}

pub async fn produce_blinded_block_v2<T: BeaconChainTypes>(
    endpoint_version: EndpointVersion,
    accept_header: Option<api_types::Accept>,
    chain: Arc<BeaconChain<T>>,
    slot: Slot,
    query: api_types::ValidatorBlocksQuery,
) -> Result<Response<Body>, warp::Rejection> {
    let randao_reveal = query.randao_reveal.decompress().map_err(|e| {
        warp_utils::reject::custom_bad_request(format!(
            "randao reveal is not a valid BLS signature: {:?}",
            e
        ))
    })?;

    let randao_verification = get_randao_verification(&query, randao_reveal.is_infinity())?;
    let block_response_type = chain
        .produce_block_with_verification(
            randao_reveal,
            slot,
            query.graffiti.map(Into::into),
            randao_verification,
            BlockProductionVersion::BlindedV2,
        )
        .await
        .map_err(warp_utils::reject::block_production_error)?;

    build_response_v2(chain, block_response_type, endpoint_version, accept_header)
}

pub async fn produce_block_v2<T: BeaconChainTypes>(
    endpoint_version: EndpointVersion,
    accept_header: Option<api_types::Accept>,
    chain: Arc<BeaconChain<T>>,
    slot: Slot,
    query: api_types::ValidatorBlocksQuery,
) -> Result<Response<Body>, warp::Rejection> {
    let randao_reveal = query.randao_reveal.decompress().map_err(|e| {
        warp_utils::reject::custom_bad_request(format!(
            "randao reveal is not a valid BLS signature: {:?}",
            e
        ))
    })?;

    let randao_verification = get_randao_verification(&query, randao_reveal.is_infinity())?;

    let block_response_type = chain
        .produce_block_with_verification(
            randao_reveal,
            slot,
            query.graffiti.map(Into::into),
            randao_verification,
            BlockProductionVersion::FullV2,
        )
        .await
        .map_err(warp_utils::reject::block_production_error)?;

    build_response_v2(chain, block_response_type, endpoint_version, accept_header)
}

pub fn build_response_v2<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block_response: BeaconBlockResponse<T::EthSpec>,
    endpoint_version: EndpointVersion,
    accept_header: Option<api_types::Accept>,
) -> Result<Response<Body>, warp::Rejection> {
    let BeaconBlockResponse {
        block,
        state,
        execution_payload_value,
        consensus_block_value,
    } = block_response;

    let execution_payload_blinded = true;

    let fork_name = ForkName::Base;

    match accept_header {
        Some(api_types::Accept::Ssz) => Response::builder()
            .status(200)
            .header("Content-Type", "application/octet-stream")
            .body(block.as_ssz_bytes().into())
            .map(|res: Response<Bytes>| add_consensus_version_header(res, fork_name))
            .map_err(|e| {
                warp_utils::reject::custom_server_error(format!("failed to create response: {}", e))
            }),
        _ => fork_versioned_response(endpoint_version, fork_name, block)
            .map(|response| warp::reply::json(&response).into_response())
            .map(|res| add_consensus_version_header(res, fork_name)),
    }
}
