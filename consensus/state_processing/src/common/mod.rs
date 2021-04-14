mod deposit_data_tree;
mod get_attestation_participation;
mod get_attesting_indices;
mod get_indexed_attestation;
mod initiate_validator_exit;
mod slash_validator;

pub mod altair;
pub mod base;

pub use deposit_data_tree::DepositDataTree;
pub use get_attestation_participation::get_attestation_participation;
pub use get_attesting_indices::get_attesting_indices;
pub use get_indexed_attestation::get_indexed_attestation;
pub use initiate_validator_exit::initiate_validator_exit;
pub use slash_validator::slash_validator;

use safe_arith::{ArithError, SafeArith};
use types::{BeaconState, EthSpec};

/// Increase the balance of a validator, erroring upon overflow, as per the spec.
pub fn increase_balance<E: EthSpec>(
    state: &mut BeaconState<E>,
    index: usize,
    delta: u64,
) -> Result<(), ArithError> {
    state.balances_mut()[index].safe_add_assign(delta)
}

/// Decrease the balance of a validator, saturating upon overflow, as per the spec.
pub fn decrease_balance<E: EthSpec>(state: &mut BeaconState<E>, index: usize, delta: u64) {
    state.balances_mut()[index] = state.balances()[index].saturating_sub(delta);
}
