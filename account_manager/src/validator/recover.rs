use crate::common::{read_mnemonic_from_cli, MNEMONIC_FLAG, STDIN_PASSWORD_FLAG};
use crate::validator::create::COUNT_FLAG;
use crate::wallet::create::HD_TYPE;
use crate::{SECRETS_DIR_FLAG, VALIDATOR_DIR_FLAG};
use account_utils::eth2_keystore::{keypair_from_secret, Keystore, KeystoreBuilder};
use account_utils::random_password;
use clap::{App, Arg, ArgMatches};
use eth2_wallet::bip39::Seed;
use eth2_wallet::{recover_validator_secret_from_mnemonic, KeyType, ValidatorKeystores};
use std::path::PathBuf;
use validator_dir::Builder as ValidatorDirBuilder;
pub const CMD: &str = "recover";
pub const FIRST_INDEX_FLAG: &str = "first-index";
pub const TYPE_FLAG: &str = "type";
pub const STORE_WITHDRAW_FLAG: &str = "store-withdrawal-keystore";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about(
            "Recovers validator private keys given a 12-word BIP-39 mnemonic phrase.",
        )
        .arg(
            Arg::with_name(FIRST_INDEX_FLAG)
                .long(FIRST_INDEX_FLAG)
                .value_name("FIRST_INDEX")
                .help("The first of consecutive key indexes you wish to recover. Defaults to 0.")
                .takes_value(true)
                .required(false)
                .default_value("0"),
        )
        .arg(
            Arg::with_name(COUNT_FLAG)
                .long(COUNT_FLAG)
                .value_name("COUNT")
                .help("The number of validator keys you wish to recover. Counted consecutively from the provided `--first_index`. Defaults to 1.")
                .takes_value(true)
                .required(false)
                .default_value("1"),
        )
        .arg(
            Arg::with_name(MNEMONIC_FLAG)
                .long(MNEMONIC_FLAG)
                .value_name("MNEMONIC_PATH")
                .help(
                    "If present, the mnemonic will be read in from this file.",
                )
                .takes_value(true)
        )
        .arg(
            Arg::with_name(VALIDATOR_DIR_FLAG)
                .long(VALIDATOR_DIR_FLAG)
                .value_name("VALIDATOR_DIRECTORY")
                .help(
                    "The path where the validator directories will be created. \
                    Defaults to ~/.lighthouse/validators",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name(SECRETS_DIR_FLAG)
                .long(SECRETS_DIR_FLAG)
                .value_name("SECRETS_DIR")
                .help(
                    "The path where the validator keystore passwords will be stored. \
                    Defaults to ~/.lighthouse/secrets",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name(TYPE_FLAG)
                .long(TYPE_FLAG)
                .value_name("WALLET_TYPE")
                .help(
                    "The type of wallet to create. Only HD (hierarchical-deterministic) \
                            wallets are supported presently..",
                )
                .takes_value(true)
                .possible_values(&[HD_TYPE])
                .default_value(HD_TYPE),
        )
        .arg(
            Arg::with_name(STORE_WITHDRAW_FLAG)
                .long(STORE_WITHDRAW_FLAG)
                .help(
                    "If present, the withdrawal keystore will be stored alongside the voting \
                    keypair. It is generally recommended to *not* store the withdrawal key and \
                    instead generate them from the wallet seed when required.",
                ),
        )
        .arg(
            Arg::with_name(STDIN_PASSWORD_FLAG)
                .long(STDIN_PASSWORD_FLAG)
                .help("If present, read passwords from stdin instead of tty."),
        )
}

pub fn cli_run(matches: &ArgMatches) -> Result<(), String> {
    let validator_dir = clap_utils::parse_path_with_default_in_home_dir(
        matches,
        VALIDATOR_DIR_FLAG,
        PathBuf::new().join(".lighthouse").join("validators"),
    )?;
    let secrets_dir = clap_utils::parse_path_with_default_in_home_dir(
        matches,
        SECRETS_DIR_FLAG,
        PathBuf::new().join(".lighthouse").join("secrets"),
    )?;
    let first_index: u32 = clap_utils::parse_required(matches, FIRST_INDEX_FLAG)?;
    let count: u32 = clap_utils::parse_required(matches, COUNT_FLAG)?;

    let mnemonic = read_mnemonic_from_cli(matches)?;

    let seed = Seed::new(&mnemonic, "");

    for index in first_index..first_index + count {
        let voting_password = random_password();
        let withdrawal_password = random_password();

        let derive = |key_type: KeyType, password: &[u8]| -> Result<Keystore, String> {
            let (secret, path) =
                recover_validator_secret_from_mnemonic(seed.as_bytes(), index, key_type)
                    .map_err(|e| format!("Unable to recover validator keys: {:?}", e))?;

            let keypair = keypair_from_secret(secret.as_bytes())
                .map_err(|e| format!("Unable build keystore: {:?}", e))?;

            KeystoreBuilder::new(&keypair, password, format!("{}", path))
                .map_err(|e| format!("Unable build keystore: {:?}", e))?
                .build()
                .map_err(|e| format!("Unable build keystore: {:?}", e))
        };

        let keystores = ValidatorKeystores {
            voting: derive(KeyType::Voting, voting_password.as_bytes())?,
            withdrawal: derive(KeyType::Withdrawal, withdrawal_password.as_bytes())?,
        };

        let voting_pubkey = keystores.voting.pubkey().to_string();

        ValidatorDirBuilder::new(validator_dir.clone(), secrets_dir.clone())
            .voting_keystore(keystores.voting, voting_password.as_bytes())
            .withdrawal_keystore(keystores.withdrawal, withdrawal_password.as_bytes())
            .store_withdrawal_keystore(matches.is_present(STORE_WITHDRAW_FLAG))
            .build()
            .map_err(|e| format!("Unable to build validator directory: {:?}", e))?;

        println!("{}/{}\t0x{}", index + 1, count, voting_pubkey);
    }

    Ok(())
}
