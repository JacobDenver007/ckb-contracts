use super::*;

use ckb_testtool::{builtin::ALWAYS_SUCCESS, context::Context};
use ckb_tool::ckb_crypto::secp::{Privkey, Signature as CkbSignature};
use ckb_tool::ckb_types::H256;
use ckb_tool::ckb_types::{
    bytes::Buf,
    bytes::Bytes,
    core::{Capacity, TransactionBuilder, TransactionView},
    packed::*,
    prelude::*,
};
use ckb_tool::{ckb_error::assert_error_eq, ckb_hash, ckb_script::ScriptError};
use secp256k1::{PublicKey, SecretKey};

const MAX_CYCLES: u64 = 10000_0000;

// errors
const ERROR_AMOUNT: i8 = 5;

fn build_test_context() -> (Context, TransactionView) {
    // deploy cross typescript
    let mut context = Context::default();
    let secp256k1_bin: Bytes = Loader::default().load_binary("sign");
    let secp256k1_bin_out_point = context.deploy_contract(secp256k1_bin);
    // deploy always_success script
    let always_success_out_point = context.deploy_contract(ALWAYS_SUCCESS.clone());

    // build lock script
    let lock_script = context
        .build_script(&always_success_out_point, Default::default())
        .expect("script");
    let lock_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point)
        .build();

    // build cross typescript
    // let cross_typescript_args: Bytes = inputs[0].previous_output().as_bytes();
    let secp256k1_typescript_args = {
        let privkey_bytes =
            hex::decode("d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2b0")
                .unwrap();
        let secret_key = SecretKey::parse_slice(privkey_bytes.as_slice()).unwrap();
        let secp_pubkey = PublicKey::from_secret_key(&secret_key);

        let mut blake2b = ckb_hash::new_blake2b();
        let mut pubkey_hash = [0u8; 32];
        blake2b.update(secp_pubkey.serialize_compressed().to_vec().as_slice());
        blake2b.finalize(&mut pubkey_hash);
        Bytes::from(pubkey_hash.to_vec())
    };
    let secp256k1_typescript = context
        .build_script(&secp256k1_bin_out_point, secp256k1_typescript_args)
        .expect("script");
    let secp256k1_type_script_dep = CellDep::new_builder()
        .out_point(secp256k1_bin_out_point)
        .build();

    let input_ckb = Capacity::bytes(1000).unwrap().as_u64();
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(input_ckb.pack())
            .lock(lock_script.clone())
            .type_(Some(secp256k1_typescript.clone()).pack())
            .build(),
        Bytes::from("test"),
    );

    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let inputs = vec![input];

    // prepare outputs
    let output_ckb = input_ckb;
    let output = CellOutput::new_builder()
        .capacity(output_ckb.pack())
        .lock(lock_script.clone())
        .type_(Some(secp256k1_typescript.clone()).pack())
        .build();

    let outputs = vec![output];

    let privkey_bytes =
        hex::decode("d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2b0").unwrap();
    let privkey = Privkey::from_slice(privkey_bytes.as_slice());

    let raw_msg = Bytes::from("test");

    let signature = sign_msg(raw_msg.bytes(), &privkey);
    // prepare witness for WitnessArgs.InputType
    let cc_witness: Vec<u8> = signature.serialize();
    let witness = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(cc_witness)).pack())
        .build();

    let outputs_data = vec![Bytes::new(); 1];
    // build transaction
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .witness(witness.as_bytes().pack())
        .cell_dep(lock_script_dep)
        .cell_dep(secp256k1_type_script_dep)
        .build();
    (context, tx)
}

pub fn sign_msg(raw_msg: &[u8], privkey: &Privkey) -> CkbSignature {
    let mut blake2b = ckb_hash::new_blake2b();
    let mut message = [0u8; 32];
    blake2b.update(raw_msg);
    blake2b.finalize(&mut message);
    let message = H256::from(message);
    privkey.sign_recoverable(&message).expect("sign")
}

#[test]
fn test_verify() {
    let (mut context, tx) = build_test_context();
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");

    dbg!("tx", &cycles);
}
