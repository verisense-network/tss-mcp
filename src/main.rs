mod testing;
pub use tss_sdk::*;
mod identity;
mod mock;
pub use identity::*;
use std::path::PathBuf;

use hex::ToHex;
use std::sync::{Arc, Mutex};
use tokio::time::Duration;
use tss_sdk::crypto::CryptoType;
use tss_sdk::node::Node;
pub async fn get_public_key(
    tss_node: Arc<Node<crate::VrsTssValidatorIdentity>>,
    crypto_type: CryptoType,
    tweak_data: Vec<u8>,
    timeout: Option<Duration>,
) -> Result<String, String> {
    let auto_dkg = tss_node
        .auto_dkg_async(timeout)
        .await
        .map_err(|e| e.to_string())?;
    let pkid = auto_dkg
        .get_pkid_by_crypto_type(crypto_type)
        .map_err(|e| e.to_string())?;
    let public_key = tss_node
        .pk_async(pkid, Some(tweak_data), timeout)
        .await
        .map_err(|e| e.to_string())?;
    if crypto_type == CryptoType::EcdsaSecp256k1 {
        Ok(public_key
            .compressed_pk_k256()
            .map_err(|e| e.to_string())?
            .encode_hex::<String>())
    } else {
        Ok(public_key.group_public_key_tweak.encode_hex::<String>())
    }
}
pub async fn sign(
    tss_node: Arc<Node<crate::VrsTssValidatorIdentity>>,
    crypto_type: CryptoType,
    message: Vec<u8>,
    tweak_data: Vec<u8>,
    timeout: Option<Duration>,
) -> Result<String, String> {
    let auto_dkg = tss_node
        .auto_dkg_async(timeout)
        .await
        .map_err(|e| e.to_string())?;
    let pkid = auto_dkg
        .get_pkid_by_crypto_type(crypto_type)
        .map_err(|e| e.to_string())?;
    let signature = tss_node
        .sign_async(pkid, message, Some(tweak_data), timeout)
        .await
        .map_err(|e| e.to_string())?;
    if crypto_type == CryptoType::EcdsaSecp256k1 {
        Ok(signature
            .signature_with_rsv()
            .map_err(|e| e.to_string())?
            .encode_hex::<String>())
    } else {
        Ok(signature.signature().encode_hex::<String>())
    }
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use sha3::{Digest, Keccak256};
    use tss_sdk::crypto::ValidatorIdentityKeypair;
    
    let node = Node::<crate::VrsTssValidatorIdentity>::new(
        crate::TssKeystore::random_generate_keypair(),
        PathBuf::from(".test_node"),
        "/ip4/34.71.144.40/tcp/12944".parse().unwrap(),
        "12D3KooWFcGs16mdf3HuNd2KMx5WYNsDyyDVz9h6Udg6WWg3CCxh"
            .parse()
            .unwrap(),
    )?;
    let node = Arc::new(node);
    
    println!("Getting public key...");
    let public_key = get_public_key(
        node.clone(),
        CryptoType::EcdsaSecp256k1,
        b"test".to_vec(),
        Some(Duration::from_secs(10)),
    )
    .await?;
    println!("Public key: {:?}", public_key);
    
    println!("Signing message...");
    let signature = sign(
        node.clone(),
        CryptoType::EcdsaSecp256k1,
        Keccak256::digest(b"test").to_vec(),
        b"test".to_vec(),
        Some(Duration::from_secs(10)),
    )
    .await?;
    println!("Signature: {:?}", signature);
    
    Ok(())
}
