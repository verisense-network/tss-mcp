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
#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{Digest, Keccak256};
    use sp_core::crypto::AccountId32;
    use sp_core::crypto::KeyTypeId;
    use sp_core::crypto::Pair as CryptoPair;
    use sp_core::sr25519::{Pair, Public, Signature};
    use sp_keystore::KeystorePtr;
    use std::path::Path;
    use tss_sdk::crypto::ValidatorIdentityKeypair;
    #[tokio::test]
    async fn test_node_runtime() {
        let node = Node::<crate::VrsTssValidatorIdentity>::new(
            crate::TssKeystore::random_generate_keypair(),
            PathBuf::from(".test_node"),
            "/ip4/34.71.144.40/tcp/12944".parse().unwrap(),
            "12D3KooWFcGs16mdf3HuNd2KMx5WYNsDyyDVz9h6Udg6WWg3CCxh"
                .parse()
                .unwrap(),
        )
        .unwrap();
        let node = Arc::new(node);
        let public_key = get_public_key(
            node.clone(),
            CryptoType::EcdsaSecp256k1,
            b"test".to_vec(),
            Some(Duration::from_secs(10)),
        )
        .await
        .unwrap();
        println!("public_key: {:?}", public_key);
        let signature = sign(
            node.clone(),
            CryptoType::EcdsaSecp256k1,
            b"test".to_vec(),
            b"test".to_vec(),
            Some(Duration::from_secs(10)),
        )
        .await
        .unwrap();
        println!("signature: {:?}", signature);
    }
}
