mod testing;
pub use tss_sdk::*;
mod identity;
mod mock;
pub use identity::*;
use std::path::PathBuf;

use hex::ToHex;
use rmcp::{
    Json, ServiceExt,
    handler::server::{router::tool::ToolRouter, tool::Parameters, wrapper},
    tool, tool_handler, tool_router,
    transport::stdio,
};
use std::sync::Arc;
use tokio::time::Duration;
use tss_sdk::crypto::CryptoType;
use tss_sdk::node::Node;

use serde_json::{Value, json};
use sha3::{Digest, Keccak256};
use tokio::sync::RwLock;
use tss_sdk::crypto::ValidatorIdentityKeypair;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct GetPublicKeyRequest {
    #[schemars(description = "Crypto type")]
    pub crypto_type: CryptoTypeEnum,
    #[schemars(description = "Tweak data for key derivation")]
    pub tweak_hex: String,
    #[schemars(description = "Timeout in seconds")]
    pub timeout_secs: Option<u64>,
}
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct GetPublicKeyResponse {
    pub public_key_hex: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub enum CryptoTypeEnum {
    #[schemars(description = "P256")]
    P256,
    #[schemars(description = "Ed25519")]
    Ed25519,
    #[schemars(description = "Secp256k1")]
    Secp256k1,
    #[schemars(description = "Secp256k1Taproot")]
    Secp256k1Tr,
    #[schemars(description = "Ed448")]
    Ed448,
    #[schemars(description = "Ristretto255")]
    Ristretto255,
    #[schemars(description = "EcdsaSecp256k1")]
    EcdsaSecp256k1,
}
impl From<CryptoTypeEnum> for CryptoType {
    fn from(value: CryptoTypeEnum) -> Self {
        match value {
            CryptoTypeEnum::P256 => CryptoType::P256,
            CryptoTypeEnum::Ed25519 => CryptoType::Ed25519,
            CryptoTypeEnum::Secp256k1 => CryptoType::Secp256k1,
            CryptoTypeEnum::Secp256k1Tr => CryptoType::Secp256k1Tr,
            CryptoTypeEnum::Ed448 => CryptoType::Ed448,
            CryptoTypeEnum::Ristretto255 => CryptoType::Ristretto255,
            CryptoTypeEnum::EcdsaSecp256k1 => CryptoType::EcdsaSecp256k1,
        }
    }
}
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SignRequest {
    #[schemars(description = "Crypto type")]
    pub crypto_type: CryptoTypeEnum,
    #[schemars(description = "Message to sign")]
    pub message: String,
    #[schemars(description = "Tweak data for key derivation")]
    pub tweak_data: String,
    #[schemars(description = "Timeout in seconds")]
    pub timeout_secs: Option<u64>,
}
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SignResponse {
    #[schemars(description = "Hash of the message")]
    pub message_hash_hex: String,
    #[schemars(description = "Signature")]
    pub signature_hex: String,
}
#[derive(Clone)]
pub struct TssServer {
    node: Arc<Node<crate::VrsTssValidatorIdentity>>,
    tool_router: ToolRouter<TssServer>,
}

#[tool_handler(router = self.tool_router)]
impl rmcp::ServerHandler for TssServer {}
impl Default for TssServer {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

#[tool_router(router = tool_router)]
impl TssServer {
    pub fn new() -> Result<Self, String> {
        let node = Node::<VrsTssValidatorIdentity>::new(
            TssKeystore::random_generate_keypair(),
            PathBuf::from(".tss_node"),
            "/ip4/34.71.144.40/tcp/12944".parse().unwrap(),
            "12D3KooWFcGs16mdf3HuNd2KMx5WYNsDyyDVz9h6Udg6WWg3CCxh"
                .parse()
                .unwrap(),
        )
        .map_err(|e| e.to_string())?;
        Ok(Self {
            node: Arc::new(node),
            tool_router: Self::tool_router(),
        })
    }
    #[tool(
        name = "get_public_key",
        description = "Get a threshold signature scheme public key"
    )]
    pub async fn get_public_key(
        &self,
        params: Parameters<GetPublicKeyRequest>,
    ) -> Result<Json<GetPublicKeyResponse>, String> {
        let tweak_data = hex::decode(params.0.tweak_hex).map_err(|e| e.to_string())?;
        let public_key = get_public_key(
            self.node.clone(),
            params.0.crypto_type.into(),
            tweak_data,
            params.0.timeout_secs.map(Duration::from_secs),
        )
        .await?;
        Ok(wrapper::Json(GetPublicKeyResponse {
            public_key_hex: public_key,
        }))
    }
    #[tool(
        name = "sign",
        description = "Sign a message using threshold signature scheme"
    )]
    pub async fn sign(
        &self,
        params: Parameters<SignRequest>,
    ) -> Result<Json<SignResponse>, String> {
        let tweak_data = hex::decode(params.0.tweak_data).map_err(|e| e.to_string())?;
        let message_hash = sha2::Sha256::digest(&params.0.message.as_bytes()).to_vec();
        let signature = sign(
            self.node.clone(),
            params.0.crypto_type.into(),
            message_hash.clone(),
            tweak_data,
            params.0.timeout_secs.map(Duration::from_secs),
        )
        .await?;
        Ok(wrapper::Json(SignResponse {
            message_hash_hex: message_hash.encode_hex::<String>(),
            signature_hex: signature,
        }))
    }
}

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
    Ok(())
    // env_logger::init();

    // let tss_server = Arc::new(TssServer::new()?);
}

// #[tokio::main]
// async fn main() -> Result<(), Box<dyn std::error::Error>> {
//     env_logger::init();

//     let tss_server = Arc::new(TssServer::new());

//     let server = ServerBuilder::new()
//         .with_name("VeriSense TSS MCP Server")
//         .with_version("0.1.0")
//         .with_tools(move |_req: &Request| {
//             let tools = vec![
//                 Tool {
//                     info: ToolInfo {
//                         name: "get_public_key".to_string(),
//                         description: Some(
//                             "Get a threshold signature scheme public key".to_string(),
//                         ),
//                         input_schema: CallSchema {
//                             schema_type: CallSchemaType::Object,
//                             properties: Some(CallSchemaProperties {
//                                 crypto_type: Some(CallSchema {
//                                     schema_type: CallSchemaType::String,
//                                     description: Some(
//                                         "Crypto type: ecdsa_secp256k1, ecdsa_secp256r1, ed25519, bls12_381 (default: ecdsa_secp256k1)".to_string(),
//                                     ),
//                                     ..Default::default()
//                                 }),
//                                 tweak_data: Some(CallSchema {
//                                     schema_type: CallSchemaType::String,
//                                     description: Some(
//                                         "Tweak data for key derivation (default: 'default')".to_string(),
//                                     ),
//                                     ..Default::default()
//                                 }),
//                                 timeout_secs: Some(CallSchema {
//                                     schema_type: CallSchemaType::Number,
//                                     description: Some(
//                                         "Timeout in seconds (default: 30)".to_string(),
//                                     ),
//                                     ..Default::default()
//                                 }),
//                             }),
//                             ..Default::default()
//                         },
//                     },
//                 },
//                 Tool {
//                     info: ToolInfo {
//                         name: "sign".to_string(),
//                         description: Some(
//                             "Sign a message using threshold signature scheme".to_string(),
//                         ),
//                         input_schema: CallSchema {
//                             schema_type: CallSchemaType::Object,
//                             properties: Some(CallSchemaProperties {
//                                 message: Some(CallSchema {
//                                     schema_type: CallSchemaType::String,
//                                     description: Some(
//                                         "Message to sign (string or hex)".to_string(),
//                                     ),
//                                     required: Some(vec!["message".to_string()]),
//                                     ..Default::default()
//                                 }),
//                                 crypto_type: Some(CallSchema {
//                                     schema_type: CallSchemaType::String,
//                                     description: Some(
//                                         "Crypto type: ecdsa_secp256k1, ecdsa_secp256r1, ed25519, bls12_381 (default: ecdsa_secp256k1)".to_string(),
//                                     ),
//                                     ..Default::default()
//                                 }),
//                                 hash_message: Some(CallSchema {
//                                     schema_type: CallSchemaType::Boolean,
//                                     description: Some(
//                                         "Whether to hash the message with Keccak256 (default: true)".to_string(),
//                                     ),
//                                     ..Default::default()
//                                 }),
//                                 tweak_data: Some(CallSchema {
//                                     schema_type: CallSchemaType::String,
//                                     description: Some(
//                                         "Tweak data for key derivation (default: 'default')".to_string(),
//                                     ),
//                                     ..Default::default()
//                                 }),
//                                 timeout_secs: Some(CallSchema {
//                                     schema_type: CallSchemaType::Number,
//                                     description: Some(
//                                         "Timeout in seconds (default: 30)".to_string(),
//                                     ),
//                                     ..Default::default()
//                                 }),
//                             }),
//                             required: Some(vec!["message".to_string()]),
//                             ..Default::default()
//                         },
//                     },
//                 },
//             ];
//             Ok(ToolsList { tools })
//         })
//         .with_call_tool({
//             let tss_server = Arc::clone(&tss_server);
//             move |call: Call| {
//                 let tss_server = Arc::clone(&tss_server);
//                 Box::pin(async move {
//                     let result = match call.tool.as_str() {
//                         "get_public_key" => {
//                             tss_server
//                                 .handle_get_public_key(call.arguments)
//                                 .await
//                                 .map_err(|e| rmcp::types::Error {
//                                     code: -32603,
//                                     message: e,
//                                     data: None,
//                                 })?
//                         }
//                         "sign" => {
//                             tss_server
//                                 .handle_sign(call.arguments)
//                                 .await
//                                 .map_err(|e| rmcp::types::Error {
//                                     code: -32603,
//                                     message: e,
//                                     data: None,
//                                 })?
//                         }
//                         _ => {
//                             return Err(rmcp::types::Error {
//                                 code: -32601,
//                                 message: format!("Unknown tool: {}", call.tool),
//                                 data: None,
//                             })
//                         }
//                     };

//                     Ok(vec![Content {
//                         content_type: "text".to_string(),
//                         text: Some(serde_json::to_string_pretty(&result).unwrap()),
//                         ..Default::default()
//                     }])
//                 })
//             }
//         })
//         .build();

//     let server = Server::new(server);
//     let transport = rmcp::transports::stdio::StdioTransport::new();

//     println!("VeriSense TSS MCP Server starting...");
//     server.run(transport).await?;

//     Ok(())
// }
