mod testing;
use serde::{Deserialize, Serialize};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
pub use tss_sdk::*;
mod identity;
pub use identity::*;
use std::path::PathBuf;

use hex::ToHex;
use rmcp::{
    ErrorData, Json, RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, tool::Parameters, wrapper},
    model::{
        Implementation, InitializeRequestParam, InitializeResult, ProtocolVersion,
        ServerCapabilities, ServerInfo,
    },
    service::RequestContext,
    tool, tool_handler, tool_router,
    transport::{
        StreamableHttpService, streamable_http_server::session::local::LocalSessionManager,
    },
};
use std::sync::Arc;
use tokio::time::Duration;
use tss_sdk::crypto::CryptoType;
use tss_sdk::node::Node;

use sha3::Digest;
use tss_sdk::crypto::ValidatorIdentityKeypair;

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GetPublicKeyRequest {
    #[schemars(
        description = "Crypto type, e.g. P256, Ed25519, Secp256k1, Secp256k1Tr, Ed448, Ristretto255, EcdsaSecp256k1"
    )]
    pub crypto_type: String,
    #[schemars(description = "Tweak data for key derivation")]
    pub tweak_data: String,
    #[schemars(description = "Timeout in seconds")]
    pub timeout_secs: Option<u64>,
}
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GetPublicKeyResponse {
    pub public_key_hex: String,
}
#[cfg(test)]
mod tests {
    use super::*;
    use schemars::schema_for;
    #[test]
    fn test() {
        let schema = schema_for!(GetPublicKeyRequest);
        println!("{}", serde_json::to_string_pretty(&schema).unwrap());
    }
}
fn get_crypto_type(crypto_type: String) -> CryptoType {
    let normalized = crypto_type.to_lowercase().replace("-", "").replace("_", "");
    match normalized.as_str() {
        "p256" => CryptoType::P256,
        "ed25519" => CryptoType::Ed25519,
        "secp256k1" => CryptoType::Secp256k1,
        "secp256k1tr" | "secp256k1taproot" | "taproot" => CryptoType::Secp256k1Tr,
        "ed448" => CryptoType::Ed448,
        "ristretto255" => CryptoType::Ristretto255,
        "ecdsasecp256k1" => CryptoType::EcdsaSecp256k1,
        _ => CryptoType::P256,
    }
}
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SignRequest {
    #[schemars(
        description = "Crypto type, e.g. P256, Ed25519, Secp256k1, Secp256k1Tr, Ed448, Ristretto255, EcdsaSecp256k1"
    )]
    pub crypto_type: String,
    #[schemars(description = "Message to sign")]
    pub message: String,
    #[schemars(description = "Tweak data for key derivation")]
    pub tweak_data: String,
    #[schemars(description = "Timeout in seconds")]
    pub timeout_secs: Option<u64>,
}
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
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

impl Default for TssServer {
    fn default() -> Self {
        Self::new().unwrap()
    }
}
use load_dotenv::load_dotenv;
load_dotenv!();
#[tool_router(router = tool_router)]
impl TssServer {
    pub fn new() -> Result<Self, String> {
        let node = Node::<VrsTssValidatorIdentity>::new(
            TssKeystore::random_generate_keypair(),
            PathBuf::from(".tss_node"),
            format!("/ip4/{}/tcp/12944", env!("IP")).parse().unwrap(),
            env!("PEER_ID").parse().unwrap(),
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
    ) -> Result<Json<GetPublicKeyResponse>, ErrorData> {
        let tweak_data = params.0.tweak_data.into_bytes();
        let public_key = get_public_key(
            self.node.clone(),
            get_crypto_type(params.0.crypto_type),
            tweak_data,
            params.0.timeout_secs.map(Duration::from_secs),
        )
        .await
        .map_err(|e| ErrorData::invalid_params(e, None))?;
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
    ) -> Result<Json<SignResponse>, ErrorData> {
        let tweak_data = params.0.tweak_data.into_bytes();
        let message_hash = sha2::Sha256::digest(&params.0.message.as_bytes()).to_vec();
        let signature = sign(
            self.node.clone(),
            get_crypto_type(params.0.crypto_type),
            message_hash.clone(),
            tweak_data,
            params.0.timeout_secs.map(Duration::from_secs),
        )
        .await
        .map_err(|e| ErrorData::invalid_params(e, None))?;
        Ok(wrapper::Json(SignResponse {
            message_hash_hex: message_hash.encode_hex::<String>(),
            signature_hex: signature,
        }))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for TssServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2025_03_26,
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .build(),
            server_info: Implementation::from_build_env(),
            instructions: Some("This server provides a threshold signature scheme tool that can get public key and sign message.".to_string()),
        }
    }

    async fn initialize(
        &self,
        _request: InitializeRequestParam,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, rmcp::ErrorData> {
        if let Some(http_request_part) = context.extensions.get::<axum::http::request::Parts>() {
            let initialize_headers = &http_request_part.headers;
            let initialize_uri = &http_request_part.uri;
            tracing::info!(?initialize_headers, %initialize_uri, "initialize from http server");
        }
        Ok(self.get_info())
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
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        signal(SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = terminate => {} }
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "debug".to_string().into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let service = StreamableHttpService::new(
        || TssServer::new().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)),
        LocalSessionManager::default().into(),
        Default::default(),
    );

    let router = axum::Router::new().nest_service("/mcp", service);
    let tcp_listener = tokio::net::TcpListener::bind("0.0.0.0:80").await?;
    let _ = axum::serve(tcp_listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await;
    Ok(())
}
