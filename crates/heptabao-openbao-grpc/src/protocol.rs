//! Exact public Wrapper messages from plugin/v2.4.0 and wrapping/v2.9.0.
//!
//! Field numbers come from the vendored public .proto files, not Go code.
//! Prost derives supply protobuf encoding. Debug output is always redacted.

use zeroize::Zeroize;
macro_rules! redacted {
    ($name:ident) => {
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

pub mod wrapping {
    use zeroize::Zeroize;
    #[derive(Clone, PartialEq, ::prost::Message)]
    #[prost(skip_debug)]
    pub struct WrapperConfig {
        #[prost(btree_map = "string, string", tag = "10")]
        pub metadata: std::collections::BTreeMap<String, String>,
    }
    redacted!(WrapperConfig);
    impl Drop for WrapperConfig {
        fn drop(&mut self) {
            for (mut key, mut value) in std::mem::take(&mut self.metadata) {
                key.zeroize();
                value.zeroize();
            }
        }
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    #[prost(skip_debug)]
    pub struct BlobInfo {
        #[prost(bytes = "vec", tag = "1")]
        pub ciphertext: Vec<u8>,
        #[prost(bytes = "vec", tag = "2")]
        pub iv: Vec<u8>,
        #[prost(message, optional, tag = "5")]
        pub key_info: Option<KeyInfo>,
    }
    redacted!(BlobInfo);
    impl Drop for BlobInfo {
        fn drop(&mut self) {
            self.ciphertext.zeroize();
            self.iv.zeroize();
            self.key_info = None;
        }
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    #[prost(skip_debug)]
    pub struct KeyInfo {
        #[prost(uint64, tag = "1")]
        pub mechanism: u64,
        #[prost(string, tag = "3")]
        pub key_id: String,
        #[prost(bytes = "vec", tag = "5")]
        pub wrapped_key: Vec<u8>,
    }
    redacted!(KeyInfo);
    impl Drop for KeyInfo {
        fn drop(&mut self) {
            self.key_id.zeroize();
            self.wrapped_key.zeroize();
        }
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    #[prost(skip_debug)]
    pub struct RpcOptions {
        #[prost(string, tag = "10")]
        pub with_key_id: String,
        #[prost(bytes = "vec", tag = "20")]
        pub with_aad: Vec<u8>,
        #[prost(btree_map = "string, string", tag = "30")]
        pub with_config_map: std::collections::BTreeMap<String, String>,
        #[prost(bool, tag = "90")]
        pub with_disallow_env_vars: bool,
    }
    redacted!(RpcOptions);
    impl Drop for RpcOptions {
        fn drop(&mut self) {
            self.with_key_id.zeroize();
            self.with_aad.zeroize();
            for (mut key, mut value) in std::mem::take(&mut self.with_config_map) {
                key.zeroize();
                value.zeroize();
            }
        }
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct SetConfigRequest {
    #[prost(message, optional, tag = "20")]
    pub options: Option<wrapping::RpcOptions>,
}
redacted!(SetConfigRequest);
impl Drop for SetConfigRequest {
    fn drop(&mut self) {
        self.options = None;
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct SetConfigResponse {
    #[prost(string, tag = "1")]
    pub wrapper_id: String,
    #[prost(message, optional, tag = "10")]
    pub wrapper_config: Option<wrapping::WrapperConfig>,
}
redacted!(SetConfigResponse);
impl Drop for SetConfigResponse {
    fn drop(&mut self) {
        self.wrapper_id.zeroize();
        self.wrapper_config = None;
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct TypeRequest {
    #[prost(string, tag = "1")]
    pub wrapper_id: String,
}
redacted!(TypeRequest);
impl Drop for TypeRequest {
    fn drop(&mut self) {
        self.wrapper_id.zeroize();
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct TypeResponse {
    #[prost(string, tag = "10")]
    pub r#type: String,
}
redacted!(TypeResponse);
impl Drop for TypeResponse {
    fn drop(&mut self) {
        self.r#type.zeroize();
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct KeyIdRequest {
    #[prost(string, tag = "1")]
    pub wrapper_id: String,
}
redacted!(KeyIdRequest);
impl Drop for KeyIdRequest {
    fn drop(&mut self) {
        self.wrapper_id.zeroize();
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct KeyIdResponse {
    #[prost(string, tag = "10")]
    pub key_id: String,
}
redacted!(KeyIdResponse);
impl Drop for KeyIdResponse {
    fn drop(&mut self) {
        self.key_id.zeroize();
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct EncryptRequest {
    #[prost(string, tag = "1")]
    pub wrapper_id: String,
    #[prost(bytes = "vec", tag = "10")]
    pub plaintext: Vec<u8>,
    #[prost(message, optional, tag = "20")]
    pub options: Option<wrapping::RpcOptions>,
}
redacted!(EncryptRequest);
impl Drop for EncryptRequest {
    fn drop(&mut self) {
        self.wrapper_id.zeroize();
        self.plaintext.zeroize();
        self.options = None;
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct EncryptResponse {
    #[prost(message, optional, tag = "10")]
    pub ciphertext: Option<wrapping::BlobInfo>,
}
redacted!(EncryptResponse);
impl Drop for EncryptResponse {
    fn drop(&mut self) {
        self.ciphertext = None;
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct DecryptRequest {
    #[prost(string, tag = "1")]
    pub wrapper_id: String,
    #[prost(message, optional, tag = "10")]
    pub ciphertext: Option<wrapping::BlobInfo>,
    #[prost(message, optional, tag = "20")]
    pub options: Option<wrapping::RpcOptions>,
}
redacted!(DecryptRequest);
impl Drop for DecryptRequest {
    fn drop(&mut self) {
        self.wrapper_id.zeroize();
        self.ciphertext = None;
        self.options = None;
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct DecryptResponse {
    #[prost(bytes = "vec", tag = "10")]
    pub plaintext: Vec<u8>,
}
redacted!(DecryptResponse);
impl Drop for DecryptResponse {
    fn drop(&mut self) {
        self.plaintext.zeroize();
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct InitRequest {
    #[prost(string, tag = "1")]
    pub wrapper_id: String,
    #[prost(message, optional, tag = "20")]
    pub options: Option<wrapping::RpcOptions>,
}
redacted!(InitRequest);
impl Drop for InitRequest {
    fn drop(&mut self) {
        self.wrapper_id.zeroize();
        self.options = None;
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct InitResponse {}
redacted!(InitResponse);
impl Drop for InitResponse {
    fn drop(&mut self) {}
}

#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct FinalizeRequest {
    #[prost(string, tag = "1")]
    pub wrapper_id: String,
    #[prost(message, optional, tag = "20")]
    pub options: Option<wrapping::RpcOptions>,
}
redacted!(FinalizeRequest);
impl Drop for FinalizeRequest {
    fn drop(&mut self) {
        self.wrapper_id.zeroize();
        self.options = None;
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct FinalizeResponse {}
redacted!(FinalizeResponse);
impl Drop for FinalizeResponse {
    fn drop(&mut self) {}
}
