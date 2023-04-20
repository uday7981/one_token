
use ic_cdk::{export::{
    candid::{CandidType,candid_method,types::number::Nat},
    serde::{Deserialize,Serialize},
    Principal,
}, api::call::reply_raw, print};
use ic_cdk::{query,update};
use std::str::FromStr;
use std::cell::RefCell;
use tx_from_scratch::Transaction;
// use ethereum_types::H160;
// use ethereum_tx_sign::{LegacyTransaction,Transaction};
use rlp::{RlpStream, Encodable};
use std::convert::TryInto;
use serde_json::Value;

use ic_cdk::api::management_canister::http_request::{
    CanisterHttpRequestArgument,
    HttpHeader,
    HttpMethod,
    HttpResponse,
    http_request,
    TransformFunc,
    TransformContext,
    TransformArgs
};

fn convert(slice: &[u8]) -> [u8; 20] {
    slice.try_into().expect("slice with incorrect length")
}
thread_local! {
    static NONCE: RefCell<Nat> = RefCell::new(Nat::from(0));
}

fn rlp_encode_parts(parts: &Vec<Box<dyn Encodable>>) -> Vec<u8> {
    let mut rlp_stream = RlpStream::new();
    rlp_stream.begin_unbounded_list();
    for part in parts.iter() {
        rlp_stream.append(part);
    }
    rlp_stream.finalize_unbounded_list();
    rlp_stream.out().to_vec()
}

#[ic_cdk_macros::query]
fn greet(name: String) -> String {
    format!("Hello, {}!", name)
}
#[derive(CandidType, Serialize, Debug)]
struct PublicKeyReply {
    pub public_key_hex: String,
    pub eth_address: String,
}

#[derive(CandidType, Serialize, Debug)]
struct SignatureReply {
    pub signature_hex: String,
}

#[derive(CandidType, Serialize, Debug)]
struct SignatureVerificationReply {
    pub is_signature_valid: bool,
}

type CanisterId = Principal;

#[derive(CandidType, Serialize, Debug)]
struct ECDSAPublicKey {
    pub canister_id: Option<CanisterId>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: EcdsaKeyId,
}

#[derive(CandidType, Deserialize, Debug)]
struct ECDSAPublicKeyReply {
    pub public_key: Vec<u8>,
    pub chain_code: Vec<u8>,
}

#[derive(CandidType, Serialize, Debug)]
struct SignWithECDSA {
    pub message_hash: Vec<u8>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: EcdsaKeyId,
}

#[derive(CandidType, Deserialize, Debug)]
struct SignWithECDSAReply {
    pub signature: Vec<u8>,
}

#[derive(CandidType, Serialize, Debug, Clone)]
struct EcdsaKeyId {
    pub curve: EcdsaCurve,
    pub name: String,
}
#[derive(CandidType, Serialize, Debug, Clone)]
struct SignOutput{
    pub tx_sign: String
}


#[derive(CandidType, Serialize, Debug, Clone)]
pub enum EcdsaCurve {
    #[serde(rename = "secp256k1")]
    Secp256k1,
}
enum EcdsaKeyIds {
    #[allow(unused)]
    TestKeyLocalDevelopment,
    #[allow(unused)]
    TestKey1,
    #[allow(unused)]
    ProductionKey1,
}
impl EcdsaKeyIds {
    fn to_key_id(&self) -> EcdsaKeyId {
        EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: match self {
                Self::TestKeyLocalDevelopment => "dfx_test_key",
                Self::TestKey1 => "test_key_1",
                Self::ProductionKey1 => "key_1",
            }
            .to_string(),
        }
    }
}

fn mgmt_canister_id() -> CanisterId {
    CanisterId::from_str(&"aaaaa-aa").unwrap()
}
#[update]
async fn public_key() -> Result<PublicKeyReply,String>{
    let request = ECDSAPublicKey {
        canister_id:None,
        derivation_path:vec![],
        key_id:EcdsaKeyIds::TestKeyLocalDevelopment.to_key_id(),
    };
    let (res,): (ECDSAPublicKeyReply,) = 
        ic_cdk::call(mgmt_canister_id(),"ecdsa_public_key", (request,))
        .await
        .map_err(|e| format!("ecdsa_public_key failed {}",e.1))?;
     
    // let public_key_bytes = hex::decode(res.public_key)
    // let public_key_bytes =  hex::decode(&res.public_key).map_err(|e| format!("hex::decode failed: {}", e))?;

    // let secp = Secp256k1::new();
    // let public_key = PublicKey::from_slice(&public_key_bytes);
    // let serialized_pubkey = public_key.serialize_uncompressed();
    // let hash = Keccak256::digest(&serialized_pubkey[1..]);
    // let address_bytes = &hash[12..];
    // let address = format!("0x{:x?}", address_bytes);
    let  hash = keccak256(&res.public_key);

    let address_bytes = &hash[12..];
    let address = format!("{}{}","0x",hex::encode(&address_bytes));
    
    
    Ok(PublicKeyReply{
        public_key_hex: hex::encode(&res.public_key),
        eth_address:address
    })
}
fn sha256(input: &Vec<u8>) -> Vec<u8> {
    use sha2::{Digest,Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&input);
    hasher.finalize().to_vec()
}
#[derive(serde::Serialize, serde::Deserialize)]
struct RpcRequest {
    jsonrpc: String,
    method: String,
    params: Vec<Value>,
    id: String,
}
#[query]
fn transform(raw: TransformArgs) -> HttpResponse {
    let mut res = HttpResponse {
        status: raw.response.status.clone(),
        ..Default::default()
    };
    if res.status == 200 {
        res.body = raw.response.body;
    } else {
        ic_cdk::api::print(format!("Received an error from jsonropc: err = {:?}", raw));
    }
    res
}
#[update]
async fn sign() -> Result<SignOutput,String>{
    let address_to = "0x64aDb30D59b2dF0bd0433660Ba6c641B156974f9";
    let to_address_bytes = hex::decode(&address_to[2..]).map_err(|e| format!("hex::decode failed: {}", e))?;
    let chain_id = 1;
    let tx = Transaction{
        chain_id: chain_id,
        data: Vec::new(),
        gas_price: 46,
        gas: 200,
        value:3000000,
        nonce:0,
        to: Some(convert(to_address_bytes.as_slice()))

    };
    let hash = tx.hash();
    let request = SignWithECDSA {
        message_hash : hash,
        derivation_path: vec![],
        key_id: EcdsaKeyIds::TestKeyLocalDevelopment.to_key_id()
    };
    let (response,): (SignWithECDSAReply,) = ic_cdk::api::call::call_with_payment(
        mgmt_canister_id(),
         "sign_with_ecdsa",
          (request,), 
          25_000_000_000
        )
        .await
        .map_err(|e| format!("Sign in with ecdsa failed {}",e.1))?;
    
        let v = ( chain_id * 2 )+35;
        let r = response.signature[0..32].to_vec();
        let s = response.signature[32..64].to_vec();
        let mut stream = RlpStream::new();
        stream.begin_unbounded_list();
        stream.append(&tx.nonce);
        stream.append(&tx.gas_price);
        stream.append(&tx.gas_price);
        stream.append(&tx.gas);
        if tx.to.is_none(){
            stream.append(&Vec::new());
        }
        else{
            stream.append(&tx.to.unwrap().to_vec());
        }
        stream.append(&tx.value);
        stream.append(&tx.data);
        stream.append(&v);
        stream.append(&r);
        stream.append(&s);
        stream.finalize_unbounded_list();
    let stream_out =    stream.out().to_vec();
    let tx_sign =  hex::encode(&stream_out);
    let final_tx = format!("{}{}","0x",tx_sign);
    let rpc_request = RpcRequest{
        id:"1".into(),
        jsonrpc:"2.0".into(),
        method:"eth_gasPrice".into(),
        params:vec![]
    };
    let json_rpc = serde_json::to_vec(
        &rpc_request
    ).map_err(|e| format!("hex::decode failed: {}", e))?;
    let request = CanisterHttpRequestArgument{
        url:"https://goerli.infura.io/v3/260bec7447134609a3d9488ae6481170".to_string(),
        max_response_bytes: Some(400000),
        method:HttpMethod::POST,
        headers:vec![
            HttpHeader{
                name:"Content-Type".to_string(),
                value:"application/json".to_string()
            }
        ],
        body: Some(
            json_rpc
        ),
        transform:Some(TransformContext::new(transform, vec![]))
        
    };
    
    match http_request(request).await {
        Ok((result,))=>{
            
            Ok(SignOutput{
                tx_sign:format!("{:?}",result.body)
            })
        }
        Err((r, m)) => {
            let message =
                format!("The http_request resulted into error. RejectionCode: {r:?}, Error: {m}");
            Err(message)
        }
    }
    
   
}


fn keccak256(bytes: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    hasher.finalize(&mut output);
    output
}


