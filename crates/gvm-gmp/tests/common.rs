use gvm_gmp::EntityId;
use gvm_protocol::Request;

pub fn xml(request: impl Request) -> String {
    String::from_utf8(request.to_bytes()).expect("valid utf8")
}

pub fn id(s: &str) -> EntityId {
    EntityId::new(s).expect("valid id")
}

