use gatekeeper_core::{GatekeeperReader, NfcTag, Realm, RealmType};

fn main() {
  let auth_key = std::env::var("GK_REALM_MEMBER_PROJECTS_AUTH_KEY").unwrap();
  let read_key = std::env::var("GK_REALM_MEMBER_PROJECTS_READ_KEY").unwrap();
  let signing_public_key =
    std::env::var("GK_REALM_MEMBER_PROJECTS_PUBLIC_KEY").unwrap();
  let mobile_decryption_private_key =
    std::env::var("GK_REALM_MEMBER_PROJECTS_MOBILE_CRYPT_PRIVATE_KEY").unwrap();
  let mobile_private_key =
    std::env::var("GK_REALM_MEMBER_PROJECTS_MOBILE_PRIVATE_KEY").unwrap();
  let realm = Realm::new(
    RealmType::MemberProjects,
    auth_key.into_bytes(),
    read_key.into_bytes(),
    signing_public_key.as_bytes(),
    mobile_decryption_private_key.as_bytes(),
    mobile_private_key.as_bytes(),
    None,
  );
  let mut gatekeeper_reader =
    GatekeeperReader::new("pn532_uart:/dev/ttyUSB0".to_string(), realm)
      .expect("Failed to open gatekeeper");
  for tag in gatekeeper_reader.get_nearby_tags() {
    println!("Found a tag nearby: {tag}");
    if let Ok(association_id) = tag.authenticate() {
      println!("Association ID for tag: {association_id}");
    }
  }
}
