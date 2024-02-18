use crate::{GatekeeperReader, NfcError, NfcTag, Realm, UndifferentiatedTag};
use freefare_sys::{
  freefare_free_tag, freefare_get_tags, freefare_perror,
  mifare_desfire_aes_key_new, mifare_desfire_aid_new,
  mifare_desfire_authenticate, mifare_desfire_connect,
  mifare_desfire_disconnect, mifare_desfire_key_free,
  mifare_desfire_read_data_ex, mifare_desfire_select_application,
};
use openssl::{
  error::ErrorStack,
  hash::MessageDigest,
  md::Md,
  md_ctx::MdCtx,
  pkcs5::pbkdf2_hmac,
  pkey::{PKeyRef, Public},
};
use std::ffi::CString;
use std::fmt::Write;

const GK_PBKDF2_ITERATIONS: usize = 10000;
const GK_BASE_AID: u32 = 0xff77f0;
const GK_AES_KEY_LENGTH: usize = 16;
const MDCM_ENCIPHERED: i32 = 0x03;
const GK_ASSOCIATION_LENGTH: usize = 37;
const GK_READ_PADDING: usize = 2 * 16 + 1;

impl<'device> GatekeeperReader<'device> {
  /// Searches for nearby NFC tags, and returns a list of the discovered tags
  pub(crate) fn find_desfire_tags<'a>(
    &'a self,
  ) -> Vec<UndifferentiatedTag<'a>> {
    let mut tags_out: Vec<UndifferentiatedTag<'a>> = vec![];
    unsafe {
      let tags =
        freefare_get_tags(self.device_wrapper.as_ref().unwrap().device);

      if !tags.is_null() {
        let mut tags_tmp = tags;
        while !tags_tmp.read().is_null() {
          tags_out.push(UndifferentiatedTag::Desfire(DesfireNfcTag {
            tag: tags_tmp.read(),
            realm: &self.realm,
          }));
          tags_tmp = tags_tmp.add(1);
        }
        // Free the outer list, inner pointers are fine
        libc::free(tags as *mut libc::c_void);
      }
    }
    tags_out
  }
}

/// Desfire NFC tag. Internally backed by a [`freefare_sys::Struct_freefare_tag`]
/// which will be freed when dropped.
#[derive(Debug)]
pub struct DesfireNfcTag<'a> {
  tag: *mut freefare_sys::Struct_freefare_tag,
  realm: &'a Realm<'a>,
}

impl Drop for DesfireNfcTag<'_> {
  fn drop(&mut self) {
    unsafe { freefare_free_tag(self.tag) };
  }
}

/// Derive a key
fn derive_key<const KEY_SIZE: usize>(
  secret: &[u8],
  app_id: u32,
  key_no: u8,
  data: Option<&[u8]>,
) -> Result<[u8; KEY_SIZE], ErrorStack> {
  let mut salt = Vec::from(app_id.to_string().as_bytes());
  salt.extend_from_slice(key_no.to_string().as_bytes());
  if let Some(data) = data {
    salt.extend_from_slice(data);
  }

  let mut output = [0u8; KEY_SIZE];
  pbkdf2_hmac(
    secret,
    &salt,
    GK_PBKDF2_ITERATIONS,
    MessageDigest::sha256(),
    &mut output,
  )?;
  Ok(output)
}

impl<'device> NfcTag for DesfireNfcTag<'device> {
  fn authenticate(&self) -> Result<String, NfcError> {
    let app_id = GK_BASE_AID + (self.realm.slot as u32);
    let aid = DesfireAID::new(app_id);

    let read_key =
      derive_key::<GK_AES_KEY_LENGTH>(&self.realm.read_key, app_id, 1, None)
        .expect("Key derivation failed");
    log::debug!(
      "App Read Key: {}",
      read_key.iter().fold(String::new(), |mut collector, id| {
        write!(collector, "{:02x}", id).unwrap();
        collector
      })
    );

    let read_key = DesfireAesKey::from(read_key);

    let _tag_connection = TagConnection::new(self.tag)?;

    if unsafe { mifare_desfire_select_application(self.tag, aid.0) } < 0 {
      let error = CString::new("Select application failed").unwrap();
      unsafe { freefare_perror(self.tag, error.as_ptr()) };
      return Err(NfcError::CommunicationError);
    }

    if unsafe { mifare_desfire_authenticate(self.tag, 1, read_key.0) } < 0 {
      let error = CString::new("Desfire authentication failed").unwrap();
      unsafe { freefare_perror(self.tag, error.as_ptr()) };
      return Err(NfcError::CommunicationError);
    }

    let mut association_id = [0u8; GK_ASSOCIATION_LENGTH + GK_READ_PADDING];
    if unsafe {
      mifare_desfire_read_data_ex(
        self.tag,
        1,
        0,
        GK_ASSOCIATION_LENGTH,
        association_id.as_mut_ptr() as *mut libc::c_void,
        MDCM_ENCIPHERED,
      )
    } < 0
    {
      let error = CString::new("Read association data failed").unwrap();
      unsafe { freefare_perror(self.tag, error.as_ptr()) };
      return Err(NfcError::CommunicationError);
    }
    let association_id = &association_id[..GK_ASSOCIATION_LENGTH];
    let association_id = association_id
      .strip_suffix(&[0])
      .ok_or(NfcError::BadAssociation)?;
    log::debug!(
      "Association ID: {}",
      std::str::from_utf8(association_id).unwrap_or("Invalid")
    );

    let auth_key = derive_key::<GK_AES_KEY_LENGTH>(
      &self.realm.auth_key,
      app_id,
      2,
      Some(association_id),
    )
    .expect("Key derivation failed");
    log::debug!(
      "Auth key: {}",
      auth_key.iter().fold(String::new(), |mut collector, id| {
        write!(collector, "{:02x}", id).unwrap();
        collector
      })
    );
    let auth_key = DesfireAesKey::from(auth_key);

    if unsafe { mifare_desfire_authenticate(self.tag, 2, auth_key.0) } < 0 {
      let error =
        CString::new("Desfire authentication to signature file failed")
          .unwrap();
      unsafe { freefare_perror(self.tag, error.as_ptr()) };
      return Err(NfcError::CommunicationError);
    }

    let mut signature_buf =
      vec![0u8; self.realm.desfire_signing_public_key.size() + GK_READ_PADDING];
    if unsafe {
      mifare_desfire_read_data_ex(
        self.tag,
        2,
        0,
        4,
        signature_buf.as_mut_ptr() as *mut libc::c_void,
        MDCM_ENCIPHERED,
      )
    } < 0
    {
      let error = CString::new("Desfire read signature length failed").unwrap();
      unsafe { freefare_perror(self.tag, error.as_ptr()) };
      return Err(NfcError::CommunicationError);
    }
    let sig_length: usize = ((signature_buf[0] as usize) << 24)
      | ((signature_buf[1] as usize) << 16)
      | ((signature_buf[2] as usize) << 8)
      | (signature_buf[3] as usize);

    if unsafe {
      mifare_desfire_read_data_ex(
        self.tag,
        2,
        4, // offset
        sig_length,
        signature_buf.as_mut_ptr() as *mut libc::c_void,
        MDCM_ENCIPHERED,
      )
    } < 0
    {
      let error = CString::new("Desfire read signature data failed").unwrap();
      unsafe { freefare_perror(self.tag, error.as_ptr()) };
      return Err(NfcError::CommunicationError);
    }
    let signature = &signature_buf[..sig_length];

    if verify_signature(
      association_id,
      &self.realm.desfire_signing_public_key,
      signature,
    )
    .map_err(NfcError::CryptoError)?
    {
      // Verified!
      Ok(
        String::from_utf8(association_id.to_vec())
          .map_err(|_| NfcError::BadAssociation)?,
      )
    } else {
      Err(NfcError::InvalidSignature)
    }
  }
}

/// Returns a boolean indicating whether or not the signature is valid
/// (`true` if valid, else `false`)
fn verify_signature(
  data: &[u8],
  public_key: &PKeyRef<Public>,
  signature: &[u8],
) -> Result<bool, ErrorStack> {
  let mut md_ctx = MdCtx::new()?;
  md_ctx.digest_verify_init(Some(Md::sha256()), public_key)?;
  md_ctx.digest_verify_update(data)?;
  md_ctx.digest_verify_final(signature)
}

struct DesfireAID(*mut freefare_sys::Struct_mifare_desfire_aid);
impl DesfireAID {
  fn new(aid: u32) -> Self {
    Self(unsafe { mifare_desfire_aid_new(aid) })
  }
}

impl Drop for DesfireAID {
  fn drop(&mut self) {
    unsafe { libc::free(self.0 as *mut libc::c_void) }
  }
}

struct TagConnection(*mut freefare_sys::Struct_freefare_tag);

impl TagConnection {
  fn new(
    tag: *mut freefare_sys::Struct_freefare_tag,
  ) -> Result<Self, NfcError> {
    let result = unsafe { mifare_desfire_connect(tag) };
    let tag_connection = Self(tag);
    if result < 0 {
      Err(NfcError::ConnectFailed)
    } else {
      Ok(tag_connection)
    }
  }
}

impl Drop for TagConnection {
  fn drop(&mut self) {
    unsafe { mifare_desfire_disconnect(self.0) };
  }
}

struct DesfireAesKey(*mut freefare_sys::Struct_mifare_desfire_key);

impl From<[u8; GK_AES_KEY_LENGTH]> for DesfireAesKey {
  fn from(mut key: [u8; GK_AES_KEY_LENGTH]) -> Self {
    Self(unsafe { mifare_desfire_aes_key_new(key.as_mut_ptr()) })
  }
}
impl Drop for DesfireAesKey {
  fn drop(&mut self) {
    unsafe { mifare_desfire_key_free(self.0) };
  }
}
