use nfc_sys::{
  nfc_close, nfc_exit, nfc_init, nfc_initiator_init, nfc_open, nfc_perror,
};
use openssl::error::ErrorStack;
use openssl::pkey::{PKey, Private, Public};
use std::ffi::{c_char, CString};
use std::fmt::{self, Display, Formatter};
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::time::Duration;

mod desfire;
mod mobile;
use crate::desfire::*;
use crate::mobile::*;

impl Display for NfcError {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    match self {
      Self::NonceMismatch => write!(f, "None mismatch"),
      Self::NoResponse => {
        write!(f, "Did not receive a response. Is the tag too far away?")
      }
      Self::CryptoError(err) => write!(f, "Cryptography error: {err}"),
      Self::ConnectFailed => write!(f, "Failed to connect"),
      Self::CommunicationError => {
        write!(f, "Communication failed. Is the tag too far away?")
      }
      Self::InvalidSignature => {
        write!(f, "Association had an invalid signature!")
      }
      Self::BadAssociation => write!(f, "Association ID is not valid UTF-8"),
    }
  }
}

impl std::error::Error for NfcError {}

#[derive(Debug)]
pub enum NfcError {
  // SendMismatch,
  NonceMismatch,
  NoResponse,
  CryptoError(ErrorStack),
  ConnectFailed,
  CommunicationError,
  InvalidSignature,
  BadAssociation,
}

#[derive(Debug)]
pub(crate) struct DeviceWrapper<'device> {
  _context: NfcContext<'device>,
  device: *mut nfc_sys::nfc_device,
}

impl<'device> Drop for DeviceWrapper<'device> {
  fn drop(&mut self) {
    unsafe { nfc_close(self.device) };
  }
}

/// Wrapper around [`nfc_sys::nfc_context`]. The underlying context will be
/// freed when dropped.
#[derive(Debug)]
struct NfcContext<'context> {
  context: *mut nfc_sys::nfc_context,
  _lifetime: PhantomData<&'context ()>,
}

impl Drop for NfcContext<'_> {
  fn drop(&mut self) {
    unsafe { nfc_exit(self.context) };
  }
}

impl<'a> Default for NfcContext<'a> {
  fn default() -> Self {
    let mut context_uninit = MaybeUninit::<*mut nfc_sys::nfc_context>::uninit();
    Self {
      context: unsafe {
        nfc_init(context_uninit.as_mut_ptr());
        if context_uninit.as_mut_ptr().is_null() {
          panic!("Malloc failed");
        }
        context_uninit.assume_init()
      },
      _lifetime: PhantomData,
    }
  }
}

/// Keys used to write to a particular realm.
/// Most applications will not need these
#[derive(Debug, Clone)]
pub struct RealmWriteKeys<'a> {
  /// KDF secret to get the desfire update key (used to make changes to records
  /// stored on the tag)
  update_key: &'a [u8],
  /// Key used to sign association IDs on desfire tags. Only needed for issuing
  /// new tags
  desfire_signing_private_key: PKey<Private>,
}

/// A realm is a slot on a card that has unique keys.
/// Typical realms are: `Doors`, `Drink`, `Member Projects`.
#[derive(Debug, Clone)]
pub struct Realm<'a> {
  /// Which realm do these keys belong to?
  slot: RealmType,
  /// KDF secret to get the desfire auth key (used to access the card)
  auth_key: Vec<u8>,
  /// KDF secret to get the desfire read key (used to read files on the card)
  read_key: Vec<u8>,
  /// Public key that desfire association IDs are signed by
  desfire_signing_public_key: PKey<Public>,
  /// Private key that can decrypt messages from
  /// [Flask](https://github.com/ComputerScienceHouse/devin)
  mobile_decryption_private_key: PKey<Private>,
  /// Private key used to prove to mobile tags that we're a real reader
  mobile_signing_private_key: PKey<Private>,
  /// Keys used to write to this realm. Only needed to issue new tags.
  secrets: Option<RealmWriteKeys<'a>>,
}

impl<'a> Realm<'a> {
  /// Creates a new realm with the given parameters.
  /// * `slot` identifies which realm to access
  /// * `auth_key` is the secret to derive the desfire auth key (used to gain
  ///   access to the card)
  /// * `read_key` is the secret to derive the desfire read key (used to read
  ///   files stored on the card)
  /// * `desfire_signing_public_key` is the public key that desfire association
  ///   IDs are signed by
  /// * `mobile_decryption_private_key` is the private key that can decrypt
  ///   messages sent by mobile tags.
  /// * `mobile_signing_private_key` is the private key used to prove to mobile
  ///   tags that we're authorized to read from this realm.
  /// * `secrets` optionally contains the keys needed to write to this realm.
  ///   These are only needed to issue new tags, you probably don't need them.
  pub fn new(
    slot: RealmType,
    auth_key: Vec<u8>,
    read_key: Vec<u8>,
    desfire_signing_public_key: &[u8],
    mobile_decryption_private_key: &[u8],
    mobile_signing_private_key: &[u8],
    secrets: Option<RealmWriteKeys<'a>>,
  ) -> Self {
    Self {
      slot,
      auth_key,
      read_key,
      desfire_signing_public_key: PKey::public_key_from_pem(
        desfire_signing_public_key,
      )
      .expect("Bad key format"),
      mobile_decryption_private_key: PKey::private_key_from_pem(
        mobile_decryption_private_key,
      )
      .expect("Bad key format"),
      mobile_signing_private_key: PKey::private_key_from_pem(
        mobile_signing_private_key,
      )
      .expect("Bad key format"),
      secrets,
    }
  }
}

/// Selects a known realm.
#[repr(u8)]
#[derive(Debug, Clone)]
pub enum RealmType {
  /// The `Door` (slot 0) realm is used by door locks to gate access to common rooms.
  Door = 0,
  /// The `Drink` (slot 1) realm is used to authorize drink credit purchases.
  Drink = 1,
  /// The `MemberProjects` (slot 2) realm is used by anything lower-security
  /// that doesn't fall into any of those categories (e.g. `harold-nfc`).
  /// If you're looking to make a new project, this is probably the realm you
  /// should use!
  MemberProjects = 2,
}

impl Display for UndifferentiatedTag<'_> {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    match self {
      Self::Desfire(_) => write!(f, "Desfire"),
      Self::Mobile(_) => write!(f, "Mobile"),
    }
  }
}

impl Display for RealmType {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    match self {
      Self::Door => write!(f, "Door"),
      Self::Drink => write!(f, "Drink"),
      Self::MemberProjects => write!(f, "Member Projects"),
    }
  }
}

// It's a u8, it's fine...
impl Copy for RealmType {}

/// High-level interface over an NFC reader. Allows reading association IDs from
/// the realm for which it was created.
pub struct GatekeeperReader<'device> {
  /// Internal device we're reading from
  device_wrapper: Option<DeviceWrapper<'device>>,
  /// Connection string for the device
  connection_string: String,
  /// Realm to read from
  realm: Realm<'device>,
}

impl<'device> DeviceWrapper<'device> {
  /// Creates a new [`DeviceWrapper`] for the device found at `connection_string`.
  /// For more information on the format of `connection_string`, see
  /// [libnfc](https://github.com/nfc-tools/libnfc).
  fn new(connection_string: String) -> Option<Self> {
    let context = NfcContext::default();
    let device_string = CString::new(connection_string).unwrap();
    let device_string = device_string.into_bytes_with_nul();

    let mut device_string_bytes: [c_char; 1024] = [0; 1024];
    for (index, character) in device_string.into_iter().enumerate() {
      device_string_bytes[index] = character as c_char;
    }

    let device_ptr = unsafe {
      let device_ptr = nfc_open(context.context, &device_string_bytes);
      if device_ptr.is_null() {
        log::error!("Failed to open NFC device...");
        return None;
      }
      log::debug!("Opened an NFC device!");
      device_ptr
    };
    Some(Self {
      device: device_ptr,
      _context: context,
    })
  }
}

/// Wrapper over the supported NFC device types. You probably want to look at
/// this enum's [`NfcTag`] implementation.
#[derive(Debug)]
pub enum UndifferentiatedTag<'a> {
  Desfire(DesfireNfcTag<'a>),
  Mobile(MobileNfcTag<'a>),
}

/// Generic NFC tag. Could represent a [`DesfireNfctag`] or a [`MobileNfcTag`]
pub trait NfcTag {
  /// Attempt to authenticate this tag. If the tag is valid, returns the
  /// association ID. If there was an error, an [`NfcError`] is returned
  /// instead.
  fn authenticate(&self) -> Result<String, NfcError>;
}

impl NfcTag for UndifferentiatedTag<'_> {
  fn authenticate(&self) -> Result<String, NfcError> {
    match self {
      Self::Desfire(desfire) => desfire.authenticate(),
      Self::Mobile(mobile) => mobile.authenticate(),
    }
  }
}

/// Current state of the NFC reader
#[must_use]
enum ReaderStatus {
  /// NFC reader is responding to our requests
  Available,
  /// NFC reader is not responding to our requests
  Unavailable,
}

impl<'device> GatekeeperReader<'device> {
  /// Opens a connection with the NFC reader located at `connection_string`.
  /// Readers are tied to a particular [`Realm`], and can only read
  /// association IDs from that particular realm.
  pub fn new(connection_string: String, realm: Realm<'device>) -> Option<Self> {
    let device_wrapper = Some(DeviceWrapper::new(connection_string.clone())?);
    Some(Self {
      device_wrapper,
      connection_string,
      realm,
    })
  }

  /// Attempt to bring up the NFC reader's field, retrying up to 3 times.
  /// Returns a [`ReaderStatus`] indicating whether or not the reader is ready
  /// for use
  fn ensure_reader_available(&mut self) -> ReaderStatus {
    for _ in 0..3 {
      if self.device_wrapper.as_ref().map(|device_wrapper| unsafe {
        nfc_initiator_init(device_wrapper.device)
        } < 0).unwrap_or(true)
      {
        log::error!("Couldn't init NFC initiator!!!");
        if let Some(device_wrapper) = &self.device_wrapper {
          unsafe {
            let msg = CString::new("Failed to init device initiator :(").unwrap();
            nfc_perror(device_wrapper.device, msg.as_ptr())
          };
        }
        log::error!("Resetting the device and trying again!");
        std::thread::sleep(Duration::from_millis(500));
        self.device_wrapper = None;
        if let Some(device_wrapper) =
          DeviceWrapper::new(self.connection_string.clone())
        {
          self.device_wrapper = Some(device_wrapper);
        }
      } else {
        // Init success
        return ReaderStatus::Available;
      }
    }
    ReaderStatus::Unavailable
  }

  /// Searches for nearby NFC tags.
  ///
  /// **Note:** This doesn't actually authenticate the NFC
  /// tags, just searches for them. You **must** call [`NfcTag::authenticate`]
  /// before you can know who it belongs to (or if it's even a valid tag!)</div>
  pub fn get_nearby_tags(&mut self) -> Vec<UndifferentiatedTag> {
    // Before anything else, make sure the reader is available
    if let ReaderStatus::Unavailable = self.ensure_reader_available() {
      return vec![];
    }

    // First, mobile tags:
    if let Some(tag) = self.find_first_mobile_tag() {
      return vec![UndifferentiatedTag::Mobile(tag)];
    }

    // Then, Desfire stuff:
    self.find_desfire_tags()
  }
}
