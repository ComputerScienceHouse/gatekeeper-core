use crate::{DeviceWrapper, GatekeeperReader, NfcError, NfcTag, Realm};
use apdu_core::{Command, Response};
use nfc_sys::{
  nfc_baud_rate as BaudRate, nfc_device_set_property_bool,
  nfc_initiator_deselect_target, nfc_initiator_select_passive_target,
  nfc_initiator_transceive_bytes, nfc_modulation as Modulation,
  nfc_modulation_type as ModulationType, nfc_property as NfcProperty,
};
use openssl::{encrypt::Decrypter, hash::MessageDigest, sign::Signer};
use std::fmt::Write;
use std::mem::MaybeUninit;

const NONCE_LENGTH: usize = 8;
const RESPONSE_PADDING_LENGTH: usize = 2;

impl<'a> NfcTag for MobileNfcTag<'a> {
  fn authenticate(&self) -> Result<String, NfcError> {
    log::debug!("Authenticating! Sending signed nonce");
    log::debug!("{} is the realm id", self.realm.slot);
    // Concatenate self.nonce and our_nonce
    let our_nonce = rand::random::<[u8; NONCE_LENGTH]>();
    let mut signature_data = [0u8; NONCE_LENGTH * 2];
    signature_data[0..NONCE_LENGTH].copy_from_slice(&self.nonce);
    signature_data[NONCE_LENGTH..].copy_from_slice(&our_nonce);
    let mut signature = self.sign_message(&signature_data)?;
    // Add our_nonce to signature
    signature.extend_from_slice(&our_nonce);

    let encrypted_association = self
      .target
      .send(Command::new_with_payload_le(
        0xD0, 0x00, 0x00,
        0x00, // Encrypted value length is non-determinate
        512, signature,
      ))?
      .ok_or(NfcError::NoResponse)?;
    let payload = encrypted_association.payload.as_slice();
    let payload = self.decrypt_message(payload)?;
    // take last 8 bytes of association as the nonce
    let nonce = &payload[payload.len() - self.nonce.len()..payload.len()];
    // take the rest as the association
    let association_id = &payload[0..payload.len() - self.nonce.len()];

    if our_nonce != nonce {
      return Err(NfcError::NonceMismatch);
    }

    Ok(
      association_id
        .iter()
        .fold(String::new(), |mut collector, id| {
          write!(collector, "{:02x}", id).unwrap();
          collector
        }),
    )
  }
}

#[derive(Debug)]
struct NfcTargetGuard<'device> {
  device_wrapper: &'device DeviceWrapper<'device>,
}

impl<'device> NfcTargetGuard<'device> {
  fn new(device_wrapper: &'device DeviceWrapper<'device>) -> Option<Self> {
    unsafe {
      let mut nt = MaybeUninit::uninit();
      if nfc_initiator_select_passive_target(
        device_wrapper.device,
        Modulation {
          nmt: ModulationType::NMT_ISO14443A,
          nbr: BaudRate::NBR_106,
        },
        std::ptr::null(),
        0,
        nt.as_mut_ptr(),
      ) <= 0
      {
        // println!("No tag found");
        return None;
      }
    }
    Some(Self { device_wrapper })
  }

  fn send(&self, command: Command) -> Result<Option<Response>, NfcError> {
    let mut response = vec![0u8; command.le.unwrap_or(0).into()];
    let command: Vec<u8> = command.into();
    let response_size = unsafe {
      nfc_initiator_transceive_bytes(
        self.device_wrapper.device,
        command.as_ptr(),
        command.len(),
        response.as_mut_ptr(),
        response.len(),
        2000,
      )
    };
    if response_size < 0 {
      return Err(NfcError::CommunicationError);
    }
    if response_size == 0 {
      return Ok(None);
    }
    // convert response to a vec, from 0..response_size:
    response.truncate(response_size as usize);

    Ok(Some(Response::from(response)))
  }
}

impl<'device> Drop for NfcTargetGuard<'device> {
  fn drop(&mut self) {
    unsafe {
      // let ecode =
      nfc_initiator_deselect_target(self.device_wrapper.device);
      // if ecode != 0 {
      //   eprintln!("Couldn't deslect target!! {}", ecode);
      //   let msg = CString::new("Deselect target :(").unwrap();
      //   nfc_perror(self.device_wrapper.device, msg.as_ptr());
      // }
    };
  }
}

#[derive(Debug)]
pub struct MobileNfcTag<'a> {
  nonce: [u8; NONCE_LENGTH],
  target: NfcTargetGuard<'a>,
  realm: &'a Realm<'a>,
}

impl<'a> MobileNfcTag<'a> {
  fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>, NfcError> {
    // Sign message using the PKCS#8 encoded EC key realm.private_key using SHA256
    let mut signer = Signer::new(
      MessageDigest::sha384(),
      &self.realm.mobile_signing_private_key,
    )
    .unwrap();
    signer.update(message).unwrap();
    Ok(signer.sign_to_vec().unwrap())
  }

  fn decrypt_message(&self, message: &[u8]) -> Result<Vec<u8>, NfcError> {
    let decrypter =
      Decrypter::new(&self.realm.mobile_decryption_private_key).unwrap();
    let message_len = decrypter.decrypt_len(message).unwrap();
    let mut output = vec![0; message_len];
    let length = decrypter.decrypt(message, output.as_mut_slice()).unwrap();
    Ok(output[..length].into())
  }
}

impl<'device> GatekeeperReader<'device> {
  pub(crate) fn find_first_mobile_tag(&self) -> Option<MobileNfcTag> {
    unsafe {
      nfc_device_set_property_bool(
        self.device_wrapper.as_ref().unwrap().device,
        NfcProperty::NP_ACTIVATE_FIELD,
        1,
      )
    };
    unsafe {
      nfc_device_set_property_bool(
        self.device_wrapper.as_ref().unwrap().device,
        NfcProperty::NP_INFINITE_SELECT,
        0,
      )
    };

    let target = NfcTargetGuard::new(self.device_wrapper.as_ref().unwrap())?;

    let response = target
      .send(Command::new_with_payload_le(
        0x00,
        0xA4,
        0x04,
        0x00,
        (NONCE_LENGTH + RESPONSE_PADDING_LENGTH) as u16,
        vec![
          0xf0,
          0x63,
          0x73,
          0x68,
          0x72,
          0x69,
          0x74 + (self.realm.slot as u8),
        ],
      ))
      .ok()?;
    let response = response?;
    if response.payload.len() != NONCE_LENGTH {
      return None;
    }
    let nonce = &response.payload[0..NONCE_LENGTH];
    let mut nonce_arr: [u8; NONCE_LENGTH] = Default::default();
    nonce_arr.copy_from_slice(nonce);
    Some(MobileNfcTag {
      nonce: nonce_arr,
      target,
      realm: &self.realm,
    })
  }
}
