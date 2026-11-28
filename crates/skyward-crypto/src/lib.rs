pub mod encryption;
pub mod fscrypt;
pub mod gatekeeper;
pub mod keystore;
pub mod locksettings;
pub mod sqlite;
pub mod sharedsecret;
pub mod token;
pub mod user;
pub mod weaver;

#[cfg(target_os = "android")]
pub mod data;
#[cfg(target_os = "android")]
pub mod keymaster;
#[cfg(target_os = "android")]
pub mod keymint;
#[cfg(target_os = "android")]
pub mod keystore2;

#[cfg(target_os = "android")]
impl keystore::Decryptor for keymint::KeyMint<'_> {
    fn gcm_decrypt(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8], body: &[u8]) -> anyhow::Result<Vec<u8>> {
        // The keys unwrapped this way belong to the phone rather than to
        // any user, so none of them is guarded by a screen lock. Written
        // against the two kinds rather than the enum's own method, which
        // would come back here.
        match self {
            keymint::KeyMint::Newer(k) => k.gcm_decrypt(key_blob, app_id, nonce, body, None),
            keymint::KeyMint::Older(k) => k.gcm_decrypt(key_blob, app_id, nonce, body, None),
        }
    }
}
