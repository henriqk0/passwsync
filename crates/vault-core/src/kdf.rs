use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::{MasterPassword, VaultError, VaultKey};

/// Argon2id cost parameters, stored in the (authenticated) file header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfConfig {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfConfig {
    pub const DEFAULT: Self = Self {
        memory_kib: 65_536,
        iterations: 12,
        parallelism: 1,
    };
    /// Smallest accepted cost; tests use it so they stay fast without a weaker bypass.
    pub const MINIMUM: Self = Self {
        memory_kib: 19_456,
        iterations: 2,
        parallelism: 1,
    };

    /// Rejects values a malicious file could use to exhaust memory or weaken the key.
    pub fn validate(&self) -> Result<(), VaultError> {
        let in_range = (19_456..=1_048_576).contains(&self.memory_kib)
            && (2..=100).contains(&self.iterations)
            && (1..=16).contains(&self.parallelism);
        if in_range {
            Ok(())
        } else {
            Err(VaultError::KdfParamsOutOfRange)
        }
    }
}

pub(crate) fn random_salt() -> Result<[u8; 32], VaultError> {
    let mut salt = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| VaultError::Rng)?;
    Ok(salt)
}

pub(crate) fn derive_key(
    password: &MasterPassword,
    config: &KdfConfig,
    salt: &[u8; 32],
) -> Result<VaultKey, VaultError> {
    config.validate()?;
    let params = Params::new(
        config.memory_kib,
        config.iterations,
        config.parallelism,
        Some(32),
    )
    .map_err(|_| VaultError::KdfParamsOutOfRange)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut *output)
        .map_err(|_| VaultError::KdfParamsOutOfRange)?;
    Ok(VaultKey::from_bytes(*output))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn password(s: &str) -> MasterPassword {
        MasterPassword::new(s.to_string())
    }

    #[test]
    fn default_and_minimum_values() {
        assert_eq!(
            KdfConfig::DEFAULT,
            KdfConfig {
                memory_kib: 65_536,
                iterations: 12,
                parallelism: 1
            }
        );
        assert_eq!(
            KdfConfig::MINIMUM,
            KdfConfig {
                memory_kib: 19_456,
                iterations: 2,
                parallelism: 1
            }
        );
    }

    #[test]
    fn bounds_are_inclusive_and_checked_on_each_side() {
        let ok = |m, t, p| {
            KdfConfig {
                memory_kib: m,
                iterations: t,
                parallelism: p,
            }
            .validate()
        };
        assert!(ok(19_456, 2, 1).is_ok());
        assert!(ok(1_048_576, 100, 16).is_ok());
        for (m, t, p) in [
            (19_455, 2, 1),
            (1_048_577, 2, 1),
            (19_456, 1, 1),
            (19_456, 101, 1),
            (19_456, 2, 0),
            (19_456, 2, 17),
        ] {
            assert!(
                matches!(ok(m, t, p), Err(VaultError::KdfParamsOutOfRange)),
                "{m} {t} {p}"
            );
        }
    }

    #[test]
    fn derivation_is_deterministic_and_input_sensitive() {
        let salt = [1u8; 32];
        let a = derive_key(&password("correct horse"), &KdfConfig::MINIMUM, &salt).unwrap();
        let again = derive_key(&password("correct horse"), &KdfConfig::MINIMUM, &salt).unwrap();
        let other_salt =
            derive_key(&password("correct horse"), &KdfConfig::MINIMUM, &[2u8; 32]).unwrap();
        let other_password =
            derive_key(&password("battery staple"), &KdfConfig::MINIMUM, &salt).unwrap();
        assert_eq!(a.as_bytes(), again.as_bytes());
        assert_ne!(a.as_bytes(), other_salt.as_bytes());
        assert_ne!(a.as_bytes(), other_password.as_bytes());
    }

    #[test]
    fn derivation_rejects_out_of_range_config() {
        let bad = KdfConfig {
            memory_kib: 1,
            iterations: 1,
            parallelism: 1,
        };
        assert!(matches!(
            derive_key(&password("correct horse"), &bad, &[0u8; 32]),
            Err(VaultError::KdfParamsOutOfRange)
        ));
    }
}
