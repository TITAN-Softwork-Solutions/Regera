//! User-facing facade for Valv compile-time string protection.
//!
//! Valv exposes proc macros such as [`chacha!`] and [`aesgcm!`] that transform
//! string literals into encrypted byte blobs at compile time. At runtime the
//! returned [`SecretText`] decrypts only inside a closure, then drops a
//! zeroizing [`SecretStr`] wrapper.
//!
//! # Example
//!
//! ```
//! use valv::chacha;
//!
//! let host = chacha!("database.internal.example");
//! host.with_str(|value| assert_eq!(value, "database.internal.example"));
//! ```
//!
//! # Security Model
//!
//! Valv hides plaintext from naive static string extraction and reduces
//! plaintext lifetime in memory. It does not make embedded credentials
//! unrecoverable from a binary, because the program must contain enough material
//! to decrypt without external input. Use external runtime secrets for high-value
//! credentials.

#[cfg(feature = "timing_guard")]
pub use valv_core::TIMING_GUARD_MAX_GAP;
pub use valv_core::{engines, pulse, Encryptor, SecretStr, SecretText, ValvEngine, LICENSE};
#[cfg(feature = "runtime_bound")]
pub use valv_core::{RuntimeBoundError, RuntimeBoundText, MIN_RUNTIME_KEY_MATERIAL_LEN};

#[cfg(feature = "aesgcm")]
pub use valv_macros::{aesgcm, aesgcmex};
#[cfg(feature = "ascon")]
pub use valv_macros::{ascon, asconex};
#[cfg(feature = "runtime_bound")]
pub use valv_macros::{bound, boundex};
#[cfg(feature = "chacha")]
pub use valv_macros::{chacha, chachaex};
#[cfg(feature = "streammask")]
pub use valv_macros::{streammask, streammaskex};
#[cfg(feature = "xormask")]
pub use valv_macros::{xormask, xormaskex};
