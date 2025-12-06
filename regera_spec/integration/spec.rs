// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025 TITAN Softwork Solutions

/*!
================================================================================
 Regera – Engine Specification & Diagnostic Harness
--------------------------------------------------------------------------------
 Repository : REGERA
 Project    : Regera
 File       : regera_spec (bin)
 Org        : TITAN Softwork Solutions

 Description:
   Regera is a compile-time macro encryption framework for Rust that protects
   embedded string literals with high-entropy encryption engines. Each engine
   targets a specific cryptographic profile:

     • Absolut : ASCON128 × KMAC256
     • Gamera  : Complex inline assembly
     • Jesko   : ChaCha20 × Blake3
     • Sadair  : AES-GCM-256

   This binary provides:
     • A human-readable diagnostic CLI for exercising each engine.
     • A structured test harness (via `cargo test`) that asserts core runtime
       invariants of the proc-macro expansion.

 License:
   GNU Affero General Public License v3.0 (AGPL-3.0)
   See: https://www.gnu.org/licenses/agpl-3.0.html
================================================================================
*/

use std::{env, process};

#[allow(unused_imports)]
use regera::Encryptor;

use regera::{
    absolut,   absolutex,
    gamera,    gameraex,
    jesko,     jeskoex,
    sadair,    sadairex,
};

/// Simple CLI front-end.
///
/// Examples:
///   cargo run --bin regera_spec
///   cargo run --bin regera_spec -- --engine jesko
///   cargo run --bin regera_spec -- --list
fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    match args.as_slice() {
        // No arguments: run full diagnostic sweep.
        [] => {
            print_suite_header();
            run_all_diagnostics();
            print_suite_footer(true);
        }

        // List available engines.
        [flag] if flag == "--list" || flag == "-l" => {
            print_engine_list();
        }

        // Run a single engine diagnostic.
        [flag, name] if flag == "--engine" || flag == "-e" => {
            print_suite_header();

            let ok = match name.to_ascii_lowercase().as_str() {
                "jesko"   => { test_jesko_diag();   true }
                "absolut" => { test_absolut_diag(); true }
                "sadair"  => { test_sadair_diag();  true }
                "gamera"  => { test_gamera_diag();  true }
                other => {
                    eprintln!();
                    eprintln!("[ ERROR ] Unknown engine: `{other}`");
                    eprintln!("          Use `--list` to see available engines.");
                    print_suite_footer(false);
                    process::exit(2);
                }
            };

            print_suite_footer(ok);
        }

        // Anything else: usage.
        _ => {
            print_usage();
            process::exit(1);
        }
    }
}

/* =============================================================================
 *  Diagnostic CLI helpers
 * =============================================================================
 */

fn print_suite_header() {
    println!();
    println!("============================================================");
    println!(" REGERA ENGINE DIAGNOSTIC");
    println!("------------------------------------------------------------");
    println!(" Project : Regera");
    println!(" Binary  : regera_spec");
    println!(" Mode    : Diagnostic");
    println!("============================================================");
    println!();
}

fn print_suite_footer(success: bool) {
    println!();
    println!("============================================================");
    if success {
        println!(" DIAGNOSTIC RESULT : OK");
    } else {
        println!(" DIAGNOSTIC RESULT : FAILED");
    }
    println!("============================================================");
    println!();
}

fn print_usage() {
    eprintln!();
    eprintln!("Regera diagnostic harness");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  regera_spec                  Run diagnostics for all engines");
    eprintln!("  regera_spec --engine <name>  Run diagnostics for a single engine");
    eprintln!("  regera_spec --list           List available engines");
    eprintln!();
    eprintln!("Engines:");
    eprintln!("  jesko   | absolut | sadair | gamera");
    eprintln!();
}

fn print_engine_list() {
    println!();
    println!("Available engines:");
    println!("  • jesko");
    println!("  • absolut");
    println!("  • sadair");
    println!("  • gamera");
    println!();
}

/// Run diagnostics for all engines in a fixed order.
fn run_all_diagnostics() {
    test_jesko_diag();
    test_absolut_diag();
    test_sadair_diag();
    test_gamera_diag();
}

/* =============================================================================
 *  Per-engine diagnostic output (human-oriented, not assertions)
 * =============================================================================
 */

fn test_jesko_diag() {
    let secret = jesko!("KOENIG SSmVza28=");
    let [a, b]: [String; 2] = jeskoex!("odium", "andromeda");

    println!("------------------------------------------------------------");
    println!("[ JESKO ENGINE ]");
    println!("  Primary macro   : jesko!(...)");
    println!("  Sample output   : {secret}");
    println!();
    println!("  Extended macro  : jeskoex!(\"odium\", \"andromeda\")");
    println!("    [0]           : {a}");
    println!("    [1]           : {b}");
    println!("------------------------------------------------------------");
    println!();
}

fn test_absolut_diag() {
    let boot = absolut!("KOENIG U21WemEyOVM=");
    let [a, b, c]: [String; 3] =
        absolutex!("amensia", "distortion", "deep-fusion");

    println!("------------------------------------------------------------");
    println!("[ ABSOLUT ENGINE ]");
    println!("  Primary macro   : absolut!(...)");
    println!("  Sample output   : {boot}");
    println!();
    println!("  Extended macro  : absolutex!(\"amensia\", \"distortion\", \"deep-fusion\")");
    println!("    [0]           : {a}");
    println!("    [1]           : {b}");
    println!("    [2]           : {c}");
    println!("------------------------------------------------------------");
    println!();
}

fn test_sadair_diag() {
    let sig = sadair!("KOENIG U2FkYWly");
    let [x, y, z]: [String; 3] =
        sadairex!("tokyo", "space-attack", "blindspot");

    println!("------------------------------------------------------------");
    println!("[ SADAIR ENGINE ]");
    println!("  Primary macro   : sadair!(...)");
    println!("  Sample output   : {sig}");
    println!();
    println!("  Extended macro  : sadairex!(\"tokyo\", \"space-attack\", \"blindspot\")");
    println!("    [0]           : {x}");
    println!("    [1]           : {y}");
    println!("    [2]           : {z}");
    println!("------------------------------------------------------------");
    println!();
}

fn test_gamera_diag() {
    let boot = gamera!("KOENIG R2FtZXJh");
    let [a, b]: [String; 2] = gameraex!("infinity", "volume-two");

    println!("------------------------------------------------------------");
    println!("[ GAMERA ENGINE ]");
    println!("  Primary macro   : gamera!(...)");
    println!("  Sample output   : {boot}");
    println!();
    println!("  Extended macro  : gameraex!(\"infinity\", \"volume-two\")");
    println!("    [0]           : {a}");
    println!("    [1]           : {b}");
    println!("------------------------------------------------------------");
    println!();
}

/* =============================================================================
 *  Unit test harness (cargo test)
 * =============================================================================
 */

#[cfg(test)]
mod tests {
    use super::*;

    /* -------------------------------------------------------------------------
     *  Generic helpers
     * -------------------------------------------------------------------------
     */

    /// Ensure a single-value macro expansion is deterministic and non-empty.
    fn assert_single_deterministic<F>(engine: &str, make: F)
    where
        F: Fn() -> String,
    {
        let first = make();
        let second = make();

        assert!(
            !first.is_empty(),
            "[{engine}] primary macro produced empty output"
        );
        assert_eq!(
            first, second,
            "[{engine}] primary macro expansion is not deterministic"
        );
    }

    /// Ensure a multi-value macro expansion is deterministic and non-empty.
    fn assert_multi_deterministic<F, const N: usize>(engine: &str, make: F)
    where
        F: Fn() -> [String; N],
    {
        let first = make();
        let second = make();

        assert_eq!(
            first, second,
            "[{engine}] extended macro expansion is not deterministic"
        );

        for (idx, value) in first.iter().enumerate() {
            assert!(
                !value.is_empty(),
                "[{engine}] extended macro index {idx} produced empty output"
            );
        }
    }

    /* -------------------------------------------------------------------------
     *  Jesko
     * -------------------------------------------------------------------------
     */

    #[test]
    fn jesko_primary_is_deterministic_and_non_empty() {
        // jesko! returns SecretStr -> convert to String
        assert_single_deterministic("JESKO", || {
            jesko!("KOENIG SSmVza28=").to_string()
        });
    }

    #[test]
    fn jesko_extended_is_deterministic_and_non_empty() {
        assert_multi_deterministic("JESKO", || jeskoex!("odium", "andromeda"));
    }

    /* -------------------------------------------------------------------------
     *  Absolut
     * -------------------------------------------------------------------------
     */

    #[test]
    fn absolut_primary_is_deterministic_and_non_empty() {
        // absolut! returns SecretStr -> convert to String
        assert_single_deterministic("ABSOLUT", || {
            absolut!("KOENIG U21WemEyOVM=").to_string()
        });
    }

    #[test]
    fn absolut_extended_is_deterministic_and_non_empty() {
        assert_multi_deterministic("ABSOLUT", || {
            absolutex!("amensia", "distortion", "deep-fusion")
        });
    }

    /* -------------------------------------------------------------------------
     *  Sadair
     * -------------------------------------------------------------------------
     */

    #[test]
    fn sadair_primary_is_deterministic_and_non_empty() {
        // sadair! returns SecretStr -> convert to String
        assert_single_deterministic("SADAIR", || {
            sadair!("KOENIG U2FkYWly").to_string()
        });
    }

    #[test]
    fn sadair_extended_is_deterministic_and_non_empty() {
        assert_multi_deterministic("SADAIR", || {
            sadairex!("tokyo", "space-attack", "blindspot")
        });
    }

    /* -------------------------------------------------------------------------
     *  Gamera
     * -------------------------------------------------------------------------
     */

    #[test]
    fn gamera_primary_is_deterministic_and_non_empty() {
        // gamera! returns SecretStr -> convert to String
        assert_single_deterministic("GAMERA", || {
            gamera!("KOENIG R2FtZXJh").to_string()
        });
    }

    #[test]
    fn gamera_extended_is_deterministic_and_non_empty() {
        assert_multi_deterministic("GAMERA", || {
            gameraex!("infinity", "volume-two")
        });
    }
}