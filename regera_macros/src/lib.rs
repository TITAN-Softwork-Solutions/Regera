// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025
//
// REGERA Proc-Macro crate
//
// Provides compile-time string-encryption/obfuscation macros that embed encrypted
// blobs and generate tiny runtime decrypt shims. Multi-string variants (*ex!) now
// return owned `String`s for ergonomic array destructuring in tests.

extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::{Literal, TokenStream as TokenStream2};
use quote::quote;
use syn::{parse_macro_input, punctuated::Punctuated, LitStr, Token};

use regera_core::{RegeraEngine, pulse};

#[cfg(feature = "deterministic")]
fn random_seed() -> u64 {
    // Reproducible builds: provide REGERA_BUILD_SEED at compile-time.
    let s = env!("REGERA_BUILD_SEED");
    let h = blake3::hash(s.as_bytes());
    u64::from_le_bytes(h.as_bytes()[0..8].try_into().unwrap())
}

#[cfg(not(feature = "deterministic"))]
fn random_seed() -> u64 {
    use rand::{rngs::OsRng, RngCore};
    OsRng.next_u64()
}

fn exsingle_parsed(
    plain: String,
    engine: RegeraEngine,
    decrypt_fn: TokenStream2,
) -> TokenStream {
    let seed: u64 = random_seed();
    let (ct, tag, frag, mask) = pulse(engine, plain.as_bytes(), seed);

    // Turn buffers into literal tokens we can embed.
    let ct_bytes  = ct.iter().map(|b| Literal::u8_unsuffixed(*b));
    let tag_bytes = tag.iter().map(|b| Literal::u8_unsuffixed(*b));
    let frag_rows = frag.iter().map(|blk| {
        let bytes = blk.iter().map(|b| Literal::u8_unsuffixed(*b));
        quote!([#(#bytes),*])
    });
    let mask_rows = mask.iter().map(|blk| {
        let bytes = blk.iter().map(|b| Literal::u8_unsuffixed(*b));
        quote!([#(#bytes),*])
    });

    let seed_lit = Literal::u64_unsuffixed(seed);

    // Returns SecretStr (safer by default)
    let expanded = quote! {{
        let __ct:  &[u8]        = &[#(#ct_bytes),*];
        let __tag: &[u8; 32]    = &[#(#tag_bytes),*];
        let __frag:[[u8; 8]; 4] = [#(#frag_rows),*];
        let __mask:[[u8; 8]; 4] = [#(#mask_rows),*];
        #decrypt_fn(__ct, __tag, __frag, __mask, #seed_lit)
    }};
    expanded.into()
}

fn exmulti_parsed(
    items: Vec<String>,
    engine: RegeraEngine,
    decrypt_fn: TokenStream2,
) -> TokenStream {
    let base_seed: u64 = random_seed();

    let calls = items.into_iter().enumerate().map(|(i, item)| {
        let seed = base_seed ^ (i as u64);
        let (ct, tag, frag, mask) = pulse(engine, item.as_bytes(), seed);

        let ct_bytes  = ct.iter().map(|b| Literal::u8_unsuffixed(*b));
        let tag_bytes = tag.iter().map(|b| Literal::u8_unsuffixed(*b));
        let frag_rows = frag.iter().map(|blk| {
            let bytes = blk.iter().map(|b| Literal::u8_unsuffixed(*b));
            quote!([#(#bytes),*])
        });
        let mask_rows = mask.iter().map(|blk| {
            let bytes = blk.iter().map(|b| Literal::u8_unsuffixed(*b));
            quote!([#(#bytes),*])
        });

        let seed_lit = Literal::u64_unsuffixed(seed);

        // For multi: convert SecretStr -> String so arrays like [String; N] type-check.
        quote! {{
            let __ct:  &[u8]        = &[#(#ct_bytes),*];
            let __tag: &[u8; 32]    = &[#(#tag_bytes),*];
            let __frag:[[u8; 8]; 4] = [#(#frag_rows),*];
            let __mask:[[u8; 8]; 4] = [#(#mask_rows),*];
            #decrypt_fn(__ct, __tag, __frag, __mask, #seed_lit).into_inner()
        }}
    });

    quote!([#(#calls),*]).into()
}

#[proc_macro]
pub fn jesko(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr).value();
    exsingle_parsed(
        lit,
        RegeraEngine::Jesko,
        quote! { ::regera::engines::jesko::Jesko::decrypt },
    )
}

#[proc_macro]
pub fn jeskoex(input: TokenStream) -> TokenStream {
    let items = parse_macro_input!(input with Punctuated::<LitStr, Token![,]>::parse_terminated)
        .into_iter()
        .map(|s| s.value())
        .collect::<Vec<_>>();
    exmulti_parsed(
        items,
        RegeraEngine::Jesko,
        quote! { ::regera::engines::jesko::Jesko::decrypt },
    )
}

#[proc_macro]
pub fn absolut(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr).value();
    exsingle_parsed(
        lit,
        RegeraEngine::Absolut,
        quote! { ::regera::engines::absolut::Absolut::decrypt },
    )
}

#[proc_macro]
pub fn absolutex(input: TokenStream) -> TokenStream {
    let items = parse_macro_input!(input with Punctuated::<LitStr, Token![,]>::parse_terminated)
        .into_iter()
        .map(|s| s.value())
        .collect::<Vec<_>>();
    exmulti_parsed(
        items,
        RegeraEngine::Absolut,
        quote! { ::regera::engines::absolut::Absolut::decrypt },
    )
}

#[proc_macro]
pub fn sadair(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr).value();
    exsingle_parsed(
        lit,
        RegeraEngine::Sadair,
        quote! { ::regera::engines::sadair::Sadair::decrypt },
    )
}

#[proc_macro]
pub fn sadairex(input: TokenStream) -> TokenStream {
    let items = parse_macro_input!(input with Punctuated::<LitStr, Token![,]>::parse_terminated)
        .into_iter()
        .map(|s| s.value())
        .collect::<Vec<_>>();
    exmulti_parsed(
        items,
        RegeraEngine::Sadair,
        quote! { ::regera::engines::sadair::Sadair::decrypt },
    )
}

#[proc_macro]
pub fn gamera(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr).value();
    exsingle_parsed(
        lit,
        RegeraEngine::Gamera,
        quote! { ::regera::engines::gamera::Gamera::decrypt },
    )
}

#[proc_macro]
pub fn gameraex(input: TokenStream) -> TokenStream {
    let items = parse_macro_input!(input with Punctuated::<LitStr, Token![,]>::parse_terminated)
        .into_iter()
        .map(|s| s.value())
        .collect::<Vec<_>>();
    exmulti_parsed(
        items,
        RegeraEngine::Gamera,
        quote! { ::regera::engines::gamera::Gamera::decrypt },
    )
}