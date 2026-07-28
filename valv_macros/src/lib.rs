// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025

extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::{Literal, TokenStream as TokenStream2};
use quote::quote;
use syn::{parse_macro_input, punctuated::Punctuated, LitStr, Token};

#[cfg(any(
    feature = "chacha",
    feature = "ascon",
    feature = "aesgcm",
    feature = "xormask",
    feature = "streammask"
))]
use valv_core::{pulse, ValvEngine};

#[cfg(all(
    feature = "deterministic",
    any(
        feature = "chacha",
        feature = "ascon",
        feature = "aesgcm",
        feature = "xormask",
        feature = "streammask"
    )
))]
fn random_seed() -> u64 {
    let s = option_env!("VALV_BUILD_SEED").unwrap_or("valv-deterministic-default-seed");
    let h = blake3::hash(s.as_bytes());
    u64::from_le_bytes(h.as_bytes()[0..8].try_into().unwrap())
}

#[cfg(all(
    not(feature = "deterministic"),
    any(
        feature = "chacha",
        feature = "ascon",
        feature = "aesgcm",
        feature = "xormask",
        feature = "streammask"
    )
))]
fn random_seed() -> u64 {
    use rand::{rngs::OsRng, RngCore};
    OsRng.next_u64()
}

#[cfg(feature = "runtime_bound")]
fn runtime_bound_pepper(span: proc_macro2::Span) -> syn::Result<Vec<u8>> {
    let value = std::env::var("VALV_BUILD_PEPPER").map_err(|_| {
        syn::Error::new(span, "bound! requires VALV_BUILD_PEPPER during compilation")
    })?;
    let pepper = value.into_bytes();
    if pepper.len() < valv_core::MIN_RUNTIME_KEY_MATERIAL_LEN {
        return Err(syn::Error::new(
            span,
            format!(
                "VALV_BUILD_PEPPER must contain at least {} bytes",
                valv_core::MIN_RUNTIME_KEY_MATERIAL_LEN
            ),
        ));
    }
    Ok(pepper)
}

#[cfg(feature = "runtime_bound")]
fn bound_literal(plain: &[u8], pepper: &[u8]) -> syn::Result<(Vec<u8>, [u8; 12])> {
    use rand::{rngs::OsRng, RngCore};

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = valv_core::runtime_bound_encrypt(plain, pepper, &nonce)
        .map_err(|error| syn::Error::new(proc_macro2::Span::call_site(), error.to_string()))?;
    Ok((ciphertext, nonce))
}

#[cfg(feature = "runtime_bound")]
fn quote_bound_literal(ciphertext: &[u8], nonce: &[u8; 12]) -> TokenStream2 {
    let ciphertext = ciphertext.iter().map(|byte| Literal::u8_unsuffixed(*byte));
    let nonce = nonce.iter().map(|byte| Literal::u8_unsuffixed(*byte));

    quote! {{
        let __ct: &'static [u8] = &[#(#ciphertext),*];
        let __nonce: &'static [u8; 12] = &[#(#nonce),*];
        ::valv::RuntimeBoundText::new(__ct, __nonce)
    }}
}

#[cfg(any(
    feature = "chacha",
    feature = "ascon",
    feature = "aesgcm",
    feature = "xormask",
    feature = "streammask"
))]
fn exsingle_parsed(plain: String, engine: ValvEngine, decrypt_fn: TokenStream2) -> TokenStream {
    let seed: u64 = random_seed();
    let (ct, tag, frag, mask) = pulse(engine, plain.as_bytes(), seed);

    let ct_bytes = ct.iter().map(|b| Literal::u8_unsuffixed(*b));
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

    let expanded = quote! {{
        let __ct:  &'static [u8]     = &[#(#ct_bytes),*];
        let __tag: &'static [u8; 32] = &[#(#tag_bytes),*];
        let __frag: [[u8; 8]; 4]     = [#(#frag_rows),*];
        let __mask: [[u8; 8]; 4]     = [#(#mask_rows),*];

        ::valv::SecretText::new(__ct, __tag, __frag, __mask, #seed_lit, #decrypt_fn)
    }};
    expanded.into()
}

#[cfg(any(
    feature = "chacha",
    feature = "ascon",
    feature = "aesgcm",
    feature = "xormask",
    feature = "streammask"
))]
fn exmulti_parsed(items: Vec<String>, engine: ValvEngine, decrypt_fn: TokenStream2) -> TokenStream {
    let base_seed: u64 = random_seed();

    let calls = items.into_iter().enumerate().map(|(i, item)| {
        let seed = base_seed ^ (i as u64);
        let (ct, tag, frag, mask) = pulse(engine, item.as_bytes(), seed);

        let ct_bytes = ct.iter().map(|b| Literal::u8_unsuffixed(*b));
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

        quote! {{
            let __ct:  &'static [u8]     = &[#(#ct_bytes),*];
            let __tag: &'static [u8; 32] = &[#(#tag_bytes),*];
            let __frag: [[u8; 8]; 4]     = [#(#frag_rows),*];
            let __mask: [[u8; 8]; 4]     = [#(#mask_rows),*];

            ::valv::SecretText::new(__ct, __tag, __frag, __mask, #seed_lit, #decrypt_fn)
        }}
    });

    quote!([#(#calls),*]).into()
}

#[cfg(feature = "runtime_bound")]
#[proc_macro]
pub fn bound(input: TokenStream) -> TokenStream {
    let literal = parse_macro_input!(input as LitStr);
    let mut pepper = match runtime_bound_pepper(literal.span()) {
        Ok(pepper) => pepper,
        Err(error) => return error.to_compile_error().into(),
    };
    let encrypted = bound_literal(literal.value().as_bytes(), &pepper);
    pepper.fill(0);

    match encrypted {
        Ok((ciphertext, nonce)) => quote_bound_literal(&ciphertext, &nonce).into(),
        Err(error) => error.to_compile_error().into(),
    }
}

#[cfg(feature = "runtime_bound")]
#[proc_macro]
pub fn boundex(input: TokenStream) -> TokenStream {
    let literals = parse_macro_input!(input with Punctuated::<LitStr, Token![,]>::parse_terminated);
    let span = literals
        .first()
        .map(LitStr::span)
        .unwrap_or_else(proc_macro2::Span::call_site);
    let mut pepper = match runtime_bound_pepper(span) {
        Ok(pepper) => pepper,
        Err(error) => return error.to_compile_error().into(),
    };

    let encrypted = literals
        .iter()
        .map(|literal| {
            bound_literal(literal.value().as_bytes(), &pepper)
                .map(|(ciphertext, nonce)| quote_bound_literal(&ciphertext, &nonce))
        })
        .collect::<syn::Result<Vec<_>>>();
    pepper.fill(0);

    match encrypted {
        Ok(items) => quote!([#(#items),*]).into(),
        Err(error) => error.to_compile_error().into(),
    }
}

#[cfg(feature = "chacha")]
#[proc_macro]
pub fn chacha(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr).value();
    exsingle_parsed(
        lit,
        ValvEngine::ChaCha,
        quote! { <::valv::engines::chacha::ChaCha as ::valv::Encryptor>::decrypt },
    )
}

#[cfg(feature = "chacha")]
#[proc_macro]
pub fn chachaex(input: TokenStream) -> TokenStream {
    let items = parse_macro_input!(input with Punctuated::<LitStr, Token![,]>::parse_terminated)
        .into_iter()
        .map(|s| s.value())
        .collect::<Vec<_>>();
    exmulti_parsed(
        items,
        ValvEngine::ChaCha,
        quote! { <::valv::engines::chacha::ChaCha as ::valv::Encryptor>::decrypt },
    )
}

#[cfg(feature = "ascon")]
#[proc_macro]
pub fn ascon(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr).value();
    exsingle_parsed(
        lit,
        ValvEngine::Ascon,
        quote! { <::valv::engines::ascon::Ascon as ::valv::Encryptor>::decrypt },
    )
}

#[cfg(feature = "ascon")]
#[proc_macro]
pub fn asconex(input: TokenStream) -> TokenStream {
    let items = parse_macro_input!(input with Punctuated::<LitStr, Token![,]>::parse_terminated)
        .into_iter()
        .map(|s| s.value())
        .collect::<Vec<_>>();
    exmulti_parsed(
        items,
        ValvEngine::Ascon,
        quote! { <::valv::engines::ascon::Ascon as ::valv::Encryptor>::decrypt },
    )
}

#[cfg(feature = "aesgcm")]
#[proc_macro]
pub fn aesgcm(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr).value();
    exsingle_parsed(
        lit,
        ValvEngine::AesGcm,
        quote! { <::valv::engines::aesgcm::AesGcm as ::valv::Encryptor>::decrypt },
    )
}

#[cfg(feature = "aesgcm")]
#[proc_macro]
pub fn aesgcmex(input: TokenStream) -> TokenStream {
    let items = parse_macro_input!(input with Punctuated::<LitStr, Token![,]>::parse_terminated)
        .into_iter()
        .map(|s| s.value())
        .collect::<Vec<_>>();
    exmulti_parsed(
        items,
        ValvEngine::AesGcm,
        quote! { <::valv::engines::aesgcm::AesGcm as ::valv::Encryptor>::decrypt },
    )
}

#[cfg(feature = "xormask")]
#[proc_macro]
pub fn xormask(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr).value();
    exsingle_parsed(
        lit,
        ValvEngine::XorMask,
        quote! { <::valv::engines::xormask::XorMask as ::valv::Encryptor>::decrypt },
    )
}

#[cfg(feature = "xormask")]
#[proc_macro]
pub fn xormaskex(input: TokenStream) -> TokenStream {
    let items = parse_macro_input!(input with Punctuated::<LitStr, Token![,]>::parse_terminated)
        .into_iter()
        .map(|s| s.value())
        .collect::<Vec<_>>();
    exmulti_parsed(
        items,
        ValvEngine::XorMask,
        quote! { <::valv::engines::xormask::XorMask as ::valv::Encryptor>::decrypt },
    )
}

#[cfg(feature = "streammask")]
#[proc_macro]
pub fn streammask(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr).value();
    exsingle_parsed(
        lit,
        ValvEngine::StreamMask,
        quote! { <::valv::engines::streammask::StreamMask as ::valv::Encryptor>::decrypt },
    )
}

#[cfg(feature = "streammask")]
#[proc_macro]
pub fn streammaskex(input: TokenStream) -> TokenStream {
    let items = parse_macro_input!(input with Punctuated::<LitStr, Token![,]>::parse_terminated)
        .into_iter()
        .map(|s| s.value())
        .collect::<Vec<_>>();
    exmulti_parsed(
        items,
        ValvEngine::StreamMask,
        quote! { <::valv::engines::streammask::StreamMask as ::valv::Encryptor>::decrypt },
    )
}
