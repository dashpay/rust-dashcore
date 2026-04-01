//! Procedural macros for deriving FFI-compatible types from Rust types.
//!
//! Provides the `FFIType` derive macro which generates `#[repr(C)]` struct/enum
//! definitions, `From` implementations, and `extern "C"` destroy functions.
//! All generated code is wrapped in `#[cfg(feature = "ffi")]`.
//!
//! # Struct example
//!
//! ```ignore
//! #[derive(FFIType)]
//! #[ffi(prefix = "dash_spv_ffi")]
//! #[ffi_computed(percentage: f64)]
//! pub struct BlockHeadersProgress {
//!     #[ffi(convert = "into")]
//!     state: SyncState,
//!     tip_height: u32,
//!     #[ffi(convert = "instant_secs")]
//!     last_activity: Instant,
//! }
//! ```
//!
//! Generates `FFIBlockHeadersProgress` with `From<&BlockHeadersProgress>` and
//! `dash_spv_ffi_block_headers_progress_destroy`.
//!
//! # Enum example
//!
//! ```ignore
//! #[derive(FFIType)]
//! #[ffi(prefix = "dash_spv_ffi")]
//! pub enum SyncState {
//!     WaitForEvents,
//!     Syncing,
//! }
//! ```
//!
//! Generates `FFISyncState` with `From<SyncState>` and
//! `dash_spv_ffi_sync_state_destroy`.

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::{
    parse_macro_input, Attribute, Data, DeriveInput, Fields, GenericArgument, Ident, LitStr,
    PathArguments, Token, Type,
};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Derive macro for generating FFI-compatible types.
///
/// # Struct/enum-level attributes
///
/// - `#[ffi(prefix = "crate_ffi")]` — set the destroy function prefix
///   (e.g. `crate_ffi_type_name_destroy`). Defaults to `"ffi"`.
/// - `#[ffi(bidirectional)]` — (enums only) generate `From` in both directions.
/// - `#[ffi_computed(name: Type)]` — add a computed field calling `src.name()`.
/// - `#[ffi_computed(name: Type, convert = "into")]` — with `.into()` on result.
///
/// # Field attributes
///
/// - `#[ffi(skip)]` — omit this field from the FFI type.
/// - `#[ffi(convert = "into")]` — call `.into()` on the getter result.
/// - `#[ffi(convert = "as_u32")]` — cast the getter result as `u32`.
/// - `#[ffi(convert = "instant_secs")]` — call `.elapsed().as_secs()` on `Instant`.
/// - `#[ffi(convert = "result_to_ptr")]` — convert `Result<&T>`/`Option<T>` getter
///   to `*mut FFIT` via `Box::into_raw`. Destroy function will free the pointer.
/// - `#[ffi(getter = "name")]` — use a different method name than the field name.
/// - `#[ffi(ffi_type = "Type")]` — override the FFI field type.
#[proc_macro_derive(FFIType, attributes(ffi, ffi_computed))]
pub fn derive_ffi_type(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let result = match &input.data {
        Data::Struct(data_struct) => derive_struct(&input, data_struct),
        Data::Enum(data_enum) => derive_enum(&input, data_enum),
        Data::Union(_) => {
            return syn::Error::new_spanned(&input, "FFIType cannot be derived for unions")
                .to_compile_error()
                .into();
        }
    };

    result.into()
}

// ---------------------------------------------------------------------------
// Snake-case conversion
// ---------------------------------------------------------------------------

/// Convert PascalCase to snake_case. Handles consecutive uppercase like "FFI" → "ffi".
fn to_snake_case(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 4);
    let chars: Vec<char> = s.chars().collect();

    for (i, &c) in chars.iter().enumerate() {
        if c.is_uppercase() {
            let prev_is_lower = i > 0 && chars[i - 1].is_lowercase();
            let next_is_lower = i + 1 < chars.len() && chars[i + 1].is_lowercase();
            if i > 0 && (prev_is_lower || next_is_lower) {
                result.push('_');
            }
            result.push(c.to_ascii_lowercase());
        } else {
            result.push(c);
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Attribute parsing
// ---------------------------------------------------------------------------

/// Per-field configuration parsed from `#[ffi(...)]` attributes.
#[derive(Default)]
struct FieldConfig {
    skip: bool,
    convert: Option<String>,
    getter: Option<String>,
    ffi_type: Option<String>,
}

impl FieldConfig {
    fn from_attrs(attrs: &[Attribute]) -> Self {
        let mut config = Self::default();
        for attr in attrs {
            if !attr.path().is_ident("ffi") {
                continue;
            }
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("skip") {
                    config.skip = true;
                } else if meta.path.is_ident("convert") {
                    let value = meta.value()?;
                    let s: LitStr = value.parse()?;
                    config.convert = Some(s.value());
                } else if meta.path.is_ident("getter") {
                    let value = meta.value()?;
                    let s: LitStr = value.parse()?;
                    config.getter = Some(s.value());
                } else if meta.path.is_ident("ffi_type") {
                    let value = meta.value()?;
                    let s: LitStr = value.parse()?;
                    config.ffi_type = Some(s.value());
                }
                Ok(())
            });
        }
        config
    }
}

/// Struct/enum-level configuration parsed from `#[ffi(...)]` attributes.
struct TypeConfig {
    prefix: String,
    bidirectional: bool,
}

impl TypeConfig {
    fn from_attrs(attrs: &[Attribute]) -> Self {
        let mut prefix = String::from("ffi");
        let mut bidirectional = false;

        for attr in attrs {
            if !attr.path().is_ident("ffi") {
                continue;
            }
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("prefix") {
                    let value = meta.value()?;
                    let s: LitStr = value.parse()?;
                    prefix = s.value();
                } else if meta.path.is_ident("bidirectional") {
                    bidirectional = true;
                }
                Ok(())
            });
        }

        TypeConfig {
            prefix,
            bidirectional,
        }
    }
}

/// A computed field declared at the struct level via `#[ffi_computed(...)]`.
struct ComputedField {
    name: Ident,
    ty: Type,
    convert: Option<String>,
}

impl Parse for ComputedField {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let name: Ident = input.parse()?;
        input.parse::<Token![:]>()?;
        let ty: Type = input.parse()?;

        let mut convert = None;
        if input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
            let key: Ident = input.parse()?;
            if key != "convert" {
                return Err(syn::Error::new(key.span(), "expected `convert`"));
            }
            input.parse::<Token![=]>()?;
            let val: LitStr = input.parse()?;
            convert = Some(val.value());
        }

        Ok(ComputedField {
            name,
            ty,
            convert,
        })
    }
}

fn parse_computed_fields(attrs: &[Attribute]) -> Vec<ComputedField> {
    let mut computed = Vec::new();
    for attr in attrs {
        if !attr.path().is_ident("ffi_computed") {
            continue;
        }
        if let Ok(field) = attr.parse_args::<ComputedField>() {
            computed.push(field);
        }
    }
    computed
}

// ---------------------------------------------------------------------------
// Type mapping helpers
// ---------------------------------------------------------------------------

/// Extract the inner type `T` from `Option<T>`.
fn extract_option_inner(ty: &Type) -> Option<&Type> {
    if let Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            if segment.ident == "Option" {
                if let PathArguments::AngleBracketed(args) = &segment.arguments {
                    if let Some(GenericArgument::Type(inner)) = args.args.first() {
                        return Some(inner);
                    }
                }
            }
        }
    }
    None
}

/// Get the last ident from a type path.
fn type_last_ident(ty: &Type) -> Option<&Ident> {
    if let Type::Path(type_path) = ty {
        type_path.path.segments.last().map(|s| &s.ident)
    } else {
        None
    }
}

/// Map a Rust type to its FFI-compatible equivalent.
fn map_type_to_ffi(ty: &Type, config: &FieldConfig) -> TokenStream2 {
    if let Some(ref type_str) = config.ffi_type {
        let parsed: Type = syn::parse_str(type_str).expect("invalid ffi_type");
        return quote! { #parsed };
    }

    if let Some(ident) = type_last_ident(ty) {
        let ident_str = ident.to_string();
        match ident_str.as_str() {
            "u8" | "u16" | "u32" | "u64" | "i8" | "i16" | "i32" | "i64" | "f32" | "f64"
            | "bool" => return quote! { #ty },
            "usize" => return quote! { u32 },
            "Instant" => return quote! { u64 },
            _ => {
                if config.convert.as_deref() == Some("into") {
                    let ffi_ident = format_ident!("FFI{}", ident);
                    return quote! { #ffi_ident };
                }
            }
        }
    }

    if config.convert.as_deref() == Some("result_to_ptr") {
        if let Some(inner) = extract_option_inner(ty) {
            if let Some(ident) = type_last_ident(inner) {
                let ffi_ident = format_ident!("FFI{}", ident);
                return quote! { *mut #ffi_ident };
            }
        }
    }

    quote! { #ty }
}

/// Build the destroy function name: `{prefix}_{snake(original_name)}_destroy`.
fn make_destroy_fn_name(prefix: &str, original_name: &Ident) -> Ident {
    let snake = to_snake_case(&original_name.to_string());
    format_ident!("{}_{}_destroy", prefix, snake)
}

// ---------------------------------------------------------------------------
// Struct derivation
// ---------------------------------------------------------------------------

fn derive_struct(input: &DeriveInput, data: &syn::DataStruct) -> TokenStream2 {
    let name = &input.ident;
    let ffi_name = format_ident!("FFI{}", name);
    let vis = &input.vis;
    let type_config = TypeConfig::from_attrs(&input.attrs);
    let destroy_fn_name = make_destroy_fn_name(&type_config.prefix, name);

    let fields = match &data.fields {
        Fields::Named(fields) => &fields.named,
        _ => {
            return syn::Error::new_spanned(
                input,
                "FFIType can only be derived for structs with named fields",
            )
            .to_compile_error();
        }
    };

    let computed_fields = parse_computed_fields(&input.attrs);

    let mut ffi_fields = Vec::new();
    let mut from_fields = Vec::new();
    let mut ptr_destroy_stmts = Vec::new();

    // Computed fields first (appear at the top of the FFI struct)
    for computed in &computed_fields {
        let field_name = &computed.name;
        let field_type = &computed.ty;

        ffi_fields.push(quote! { pub #field_name: #field_type });

        let conversion = match computed.convert.as_deref() {
            Some("into") => quote! { src.#field_name().into() },
            _ => quote! { src.#field_name() },
        };
        from_fields.push(quote! { #field_name: #conversion });
    }

    // Struct fields
    for field in fields {
        let field_name = field.ident.as_ref().unwrap();
        let field_type = &field.ty;
        let config = FieldConfig::from_attrs(&field.attrs);

        if config.skip {
            continue;
        }

        let ffi_field_type = map_type_to_ffi(field_type, &config);

        ffi_fields.push(quote! { pub #field_name: #ffi_field_type });

        let getter_name = if let Some(ref g) = config.getter {
            format_ident!("{}", g)
        } else {
            field_name.clone()
        };

        let conversion = match config.convert.as_deref() {
            Some("into") => quote! { src.#getter_name().into() },
            Some("as_u32") => quote! { src.#getter_name() as u32 },
            Some("instant_secs") => quote! { src.#getter_name().elapsed().as_secs() },
            Some("result_to_ptr") => {
                let ffi_inner = if let Some(inner) = extract_option_inner(field_type) {
                    if let Some(ident) = type_last_ident(inner) {
                        let ffi_ident = format_ident!("FFI{}", ident);
                        quote! { #ffi_ident }
                    } else {
                        quote! { compile_error!("result_to_ptr: cannot determine inner type") }
                    }
                } else {
                    quote! { compile_error!("result_to_ptr requires Option<T> field type") }
                };

                // Build destroy statement for this pointer field
                if let Some(inner) = extract_option_inner(field_type) {
                    if let Some(ident) = type_last_ident(inner) {
                        let inner_destroy =
                            make_destroy_fn_name(&type_config.prefix, ident);
                        ptr_destroy_stmts.push(quote! {
                            if !p.#field_name.is_null() {
                                #inner_destroy(p.#field_name);
                            }
                        });
                    }
                }

                quote! {
                    src.#getter_name()
                        .ok()
                        .map(|p| Box::into_raw(Box::new(#ffi_inner::from(p))))
                        .unwrap_or(std::ptr::null_mut())
                }
            }
            _ => quote! { src.#getter_name() },
        };

        from_fields.push(quote! { #field_name: #conversion });
    }

    let destroy_body = if ptr_destroy_stmts.is_empty() {
        quote! {
            if !ptr.is_null() {
                drop(Box::from_raw(ptr));
            }
        }
    } else {
        quote! {
            if !ptr.is_null() {
                let p = Box::from_raw(ptr);
                #(#ptr_destroy_stmts)*
            }
        }
    };

    quote! {
        #[cfg(feature = "ffi")]
        #[repr(C)]
        #[derive(Debug, Clone)]
        #vis struct #ffi_name {
            #(#ffi_fields),*
        }

        #[cfg(feature = "ffi")]
        impl From<&#name> for #ffi_name {
            fn from(src: &#name) -> Self {
                Self {
                    #(#from_fields),*
                }
            }
        }

        #[cfg(feature = "ffi")]
        #[no_mangle]
        pub unsafe extern "C" fn #destroy_fn_name(ptr: *mut #ffi_name) {
            #destroy_body
        }
    }
}

// ---------------------------------------------------------------------------
// Enum derivation
// ---------------------------------------------------------------------------

fn derive_enum(input: &DeriveInput, data: &syn::DataEnum) -> TokenStream2 {
    let name = &input.ident;
    let ffi_name = format_ident!("FFI{}", name);
    let vis = &input.vis;
    let type_config = TypeConfig::from_attrs(&input.attrs);
    let destroy_fn_name = make_destroy_fn_name(&type_config.prefix, name);

    let mut ffi_variants = Vec::new();
    let mut from_arms = Vec::new();
    let mut reverse_arms = Vec::new();

    for (idx, variant) in data.variants.iter().enumerate() {
        let variant_name = &variant.ident;
        let discriminant = syn::LitInt::new(&idx.to_string(), Span::call_site());

        ffi_variants.push(quote! { #variant_name = #discriminant });

        let pattern = match &variant.fields {
            Fields::Unit => quote! { #name::#variant_name },
            Fields::Unnamed(_) => quote! { #name::#variant_name(..) },
            Fields::Named(_) => quote! { #name::#variant_name { .. } },
        };
        from_arms.push(quote! { #pattern => #ffi_name::#variant_name });

        if type_config.bidirectional {
            reverse_arms.push(quote! { #ffi_name::#variant_name => #name::#variant_name });
        }
    }

    let reverse_impl = if type_config.bidirectional {
        quote! {
            #[cfg(feature = "ffi")]
            impl From<#ffi_name> for #name {
                fn from(src: #ffi_name) -> Self {
                    match src {
                        #(#reverse_arms),*
                    }
                }
            }
        }
    } else {
        quote! {}
    };

    quote! {
        #[cfg(feature = "ffi")]
        #[repr(C)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #vis enum #ffi_name {
            #(#ffi_variants),*
        }

        #[cfg(feature = "ffi")]
        impl From<#name> for #ffi_name {
            fn from(src: #name) -> Self {
                match src {
                    #(#from_arms),*
                }
            }
        }

        #reverse_impl

        #[cfg(feature = "ffi")]
        #[no_mangle]
        pub unsafe extern "C" fn #destroy_fn_name(ptr: *mut #ffi_name) {
            if !ptr.is_null() {
                drop(Box::from_raw(ptr));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snake_case_conversion() {
        assert_eq!(to_snake_case("BlockHeadersProgress"), "block_headers_progress");
        assert_eq!(to_snake_case("SyncState"), "sync_state");
        assert_eq!(to_snake_case("FiltersProgress"), "filters_progress");
        assert_eq!(to_snake_case("ChainLockProgress"), "chain_lock_progress");
        assert_eq!(to_snake_case("InstantSendProgress"), "instant_send_progress");
        assert_eq!(to_snake_case("SyncProgress"), "sync_progress");
        assert_eq!(to_snake_case("MempoolProgress"), "mempool_progress");
        assert_eq!(to_snake_case("HTTPServer"), "http_server");
    }

    #[test]
    fn destroy_fn_naming() {
        let name = Ident::new("BlockHeadersProgress", Span::call_site());
        assert_eq!(
            make_destroy_fn_name("dash_spv_ffi", &name).to_string(),
            "dash_spv_ffi_block_headers_progress_destroy"
        );
        assert_eq!(
            make_destroy_fn_name("ffi", &name).to_string(),
            "ffi_block_headers_progress_destroy"
        );
    }
}
