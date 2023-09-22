use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod vault_engine;
use crate::vault_engine::VaultEngineAttributes;

#[proc_macro_attribute]
pub fn vault_engine(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attrs = parse_macro_input!(attr as VaultEngineAttributes);
    let input = parse_macro_input!(item as DeriveInput);

    vault_engine::impl_vault_engine(attrs, input)
        .unwrap_or_else(|err| syn::Error::into_compile_error(err).into())
}
