use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
    DeriveInput, Expr, ExprLit, ExprPath, Lit, LitStr, Meta, MetaNameValue, Path, Token,
};

#[derive(Default)]
pub struct VaultEngineAttributes {
    pub subpath: Option<LitStr>,
    pub client_type: Option<Path>,
}

impl Parse for VaultEngineAttributes {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut attrs = VaultEngineAttributes::default();

        for meta in Punctuated::<Meta, Token![,]>::parse_terminated(input)? {
            match meta {
                Meta::NameValue(MetaNameValue {
                    path,
                    value:
                        Expr::Lit(ExprLit {
                            lit: Lit::Str(lit), ..
                        }),
                    ..
                }) if path.is_ident("subpath") => attrs.subpath = Some(lit),

                Meta::NameValue(MetaNameValue {
                    path,
                    value: Expr::Path(ExprPath { path: value, .. }),
                    ..
                }) if path.is_ident("client") => attrs.client_type = Some(value),

                _ => todo!(),
            }
        }

        Ok(attrs)
    }
}

pub fn impl_vault_engine(
    attrs: VaultEngineAttributes,
    input: DeriveInput,
) -> syn::Result<TokenStream> {
    let ident = input.ident;

    let subpath = attrs
        .subpath
        .map(|lit| {
            quote! { Some(#lit) }
        })
        .unwrap_or(quote! { None });

    let client = attrs.client_type.unwrap();

    Ok(quote! {
        #[automatically_derived]
        pub struct #ident {
            mount: String,
            client: VaultClient,
        }

        #[automatically_derived]
        impl Engine for #ident {
            type Client = #client;

            fn mount(&self) -> &String {
                &self.mount
            }

            fn mount_mut(&mut self) -> &mut String {
                &mut self.mount
            }

            fn client(&self) -> &Self::Client {
                &self.client
            }

            fn subpath(&self) -> Option<&str> {
                #subpath
            }
        }

        #[automatically_derived]
        impl From<#client> for #ident {
            fn from(value: #client) -> Self {
                #ident {
                    client: value,
                    mount: "".to_string(),
                }
            }
        }
    }
    .into())
}
