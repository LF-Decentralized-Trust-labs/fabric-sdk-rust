use proc_macro:: TokenStream;
use quote::quote;
use syn::{Ident, ItemFn, LitStr, Path, Token, parse::{Parse, ParseStream}, punctuated::Punctuated, spanned::Spanned};

struct RouteInput {
    paths: Punctuated<Path, Token![,]>,
}
impl Parse for RouteInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let paths = Punctuated::<Path, Token![,]>::parse_terminated(input)?;
        Ok(RouteInput { paths })
    }
}

/// Optional argument to `#[transaction]` overriding the name a function is
/// exposed under to external callers, e.g. `#[transaction(GetAll)]`.
/// Accepts either a bare identifier or a string literal.
struct TransactionArgs {
    name: Option<String>,
}
impl Parse for TransactionArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.is_empty() {
            return Ok(TransactionArgs { name: None });
        }
        let name = if input.peek(LitStr) {
            input.parse::<LitStr>()?.value()
        } else {
            input.parse::<Ident>()?.to_string()
        };
        Ok(TransactionArgs { name: Some(name) })
    }
}

#[proc_macro]
pub fn functions(item: TokenStream) -> TokenStream {
    let item = syn::parse_macro_input!(item as RouteInput);
    let mut generated_items = Vec::new();
    for path in item.paths{
        let mut path_clone = path.clone();
        let span = path_clone.span();

        let generated_name = adapt_name(
            &path_clone
                .segments
                .last()
                .expect("path has at least one segment")
                .ident
                .to_string(),
        );

        if let Some(last_seg) = path_clone.segments.last_mut() {
            last_seg.ident = Ident::new(&generated_name, span);
        }

        generated_items.push(quote! { Box::new(#path_clone {}) });
    }
    // Assemble the final vec![…] expression.
    let generated = quote! {
        vec![ #(#generated_items),* ]
    };
    generated.into()
}

#[proc_macro_attribute]
pub fn transaction(args: TokenStream, item: TokenStream) -> TokenStream {
    let args = syn::parse_macro_input!(args as TransactionArgs);
    let item = syn::parse_macro_input!(item as ItemFn);

    let fn_name = item.sig.ident.to_string();
    // Name exposed to external callers: the override if given, otherwise the
    // function's own name.
    let name_string = args.name.unwrap_or_else(|| fn_name.clone());
    // The generated struct keeps a name derived from the function name so the
    // `functions!` macro can locate it from the function path.
    let name_ident = Ident::new(adapt_name(&fn_name).as_str(),item.span());
    let fn_ident = item.sig.ident.clone();
    let argument_size = item.sig.inputs.len()-1;
    let indices = 0..argument_size;
    // Fully-qualified paths so the generated code is self-contained and does not
    // depend on what the caller has brought into scope (e.g. `use fabric_sdk::prelude::*`).
    let indexed_args = quote! {
        #(
            match ::fabric_sdk::prelude::serde_json::from_str(args[#indices].as_str()){
                Ok(value) => value,
                Err(_) => {
                    ::fabric_sdk::prelude::serde_json::from_str(format!("\"{}\"",args[#indices]).as_str()).map_err(|e| format!("Unable to deserialize argument; {e}"))?
                }
            }
        ),*
    };

    let generated = quote! {
            pub struct #name_ident{}
            impl ::fabric_sdk::chaincode::Callable for #name_ident {
                fn call(&self, ctx: ::fabric_sdk::chaincode::context::Context, args: Vec<String>) -> ::fabric_sdk::prelude::tokio::task::JoinHandle<Result<String, String>> {
                    ::fabric_sdk::prelude::tokio::spawn(async move{
                        if args.len() != #argument_size{
                            return Err(format!("Found {} arguments but expected {}",args.len(),#argument_size));
                        }
                        ::fabric_sdk::prelude::serde_json::to_string(&#fn_ident(ctx, #indexed_args).await).map_err(|e| e.to_string())
                    })
                }
                fn name(&self) -> &str{
                    #name_string
                }
            }
            #[allow(unused)]
            #item
        };
    generated.into()
}

fn adapt_name(name_string: &String) -> String{
    let mut name = String::with_capacity(name_string.len());
    let mut capitalize_next = true;
    for ch in name_string.chars() {
        if ch == '_' {
            capitalize_next = true;
            continue;
        }
        if capitalize_next {
            for up in ch.to_uppercase() {
                name.push(up);
            }
            capitalize_next = false;
        } else {
            name.push(ch);
        }
    }
    name
}
