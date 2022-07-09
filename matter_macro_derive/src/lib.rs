use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{format_ident, quote};
use syn::Lit::{Int, Str};
use syn::NestedMeta::Meta;
use syn::{parse_macro_input, DeriveInput, Lifetime};
use syn::{
    Meta::{List, NameValue},
    MetaList, MetaNameValue, Type,
};

struct TlvArgs {
    start: u8,
    datatype: String,
    unordered: bool,
    lifetime: syn::Lifetime,
}

impl Default for TlvArgs {
    fn default() -> Self {
        Self {
            start: 0,
            datatype: "struct".to_string(),
            unordered: false,
            lifetime: Lifetime::new("'_", Span::call_site()),
        }
    }
}

fn parse_tlvargs(ast: &DeriveInput) -> TlvArgs {
    let mut tlvargs: TlvArgs = Default::default();

    if ast.attrs.len() > 0 {
        if let List(MetaList {
            path,
            paren_token: _,
            nested,
        }) = ast.attrs[0].parse_meta().unwrap()
        {
            if path.is_ident("tlvargs") {
                for a in nested {
                    if let Meta(NameValue(MetaNameValue {
                        path: key_path,
                        eq_token: _,
                        lit: key_val,
                    })) = a
                    {
                        if key_path.is_ident("start") {
                            if let Int(litint) = key_val {
                                tlvargs.start = litint.base10_parse::<u8>().unwrap();
                            }
                        } else if key_path.is_ident("lifetime") {
                            if let Str(litstr) = key_val {
                                tlvargs.lifetime =
                                    Lifetime::new(&litstr.value(), Span::call_site());
                            }
                        } else if key_path.is_ident("datatype") {
                            if let Str(litstr) = key_val {
                                tlvargs.datatype = litstr.value();
                            }
                        } else if key_path.is_ident("unordered") {
                            tlvargs.unordered = true;
                        }
                    }
                }
            }
        }
    }
    tlvargs
}

/// Derive ToTLV Macro
///
/// This macro works for structures. It will create an implementation
/// of the ToTLV trait for that structure.  All the members of the
/// structure, sequentially, will get Context tags starting from 0
/// Some configurations are possible through the 'tlvargs' attributes.
/// For example:
///  #[tlvargs(start = 1, datatype = "list")]
///
/// start: This can be used to override the default tag from which the
///        encoding starts (Default: 0)
/// datatype: This can be used to define whether this data structure is
///        to be encoded as a structure or list. Possible values: list
///        (Default: struct)

#[proc_macro_derive(ToTLV, attributes(tlvargs))]
pub fn derive_totlv(item: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(item as DeriveInput);
    let struct_name = &ast.ident;

    let tlvargs = parse_tlvargs(&ast);
    let start = tlvargs.start;
    let datatype = format_ident!("start_{}", tlvargs.datatype);

    let generics = ast.generics;

    let fields = if let syn::Data::Struct(syn::DataStruct {
        fields: syn::Fields::Named(ref fields),
        ..
    }) = ast.data
    {
        fields
    } else {
        panic!("Derive ToTLV - Only supported Struct for now")
    };

    let mut idents = Vec::new();

    for field in fields.named.iter() {
        //        let field_name: &syn::Ident = field.ident.as_ref().unwrap();
        //        let name: String = field_name.to_string();
        //        let literal_key_str = syn::LitStr::new(&name, field.span());
        //        let type_name = &field.ty;
        //        keys.push(quote! { #literal_key_str });
        idents.push(&field.ident);
        //        types.push(type_name.to_token_stream());
    }

    let expanded = quote! {
        impl #generics ToTLV for #struct_name #generics {
            fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
                tw. #datatype (tag_type)?;
                let mut tag = #start;
                #(
                    self.#idents.to_tlv(tw, TagType::Context(tag))?;
                    tag += 1;
                )*
                tw.end_container()
            }
        }
    };
    //    panic!("The generated code is {}", expanded);
    expanded.into()
}

/// Derive FromTLV Macro
///
/// This macro works for structures. It will create an implementation
/// of the FromTLV trait for that structure.  All the members of the
/// structure, sequentially, will get Context tags starting from 0
/// Some configurations are possible through the 'tlvargs' attributes.
/// For example:
///  #[tlvargs(lifetime = "'a", start = 1, datatype = "list", unordered)]
///
/// start: This can be used to override the default tag from which the
///        decoding starts (Default: 0)
/// datatype: This can be used to define whether this data structure is
///        to be decoded as a structure or list. Possible values: list
///        (Default: struct)
/// lifetime: If the structure has a lifetime annotation, use this variable
///        to indicate that. The 'impl' will then use that lifetime
///        indicator.
/// unordered: By default, the decoder expects that the tags are in
///        sequentially increasing order. Set this if that is not the case.

#[proc_macro_derive(FromTLV, attributes(tlvargs))]
pub fn derive_fromtlv(item: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(item as DeriveInput);
    let struct_name = &ast.ident;

    let tlvargs = parse_tlvargs(&ast);
    let start = tlvargs.start;
    let lifetime = tlvargs.lifetime;
    let datatype = format_ident!("confirm_{}", tlvargs.datatype);

    let generics = ast.generics;

    let fields = if let syn::Data::Struct(syn::DataStruct {
        fields: syn::Fields::Named(ref fields),
        ..
    }) = ast.data
    {
        fields
    } else {
        panic!("Derive FromTLV - Only supported Struct for now")
    };

    let mut idents = Vec::new();
    let mut types = Vec::new();

    for field in fields.named.iter() {
        let type_name = &field.ty;
        idents.push(&field.ident);

        if let Type::Path(path) = type_name {
            types.push(&path.path.segments[0].ident);
        } else {
            panic!("Don't know what to do");
        }
    }

    // Currently we don't use find_tag() because the tags come in sequential
    // order. If ever the tags start coming out of order, we can use find_tag()
    // instead
    let expanded = if !tlvargs.unordered {
        quote! {
           impl #generics FromTLV <#lifetime> for #struct_name #generics {
               fn from_tlv(t: &TLVElement<#lifetime>) -> Result<Self, Error> {
                   let mut t_iter = t.#datatype ()?.iter().ok_or(Error::Invalid)?;
                   let mut tag = #start;
                   let mut item = t_iter.next();
                   #(
                       let #idents = if Some(true) == item.map(|x| x.check_ctx_tag(tag)) {
                           let backup = item;
                           item = t_iter.next();
                           #types::from_tlv(&backup.unwrap())
                       } else {
                           #types::tlv_not_found()
                       }?;
                       tag += 1;
                   )*

                   Ok(Self {
                       #(#idents,
                       )*
                   })
               }
           }
        }
    } else {
        quote! {
           impl #generics FromTLV <#lifetime> for #struct_name #generics {
               fn from_tlv(t: &TLVElement<#lifetime>) -> Result<Self, Error> {
                   let mut tag = #start;
                   #(
                       let #idents = if let Ok(s) = t.find_tag(tag as u32) {
                           #types::from_tlv(&s)
                       } else {
                           #types::tlv_not_found()
                       }?;
                       tag += 1;
                   )*

                   Ok(Self {
                       #(#idents,
                       )*
                   })
               }
           }
        }
    };
    //        panic!("The generated code is {}", expanded);
    expanded.into()
}
