use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::Lit::{Int, Str};
use syn::NestedMeta::Meta;
use syn::{parse_macro_input, DeriveInput, Lifetime};
use syn::{
    Meta::{List, NameValue},
    MetaList, MetaNameValue, Type,
};

#[proc_macro_derive(ToTLV, attributes(tlvargs))]
pub fn derive_totlv(item: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(item as DeriveInput);
    let struct_name = &ast.ident;

    let mut tag_start = 0_u8;

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
                                tag_start = litint.base10_parse::<u8>().unwrap();
                            }
                        }
                    }
                }
            }
        }
    }
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

    //    let mut keys = Vec::new();
    let mut idents = Vec::new();
    //    let mut types = Vec::new();

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
                tw.start_struct(tag_type)?;
                let mut tag = #tag_start;
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

#[proc_macro_derive(FromTLV, attributes(tlvargs))]
pub fn derive_fromtlv(item: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(item as DeriveInput);
    let struct_name = &ast.ident;

    let mut tag_start = 0_u8;
    let mut lifetime = Lifetime::new("'_", Span::call_site());

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
                                tag_start = litint.base10_parse::<u8>().unwrap();
                            }
                        } else if key_path.is_ident("lifetime") {
                            if let Str(litstr) = key_val {
                                lifetime = Lifetime::new(&litstr.value(), Span::call_site());
                                // panic!("key val is {:?}", litstr.value());
                            }
                        }
                    }
                }
            }
        }
    }
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
            //            panic!("type is {:?}", path.path.segments[0].ident);
            types.push(&path.path.segments[0].ident);
        } else {
            panic!("Don't know what to do");
        }
    }

    let expanded = quote! {
        impl #generics FromTLV <#lifetime> for #struct_name #generics {
            fn from_tlv(t: &TLVElement<#lifetime>) -> Result<Self, Error> {
                let mut t_iter = t.confirm_struct()?.iter().ok_or(Error::Invalid)?;
                let mut tag = #tag_start;
                #(
                    let item = t_iter.next().ok_or(Error::Invalid)?;
                    let #idents = if let TagType::Context(recvd_tag) = item.get_tag() {
                        if recvd_tag != tag {
                            return Err(Error::Invalid);
                        }
                        #types::from_tlv(&item)
                    } else {
                        Err(Error::Invalid)
                    }?;
                    tag += 1;
                )*

                Ok(Self {
                    #(#idents,
                    )*
                })
            }
        }
    };
    //    panic!("The generated code is {}", expanded);
    expanded.into()
}
