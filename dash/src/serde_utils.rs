//! Dash serde utilities.
//!
//! This module is for special serde serializations.
//!

pub(crate) struct SerializeBytesAsHex<'a>(pub(crate) &'a [u8]);

impl<'a> serde::Serialize for SerializeBytesAsHex<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use hex_conservative::DisplayHex;

        serializer.collect_str(&format_args!("{:x}", self.0.as_hex()))
    }
}

macro_rules! serde_string_serialize_impl {
    ($name:ty, $expecting:literal) => {
        impl $crate::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: $crate::serde::Serializer,
            {
                serializer.collect_str(&self)
            }
        }
    };
}

macro_rules! serde_string_deserialize_impl {
    ($name:ty, $expecting:literal) => {
        impl<'de> $crate::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<$name, D::Error>
            where
                D: $crate::serde::de::Deserializer<'de>,
            {
                use core::fmt::{self, Formatter};

                struct Visitor;
                impl<'de> $crate::serde::de::Visitor<'de> for Visitor {
                    type Value = $name;

                    fn expecting(&self, f: &mut Formatter) -> fmt::Result {
                        f.write_str($expecting)
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        v.parse::<$name>().map_err(E::custom)
                    }
                }

                deserializer.deserialize_str(Visitor)
            }
        }
    };
}

pub(crate) use {serde_string_deserialize_impl, serde_string_serialize_impl};

/// A combination macro where the human-readable serialization is done like
/// serde_string_impl and the non-human-readable impl is done as a struct.
///
/// The deserialize impl uses a *single* visitor that handles all three shapes
/// (`visit_str`, `visit_seq`, `visit_map`) — required to interoperate with
/// serde's `ContentDeserializer`, the format-agnostic intermediate buffer
/// serde uses to dispatch internally-tagged enums (`#[serde(tag = "...")]`),
/// `flatten`, and untagged enums. `ContentDeserializer` always reports
/// `is_human_readable() == true` regardless of the upstream format (this is
/// intentional in serde's source: see long-standing upstream issues — the
/// recommended pattern is "don't branch on `is_human_readable()` for shape
/// dispatch — accept any shape"). A value originally written by a
/// non-human-readable encoder can therefore be replayed into the
/// human-readable branch as a map and must be accepted there. See the
/// regression test
/// `outpoint::tests::serde_round_trip_through_internally_tagged_enum`.
macro_rules! serde_struct_human_string_impl {
    ($name:ident, $expecting:literal, $($fe:ident),*) => (
        impl<'de> $crate::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<$name, D::Error>
            where
                D: $crate::serde::de::Deserializer<'de>,
            {
                use core::fmt::{self, Formatter};
                use core::str::FromStr;
                use $crate::serde::de::IgnoredAny;

                #[allow(non_camel_case_types)]
                enum Enum { Unknown__Field, $($fe),* }

                struct EnumVisitor;
                impl<'de> $crate::serde::de::Visitor<'de> for EnumVisitor {
                    type Value = Enum;

                    fn expecting(&self, f: &mut Formatter) -> fmt::Result {
                        f.write_str("a field name")
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        match v {
                            $(
                            stringify!($fe) => Ok(Enum::$fe)
                            ),*,
                            _ => Ok(Enum::Unknown__Field)
                        }
                    }
                }

                impl<'de> $crate::serde::Deserialize<'de> for Enum {
                    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                    where
                        D: $crate::serde::de::Deserializer<'de>,
                    {
                        deserializer.deserialize_str(EnumVisitor)
                    }
                }

                struct Visitor;

                impl<'de> $crate::serde::de::Visitor<'de> for Visitor {
                    type Value = $name;

                    fn expecting(&self, f: &mut Formatter) -> fmt::Result {
                        f.write_str($expecting)
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        $name::from_str(v).map_err(E::custom)
                    }

                    fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
                    where
                        V: $crate::serde::de::SeqAccess<'de>,
                    {
                        use $crate::serde::de::Error;

                        let length = 0;
                        $(
                            let $fe = seq.next_element()?.ok_or_else(|| {
                                Error::invalid_length(length, &self)
                            })?;
                            #[allow(unused_variables)]
                            let length = length + 1;
                        )*

                        let ret = $name {
                            $($fe),*
                        };

                        Ok(ret)
                    }

                    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                    where
                        A: $crate::serde::de::MapAccess<'de>,
                    {
                        use $crate::serde::de::Error;

                        $(let mut $fe = None;)*

                        loop {
                            match map.next_key::<Enum>()? {
                                Some(Enum::Unknown__Field) => {
                                    map.next_value::<IgnoredAny>()?;
                                }
                                $(
                                    Some(Enum::$fe) => {
                                        if $fe.is_some() {
                                            return Err(A::Error::duplicate_field(stringify!($fe)));
                                        }
                                        $fe = Some(map.next_value()?);
                                    }
                                )*
                                None => { break; }
                            }
                        }

                        $(
                            let $fe = match $fe {
                                Some(x) => x,
                                None => return Err(A::Error::missing_field(stringify!($fe))),
                            };
                        )*

                        let ret = $name {
                            $($fe),*
                        };

                        Ok(ret)
                    }
                }
                // end type defs

                static FIELDS: &'static [&'static str] = &[$(stringify!($fe)),*];

                if deserializer.is_human_readable() {
                    // Self-describing format (raw JSON, or a `ContentDeserializer`
                    // replaying buffered content for an internally-tagged enum).
                    // `deserialize_any` lets the deserializer dispatch to whichever
                    // visit_* method matches the actual data shape — so we accept
                    // the canonical "txid:vout" string form, plus the struct/seq
                    // forms that show up when a non-human-readable struct is
                    // re-deserialized via `ContentDeserializer`.
                    deserializer.deserialize_any(Visitor)
                } else {
                    deserializer.deserialize_struct(stringify!($name), FIELDS, Visitor)
                }
            }
        }

        impl $crate::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: $crate::serde::Serializer,
            {
                if serializer.is_human_readable() {
                    serializer.collect_str(&self)
                } else {
                    use $crate::serde::ser::SerializeStruct;

                    // Only used to get the struct length.
                    static FIELDS: &'static [&'static str] = &[$(stringify!($fe)),*];

                    let mut st = serializer.serialize_struct(stringify!($name), FIELDS.len())?;

                    $(
                        st.serialize_field(stringify!($fe), &self.$fe)?;
                    )*

                    st.end()
                }
            }
        }
    )
}
pub(crate) use serde_struct_human_string_impl;
