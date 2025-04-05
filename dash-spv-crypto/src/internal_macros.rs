#[macro_export]
macro_rules! user_enum {
    (
        $(#[$attr:meta])*
        pub enum $name:ident {
            $(#[$doc:meta]
              $elem:ident <-> $txt:expr),*
        }
    ) => (
        $(#[$attr])*
        pub enum $name {
            $(#[$doc] $elem),*
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                f.pad(match *self {
                    $($name::$elem => $txt),*
                })
            }
        }

        impl ::core::str::FromStr for $name {
            type Err = $crate::io::Error;
            #[inline]
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($txt => Ok($name::$elem)),*,
                    _ => {
                        #[cfg(not(feature = "std"))] let message = "Unknown network";
                        #[cfg(feature = "std")] let message = format!("Unknown network (type {})", s);
                        Err($crate::io::Error::new(
                            $crate::io::ErrorKind::InvalidInput,
                            message,
                        ))
                    }
                }
            }
        }

        #[cfg(feature = "serde")]
        #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
        impl<'de> ::serde::Deserialize<'de> for $name {
            #[inline]
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                use ::core::fmt::{self, Formatter};

                struct Visitor;
                impl<'de> ::serde::de::Visitor<'de> for Visitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                        formatter.write_str("an enum value")
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: ::serde::de::Error,
                    {
                        static FIELDS: &'static [&'static str] = &[$(stringify!($txt)),*];

                        $( if v == $txt { Ok($name::$elem) } )else*
                        else {
                            Err(E::unknown_variant(v, FIELDS))
                        }
                    }

                    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
                    where
                        E: ::serde::de::Error,
                    {
                        self.visit_str(v)
                    }

                    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
                    where
                        E: ::serde::de::Error,
                    {
                        self.visit_str(&v)
                    }

                }

                deserializer.deserialize_str(Visitor)
            }
        }

        #[cfg(feature = "serde")]
        #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
        impl ::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                serializer.collect_str(&self)
            }
        }
    );
}

#[macro_export]
macro_rules! display_from_debug {
    ($thing:ident) => {
        impl ::core::fmt::Display for $thing {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> Result<(), ::core::fmt::Error> {
                ::core::fmt::Debug::fmt(self, f)
            }
        }
    }
}
