//! Various macros used by the Rust Bitcoin ecosystem.
//!

/// Implements standard array methods for a given wrapper type.
#[macro_export]
macro_rules! impl_array_newtype {
    ($thing:ident, $ty:ty, $len:literal) => {
        impl<'a> core::convert::From<[$ty; $len]> for $thing {
            fn from(data: [$ty; $len]) -> Self {
                $thing(data)
            }
        }

        impl<'a> core::convert::TryFrom<&'a [$ty]> for $thing {
            type Error = core::array::TryFromSliceError;

            fn try_from(data: &'a [$ty]) -> Result<Self, Self::Error> {
                use core::convert::TryInto;

                Ok($thing(data.try_into()?))
            }
        }

        impl AsRef<[$ty; $len]> for $thing {
            fn as_ref(&self) -> &[$ty; $len] {
                &self.0
            }
        }

        impl AsMut<[$ty; $len]> for $thing {
            fn as_mut(&mut self) -> &mut [$ty; $len] {
                &mut self.0
            }
        }

        impl AsRef<[$ty]> for $thing {
            fn as_ref(&self) -> &[$ty] {
                &self.0
            }
        }

        impl AsMut<[$ty]> for $thing {
            fn as_mut(&mut self) -> &mut [$ty] {
                &mut self.0
            }
        }

        impl<I> core::ops::Index<I> for $thing
        where
            [$ty]: core::ops::Index<I>,
        {
            type Output = <[$ty] as core::ops::Index<I>>::Output;

            #[inline]
            fn index(&self, index: I) -> &Self::Output {
                &self.0[index]
            }
        }
    };
}

/// Implements `Debug` by calling through to `Display`.
#[macro_export]
macro_rules! debug_from_display {
    ($thing:ident) => {
        impl core::fmt::Debug for $thing {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
                core::fmt::Display::fmt(self, f)
            }
        }
    };
}
