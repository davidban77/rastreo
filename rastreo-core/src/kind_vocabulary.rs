//! Declares a kind enum and its vocabulary from a single variant list.

/// Defines a fieldless kind enum together with `all`, `index`, `label`, `from_label`, and the
/// variant-count constant, all derived from the one variant list in the invocation.
macro_rules! kind_vocabulary {
    (
        $(#[$enum_meta:meta])*
        $vis:vis enum $name:ident {
            $( $(#[$variant_meta:meta])* $variant:ident => $label:literal ),+ $(,)?
        }

        $(#[$count_meta:meta])*
        $count_vis:vis const $count:ident;
    ) => {
        $(#[$enum_meta])*
        $vis enum $name {
            $( $(#[$variant_meta])* $variant, )+
        }

        $(#[$count_meta])*
        $count_vis const $count: usize = [$($name::$variant),+].len();

        impl $name {
            /// Every variant, in declaration order.
            pub const fn all() -> &'static [$name; $count] {
                &[$($name::$variant),+]
            }

            /// Position in [`Self::all`].
            pub const fn index(self) -> usize {
                self as usize
            }

            /// Canonical name of the variant; the only string [`Self::from_label`] maps back to it.
            pub const fn label(self) -> &'static str {
                match self {
                    $( $name::$variant => $label, )+
                }
            }

            /// Inverse of [`Self::label`]; `None` for any string that is not a canonical label.
            pub fn from_label(label: &str) -> Option<$name> {
                match label {
                    $( $label => Some($name::$variant), )+
                    _ => None,
                }
            }
        }
    };
}

pub(crate) use kind_vocabulary;

#[cfg(test)]
mod tests {
    kind_vocabulary! {
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[non_exhaustive]
        enum SampleKind {
            #[default]
            Alpha => "alpha",
            Beta => "beta",
            Gamma => "gamma",
        }

        const SAMPLE_KIND_COUNT;
    }

    #[test]
    fn the_count_is_the_length_of_the_variant_list() {
        assert_eq!(SAMPLE_KIND_COUNT, 3);
        assert_eq!(SampleKind::all().len(), SAMPLE_KIND_COUNT);
    }

    #[test]
    fn the_count_is_usable_as_an_array_length() {
        let slots = [0usize; SAMPLE_KIND_COUNT];
        assert_eq!(slots.len(), SampleKind::all().len());
    }

    #[test]
    fn all_lists_the_variants_in_declaration_order() {
        assert_eq!(
            *SampleKind::all(),
            [SampleKind::Alpha, SampleKind::Beta, SampleKind::Gamma]
        );
    }

    #[test]
    fn every_index_is_the_variants_position_in_all() {
        for (position, kind) in SampleKind::all().iter().enumerate() {
            assert_eq!(kind.index(), position);
        }
    }

    #[test]
    fn every_label_round_trips_through_from_label() {
        for kind in SampleKind::all().iter().copied() {
            assert_eq!(SampleKind::from_label(kind.label()), Some(kind));
        }
    }

    #[test]
    fn from_label_rejects_anything_that_is_not_a_canonical_label() {
        for label in ["", "Alpha", "alph", "delta", " alpha"] {
            assert_eq!(SampleKind::from_label(label), None, "accepted {label:?}");
        }
    }

    #[test]
    fn the_default_attribute_reaches_the_generated_variant() {
        assert_eq!(SampleKind::default(), SampleKind::Alpha);
    }
}
