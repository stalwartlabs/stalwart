/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::{self, Display};

pub const MAX_OTHER_COLOR_LEN: usize = 32;

macro_rules! css_colors {
    ($($name:tt => $variant:ident),* $(,)?) => {
        #[derive(
            rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq, Hash,
        )]
        #[rkyv(compare(PartialEq), derive(Debug))]
        pub enum CssColor {
            $($variant,)*
            Rgb(u32),
            Other(String),
        }

        impl CssColor {
            fn named(value: &str) -> Option<Self> {
                hashify::map_ignore_case!(
                    value.as_bytes(),
                    CssColor,
                    $($name => CssColor::$variant,)*
                )
                .cloned()
            }

            fn as_named_str(&self) -> Option<&'static str> {
                match self {
                    $(CssColor::$variant => Some($name),)*
                    CssColor::Rgb(_) | CssColor::Other(_) => None,
                }
            }
        }
    };
}

css_colors!(
    "aliceblue" => Aliceblue,
    "antiquewhite" => Antiquewhite,
    "aqua" => Aqua,
    "aquamarine" => Aquamarine,
    "azure" => Azure,
    "beige" => Beige,
    "bisque" => Bisque,
    "black" => Black,
    "blanchedalmond" => Blanchedalmond,
    "blue" => Blue,
    "blueviolet" => Blueviolet,
    "brown" => Brown,
    "burlywood" => Burlywood,
    "cadetblue" => Cadetblue,
    "chartreuse" => Chartreuse,
    "chocolate" => Chocolate,
    "coral" => Coral,
    "cornflowerblue" => Cornflowerblue,
    "cornsilk" => Cornsilk,
    "crimson" => Crimson,
    "cyan" => Cyan,
    "darkblue" => Darkblue,
    "darkcyan" => Darkcyan,
    "darkgoldenrod" => Darkgoldenrod,
    "darkgray" => Darkgray,
    "darkgreen" => Darkgreen,
    "darkgrey" => Darkgrey,
    "darkkhaki" => Darkkhaki,
    "darkmagenta" => Darkmagenta,
    "darkolivegreen" => Darkolivegreen,
    "darkorange" => Darkorange,
    "darkorchid" => Darkorchid,
    "darkred" => Darkred,
    "darksalmon" => Darksalmon,
    "darkseagreen" => Darkseagreen,
    "darkslateblue" => Darkslateblue,
    "darkslategray" => Darkslategray,
    "darkslategrey" => Darkslategrey,
    "darkturquoise" => Darkturquoise,
    "darkviolet" => Darkviolet,
    "deeppink" => Deeppink,
    "deepskyblue" => Deepskyblue,
    "dimgray" => Dimgray,
    "dimgrey" => Dimgrey,
    "dodgerblue" => Dodgerblue,
    "firebrick" => Firebrick,
    "floralwhite" => Floralwhite,
    "forestgreen" => Forestgreen,
    "fuchsia" => Fuchsia,
    "gainsboro" => Gainsboro,
    "ghostwhite" => Ghostwhite,
    "gold" => Gold,
    "goldenrod" => Goldenrod,
    "gray" => Gray,
    "green" => Green,
    "greenyellow" => Greenyellow,
    "grey" => Grey,
    "honeydew" => Honeydew,
    "hotpink" => Hotpink,
    "indianred" => Indianred,
    "indigo" => Indigo,
    "ivory" => Ivory,
    "khaki" => Khaki,
    "lavender" => Lavender,
    "lavenderblush" => Lavenderblush,
    "lawngreen" => Lawngreen,
    "lemonchiffon" => Lemonchiffon,
    "lightblue" => Lightblue,
    "lightcoral" => Lightcoral,
    "lightcyan" => Lightcyan,
    "lightgoldenrodyellow" => Lightgoldenrodyellow,
    "lightgray" => Lightgray,
    "lightgreen" => Lightgreen,
    "lightgrey" => Lightgrey,
    "lightpink" => Lightpink,
    "lightsalmon" => Lightsalmon,
    "lightseagreen" => Lightseagreen,
    "lightskyblue" => Lightskyblue,
    "lightslategray" => Lightslategray,
    "lightslategrey" => Lightslategrey,
    "lightsteelblue" => Lightsteelblue,
    "lightyellow" => Lightyellow,
    "lime" => Lime,
    "limegreen" => Limegreen,
    "linen" => Linen,
    "magenta" => Magenta,
    "maroon" => Maroon,
    "mediumaquamarine" => Mediumaquamarine,
    "mediumblue" => Mediumblue,
    "mediumorchid" => Mediumorchid,
    "mediumpurple" => Mediumpurple,
    "mediumseagreen" => Mediumseagreen,
    "mediumslateblue" => Mediumslateblue,
    "mediumspringgreen" => Mediumspringgreen,
    "mediumturquoise" => Mediumturquoise,
    "mediumvioletred" => Mediumvioletred,
    "midnightblue" => Midnightblue,
    "mintcream" => Mintcream,
    "mistyrose" => Mistyrose,
    "moccasin" => Moccasin,
    "navajowhite" => Navajowhite,
    "navy" => Navy,
    "oldlace" => Oldlace,
    "olive" => Olive,
    "olivedrab" => Olivedrab,
    "orange" => Orange,
    "orangered" => Orangered,
    "orchid" => Orchid,
    "palegoldenrod" => Palegoldenrod,
    "palegreen" => Palegreen,
    "paleturquoise" => Paleturquoise,
    "palevioletred" => Palevioletred,
    "papayawhip" => Papayawhip,
    "peachpuff" => Peachpuff,
    "peru" => Peru,
    "pink" => Pink,
    "plum" => Plum,
    "powderblue" => Powderblue,
    "purple" => Purple,
    "red" => Red,
    "rosybrown" => Rosybrown,
    "royalblue" => Royalblue,
    "saddlebrown" => Saddlebrown,
    "salmon" => Salmon,
    "sandybrown" => Sandybrown,
    "seagreen" => Seagreen,
    "seashell" => Seashell,
    "sienna" => Sienna,
    "silver" => Silver,
    "skyblue" => Skyblue,
    "slateblue" => Slateblue,
    "slategray" => Slategray,
    "slategrey" => Slategrey,
    "snow" => Snow,
    "springgreen" => Springgreen,
    "steelblue" => Steelblue,
    "tan" => Tan,
    "teal" => Teal,
    "thistle" => Thistle,
    "tomato" => Tomato,
    "turquoise" => Turquoise,
    "violet" => Violet,
    "wheat" => Wheat,
    "white" => White,
    "whitesmoke" => Whitesmoke,
    "yellow" => Yellow,
    "yellowgreen" => Yellowgreen,
);

impl CssColor {
    pub fn parse(value: &str) -> Option<Self> {
        if !value.bytes().any(|byte| byte.is_ascii_uppercase()) {
            if let Some(rgb) = value
                .strip_prefix('#')
                .filter(|hex| hex.len() == 6 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
                .and_then(|hex| u32::from_str_radix(hex, 16).ok())
            {
                return Some(CssColor::Rgb(rgb));
            }
            if let Some(color) = CssColor::named(value) {
                return Some(color);
            }
        }

        (!value.is_empty()
            && value.len() <= MAX_OTHER_COLOR_LEN
            && value
                .bytes()
                .all(|byte| byte.is_ascii_graphic() || byte == b' '))
        .then(|| CssColor::Other(value.to_string()))
    }

    pub fn is_standard(&self) -> bool {
        match self {
            CssColor::Other(value) => {
                value.strip_prefix('#').is_some_and(|hex| {
                    matches!(hex.len(), 3 | 6) && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                }) || CssColor::named(value).is_some()
            }
            _ => true,
        }
    }
}

impl Display for CssColor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CssColor::Rgb(rgb) => write!(f, "#{rgb:06x}"),
            CssColor::Other(value) => f.write_str(value),
            named => f.write_str(named.as_named_str().unwrap_or_default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_display() {
        for (input, standard) in [
            ("AliceBlue", true),
            ("aliceblue", true),
            ("yellowgreen", true),
            ("#1A2b3C", true),
            ("#1a2b3c", true),
            ("#abc", true),
            ("#ABC", true),
            ("#+abcde", false),
            ("#abcdeg", false),
            ("rgb(1, 2, 3)", false),
        ] {
            let color = CssColor::parse(input).expect(input);
            assert_eq!(color.to_string(), input);
            assert_eq!(color.is_standard(), standard, "{input}");
        }
        assert_eq!(CssColor::parse("aliceblue"), Some(CssColor::Aliceblue));
        assert_eq!(CssColor::parse("#1a2b3c"), Some(CssColor::Rgb(0x1a2b3c)));
        assert!(matches!(CssColor::parse("#000000"), Some(CssColor::Rgb(0))));
        for verbatim in ["AliceBlue", "#1A2b3C", "#+abcde", "#ABC"] {
            assert_eq!(
                CssColor::parse(verbatim),
                Some(CssColor::Other(verbatim.to_string()))
            );
        }
        assert!(CssColor::parse("").is_none());
        assert!(CssColor::parse(&"a".repeat(MAX_OTHER_COLOR_LEN + 1)).is_none());
        assert!(CssColor::parse("red\u{7}").is_none());
    }

    #[test]
    fn compact_size() {
        assert!(std::mem::size_of::<ArchivedCssColor>() <= 12);
    }
}
