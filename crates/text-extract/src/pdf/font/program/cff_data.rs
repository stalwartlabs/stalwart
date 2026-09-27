/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub(super) static STANDARD_STRING_NAMES: &[u8] = b".notdefspaceexclamquotedblnumbersigndollarpercentampersandquoterightparenleftparenrightasteriskpluscommahyphenperiodslashzeroonetwothreefourfivesixseveneightninecolonsemicolonlessequalgreaterquestionatABCDEFGHIJKLMNOPQRSTUVWXYZbracketleftbackslashbracketrightasciicircumunderscorequoteleftabcdefghijklmnopqrstuvwxyzbraceleftbarbracerightasciitildeexclamdowncentsterlingfractionyenflorinsectioncurrencyquotesinglequotedblleftguillemotleftguilsinglleftguilsinglrightfiflendashdaggerdaggerdblperiodcenteredparagraphbulletquotesinglbasequotedblbasequotedblrightguillemotrightellipsisperthousandquestiondowngraveacutecircumflextildemacronbrevedotaccentdieresisringcedillahungarumlautogonekcaronemdashAEordfeminineLslashOslashOEordmasculineaedotlessilslashoslashoegermandblsonesuperiorlogicalnotmutrademarkEthonehalfplusminusThornonequarterdividebrokenbardegreethornthreequarterstwosuperiorregisteredminusethmultiplythreesuperiorcopyrightAacuteAcircumflexAdieresisAgraveAringAtildeCcedillaEacuteEcircumflexEdieresisEgraveIacuteIcircumflexIdieresisIgraveNtildeOacuteOcircumflexOdieresisOgraveOtildeScaronUacuteUcircumflexUdieresisUgraveYacuteYdieresisZcaronaacuteacircumflexadieresisagravearingatildeccedillaeacuteecircumflexedieresisegraveiacuteicircumflexidieresisigraventildeoacuteocircumflexodieresisograveotildescaronuacuteucircumflexudieresisugraveyacuteydieresiszcaronexclamsmallHungarumlautsmalldollaroldstyledollarsuperiorampersandsmallAcutesmallparenleftsuperiorparenrightsuperiortwodotenleaderonedotenleaderzerooldstyleoneoldstyletwooldstylethreeoldstylefouroldstylefiveoldstylesixoldstylesevenoldstyleeightoldstylenineoldstylecommasuperiorthreequartersemdashperiodsuperiorquestionsmallasuperiorbsuperiorcentsuperiordsuperioresuperiorisuperiorlsuperiormsuperiornsuperiorosuperiorrsuperiorssuperiortsuperiorffffifflparenleftinferiorparenrightinferiorCircumflexsmallhyphensuperiorGravesmallAsmallBsmallCsmallDsmallEsmallFsmallGsmallHsmallIsmallJsmallKsmallLsmallMsmallNsmallOsmallPsmallQsmallRsmallSsmallTsmallUsmallVsmallWsmallXsmallYsmallZsmallcolonmonetaryonefittedrupiahTildesmallexclamdownsmallcentoldstyleLslashsmallScaronsmallZcaronsmallDieresissmallBrevesmallCaronsmallDotaccentsmallMacronsmallfiguredashhypheninferiorOgoneksmallRingsmallCedillasmallquestiondownsmalloneeighththreeeighthsfiveeighthsseveneighthsonethirdtwothirdszerosuperiorfoursuperiorfivesuperiorsixsuperiorsevensuperioreightsuperiorninesuperiorzeroinferioroneinferiortwoinferiorthreeinferiorfourinferiorfiveinferiorsixinferiorseveninferioreightinferiornineinferiorcentinferiordollarinferiorperiodinferiorcommainferiorAgravesmallAacutesmallAcircumflexsmallAtildesmallAdieresissmallAringsmallAEsmallCcedillasmallEgravesmallEacutesmallEcircumflexsmallEdieresissmallIgravesmallIacutesmallIcircumflexsmallIdieresissmallEthsmallNtildesmallOgravesmallOacutesmallOcircumflexsmallOtildesmallOdieresissmallOEsmallOslashsmallUgravesmallUacutesmallUcircumflexsmallUdieresissmallYacutesmallThornsmallYdieresissmall001.000001.001001.002001.003BlackBoldBookLightMediumRegularRomanSemibold";
pub(super) static STANDARD_STRING_OFFSETS: [u16; 392] = [
    0, 7, 12, 18, 26, 36, 42, 49, 58, 68, 77, 87, 95, 99, 104, 110, 116, 121, 125, 128, 131, 136,
    140, 144, 147, 152, 157, 161, 166, 175, 179, 184, 191, 199, 201, 202, 203, 204, 205, 206, 207,
    208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226,
    227, 238, 247, 259, 270, 280, 289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301,
    302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 324, 327, 337, 347, 357,
    361, 369, 377, 380, 386, 393, 401, 412, 424, 437, 450, 464, 466, 468, 474, 480, 489, 503, 512,
    518, 532, 544, 557, 571, 579, 590, 602, 607, 612, 622, 627, 633, 638, 647, 655, 659, 666, 678,
    684, 689, 695, 697, 708, 714, 720, 722, 734, 736, 744, 750, 756, 758, 768, 779, 789, 791, 800,
    803, 810, 819, 824, 834, 840, 849, 855, 860, 873, 884, 894, 899, 902, 910, 923, 932, 938, 949,
    958, 964, 969, 975, 983, 989, 1000, 1009, 1015, 1021, 1032, 1041, 1047, 1053, 1059, 1070, 1079,
    1085, 1091, 1097, 1103, 1114, 1123, 1129, 1135, 1144, 1150, 1156, 1167, 1176, 1182, 1187, 1193,
    1201, 1207, 1218, 1227, 1233, 1239, 1250, 1259, 1265, 1271, 1277, 1288, 1297, 1303, 1309, 1315,
    1321, 1332, 1341, 1347, 1353, 1362, 1368, 1379, 1396, 1410, 1424, 1438, 1448, 1465, 1483, 1497,
    1511, 1523, 1534, 1545, 1558, 1570, 1582, 1593, 1606, 1619, 1631, 1644, 1663, 1677, 1690, 1699,
    1708, 1720, 1729, 1738, 1747, 1756, 1765, 1774, 1783, 1792, 1801, 1810, 1812, 1815, 1818, 1835,
    1853, 1868, 1882, 1892, 1898, 1904, 1910, 1916, 1922, 1928, 1934, 1940, 1946, 1952, 1958, 1964,
    1970, 1976, 1982, 1988, 1994, 2000, 2006, 2012, 2018, 2024, 2030, 2036, 2042, 2048, 2061, 2070,
    2076, 2086, 2101, 2113, 2124, 2135, 2146, 2159, 2169, 2179, 2193, 2204, 2214, 2228, 2239, 2248,
    2260, 2277, 2286, 2298, 2309, 2321, 2329, 2338, 2350, 2362, 2374, 2385, 2398, 2411, 2423, 2435,
    2446, 2457, 2470, 2482, 2494, 2505, 2518, 2531, 2543, 2555, 2569, 2583, 2596, 2607, 2618, 2634,
    2645, 2659, 2669, 2676, 2689, 2700, 2711, 2727, 2741, 2752, 2763, 2779, 2793, 2801, 2812, 2823,
    2834, 2850, 2861, 2875, 2882, 2893, 2904, 2915, 2931, 2945, 2956, 2966, 2980, 2987, 2994, 3001,
    3008, 3013, 3017, 3021, 3026, 3032, 3039, 3044, 3052,
];

pub(super) static EXPERT_CHARSET: [u16; 165] = [
    1, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 13, 14, 15, 99, 239, 240, 241, 242, 243,
    244, 245, 246, 247, 248, 27, 28, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260,
    261, 262, 263, 264, 265, 266, 109, 110, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277,
    278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295, 296,
    297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315,
    316, 317, 318, 158, 155, 163, 319, 320, 321, 322, 323, 324, 325, 326, 150, 164, 169, 327, 328,
    329, 330, 331, 332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347,
    348, 349, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359, 360, 361, 362, 363, 364, 365, 366,
    367, 368, 369, 370, 371, 372, 373, 374, 375, 376, 377, 378,
];

pub(super) static EXPERT_SUBSET_CHARSET: [u16; 86] = [
    1, 231, 232, 235, 236, 237, 238, 13, 14, 15, 99, 239, 240, 241, 242, 243, 244, 245, 246, 247,
    248, 27, 28, 249, 250, 251, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265,
    266, 109, 110, 267, 268, 269, 270, 272, 300, 301, 302, 305, 314, 315, 158, 155, 163, 320, 321,
    322, 323, 324, 325, 326, 150, 164, 169, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 337,
    338, 339, 340, 341, 342, 343, 344, 345, 346,
];
