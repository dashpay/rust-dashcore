//! Comprehensive tests for mnemonic functionality
//!
//! Tests BIP39 mnemonic generation, validation, recovery, and multi-language support.

#[cfg(test)]
mod tests {
    use crate::mnemonic::Language;
    use crate::Mnemonic;
    use bip39::Mnemonic as Bip39Mnemonic;
    use hex_conservative::decode_to_vec;

    // The complete English (TREZOR) and Japanese BIP-39 vector sets, as the bip39 3.0.0
    // crate (CC0-1.0) carries them.
    const ENGLISH_SEED_VECTORS: &[(&str, &str, &str)] = &[
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "TREZOR",
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        ),
        (
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "TREZOR",
            "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
        ),
        (
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            "TREZOR",
            "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
        ),
        (
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            "TREZOR",
            "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
        ),
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
            "TREZOR",
            "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
        ),
        (
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
            "TREZOR",
            "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
        ),
        (
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
            "TREZOR",
            "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
        ),
        (
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
            "TREZOR",
            "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
        ),
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            "TREZOR",
            "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
        ),
        (
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
            "TREZOR",
            "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
        ),
        (
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
            "TREZOR",
            "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
        ),
        (
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
            "TREZOR",
            "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
        ),
        (
            "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
            "TREZOR",
            "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",
        ),
        (
            "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
            "TREZOR",
            "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac",
        ),
        (
            "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
            "TREZOR",
            "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
        ),
        (
            "scheme spot photo card baby mountain device kick cradle pact join borrow",
            "TREZOR",
            "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612",
        ),
        (
            "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
            "TREZOR",
            "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d",
        ),
        (
            "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
            "TREZOR",
            "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
        ),
        (
            "cat swing flag economy stadium alone churn speed unique patch report train",
            "TREZOR",
            "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5",
        ),
        (
            "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
            "TREZOR",
            "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02",
        ),
        (
            "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
            "TREZOR",
            "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d",
        ),
        (
            "vessel ladder alter error federal sibling chat ability sun glass valve picture",
            "TREZOR",
            "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f",
        ),
        (
            "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
            "TREZOR",
            "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88",
        ),
        (
            "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
            "TREZOR",
            "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
        ),
    ];

    const JAPANESE_SEED_VECTORS: &[(&str, &str, &str)] = &[
        (
            "あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あおぞら",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55",
        ),
        (
            "そつう　れきだい　ほんやく　わかす　りくつ　ばいか　ろせん　やちん　そつう　れきだい　ほんやく　わかめ",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "aee025cbe6ca256862f889e48110a6a382365142f7d16f2b9545285b3af64e542143a577e9c144e101a6bdca18f8d97ec3366ebf5b088b1c1af9bc31346e60d9",
        ),
        (
            "そとづら　あまど　おおう　あこがれる　いくぶん　けいけん　あたえる　いよく　そとづら　あまど　おおう　あかちゃん",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "e51736736ebdf77eda23fa17e31475fa1d9509c78f1deb6b4aacfbd760a7e2ad769c714352c95143b5c1241985bcb407df36d64e75dd5a2b78ca5d2ba82a3544",
        ),
        (
            "われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　ろんぶん",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "4cd2ef49b479af5e1efbbd1e0bdc117f6a29b1010211df4f78e2ed40082865793e57949236c43b9fe591ec70e5bb4298b8b71dc4b267bb96ed4ed282c8f7761c",
        ),
        (
            "あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あらいぐま",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "d99e8f1ce2d4288d30b9c815ae981edd923c01aa4ffdc5dee1ab5fe0d4a3e13966023324d119105aff266dac32e5cd11431eeca23bbd7202ff423f30d6776d69",
        ),
        (
            "そつう　れきだい　ほんやく　わかす　りくつ　ばいか　ろせん　やちん　そつう　れきだい　ほんやく　わかす　りくつ　ばいか　ろせん　やちん　そつう　れいぎ",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "eaaf171efa5de4838c758a93d6c86d2677d4ccda4a064a7136344e975f91fe61340ec8a615464b461d67baaf12b62ab5e742f944c7bd4ab6c341fbafba435716",
        ),
        (
            "そとづら　あまど　おおう　あこがれる　いくぶん　けいけん　あたえる　いよく　そとづら　あまど　おおう　あこがれる　いくぶん　けいけん　あたえる　いよく　そとづら　いきなり",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "aec0f8d3167a10683374c222e6e632f2940c0826587ea0a73ac5d0493b6a632590179a6538287641a9fc9df8e6f24e01bf1be548e1f74fd7407ccd72ecebe425",
        ),
        (
            "われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　りんご",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "f0f738128a65b8d1854d68de50ed97ac1831fc3a978c569e415bbcb431a6a671d4377e3b56abd518daa861676c4da75a19ccb41e00c37d086941e471a4374b95",
        ),
        (
            "あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　いってい",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "23f500eec4a563bf90cfda87b3e590b211b959985c555d17e88f46f7183590cd5793458b094a4dccc8f05807ec7bd2d19ce269e20568936a751f6f1ec7c14ddd",
        ),
        (
            "そつう　れきだい　ほんやく　わかす　りくつ　ばいか　ろせん　やちん　そつう　れきだい　ほんやく　わかす　りくつ　ばいか　ろせん　やちん　そつう　れきだい　ほんやく　わかす　りくつ　ばいか　ろせん　まんきつ",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "cd354a40aa2e241e8f306b3b752781b70dfd1c69190e510bc1297a9c5738e833bcdc179e81707d57263fb7564466f73d30bf979725ff783fb3eb4baa86560b05",
        ),
        (
            "そとづら　あまど　おおう　あこがれる　いくぶん　けいけん　あたえる　いよく　そとづら　あまど　おおう　あこがれる　いくぶん　けいけん　あたえる　いよく　そとづら　あまど　おおう　あこがれる　いくぶん　けいけん　あたえる　うめる",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "6b7cd1b2cdfeeef8615077cadd6a0625f417f287652991c80206dbd82db17bf317d5c50a80bd9edd836b39daa1b6973359944c46d3fcc0129198dc7dc5cd0e68",
        ),
        (
            "われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　らいう",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "a44ba7054ac2f9226929d56505a51e13acdaa8a9097923ca07ea465c4c7e294c038f3f4e7e4b373726ba0057191aced6e48ac8d183f3a11569c426f0de414623",
        ),
        (
            "せまい　うちがわ　あずき　かろう　めずらしい　だんち　ますく　おさめる　ていぼう　あたる　すあな　えしゃく",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "344cef9efc37d0cb36d89def03d09144dd51167923487eec42c487f7428908546fa31a3c26b7391a2b3afe7db81b9f8c5007336b58e269ea0bd10749a87e0193",
        ),
        (
            "ぬすむ　ふっかつ　うどん　こうりつ　しつじ　りょうり　おたがい　せもたれ　あつめる　いちりゅう　はんしゃ　ごますり　そんけい　たいちょう　らしんばん　ぶんせき　やすみ　ほいく",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "b14e7d35904cb8569af0d6a016cee7066335a21c1c67891b01b83033cadb3e8a034a726e3909139ecd8b2eb9e9b05245684558f329b38480e262c1d6bc20ecc4",
        ),
        (
            "くのう　てぬぐい　そんかい　すろっと　ちきゅう　ほあん　とさか　はくしゅ　ひびく　みえる　そざい　てんすう　たんぴん　くしょう　すいようび　みけん　きさらぎ　げざん　ふくざつ　あつかう　はやい　くろう　おやゆび　こすう",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "32e78dce2aff5db25aa7a4a32b493b5d10b4089923f3320c8b287a77e512455443298351beb3f7eb2390c4662a2e566eec5217e1a37467af43b46668d515e41b",
        ),
        (
            "あみもの　いきおい　ふいうち　にげる　ざんしょ　じかん　ついか　はたん　ほあん　すんぽう　てちがい　わかめ",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "0acf902cd391e30f3f5cb0605d72a4c849342f62bd6a360298c7013d714d7e58ddf9c7fdf141d0949f17a2c9c37ced1d8cb2edabab97c4199b142c829850154b",
        ),
        (
            "すろっと　にくしみ　なやむ　たとえる　へいこう　すくう　きない　けってい　とくべつ　ねっしん　いたみ　せんせい　おくりがな　まかい　とくい　けあな　いきおい　そそぐ",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "9869e220bec09b6f0c0011f46e1f9032b269f096344028f5006a6e69ea5b0b8afabbb6944a23e11ebd021f182dd056d96e4e3657df241ca40babda532d364f73",
        ),
        (
            "かほご　きうい　ゆたか　みすえる　もらう　がっこう　よそう　ずっと　ときどき　したうけ　にんか　はっこう　つみき　すうじつ　よけい　くげん　もくてき　まわり　せめる　げざい　にげる　にんたい　たんそく　ほそく",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "713b7e70c9fbc18c831bfd1f03302422822c3727a93a5efb9659bec6ad8d6f2c1b5c8ed8b0b77775feaf606e9d1cc0a84ac416a85514ad59f5541ff5e0382481",
        ),
        (
            "めいえん　さのう　めだつ　すてる　きぬごし　ろんぱ　はんこ　まける　たいおう　さかいし　ねんいり　はぶらし",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "06e1d5289a97bcc95cb4a6360719131a786aba057d8efd603a547bd254261c2a97fcd3e8a4e766d5416437e956b388336d36c7ad2dba4ee6796f0249b10ee961",
        ),
        (
            "せんぱい　おしえる　ぐんかん　もらう　きあい　きぼう　やおや　いせえび　のいず　じゅしん　よゆう　きみつ　さといも　ちんもく　ちわわ　しんせいじ　とめる　はちみつ",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "1fef28785d08cbf41d7a20a3a6891043395779ed74503a5652760ee8c24dfe60972105ee71d5168071a35ab7b5bd2f8831f75488078a90f0926c8e9171b2bc4a",
        ),
        (
            "こころ　いどう　きあつ　そうがんきょう　へいあん　せつりつ　ごうせい　はいち　いびき　きこく　あんい　おちつく　きこえる　けんとう　たいこ　すすめる　はっけん　ていど　はんおん　いんさつ　うなぎ　しねま　れいぼう　みつかる",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "43de99b502e152d4c198542624511db3007c8f8f126a30818e856b2d8a20400d29e7a7e3fdd21f909e23be5e3c8d9aee3a739b0b65041ff0b8637276703f65c2",
        ),
        (
            "うりきれ　さいせい　じゆう　むろん　とどける　ぐうたら　はいれつ　ひけつ　いずれ　うちあわせ　おさめる　おたく",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "3d711f075ee44d8b535bb4561ad76d7d5350ea0b1f5d2eac054e869ff7963cdce9581097a477d697a2a9433a0c6884bea10a2193647677977c9820dd0921cbde",
        ),
        (
            "うりきれ　うねる　せっさたくま　きもち　めんきょ　へいたく　たまご　ぜっく　びじゅつかん　さんそ　むせる　せいじ　ねくたい　しはらい　せおう　ねんど　たんまつ　がいけん",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "753ec9e333e616e9471482b4b70a18d413241f1e335c65cd7996f32b66cf95546612c51dcf12ead6f805f9ee3d965846b894ae99b24204954be80810d292fcdd",
        ),
        (
            "うちゅう　ふそく　ひしょ　がちょう　うけもつ　めいそう　みかん　そざい　いばる　うけとる　さんま　さこつ　おうさま　ぱんつ　しひょう　めした　たはつ　いちぶ　つうじょう　てさぎょう　きつね　みすえる　いりぐち　かめれおん",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "346b7321d8c04f6f37b49fdf062a2fddc8e1bf8f1d33171b65074531ec546d1d3469974beccb1a09263440fc92e1042580a557fdce314e27ee4eabb25fa5e5fe",
        ),
    ];

    // Seed hex computed with Python hashlib.pbkdf2_hmac and unicodedata NFKD normalization.
    // The last three phrases are 127, 128 and 129 bytes, around the HMAC key block size.
    const ADDITIONAL_SEED_VECTORS: &[(&str, &str, &str)] = &[
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
        ),
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "Åé",
            "c95759e30618e65a305b1fea65760d2da1d0758763bdbf07bc8a840716c5a391a0ffdbd2f834cb861bcb68d6124991a80c28f5e8769829f88d66beff6c0b2b69",
        ),
        (
            "someone memory charge laptop enact artefact polar section wreck uniform salad drum divorce insect excuse forward ecology regret",
            "TREZOR",
            "cf37c10684dae28c8e0070736b21787a21700419913d4b95e9e192fccf09468347982da637574fda30c9ccc4509cb7eb5bad0e12d447fe281964a4bec23f8d89",
        ),
        (
            "inside resource lens rural weird length scatter dilemma cruise vehicle inherit broccoli maple rabbit remain drama obscure employ",
            "TREZOR",
            "a4b146f5263418985510d0d050c3781546e47257b3788bb69f8258ee888fdfef12a5e466f226a06e8a9e943ee0c0d3717b2f750b41dbe1170e536fe388218704",
        ),
        (
            "chief mosquito surround donate lawsuit disease food evil strike only midnight enact thing practice erosion resource reward engage",
            "TREZOR",
            "758b0a2a587dc55cd51a46bc7765a2c869489f13a0b5abf0e80fbf8de827263c22409e0f210311c538450d5db916a84d99849f388d65434a30dfd1e428f0a29e",
        ),
    ];

    #[test]
    fn test_mnemonic_generation() {
        // Test generation with default word count (12 words)
        let mnemonic = Mnemonic::generate(12, Language::English).unwrap();
        let phrase = mnemonic.phrase();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 12);

        // Verify the mnemonic is valid
        assert!(Mnemonic::validate(&mnemonic.phrase()));
    }

    #[test]
    fn test_mnemonic_from_phrase() {
        // Test with a known valid mnemonic
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase);
        assert!(mnemonic.is_ok());

        let mnemonic = mnemonic.unwrap();
        assert_eq!(mnemonic.phrase().as_str(), phrase);
    }

    #[test]
    fn test_invalid_mnemonic() {
        // Test with invalid mnemonics
        let invalid_phrases = vec![
            "invalid words that are not in wordlist",
            "abandon abandon abandon", // Too short
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", // Missing last word
        ];

        for phrase in invalid_phrases {
            let result = Mnemonic::from_phrase(phrase);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_mnemonic_to_seed() {
        // Test seed generation with known test vector
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();

        // Test without passphrase
        let seed = mnemonic.to_seed("");
        assert_eq!(seed.len(), 64);

        // Test with passphrase
        let seed_with_pass = mnemonic.to_seed("TREZOR");
        assert_eq!(seed_with_pass.len(), 64);
        assert_ne!(&seed[..], &seed_with_pass[..]);
    }

    fn assert_seed_vectors(vectors: &[(&str, &str, &str)]) {
        for &(phrase, passphrase, seed_hex) in vectors {
            let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
            let expected = decode_to_vec(seed_hex).unwrap();
            assert_eq!(&mnemonic.to_seed(passphrase)[..], expected, "{phrase}");
        }
    }

    #[test]
    fn test_bip39_seed_english_vectors() {
        assert_seed_vectors(ENGLISH_SEED_VECTORS);
    }

    #[test]
    fn test_bip39_seed_japanese_vectors() {
        assert_seed_vectors(JAPANESE_SEED_VECTORS);
    }

    #[test]
    fn test_bip39_seed_additional_vectors() {
        assert_seed_vectors(ADDITIONAL_SEED_VECTORS);
    }

    #[test]
    fn test_bip39_seed_matches_the_bip39_crate() {
        let long_english = Mnemonic::from_entropy(&[0xa5; 32], Language::English).unwrap();
        assert!(long_english.phrase().len() > 128);

        for language in Language::ALL {
            for entropy in [&[0; 16][..], &[0xa5; 32][..]] {
                let mnemonic = Mnemonic::from_entropy(entropy, language).unwrap();
                let phrase = mnemonic.phrase();
                let reference = Bip39Mnemonic::parse_in(language.into(), phrase.as_str()).unwrap();
                for passphrase in [
                    "",
                    "TREZOR",
                    "\u{c5}\u{e9}",
                    "\u{ff21}\u{fb01}",
                    "\u{1f600}",
                    &"p".repeat(300),
                ] {
                    assert_eq!(
                        *mnemonic.to_seed(passphrase),
                        reference.to_seed(passphrase),
                        "{language:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_mnemonic_word_count() {
        // Test different word counts
        let test_cases = vec![
            ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", 12),
            ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent", 18),
            ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art", 24),
        ];

        for (phrase, expected_words) in test_cases {
            let mnemonic = Mnemonic::from_phrase(phrase);
            assert!(mnemonic.is_ok());

            let mnemonic = mnemonic.unwrap();
            let phrase = mnemonic.phrase();
            let words: Vec<&str> = phrase.split_whitespace().collect();
            assert_eq!(words.len(), expected_words);
        }
    }

    #[test]
    fn test_mnemonic_validation() {
        // Valid mnemonics
        let valid_phrases = vec![
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        ];

        for phrase in valid_phrases {
            assert!(Mnemonic::validate(phrase), "Failed to validate: {}", phrase);
        }

        // Invalid mnemonics
        let invalid_phrases = vec!["invalid words here", "", "   "];

        for phrase in invalid_phrases {
            assert!(!Mnemonic::validate(phrase), "Should not validate: {}", phrase);
        }
    }

    #[test]
    fn test_mnemonic_recovery() {
        // Generate a mnemonic and recover wallet from it
        let original = Mnemonic::generate(12, Language::English).unwrap();
        let phrase = original.phrase().to_string();

        // Recover from the phrase
        let recovered = Mnemonic::from_phrase(&phrase).unwrap();

        // They should produce the same seed
        let original_seed = original.to_seed("");
        let recovered_seed = recovered.to_seed("");
        assert_eq!(original_seed, recovered_seed);

        // And the same phrase
        assert_eq!(original.phrase(), recovered.phrase());
    }

    #[test]
    fn test_mnemonic_with_different_passphrases() {
        let mnemonic = Mnemonic::from_phrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();

        // Different passphrases should produce different seeds
        let seed1 = mnemonic.to_seed("");
        let seed2 = mnemonic.to_seed("password");
        let seed3 = mnemonic.to_seed("another password");

        assert_ne!(seed1, seed2);
        assert_ne!(seed2, seed3);
        assert_ne!(seed1, seed3);

        // Same passphrase should produce same seed
        let seed4 = mnemonic.to_seed("password");
        assert_eq!(seed2, seed4);
    }

    #[test]
    fn test_mnemonic_deterministic() {
        // Same phrase should always produce same seed
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let mnemonic1 = Mnemonic::from_phrase(phrase).unwrap();
        let mnemonic2 = Mnemonic::from_phrase(phrase).unwrap();

        let seed1 = mnemonic1.to_seed("test");
        let seed2 = mnemonic2.to_seed("test");

        assert_eq!(seed1, seed2);
    }

    #[test]
    fn test_mnemonic_entropy_uniqueness() {
        // Generate multiple mnemonics and ensure they're different
        let mnemonics: Vec<Mnemonic> =
            (0..10).map(|_| Mnemonic::generate(12, Language::English).unwrap()).collect();

        // Check that all phrases are unique
        let mut phrases: Vec<String> = mnemonics.iter().map(|m| m.phrase().to_string()).collect();
        phrases.sort();
        phrases.dedup();

        // Should have 10 unique phrases
        assert_eq!(phrases.len(), 10);
    }

    #[test]
    fn test_mnemonic_phrase_immutability() {
        let mnemonic = Mnemonic::generate(12, Language::English).unwrap();
        let phrase1 = mnemonic.phrase();
        let phrase2 = mnemonic.phrase();

        // Multiple calls should return the same phrase
        assert_eq!(phrase1, phrase2);
    }
}
