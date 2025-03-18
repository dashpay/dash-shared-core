use bls_signatures::{BasicSchemeMPL, G1Element, G2Element, Scheme};
use dashcore::hashes::hex::FromHex;
use dash_spv_crypto::keys::{BLSKey, OperatorPublicKey};

// #[test]
fn test_verify_secure() {
    let commitment_hash = <[u8; 32]>::from_hex("ccabc0460e2dd8ea83966cf675175e6f37bfa20c162ae773b89827664e8dc8e5").unwrap();
    let signature = <[u8; 96]>::from_hex("88bf53b96714f2d8901922fd8e3e39400c0d85f9ad218ad56344ec5d0dd04b6ab04b668d8ebb814357c716a59363b9f816c5d682c4c8508a44d25cd49fe4248ea216a9410a54fbe6ba931432f2fa88c4b01cf07818331c4fae6e41534feffa3e").unwrap();
    let keys = vec![
        OperatorPublicKey { data: <[u8; 48]>::from_hex("b25d20af1a6d0ccd3890f0aead4a05a59be22e005b6d732f855311915b351a9153b2c83d84611b2c9958f806c93f7b5f").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("af9cd8567923fea3f6e6bbf5e1b3a76bf772f6a3c72b41be15c257af50533b32cc3923cebdeda9fce7a6bc9659123d53").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("818a6d23ae53d6231f7dd73a058f125340e92f6e97897f017d9d9d4e6671bbd92241170dfcdd5a4ab8ef47ef12ddcad5").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("97a49cea05ca2e18f74af110c5ab52c89a43ced4e056a8af7ca8973401494bdaba26d1c56b46b018091d0dd64f244750").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("95a577f51dc6fd7fa4621f0a4601e48fd65418a89c2af2afef725fb4f053a8ee5841cd3fdae39ebdf5a202e0c4deca23").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("b5df04cdd8a9ffdad72b2ffaa0bf752b6fe9adc70c59834cca826a7a0f7264e4cbefd351772e30d527bc5aa9019c4ca5").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("aaba308a8db9e1c6c545f3fdfff00880a973f0685207688d3c0ee4546d732ec16a81fa1aa952fb3190ff5c6febcd1a78").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("8ea46d70601eb45319ab495e2462f981debc8316df2bb1a679ae3525c7f517e535b69a02052844374c887a9312a47984").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("81ad0f9be5a88ae62ff54fe938dfceea71be03bd4c6a7aebf75896e8d495d310acc4146aa4820bc0e5f5b06579dedea5").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("92fa57a5676925e8dfe3b340df2132f5844ad9f89594b04efa28fb4fb884fe21f411fa49120ed7a60ce9381a54232a10").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("a9cac656247969ce388f3cd37079f4b5caa9ca1a523c12cefe9ad9e8f74f859c43df6e9448975f307dfd3632b6e495e2").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("91a043738454ea2f87aa38e88912341c806b68dcf4e472fe94a425ed79b4dc15b2bfdf6df0050dba41575acc666472cf").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("8feade899f17584ccf85f2d86ccd7ced638d919b2d70d1ec90d3c062d5b5fd3b56b25376a08f3e01611cc5ea67e1f05e").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("ac9c5c77fe321ff0a115d1ba5bf7462063ef21a82ba796415f4ee538bf9e8a6a49707530c72cbb6b60026c46ff1b9443").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("8935576848f6ab7e27fff34b671953672012352e36f5147181926b8bbc9e8b43b98458704666df25d36f37d41eb7c694").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("aa0ede82d78a0a8f4c2332d431c7be496c3aa09349ed3b2db30f7eb7dcc7b6e580a9d71f7d76bdaca1b3670e0cf4cd3c").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("81ad0f9be5a88ae62ff54fe938dfceea71be03bd4c6a7aebf75896e8d495d310acc4146aa4820bc0e5f5b06579dedea5").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("90e3caa7ae519505a6e1f3b56d3a99865f70e48f772ac431c3964a33cce7fe1e736d43ec3343ad843faaaa2b2bb3a921").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("838ea498b8c554bdc1f0ce0c107d8d23d27e40b45e6df56793cab951722dd69a958dc14798ae542cf025802f4b84a3f6").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("90d4c6a24d00d70fe961b77d58eff318bb6cd00c122bcfa20f92d65d03b9fd3afa5a0effc90810103a53d53ab155f764").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("888905cc3f99e76b3a1abf714a55978d9930c2abdc77a21bd809e452e8c47c35d38e318ec3118e1944cf1a4a8df907c1").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("afc31972124bb559aecd56dfb361048ab3f5203624c6436b1676b8d440bee777d83b937febacb2d3a651df9dbd20503e").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("b6175b59aba8cc0477d4fff78bd90294f31ebd385c39bc254c7995a5dd3ccb8dc1d8869e247bf63bef8ec79317f479a9").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("ac3026b3e3023db1db9ec8e3b7678761820a2a6e96e7a5d9a39b1894170f9cea7765d3d131d60fa9d17492ba560fb1f9").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("b6e979f20241cbb73de7451779e8e059d9cb75a74b72ea6862d7ac703dc2ac07d86cec39b6e8923b55fd54dbc6177c3a").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("9502bb884b3437d65c0e025e49fb00ff6ea9f55d5bcdc36330b46c8bd18be9126b7a6d7f35f558ef8040f2c2284500a5").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("b44cee83a79fa151527e527f3f4f5ba022e73ae8b0d913c4185a45c2a129aef935a585a7a725edcb36ece72a95758688").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("b928fa4e127214ccb2b5de1660b5e371d2f3c9845077bc3900fc6aabe82ddd2e61530be3765cea15752e30fc761ab730").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("8406e459bfd155c81f9103a1fe076f1261ee7513275d744c133c5d5dfa956b1449f173bd110bbc03673f376593f32a27").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("97596d7a72b65531fffd5f610752422d6e286c975f30d026092f7900f8015073bd6f6d1b85dd3981814c093910e7dac6").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("9099dcddc6560d1039b0edb91bd700e5deae0cba43163fa289a80c2bd22335b5b0e7a1fb8f5494c0e6360e73a12fe0a8").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("a80f24b5e040dcbf86c3f468dd28bf45d9e41fbcd127fad56669d9afe358dcdc26e42f0f8b19997b1741dbb99c553aa6").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("b0051db915bd86bd938746c14440b11ee3b2801cbc6d6c1c912e8b41ea5eb1d8f852abf220ae91ecdb6da094846c1ba8").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("8196970badc74d068ec1226ffd4a656313decef59d792237a32e6ff56cd4e43030c436025831a4a3d0306a616f033810").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("852057284a7a9dbccb97fbaea3425104901dc661b69294a55c7ca800ed18d37df7ccc02367b5d6836ee4f6b052249a1d").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("8d4b5e1f48d7a77746676f09e2b995389d0f1c18601a6f909a4b542fccce87d9f5f30695d078a9181e142602d2e93f8f").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("9826a6cfb349fd60cb7ff72efa5c4f8249eab0a0274f07e2a3d52b16898b711f43f9c6171ebba6e969ac03c6554c24e6").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("8dc75e865b89e96560b38fae96f1d0a5438795778e68b705a506046245ca5dbbedb09e2379eea4c9bde0d0fd4fe05080").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("aea71272ac9a9c891f0987a75e2200a44fc063bca92892c0a174cff4c0a524935e0b870bd091329836e43ca7d7c87e7f").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("93146b3252f408f1cffc875b12b61f56c1ae02113b24c0b5aaedcda4a9b509332c8c4587450074f3e0906aaf3ceca754").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("93fe96f243c4ded9e65467182848e46285b5db0097b5b74be93f590f3d7eb0880c89df70f8a7756aa96a242692cb685f").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("b6ee48c7a71a9d8e0813e68ca09846245fa155285f24a62b0ce9cb0102b1994ec58af8ba2a01c09363bdcc395d41f3df").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("b888fe437eab3af5a7fee4e0164705458a6fda97ae390d69721a5f1d3830ec330fb53c6a29588f1f94f69adcff04ca09").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("890f1ca955443740346b5b4b0bfb8251f040074b5a2feb77e54add831bf34aaf1d84207691f6f5aa5e702152a496fadc").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("8160877a911d8bb7d1e75e2320e98cc3233c1f6972cb642424bfcec7c182c56d2c0ebb59e45f788f4d5dbfa2ebff3e3a").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("924aaa5688cb7220be4600211257ae054554583ad9233e8ca0d58abafe317129dcca9e34a1b9bbfa175b88d9fb31b55e").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("911a30e0a5f2f5135dcc5f09498e4ba5de22c7680f396599f7f29b91ac569c3d4336bc157443cf8c06682bfb5abb2271").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("8d9ee7b7e66124c4b047e1f93aed5a764ed7384292737ea17f3a7e429ce3f24d602d54b97f72d181b6f093da9b3ad3f5").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("af70ff352844250e267b31c0ddb83dffd4cac43532194bd47cbabf410ca29fa7f1ecec08c8fde8c0d13910e903016d5a").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("99b9f0fbeea3822cdc5b3654dea52103b3d9d5f01db4201955ea3689074d37da4711d8f313d4b5458eef3395aa75bfc7").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("b6693296894820bdc3c0ae76f357e544847f10a68f0046f53745370dbe861d57e194ddaf7ff7d5e73cc3f240515c448e").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("b8a2161c64bfdc7d621df51de569911a219f718bad4d6058dcca9bddf6696d43ddc4c1e3cf91640c93f820e5680efac3").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("918081d1c248d74a0737f36e5bd40aa71b512c6be6f68e3664723849ac47a62fc743c4dc7234694bda1b7701f33d2e81").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("b3ea90ebcf0d8e332e37e5ac3c676653bb1203e8db7604bb0ac64a9b655b553de514e9bff5eeb86bb3ef9178375392f9").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("b291debc5e6c56a9e1a9b77cb980115c36a4d3d584826e62fc4b6ad7834cfc21e7c80226d46e90f4fda7771b45111526").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("adfa6ff26fcf77d816b22543003500c3b32bbf888d65eebb6086046f40a13ec537d14e09c3607e6cdce366a6a56bb68a").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("87f818e5c2330ac4e7f0ef820f337addf8ab28b07c9d451304d807feda1d764c7074bccbbd941284b0d0276a96cf5e7f").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("893ac10a0d49377fca566a10881e579c263ce761157165f9a34c18304edc7b6c0c1fe9101a7338c89308510df47bc5aa").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("94eabcb82f2b0b9cda8eaa3cecd39f0058b418cb7a25795f597a811895bfcc23643bb25ae8432a52804dfb53575b649e").unwrap(), version: 2 },
        OperatorPublicKey { data: <[u8; 48]>::from_hex("94e199beb2a2a59166a12a851ef158928bc5efc25b39eb78b3a428b25384609d8c03548a94e77c0c941c90c68a4187d8").unwrap(), version: 2 },
    ];



    assert!(BLSKey::verify_secure_aggregated(commitment_hash, signature, keys, false));
}

// #[test]
fn test_verify_secure2() {
    let commitment_hash = <[u8; 32]>::from_hex("348da373550c14a3e398724cb213fe4c4011ef74b0f78c26ae61fdd1b7ce9d67").unwrap();
    let signature = G2Element::from_bytes(&Vec::from_hex("89c7cac0c3a9338c1fe67d3f715d7c0b7346633bce766420d536be5964f28aa7a7c7ea68062a66e076f36139b49068da12dc94bf3f5c6e917f64eb15ab9ecd8de2189059a57d355897a2f5d7cb4e2c7bf3602313dc855f08b4cbf32d5fc03ddb").unwrap()).unwrap();
    let public_keys = [
        "b32f6fc90c9dcaacdf9d836a2a7e60d090fe5e55b0b02f5a4f608a4b8235ba5aa7abc4e05f9387d1d942adc57c87f5b7",
        "8c9bf080a96d13b356b01e734618a77225f03b3e92684f252ccbd313764a9fd9247bde6b00d92f6b5669043e77860453",
        "b0051db915bd86bd938746c14440b11ee3b2801cbc6d6c1c912e8b41ea5eb1d8f852abf220ae91ecdb6da094846c1ba8",
        "92fa57a5676925e8dfe3b340df2132f5844ad9f89594b04efa28fb4fb884fe21f411fa49120ed7a60ce9381a54232a10",
        "93cc0376467317a70dac3d49ca1ce0c666b3f2630396fa208cc6e7d6401c691178b4cdf20deeccfe7d597e40cfba0f18",
        "95f9da603c572257802a689964ca8f4d96f9b94f33ab75968c9cb6c730a28d50b7bb72ac2cfceee6ab0755ead9cb53cd",
        "918081d1c248d74a0737f36e5bd40aa71b512c6be6f68e3664723849ac47a62fc743c4dc7234694bda1b7701f33d2e81",
        "87f3bb14d4e16bb20ebdfc97b3b067ebbcea5b0b9725b796e6c62d8a0818eff300261a62b6fbc3bdbaa97b895b66137c",
        "b4a637afe3810d73e3402b5d6a398e45222ba846a339f1c3570aa8e3f7f5b9d7acef08ac234cce4f706671498330a599",
        "93943908436a934c08582583b08cbcc50b4478bb79b7718789c25eb0ad2f3e5713ad4c152d4b1fd13cfd12bf896072e6",
        "83d890d1bc938b48547c8730000c4dcd5a940e55e82d1322ea600cc90c319111603fa52f928ec9d5dd29784b96f34af9",
        "8acab8f54530816bce0366a4f1a2319a445c535d074b53d5824a3e90b542e8b5a77181aad2e77560fb9f6fd7eb76532b",
        "983e7c881c6c556701b21eb3f837e2661ad4ae1ad5b9f11faf6cb1246daf99157f3da6491b8dca8517b33b32abce82a3",
        "80f8efb42f65ed9650078785be5d13e6e90eb9df87a99261d4de34df2b4b79a9c9b8c5e1aec7ac068ebef14636ceac4c",
        "b675a1940be872b6a0d4e1696bb39ea38179933a1bae02ae1eaf4b47f625bd939482f8791eb38925af47f73be027a64c",
        "ac1cc0f5e0a5aea680a170ec945074f5b83d83db4d208854204f57c0de220ceb63b0121bd2a7bdb214228338c575ff6f",
        "84c0ca8535c114f8f1b369f339b2653e7126610f5170b223970f4e63ad7b55ea2f61a08e263b51fb03f6940d655690f9",
        "afc31972124bb559aecd56dfb361048ab3f5203624c6436b1676b8d440bee777d83b937febacb2d3a651df9dbd20503e",
        "aaba308a8db9e1c6c545f3fdfff00880a973f0685207688d3c0ee4546d732ec16a81fa1aa952fb3190ff5c6febcd1a78",
        "8aeb5c2757211202b3afd2033ec1b4ef2dfe376ba5c6c07b45e6a7460afa4086423c4a704eb9a781514fbc513e190a62",
        "8f2df81ba65db70eaab625c5fe46f0f5e52a45b25c761686db23b4f18e547cb0d161912dd187302eb6f7c4a9a666a323",
        "94e199beb2a2a59166a12a851ef158928bc5efc25b39eb78b3a428b25384609d8c03548a94e77c0c941c90c68a4187d8",
        "b6ee48c7a71a9d8e0813e68ca09846245fa155285f24a62b0ce9cb0102b1994ec58af8ba2a01c09363bdcc395d41f3df",
        "a26fc7f30c49215b98d5cb47a350f888a306c52fa42c77e765b55288e622f03859273cae7e1cac99e67f7a9a96a6aa2c",
        "ac290b31d2e878c2d7235efb0c61f423aa37742a31318e61f8bb0bd6c110a892dc244512fec12a8b0fe7cbb08e12be28"
    ].iter().map(|s| { G1Element::from_bytes(&Vec::from_hex(s).unwrap()).unwrap() }).collect::<Vec<_>>();
    let schema = BasicSchemeMPL::new();
    let public_key = schema.aggregate_public_keys(public_keys.iter().collect::<Vec<&G1Element>>());
    let verified = schema.verify(&public_key, commitment_hash.as_ref(), &signature);
    assert!(verified);
}
