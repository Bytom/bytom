package aihash

import (
	"reflect"
	"testing"

	"github.com/bytom/common/hexutil"
	"github.com/bytom/protocol/bc"
)

// TestCreateSeed test that seed can be correctly created.
func TestCreateSeed(t *testing.T) {
	testSlicePreSeed := []struct {
		preSeed   bc.Hash
		blockHash []*bc.Hash
		seed      []byte
	}{
		{
			preSeed:   bc.BytesToHash(hexutil.MustDecode("0x7f5979fb78f082e8b1c676635db8795c4ac6faba03525fb708cb5fd68fd40c5e")),
			blockHash: bytesToSlicePointerHash(hexutil.MustDecode("0x0eb076dade912e4e2aea455e9225ef5d7c36aa6d5c66440218f408067da9e7ba")),
			seed:      hexutil.MustDecode("0x01609e244d962cf47f7aefd47f83c93e07318f859b9a2ebcd70000b3c70b1d03"),
		},
		{
			preSeed: bc.BytesToHash(hexutil.MustDecode("0xfe3c889716ee7ff8828dfc64a773c4912e215a9b82f1df38fd0de3a9e6f6c38b")),
			blockHash: bytesToSlicePointerHash(hexutil.MustDecode("0x" +
				"e93187549f97232af825848c2d5b28b58d57576799ada949d8d93c1db27a2e80" +
				"5f0dc2afa924f7ade0a1dc615113e9824728d360db19ecfdb52dff951189d755" +
				"f78003d615e2e347beb32599fec8c8ee9258becd3f839bf4d4d452e9061215a9" +
				"570eef870a250610b369c78830ac8df420b96abb7895cd98d06c5bb56ada27b9" +
				"848a4be077e0657ebee4926092d7490eb89030dffa0345d58a9fea6c881d5651" +
				"d4f470e76bd9af8496b503f049a0ef76b9a5b9fbbe866c8a49b54c46fcb6045c" +
				"36f046a5d86d48d05b2ca9b75ddcc88bead3190d108cf6ab0ff54c10a2392128" +
				"d8e09450803a2f18f67379efd90a3bcc73bc16205ea82570ebea21d8d11e3dce" +
				"2b231bde13b8e334b77e3c967a7eb7b257e2717f994ff9031c06f7f5f6ad76f7" +
				"a1c0df7dbac7fecbf9aa5249bd14a2e63de79e0cf3be1c0c434c19c62c427e8b" +
				"5c24d450ecfd42d33dc6736f69dddca59916e17b0adde1e93aee37eabb00c72d" +
				"b2351d01babc4663e8a11fe1923c3fa3d54e0af8c840bec755d7f0244f21b689" +
				"0f6ae56a7aa7281ff120e94dc86bc924f6d467b0fcac715312ca9d9bb894d3e0" +
				"b8aceaf8f72acd01a2a2737b1b813dd69d521d087d8cb80fe93eb28a38b22bf1" +
				"ba7660b875626774f93f75bee5a90501385e03fe702f7da587892598e0805fa7" +
				"3285f542afbab848c624dd4ad9423b9d265707d18d44c74a998ea84ca02363e5")),
			seed: hexutil.MustDecode("0x28240f593b479bb1709278a06351a741e5893c908ace50e711219bddf41f2211"),
		},
		{
			preSeed: bc.BytesToHash(hexutil.MustDecode("0x40aa575363fc90aef55bd1001362f319ea5aa861858f9d81fe3a271ee64497a0")),
			blockHash: bytesToSlicePointerHash(hexutil.MustDecode("0x" +
				"43ff2d59fc3a085ef57df59da93db9126f7715c24779c583d1855e01f39ee526" +
				"1afb18e671a449f24d77164e4da34d6aa357468ca18ef923540c8561a8414b34" +
				"2573a0e77261f4d52efeafc7414f758d231bb55e6c5a5d7ffb82e1a0cbe910b9" +
				"31e204d418d7c6268ed3d37f91f625a3b4e09ff6e7add7ed6b0ec0795da1c0c8" +
				"94f47f36d75327117b206d7110021bcfb956d34e64189f83e890f289d98a0b36" +
				"d5c8842cb66f5207d52d2309b9adac0ded46e8c6af20dcafb063b80d3fb21688" +
				"3fa95965ae59564bc5ab481fa85b13f3e91320d73b45a1f5155cb92b3be2ae54" +
				"6d764d770b60be493c3e83ee5f74936302db28541762c3cf0a2f73a029925193" +
				"82e597b7235d260db97451c91c086804deace061fe981fb2bff2d3557cfd53dc" +
				"754ce51c9b6928d6413f7bd680d182fa77bad25ef4a593585b26a31e0a32277f" +
				"1af9597caf31848b9f2b734d4712acc1e557ed73ae869eea43af855bc5a1f7e0" +
				"6ee4ade9f4c0807bd8cd125feb32acc8aba1747011f85467f0a0d405765da142" +
				"01648a8fe4b9bc1a561e49fd0bfb8568bbc1a2a4c62b656cba1a50b67636dad4" +
				"26f28bd50b7169ad9ca84caa25cf0e9da47ac17c7b864ddfb29920f456fee90b" +
				"98ebebf840540e89e66b440e7eda7bca1f2e80c48f0fa503f140254a89313d02" +
				"b1bb2fee73ecc07caad986f3e0418d908e2a8f171c313cde9b10207a2ff5c55d" +
				"6634698f01eb701dc99968f87abf3d5234dac958b28964210c83aeb6ea916e90" +
				"11bdec74102d0a449095c1aee3ab94a01019089b806592c083c7b3204996ce84" +
				"99aaffb092e8d5353d7ae11a468445455d7bbc18a0ef791de8ac92f4be5d3b6b" +
				"999bc6d7b5e9f5169145ce85bf8b3126741594ac88a54914396ef1caca1b8fdf" +
				"b8d1e1735297bc4c5cce908e324a462f01c18894b5584c4021e134951a6e175e" +
				"dab265b2c95ab93e0ccebbbc1a48df426946e8e4b9654fe0055515593467a0a0" +
				"3fe96b14ab895565581675e99443c091997b8508f9d7aeee381b167034ed4c33" +
				"a68f255ba00b5729824918af13c3d0f8c199d0c70974000488222c2c3c4273d9" +
				"a7c3ecd17e5e9a28b10701ef230c1f062eaeedb4a5227449d9018061e59deb65" +
				"df07c4dd1c37925c2f426b42080825b07e47157fe2d5cae8bd6d0758d520b09e" +
				"939811d5156d430f3dc510ca967668c9fd7736ab3c340a35e248030bab94bde6" +
				"06e5c37ee8a9b0c830bce7544dafaeff632a444f32af3c6c704f9955ab81f824" +
				"47c6bee4544e1e71f736a29031fe0875b969976aef1fa88b65f1b62fe4d210cf" +
				"cadb7f1e04ac11c76a26e97971d17643ab83c606e40e855e9bf1c07d28b5c927" +
				"8524c56b8e75f559e1ddd54c4dad0205b69e010209839532eba84eda4f138302" +
				"f25353798ab8548c327d2048b439736de4e278c4618eed92e12ef7ed9b5cb5ef" +
				"c30869d560137ad8419c3258c107c9e60665347fedbaef335fb7507401093ac9" +
				"3d37bce36b649181b3a359a09061ec86ea141f85b83fdd8ec5e9456afa681dc8" +
				"51ffdfb7afa41d74bdc047298b5b19dbef610280ac60d7190c2068147b9eabb4" +
				"a90f28f55da9fa7af9901f9c0a6c8863c8c8c10e3d7e7c74337e3aa08b3e5fc5" +
				"a6d52ce8f478d55890e86a2c0527e1a7e68766113dcbc82706652f45fbc93076" +
				"961c5cea55436a184362097db0b6148b48cfffbb220f361c84d88eb3e6ea6309" +
				"650fdbf021df105682637a578de3b195a09feb6610321095737d7c388b2aa3be" +
				"ea8a0f16a3b9a65ca0b0135957b271dca02b06443c3115e8b60528c8f5441d29" +
				"a8f454b7bd2be133d16cbed056c17391267fc2daef2e442fc124396b66f8c49d" +
				"e30c7639802f2dbd57d1faae4ed08940036db667ae530b2519b7dc506f50573c" +
				"91785d38ea98cf80b8c03832c138445e69e53c0c0e3151e8423835f6234d0467" +
				"892360421234cd69cfb6e3285f7d82204bd03e151cc6e63854f9f5c8e99f8fd8" +
				"750d4867a1b90cb1ea62c3a6f300897420d8486248c58ad25eb7e6ea3fbbf604" +
				"10a56d24ca835f9cf9e67dbc13eceb2a833584124cdc224b30058a634a88068a" +
				"c3da986c20646d7052f6f878237e898c54219e35628829c198d3b5c03771ae9d" +
				"8661094c17d552a3d7fc56ed2ec43ed444cc00a58b37d01f7b693ef24c13e6bb" +
				"731e7e876f24127e84188723ef0ef4dfe3dc2d0459e7f82fa7e57eda7b4288be" +
				"50664d6a5f419c780915b2797a13ba98a64e2b691ce5362f82ddc9f677d07976" +
				"d046195ae9bb6c1763194d8b6984e27e348bc6b79b68c9adf8ba9d6177617d8a" +
				"ff696df38ee73a6b434a2ea8c81e31a66d811e9471f55a378a9b2b714acbff00" +
				"c46da49e66fda0ef95dde54b9d2ecbd3bb98233cf523cbd717c2a83ceb35f1fa" +
				"2abec1ece36068c1524b855a1223104d7eb91f8d3a2e7cc9ca4a97698df5078e" +
				"289a4e6daef95f1bec11b3f88e09555bc2bf1ab9ab013f8b89fa7d02ca8d4701" +
				"7211790d168cf85e44c68078e4d078c06439faf21bff5d7fdb508cdc466b0f0e" +
				"de53e7191838c48b7b07e06df7ed1e55832b6165c63adaa4d60ac5f3a29dbc94" +
				"99619b1afaf4abd5bb670cb70e40250b668703397e39e1b67eca4cd663a6c0fa" +
				"0611dc68928bc18ac02047540cba4da500d8711e50ffd457e03c7b40849724de" +
				"502f4c6ed2e145220a3308e7eb01d59a49f447ea3771a0de8a6f0bb85b5d323c" +
				"c12f07a13110936065b78ccf09caf1964ca909f8529e47da1dd81bbd35cbde0e" +
				"43aaa3392d3666099ecc31ec42de62b804b1e80e44a1be207a11f346ff0b435d" +
				"f993c45158461768172b8b7b5dbc8aa7749f97ab4038020dc58a5d1e6d69ddef" +
				"4563a24c3f067edf5a4fcfe8fdb4c7096b391f574481287786b7ce9f086e7a8c" +
				"7542e3ab82eb4cef8f062f67d41a986f04eac19661d077d805c88ee4b894238c" +
				"24b25793271ab2bd93ce571bb2118e6aee4636920851c85e6d992010df9581a3" +
				"838731eb206a4074e4ce9b5bcbf9793030c504fab03f4d7cd1ada849124a6b32" +
				"5bf1e1e14a50b419993053ce5f9de9bbad044a82cc24b99484c07590a2275373" +
				"9ff5c15ee7325a996234302d01c991b6349ea71b3433837c2749f983e344b42f" +
				"ebadace478a812b695c2233b3485e0bedcbe3ae912e496ad2ace9c0f4e5a63e4" +
				"6d15fa02e5115aab7c77af8722dbe87a1a62214623732217daa335a49555f9d9" +
				"ff1e8e36e76edef72975ce30c674f38686892eb4d795808c586c9de810531690" +
				"ff07219499137c6864e5a72565d3b1b03b782a89c88dd638a4e51748a48923ef" +
				"4dbc730a60468e7f49ecc8ffccf038b036cc49f137cf2ac47edd2afc7bfd8a74" +
				"cc6ff774a9039e7eb780689ff2ebb41a68ae4dfcf1b625c48e388feda1d6edf3" +
				"6adc3eaab29d84d53379d4299f64e1789c20ca72a557f502b231fd4292c39c69" +
				"73c76014d33825d0029aad184633b25c5cfdee489c8c177bfa2c0ee997ab9731" +
				"b8a16bbc1f1a9a8c030a984dfd3977813320a2683ac23592b21e04bf46c47555" +
				"f8073555abec4792c2567bccc8c0b22e635ea74b0a76e8993f65defaef6b2d08" +
				"dbd5ce702e0eacae0380b22e1cf1e21305bf4e4dd67679f24b8ef8453211ce95" +
				"cec16cd62671406f9bcbad75a2cf14d26c64c6bd2d7aad194625b305d14883a5" +
				"74235441b8c8034bbb46a74a4ca7d12914bc20cd68b14c55d03db9342234d354" +
				"4cfc17a7846dea2c87d1450aca850ee9e3d0d09f2e0f18b45669c6bc6d59083b" +
				"a094a96e5d9526cbf2fa82be3bfd8f12e357778d4f40c8340ecd1199a7bbe0b1" +
				"20d5dea90386e7f3047569b3f3ea1a72c36928342c8c9b3cfb9c3cf5528fed0c" +
				"9e69b11a0feb730d04df13e002c85b3ff7c2622425c21ba9b955912b123de653" +
				"72aa90be2b341a6fe9ef7bd02fc618ba211d111beadcca196b3e5f385b1c4ee7" +
				"757d42f4e6f15afe91aa5e7cb598c53921d867ee56da7daa9ce83884ddf5d9d3" +
				"447286fb71f996147b94e98ad6d7f4741f19c2e73983f990794895b60c7ec76a" +
				"af37a91c21b714bbe953f1a59787d8e68fb3f12ba964ec97fce710b9d3c6c84c" +
				"e4bc0e6288bfa82e66bf73d5086d9e2602d104167ad0bc45c3a5cc3ea03fe445" +
				"f3ec7d9a4aab905d4ed2745bda5c46c1c606e61e25330449b536bf79869e648e" +
				"9ecc57d99ea0d7835a83c781d5d59f4fce7cc0dbcba23864b190b5b44ed8ed29" +
				"ae4f829bc825796dc927ec52e2138e0504637a73cb4feaaae0cd8595eca1c2af" +
				"beac2cd0df957cacb3a117bef463216c8347f6a7d2022e335f0ff28bab417837" +
				"4e1f3cf4146c9a26ca00f786d9ae0b7d9ed9ebfbb773ace265afde2b24d62c8c" +
				"061b0b9a16bf3601355ff0c79329a811281d46afe2fdcdaf0fae3ec8f45eab79" +
				"53ee578dc0a12c7a41298a43653613539058b1f71fef9118878505707b69e655" +
				"b2247231ae14cedaabac45203f4ee773ef24e0aa6c3242d41bf5637277a60bd0" +
				"6837e6657f1aeb7ac8c4a545d81111741769b6ed4c6f4c2700f11f0c3c5ecba3" +
				"9d46f9063fe0b94491cee674c8e589680f66b0869006aa264a7a4a0c066bb25b" +
				"2a1543383b19c8a5c12dd284d87af4d8e0d5bcec178d7ea83f3c9452637a5558" +
				"f5d794d4ce6ae53af6d52e9fedc80d34092f6d8e561f3fcdb7d52d60fb97aad4" +
				"de1e2523c8e78cd6fed5e0b4d82328d27d2aa04006c5016064f37b98273322a2" +
				"8b490ad23ce1084aefbf7194e574ce8fd0dcb825a462e9715cf583038c71f331" +
				"4222d11f3bd37a163ba33673fbaa069772c9915b7de1d703c996c0966f48fb0c" +
				"c8bcfdf3efd4dcef505a66f1b98089aff0a96a7fba0a4cecd92d8f12d70e842a" +
				"48a68f171a6a277a0083efc81a279fed8f7b26c6c503f7289d717ab3e0ab0222" +
				"def0c318208caa962fab895ae972c9494ef40ac2ac7a1e2acd280f4c4fd6fd0e" +
				"787c5324b9c90fe40e74f159a9068c795a26ef4b6dae362e744d96c20ba4489a" +
				"4dcd745806512104d4f311c5a5ba777307771e6c1e42894d9319f2507bce863c" +
				"6bf1a22c0940ede6628e35fd7c8616760aa5404c92fc55c97acaf5a34d297950" +
				"8a7e7a5c935171a2e97f37b3ce7734e88c0dc58148071c2a707d1ac783777bd3" +
				"e9d286b4beeca1465471390b3dbf8733df1cb6f81a889f2e8578756e098ff720" +
				"9dc2b2b1101a8b3af594dedd67efbf7b7fcd0207355ccc525c00425c619d71da" +
				"7a23cf897f647e29f827ba5bff9a4c047a2e000478cb3239e6f008931911958d" +
				"08fb5e8d2178a2eb7d10146308568bb1341b9a00e4aab21a0d4b3813f4a445a2" +
				"2d8c41a1913942caf48f3b464f3895b7cecabbede3c5bd59335d18b6f6995f3b" +
				"fa009eb1ae8d6fddbe8706b02075f5b82a42a434000856b821206bcfafe4961d" +
				"493a999402b35789d92d7457555f18ec6e8ff4279912d6dd8f9a68c84be47ff9" +
				"dacee303c5ff9421f363426f7e1e011a4dae8065fe41aad6e0704930184417d0" +
				"9df7743acecca87da7c1eefeb003140cb4a8bf48f8d71541759aee45573b924f" +
				"9b776a0e8addb010fd3a334251170c50f613963cab41ce73e7f7a0eb6160fc4b" +
				"7233b9c111d902bbbf1ce38264a820f21b79c144397c19f385e7f952316171ac" +
				"6d6490e093538ef46a9422f52a777d36533e49993f7a5a18673a01ba22b6e45e" +
				"716b3ccd9ed920f0facb27dd5df40133dd2821f9421fd1e866b74346b85169e5" +
				"85981a22d50dde5822263d241ef438dcfb70bc230d2e57c7e5de3e70021aa68e" +
				"57554ec6fd2c404b28afb6b1e14cd38d11fb0df1111a0dd455ec0c83033a7937")),
			seed: hexutil.MustDecode("0xb17d1c5601497db0a396a1909cdfebf4ce1daa1af7fd35c97f9e4ff12afc3861"),
		},
	}
	for i, tt := range testSlicePreSeed {
		seed := createSeed(&tt.preSeed, tt.blockHash)

		if !reflect.DeepEqual(seed, tt.seed) {
			t.Errorf("seed %d: content mismatch: %x, right is: %x", i, seed, tt.seed)
		}
	}
}

// Tests that verification caches can be correctly generated.
func TestGenerateCache(t *testing.T) {
	tests := []struct {
		size  uint64
		seed  []byte
		cache []byte
	}{
		{
			size: 1024,
			seed: hexutil.MustDecode("0x0000000000000000000000000000000000000000000000000000000000000000"),
			cache: hexutil.MustDecode("0x" +
				"e0028c951d70b506f3da3f5cc26256decec29b2b13cbd902b766e0e6830e6602ed9aded0cb2cdedd0c712f159c207542d765cb271c80af0de8a4b3158f5078a3" +
				"facf7f92c9a066bb8ded2405508deaac26f61d08cf56f9952418365cd1109452cb7702c0bfaf25d23fc6bca0e4d87e30ccf012689e00ad77698c0ada6d62c831" +
				"469e3c12ccb5df3b6540d975d9cadd630f4eaf3aa10a092c25bc25ce562281f474c4ae803431d22bb92678e8a4185945f60f650086f2aad6ea3ed7b0ffc75b2a" +
				"2b67911c792f6cc414ae398d16ccef91022502d1ef5bded2c5194b86d33782d727a1bb58dbffbe6109e06454284f0434754c42e2321e3a37441b2022451207a4" +
				"6299b88e96e028e59e6a38d221ab49b45b354bc4fa8e62f3ef2ade6760d4aca60f47dcb80edab7a5df474631baf8a7bbcd275de8e46f9723ea46f05f5babb7c2" +
				"243d92f5a1328a4cc9f4cb6da60ee6f7b362472f7ad4fc117e3646c85061574c12e110bdfcd98d90f0d19b6bff5b44a7c69da1975c3a8522095eb9217e553c28" +
				"f7b139d522c043ba7d897ec77f15a3491fbd0e1eeb9d4891247707db3e76fb11e73ecf03a2e1d21b1bcc78e865d8451b15d338b2cdf757d29139ed9a1abdfc78" +
				"40b3183422b8b3c461c96abda221a41c2f310fa37805f06ecf9b003928cebd9ede832e0448b6dc5ba99c94443a62f8a9a23ca8ead5f2103bba9295d0b8b35987" +
				"f91925d561cc6bb4f8155de6ed82cb0bd2c3c829c392fb82e30dfae3b42d49736afabc3f0b79d431e27dd8685afa2316accd6847fe178cd428dc0c2ac6b40c03" +
				"ee46288bfcbc4722d6116d919b453d403b57a7cec3899ba6c6eaa2a9e4e73b8c3c210d3da485c12d26d9acb780952fd0338bb8d20db14a4a5d892110a1ec19bd" +
				"7a6773fc47e0c1e1e59c5ab4a1c8fb2f86849d6b15071356e2958ea7f084d89a248afc68a9a7cc1ba96ef353bc9a7f222d0aa1b920a25c84c6e4231d3f836b5c" +
				"1d4fe8894282dc7269d9724a038500118cb8e74922ebc17c046df6ef5c707c278f4b9ed3325e3af7659233f10e1a3fb1d96702fb364692810f53f79b037edff2" +
				"973af9d6d6819434c34dfb0ac4f22c977f627ea0013ecec6a49339ff09dd011876741e26bac7e64191ed17e1ab423c6358a5e36702f841b2607d0639d2e87061" +
				"d77fec191b2e020b0df5f7daf4491e9a6701f66d103c6feaf6d67aa4cbb877bbed87461ceeb4eee6148a5cfc8070dd79c9e34ff072e2e5a553259794ac027fec" +
				"e41ee110c41a9582cd2f5368c98a95f7b6ba93520046e819debfc3c93f5100462aaf7616c84a6d872ec0ee13b69b5226e7c9937d3f3f5f511c31921b492bba38" +
				"e1140b92e1c20aac1a2c81ac51f80a79cfbe4aa1a31a18e7c58ebf3a0a151ce7c2f761769d5e4e09a72ba0771cf840ecfc1416348260379c5ffa04cf4feaf437"),
		},
		{
			size: 1024,
			seed: hexutil.MustDecode("0x9e6291970cb44dd94008c79bcaf9d86f18b4b49ba5b2a04781db7199ed3b9e4e"),
			cache: hexutil.MustDecode("0x" +
				"b0930b1af3bbdb6cf86dffaba042b186fc0e0380f2cbab6cc9282d18768364ae8313dc9b899273f35aab6247412b7a7fe42993af481e20e324666c640186fcd3" +
				"31d4feeea3c62dc91a9117cef60e8e51a644d47c3641558c04adefbd6d170e68da7f7f35c6f3c83c6cca5156df5c2d5affe1823b5cbde280fd383aa894268e3f" +
				"68c9502be1893aeab172831e8ce036a2d0fb7e488d4aa99aaceda25e082a0407505e0bef8aeda0f2661751f00bfcd6a3509f6fa5fcba58bbb0054145f2d4873c" +
				"d97644d0daeb9d7d9fb99746a983e5a36d7f409775d1eb87e4aa781d3ef3caad480271ed37fbf38940ba43a1eb93959cbd20756bf7f9c45704ce3d6663753f95" +
				"ca9a0a9d8043e8ad3914451a8032b204ccf4bdbadbe4226ac002f80f73278a0f0a4312c4ef9fed775bc7f96810f09f38889a7e3dc25353cd9bb89d141d698f35" +
				"243d92f5a1328a4cc9f4cb6da60ee6f7b362472f7ad4fc117e3646c85061574c12e110bdfcd98d90f0d19b6bff5b44a7c69da1975c3a8522095eb9217e553c28" +
				"d036d0815e3ea9be14957e09980fb3a3185e7569c9d0d87fed34f910250fba3a59ec784e90dab7e842cf01bdd75fb05f592fdc93248e5aece012e16f6211e2b9" +
				"72e95ad9e6026f3c83da205db0b12e2dfdcb86b6f4294ca77234a6cd5a361a89ff345c72ce1cba1855548409bb04c9ba58c5b20594774ab42048440f189ba1be" +
				"7c043eb10b9a998eca952d57a11632b5a82e3a61e8bd6c7b36d2db4af30d10b45e8ae329167244d66d925d62cd406d483747f100c876abad1edc12d2aa84ea62" +
				"ea0f33063faa13ea4df2016b399f71b4a73e12f68275b680d31d62e23a8c000be37f9881040d220e1e9898730525e2e5645c3a98044b78b6d28bfa4328ca1eaf" +
				"377a142dc3b54ead8d8856baad7f91994e957b9ae2d0bcffc47966a75c638b84bce644659f6266873a2561cca67ced1073096df2e6a501aa2b78105cdcbdd6bc" +
				"c4afc9d3cf5a2c228169a94b71467199c9a1e3331bd3227e07ad0fc31c3c112c55e7e9beff8879324ba307350621443e3023bc3c773118404b536ced64f47ffb" +
				"5ccd43f94e27fc6ff2080d20db51dbe7b8f4615e273fc81341b3114a727c6f6bebe76a9b672b5b4befc8eb3f459e002b8799b32636c40dcb13d999e6cca300b2" +
				"6d19580a16496e1da91c0796b2cf4704789af384e58401625d7186fd59bca64c95eef243243b44fa5920a2f4aee99ff6d7f50f3cd8812754fea4ba624ac17009" +
				"cebac75e06e61796066a839afe6ffca8436ee0651a7ed7e2ce3e981675f03be25095f66996b6de5f9e216bc0ffb868d900b43b105e00e2a57a219617e52de0d6" +
				"243d92f5a1328a4cc9f4cb6da60ee6f7b362472f7ad4fc117e3646c85061574c12e110bdfcd98d90f0d19b6bff5b44a7c69da1975c3a8522095eb9217e553c28"),
		},
	}

	for i, tt := range tests {
		cache := make([]uint32, tt.size/4)
		generateCache(cache, tt.seed)

		want := make([]uint32, tt.size/4)
		prepare(want, tt.cache)

		if !reflect.DeepEqual(cache, want) {
			t.Errorf("cache %d: content mismatch: have %x, want %x", i, cache, want)
		}
	}
}

// convert []byte to []*bc.Hash
func bytesToSlicePointerHash(src []byte) []*bc.Hash {
	var sbh []*bc.Hash
	for i := 0; i < len(src)/32; i++ {
		s := src[i*32 : (i+1)*32]
		tmp := bc.BytesToHash(s)
		sbh = append(sbh, &tmp)
	}

	return sbh
}
