from types import SimpleNamespace
from typing import Callable, Tuple

from eddsa_threshold.eddsa.algorithms.ed25519 import Ed25519
from eddsa_threshold.eddsa.algorithms.ed448 import Ed448
from eddsa_threshold.eddsa.curves.ed25519.ed25519_curve import Ed25519Curve
from eddsa_threshold.eddsa.curves.ed448.ed448_curve import Ed448Curve
from eddsa_threshold.frost.core.ed25519.frost_hashing import Ed25519FrostHashing
from eddsa_threshold.frost.core.ed448.frost_hashing import Ed448FrostHashing


def le_hex_to_int(b: bytes) -> int:
    return int.from_bytes(bytes.fromhex(b.decode()), "little")

ed25519_vector = SimpleNamespace(
    # E.1. FROST(Ed25519, SHA-512)
    alg="FROST(Ed25519, SHA-512)",
    # Test vectors from RFC9591

    # Configuration information

    MAX_PARTICIPANTS=3,
    MIN_PARTICIPANTS=2,
    NUM_PARTICIPANTS=2,

    # Group input parameters
    participant_list=[1, 2, 3],
    signing_participant_list=[1, 3],
    group_secret_key=le_hex_to_int(b"7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304"),
    group_public_key_expected=b"15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673",
    message=b"74657374",
    share_polynomial_coefficients={
        1: le_hex_to_int(b"178199860edd8c62f5212ee91eff1295d0d670ab4ed4506866bae57e7030b204")
    },

    # Signer input parameters
    participant_shares={
        1: le_hex_to_int(b"929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509"),
        2: le_hex_to_int(b"a91e66e012e4364ac9aaa405fcafd370402d9859f7b6685c07eed76bf409e80d"),
        3: le_hex_to_int(b"d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02")
    },

    # Signer round one outputs
    hiding_nonce_randomness={
        1: b"0fd2e39e111cdc266f6c0f4d0fd45c947761f1f5d3cb583dfcb9bbaf8d4c9fec",
        3: b"86d64a260059e495d0fb4fcc17ea3da7452391baa494d4b00321098ed2a0062f"
    },
    binding_nonce_randomness={
        1: b"69cd85f631d5f7f2721ed5e40519b1366f340a87c2f6856363dbdcda348a7501",
        3: b"13e6b25afb2eba51716a9a7d44130c0dbae0004a9ef8d7b5550c8a0e07c61775"
    },
    hiding_nonce={
        1: le_hex_to_int(b"812d6104142944d5a55924de6d49940956206909f2acaeedecda2b726e630407"),
        3: le_hex_to_int(b"c256de65476204095ebdc01bd11dc10e57b36bc96284595b8215222374f99c0e")
    },
    binding_nonce={
        1: le_hex_to_int(b"b1110165fc2334149750b28dd813a39244f315cff14d4e89e6142f262ed83301"),
        3: le_hex_to_int(b"243d71944d929063bc51205714ae3c2218bd3451d0214dfb5aeec2a90c35180d")
    },
    hiding_nonce_commitment={
        1: b"b5aa8ab305882a6fc69cbee9327e5a45e54c08af61ae77cb8207be3d2ce13de3",
        3: b"cfbdb165bd8aad6eb79deb8d287bcc0ab6658ae57fdcc98ed12c0669e90aec91"
    },
    binding_nonce_commitment={
        1: b"67e98ab55aa310c3120418e5050c9cf76cf387cb20ac9e4b6fdb6f82a469f932",
        3: b"7487bc41a6e712eea2f2af24681b58b1cf1da278ea11fe4e8b78398965f13552"
    },
    binding_factor_input={
        1: le_hex_to_int(b"15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673504df914fa965023fb75c25ded4bb260f417de6d32e5c442c6ba313791cc9a4948d6273e8d3511f93348ea7a708a9b862bc73ba2a79cfdfe07729a193751cbc973af46d8ac3440e518d4ce440a0e7d4ad5f62ca8940f32de6d8dc00fc12c660b817d587d82f856d277ce6473cae6d2f5763f7da2e8b4d799a3f3e725d4522ec70100000000000000000000000000000000000000000000000000000000000000"),
        3: le_hex_to_int(b"15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673504df914fa965023fb75c25ded4bb260f417de6d32e5c442c6ba313791cc9a4948d6273e8d3511f93348ea7a708a9b862bc73ba2a79cfdfe07729a193751cbc973af46d8ac3440e518d4ce440a0e7d4ad5f62ca8940f32de6d8dc00fc12c660b817d587d82f856d277ce6473cae6d2f5763f7da2e8b4d799a3f3e725d4522ec70300000000000000000000000000000000000000000000000000000000000000")
    },
    binding_factor={
        1: le_hex_to_int(b"f2cb9d7dd9beff688da6fcc83fa89046b3479417f47f55600b106760eb3b5603"),
        3: le_hex_to_int(b"b087686bf35a13f3dc78e780a34b0fe8a77fef1b9938c563f5573d71d8d7890f")
    },

    # Signer round two outputs
    sig_share={
        1: le_hex_to_int(b"001719ab5a53ee1a12095cd088fd149702c0720ce5fd2f29dbecf24b7281b603"),
        3: le_hex_to_int(b"bd86125de990acc5e1f13781d8e32c03a9bbd4c53539bbc106058bfd14326007")
    },

    sig_expected=b"36282629c383bb820a88b71cae937d41f2f2adfcc3d02e55507e2fb9e2dd3cbebd9d2b0844e49ae0f3fa935161e1419aab7b47d21a37ebeae1f17d4987b3160b"
)

ed448_vector = SimpleNamespace(
    # E.2. FROST(Ed448, SHAKE256)
    alg="FROST(Ed448, SHAKE256)",
    # Test vectors from RFC9591

    # Configuration information

    MAX_PARTICIPANTS=3,
    MIN_PARTICIPANTS=2,
    NUM_PARTICIPANTS=2,

    # Group input parameters
    participant_list=[1, 2, 3],
    signing_participant_list=[1, 3],
    group_secret_key=le_hex_to_int(b"6298e1eef3c379392caaed061ed8a31033c9e9e3420726f23b404158a401cd9df24632adfe6b418dc942d8a091817dd8bd70e1c72ba52f3c00"),
    group_public_key_expected=b"3832f82fda00ff5365b0376df705675b63d2a93c24c6e81d40801ba265632be10f443f95968fadb70d10786827f30dc001c8d0f9b7c1d1b000",
    message=b"74657374",
    share_polynomial_coefficients={
        1: le_hex_to_int(b"dbd7a514f7a731976620f0436bd135fe8dddc3fadd6e0d13dbd58a1981e587d377d48e0b7ce4e0092967c5e85884d0275a7a740b6abdcd0500")
    },

    # Signer input parameters
    participant_shares={
        1: le_hex_to_int(b"4a2b2f5858a932ad3d3b18bd16e76ced3070d72fd79ae4402df201f525e754716a1bc1b87a502297f2a99d89ea054e0018eb55d39562fd0100"),
        2: le_hex_to_int(b"2503d56c4f516444a45b080182b8a2ebbe4d9b2ab509f25308c88c0ea7ccdc44e2ef4fc4f63403a11b116372438a1e287265cadeff1fcb0700"),
        3: le_hex_to_int(b"00db7a8146f995db0a7cf844ed89d8e94c2b5f259378ff66e39d172828b264185ac4decf7219e4aa4478285b9c0eef4fccdf3eea69dd980d00")
    },

    # Signer round one outputs
    hiding_nonce_randomness={
        1: b"9cda90c98863ef3141b75f09375757286b4bc323dd61aeb45c07de45e4937bbd",
        3: b"b3adf97ceea770e703ab295babf311d77e956a20d3452b4b3344aa89a828e6df"
    },
    binding_nonce_randomness={
        1: b"781bf4881ffe1aa06f9341a747179f07a49745f8cd37d4696f226aa065683c0a",
        3: b"81dbe7742b0920930299197322b255734e52bbb91f50cfe8ce689f56fadbce31"
    },
    hiding_nonce={
        1: le_hex_to_int(b"f922beb51a5ac88d1e862278d89e12c05263b945147db04b9566acb2b5b0f7422ccea4f9286f4f80e6b646e72143eeaecc0e5988f8b2b93100"),
        3: le_hex_to_int(b"ccb5c1e82f23e0a4b966b824dbc7b0ef1cc5f56eeac2a4126e2b2143c5f3a4d890c52d27803abcf94927faf3fc405c0b2123a57a93cefa3b00")
    },
    binding_nonce={
        1: le_hex_to_int(b"1890f16a120cdeac092df29955a29c7cf29c13f6f7be60e63d63f3824f2d37e9c3a002dfefc232972dc08658a8c37c3ec06a0c5dc146150500"),
        3: le_hex_to_int(b"e089df9bf311cf711e2a24ea27af53e07b846d09692fe11035a1112f04d8b7462a62f34d8c01493a22b57a1cbf1f0a46c77d64d46449a90100")
    },
    hiding_nonce_commitment={
        1: b"3518c2246c874569e54ab254cb1da666ca30f7879605cc43b4d2c47a521f8b5716080ab723d3a0cd04b7e41f3cc1d3031c94ccf3829b23fe80",
        3: b"1254546d7d104c04e4fbcf29e05747e2edd392f6787d05a6216f3713ef859efe573d180d291e48411e5e3006e9f90ee986ccc26b7a42490b80"
    },
    binding_nonce_commitment={
        1: b"11b3d5220c57d02057497de3c4eebab384900206592d877059b0a5f1d5250d002682f0e22dff096c46bb81b46d60fcfe7752ed47cea76c3900",
        3: b"3ef0cec20be15e56b3ddcb6f7b956fca0c8f71990f45316b537b4f64c5e8763e6629d7262ff7cd0235d0781f23be97bf8fa8817643ea19cd00"
    },
    binding_factor_input={
        1: le_hex_to_int(b"3832f82fda00ff5365b0376df705675b63d2a93c24c6e81d40801ba265632be10f443f95968fadb70d10786827f30dc001c8d0f9b7c1d1b000e9a0f30b97fe77ef751b08d4e252a3719ae9135e7f7926f7e3b7dd6656b27089ca354997fe5a633aa0946c89f022462e7e9d50fd6ef313f72d956ea4571089427daa1862f623a41625177d91e4a8f350ce9c8bd3bc7c766515dc1dd3a0eab93777526b616cccb148fe1e5992dc1ae705c8ba2f97ca8983328d41d375ed1e5fde5c9d672121c9e8f177f4a1a9b2575961531b33f054451363c8f27618382cd66ce14ad93b68dac6a09f5edcbccc813906b3fc50b8fef1cc09757b06646f38ceed1674cd6ced28a59c93851b325c6a9ef6a4b3b88860b7138ee246034561c7460db0b3fae5010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
        3: le_hex_to_int(b"3832f82fda00ff5365b0376df705675b63d2a93c24c6e81d40801ba265632be10f443f95968fadb70d10786827f30dc001c8d0f9b7c1d1b000e9a0f30b97fe77ef751b08d4e252a3719ae9135e7f7926f7e3b7dd6656b27089ca354997fe5a633aa0946c89f022462e7e9d50fd6ef313f72d956ea4571089427daa1862f623a41625177d91e4a8f350ce9c8bd3bc7c766515dc1dd3a0eab93777526b616cccb148fe1e5992dc1ae705c8ba2f97ca8983328d41d375ed1e5fde5c9d672121c9e8f177f4a1a9b2575961531b33f054451363c8f27618382cd66ce14ad93b68dac6a09f5edcbccc813906b3fc50b8fef1cc09757b06646f38ceed1674cd6ced28a59c93851b325c6a9ef6a4b3b88860b7138ee246034561c7460db0b3fae5030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    },
    binding_factor={
        1: le_hex_to_int(b"71966390dfdbed73cf9b79486f3b70e23b243e6c40638fb55998642a60109daecbfcb879eed9fe7dbbed8d9e47317715a5740f772173342e00"),
        3: le_hex_to_int(b"236a6f7239ac2019334bad21323ec93bef2fead37bd55114356419f3fc1fb59f797f44079f28b1a64f51dd0a113f90f2c3a1c27d2faa4f1300")
    },

    # Signer round two outputs
    sig_share={
        1: le_hex_to_int(b"e1eb9bfbef792776b7103891032788406c070c5c315e3bf5d64acd46ea8855e85b53146150a09149665cbfec71626810b575e6f4dbe9ba3700"),
        3: le_hex_to_int(b"815434eb0b9f9242d54b8baf2141fe28976cabe5f441ccfcd5ee7cdb4b52185b02b99e6de28e2ab086c7764068c5a01b5300986b9f084f3e00")
    },

    sig_expected=b"cd642cba59c449dad8e896a78a60e8edfcbd9040df524370891ff8077d47ce721d683874483795f0d85efcbd642c4510614328605a19c6ed806ffb773b6956419537cdfdb2b2a51948733de192dcc4b82dc31580a536db6d435e0cb3ce322fbcf9ec23362dda27092c08767e607bf2093600"
)

def case_frost_ed25519() -> Tuple[SimpleNamespace, Callable, Callable, Callable]:
    """Inputs for simple FROST signing and verification test with ed25519"""
    return ed25519_vector, lambda: Ed25519FrostHashing(), lambda: Ed25519Curve(), lambda sig, msg, pk: Ed25519.verify(sig, msg, pk)


def case_frost_ed448() -> Tuple[SimpleNamespace, Callable, Callable, Callable]:
    """Inputs for simple FROST signing and verification test with ed448"""
    return ed448_vector, lambda: Ed448FrostHashing(), lambda: Ed448Curve(), lambda sig, msg, pk: Ed448.verify(sig, msg, pk, b"")
