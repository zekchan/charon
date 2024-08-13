// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package validatorapi_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	eth2capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	eth2deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	specDeneb "github.com/attestantio/go-eth2-client/spec/deneb"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/validatorapi"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
	"github.com/obolnetwork/charon/testutil/validatormock"
)

func mustParseHex(t *testing.T, hexstr string) []byte {
	b, err := hex.DecodeString(hexstr)
	require.NoError(t, err)

	return b
}

func TestEmptyBlockHash(t *testing.T) {
	emptySszStr := "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000540000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000880100008801000088010000880100008801000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000880100009803000098030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100200001002000000000000000000000000000000000000"
	emptySsz := mustParseHex(t, emptySszStr)
	m := &specDeneb.BeaconBlock{}
	err := m.UnmarshalSSZ(emptySsz)
	require.NoError(t, err)

	emptyHash, err := m.HashTreeRoot()
	require.NoError(t, err)
	require.Equal(t, "bef96cb938fd48b2403d3e662664325abb0102ed12737cbb80d717520e50cf4a", hex.EncodeToString(emptyHash[:]))
}

func TestRealBlockHash(t *testing.T) {
	realSszStr := "f9a3af0000000000d71c000000000000c6466315901689c1e5d394882e3d4ff255fe71e4b4307afa2228336e635679c944be70ad5eed6324b74a7cce916b4d17e1771d90b2f76fd69d071288c6966f9a5400000093d604d1bc987d164d08f3f5f62628c8ba0c971631c1e9abfc586768092b62e2f065c8af4ebfc62a992f19cf1c23b54b0b08d58271934c60466cbcd4754829e358e2f1949fdf3a9f9cdcfe48ec3baa070f85a879fe72f865aced07e5fcb70faae6762f220810d8e05974003bcb3e82ebb9d2405073d1c1880e47e691c2150eafcc0500000000000059a3830efb4f8aa6ad53a493f6b1559130a4af7eb645592c0c2078b518846ff6636861726f6e2f76312e312e302d6465762d38306635613236000000000000008801000088010000880100008803000088030000f7fffeef5fdfdffffffffe7efbfafffd66ffbffffbf7ffffddddf7f3bffefeffff77ffffdffdffffeffff6ffedffb7d7fffffeffdfff5ffffddeeffefff5f7f681bb059da6de33c684276ef984e6b1c1088886f65f175dafb55349afac38dcd6cf65307e143bd7e15edabbc187a0fe8e01931f7c2f29abec375209d3d8815ac926f6ed180ecf0170bc6cb6e56b9a26757c4212de28719dbcfd90992fc77faa4c8803000002070000020700000800000004010000e4000000f8a3af00000000000000000000000000c6466315901689c1e5d394882e3d4ff255fe71e4b4307afa2228336e635679c93efa0a0000000000e149b7cd91551da03f1e49fbc915aa11ab7e51f5c726f361f79df2060c2d0f2c3ffa0a00000000005c7a5529e933b87765891fd97e745603935d1e6bb0ddbb89ede50555b68b65ea8051031ef70b745fb70d32d8f5b979b3151d439dbc23895a8bad7a38a9bae576926b2e8a87d254b3f567235e9875f7ba193ac2bdeff70f8659b4334955b1218a76e065c9229e88ea2a1e8a5dcca36c3a96e8fea0898d2ec300a1b51514a6444cfffff7ffffffd7fff7f77fdefffffffffffaffffffb7ff01e4000000f8a3af00000000000100000000000000c6466315901689c1e5d394882e3d4ff255fe71e4b4307afa2228336e635679c93efa0a0000000000e149b7cd91551da03f1e49fbc915aa11ab7e51f5c726f361f79df2060c2d0f2c3ffa0a00000000005c7a5529e933b87765891fd97e745603935d1e6bb0ddbb89ede50555b68b65eaa004ca21d0fcd9213ef1592471a42a4a6821e730d85ba948c0f1feee6fcb3822a1fcb9962d3a6f8aa6ebd6b2e677ac75067261c9bf5f43cb8fb86a9f6742cb4bf504b7d19dcda658899b32506bef94b8e00d1f7131586aa0d3a55c63d6799abbfffe6dafffb7feffffdffffecdfd6ef7fc7fffbfffff77035ed761013f26733d7fe24d7cfb62a338bb38239768f0a6cb2ab89e2de922e76f7ce7390c41ce3416c4a0a297761c71763d89ca3bda8843a990dbe3ea101de148d3077fe1e52ee20c833c56c8cee2a96013334ff556e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004dfa4f9f61abdfa4cb4310193e2c7c0919edb3514360695421ad775d0c8a8a08825daa000000000004bb07010000000000000000000000002922b26600000000100200000700000000000000000000000000000000000000000000000000000000000000622835fa8ecff60dc5344466dd6988090211133b486afebfc53b0f472bb8d28c1a0200001a020000000000000000000000000000000000004e65746865726d696e64a6e9f702000000003808000000000000cc4e00a72d871d6c328bcfe9025ad93d0a26df5155ff0b0000000000a7e9f702000000003908000000000000cc4e00a72d871d6c328bcfe9025ad93d0a26df51a849110000000000a8e9f702000000003a08000000000000cc4e00a72d871d6c328bcfe9025ad93d0a26df51f1d80b0000000000a9e9f702000000003b08000000000000cc4e00a72d871d6c328bcfe9025ad93d0a26df5181b80b0000000000aae9f702000000003c08000000000000cc4e00a72d871d6c328bcfe9025ad93d0a26df51b5de0b0000000000abe9f702000000003d08000000000000cc4e00a72d871d6c328bcfe9025ad93d0a26df5112020c0000000000ace9f702000000003e08000000000000cc4e00a72d871d6c328bcfe9025ad93d0a26df5192de0b0000000000ade9f702000000003f08000000000000cc4e00a72d871d6c328bcfe9025ad93d0a26df5136ff0b0000000000"
	realSsz := mustParseHex(t, realSszStr)
	m := &specDeneb.BeaconBlock{}
	err := m.UnmarshalSSZ(realSsz)
	require.NoError(t, err)

	realHash, err := m.HashTreeRoot()
	require.NoError(t, err)
	require.Equal(t, "3f1d4b709ead918876f4f3bb4f2be0d820e3f95f1a0a13ed7be70871841a2fb9", hex.EncodeToString(realHash[:]))

	domain := mustParseHex(t, "000000000e52e6531f9e84942309e5ab7978fd1cc8afd2c5bd1fa1d9d3f9f9a7")
	sigroot, err := (&eth2p0.SigningData{ObjectRoot: realHash, Domain: eth2p0.Domain(domain)}).HashTreeRoot()
	require.NoError(t, err)
	require.Equal(t, "0dd09709a8a360a1ee858c8026ee162f47d98f7f39ccee93f3e988830d432ede", hex.EncodeToString(sigroot[:]))
}

func TestProposalHash(t *testing.T) {
	proposalStr := "{\"Version\":\"deneb\",\"Blinded\":false,\"ConsensusValue\":null,\"ExecutionValue\":null,\"Phase0\":null,\"Altair\":null,\"Bellatrix\":null,\"BellatrixBlinded\":null,\"Capella\":null,\"CapellaBlinded\":null,\"Deneb\":{\"signed_block\":{\"message\":{\"slot\":\"11494453\",\"proposer_index\":\"7384\",\"parent_root\":\"0xf22ae450058b4d3247257c732863adc8f73602e999749ee9ec472cfb779e0baa\",\"state_root\":\"0x3959d53aca076eaed1fe318890320ea5b51a5c8b401cf9ff7227c766e154eb2c\",\"body\":{\"randao_reveal\":\"0xae4562f5772dba9c90855e2266e69b2273579b62da1cd15b9c601a143395e3ce3171b6937f30db2e7a902ff2cb4ffe371210824863e0a9d785df4ad61f6bcdc5fce0a625f5910bc4d4c08bd832fde93b33b7344d2a031d6dd236fe918a1e3862\",\"eth1_data\":{\"deposit_root\":\"0xa30ff0f357a12bab11ef6b4b93578fdb5e74555bee49fd4cd254e71a65f55304\",\"deposit_count\":\"1482\",\"block_hash\":\"0xdf5686d4fb835110f2bbeca969bb4db907125c4d48a9685bd9dbb4385265eca4\"},\"graffiti\":\"0x636861726f6e2f76312e312e302d6465762d6332616137633100000000000000\",\"proposer_slashings\":[],\"attester_slashings\":[],\"attestations\":[{\"aggregation_bits\":\"0xffbfb76ffffeff7ffffeeffbffebffdf6f7fdfbf7fffdf01\",\"data\":{\"slot\":\"11494452\",\"index\":\"1\",\"beacon_block_root\":\"0xf22ae450058b4d3247257c732863adc8f73602e999749ee9ec472cfb779e0baa\",\"source\":{\"epoch\":\"718402\",\"root\":\"0x8d1483afaa7b06d692ed194e31653b1515eb9ba57fa609b2379503651c725a6a\"},\"target\":{\"epoch\":\"718403\",\"root\":\"0xdb0ee80920632a0e67b047208ed24190ef8c7ad2631e7bffe3e6f0868172bc41\"}},\"signature\":\"0xa25810954ab5bc5d2fd07e4dd68fb9137f91864f6b54d60cc8e88b984fa3c40cde773d5aee06948ec7efe778952b8ebd0220fbd96e8b9d188f46290e4a2bd4d1ed7fa1695bddf86e6db8eefd41e20d22f467998d769b64ee3a15f3b2eb92221f\"},{\"aggregation_bits\":\"0x7fff7ffe7e7deeefef7fddfffb9effbffbeffbffbe7efd03\",\"data\":{\"slot\":\"11494452\",\"index\":\"0\",\"beacon_block_root\":\"0xf22ae450058b4d3247257c732863adc8f73602e999749ee9ec472cfb779e0baa\",\"source\":{\"epoch\":\"718402\",\"root\":\"0x8d1483afaa7b06d692ed194e31653b1515eb9ba57fa609b2379503651c725a6a\"},\"target\":{\"epoch\":\"718403\",\"root\":\"0xdb0ee80920632a0e67b047208ed24190ef8c7ad2631e7bffe3e6f0868172bc41\"}},\"signature\":\"0x8fe5475507d01d2e6aa0634d219a9a9f08d78ebae955d237407d25dd1953b5058115f1b13ae75e93ab3603b3177a6fe40994bb2b5c0ff04f15ee0129f9210d5c5482cf66150c062c3013c7e2c00c7593f74181f552ee46390bd5075e45db89eb\"}],\"deposits\":[],\"voluntary_exits\":[],\"sync_aggregate\":{\"sync_committee_bits\":\"0xeffbcfbbf6efccfefbf15fdaffdd3fff7ffffffffeffffdffffffdffd7f9b7fffbfffbffbfff7e7babfefe1fffbffffefdfdffdfdffbdfffbfffff7ff5fb7b7f\",\"sync_committee_signature\":\"0x909310abdad901c3180df6289a5e7a783c6956ce6b78ee71ce87aa79f47b5ddb9fbaf330752159a69ec5061b128ff2040aab93df228f35de41ef0b41683a45f5d5f1cf7f418cd2817c4ec9642928edfcaf3652e64641a6aef7741c5470452778\"},\"execution_payload\":{\"parent_hash\":\"0x96c1dbe01ab7404215ee879c91e4a59a38900a6baeab039ece4090f03ff2fa9b\",\"fee_recipient\":\"0x7cE7390C41Ce3416c4A0a297761C71763d89Ca3B\",\"state_root\":\"0x87d2dba868039731d2d423e0152582fdd26b376c1c38ff4b54e1c0055503c79c\",\"receipts_root\":\"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421\",\"logs_bloom\":\"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"prev_randao\":\"0x8e9aa79c4feab46c6fe9159b7059d4caab6c2b569349ccaf30ce9eddd86eda6f\",\"block_number\":\"11150825\",\"gas_limit\":\"17282130\",\"gas_used\":\"0\",\"timestamp\":\"1722868565\",\"extra_data\":\"0x4e65746865726d696e64\",\"base_fee_per_gas\":\"7\",\"block_hash\":\"0xeb5c4bac09771aa0cba68b69f0a3400a4dd7d941cbe82b7e92cfdefba13a2c11\",\"transactions\":[],\"withdrawals\":[{\"index\":\"49687774\",\"validator_index\":\"1574\",\"address\":\"0xcc4e00a72d871d6c328bcfe9025ad93d0a26df51\",\"amount\":\"786366\"},{\"index\":\"49687775\",\"validator_index\":\"1575\",\"address\":\"0xcc4e00a72d871d6c328bcfe9025ad93d0a26df51\",\"amount\":\"794759\"},{\"index\":\"49687776\",\"validator_index\":\"1576\",\"address\":\"0xcc4e00a72d871d6c328bcfe9025ad93d0a26df51\",\"amount\":\"770911\"},{\"index\":\"49687777\",\"validator_index\":\"1577\",\"address\":\"0xcc4e00a72d871d6c328bcfe9025ad93d0a26df51\",\"amount\":\"779355\"},{\"index\":\"49687778\",\"validator_index\":\"1578\",\"address\":\"0xcc4e00a72d871d6c328bcfe9025ad93d0a26df51\",\"amount\":\"766051\"},{\"index\":\"49687779\",\"validator_index\":\"1579\",\"address\":\"0xcc4e00a72d871d6c328bcfe9025ad93d0a26df51\",\"amount\":\"748497\"},{\"index\":\"49687780\",\"validator_index\":\"1580\",\"address\":\"0xcc4e00a72d871d6c328bcfe9025ad93d0a26df51\",\"amount\":\"759050\"},{\"index\":\"49687781\",\"validator_index\":\"1581\",\"address\":\"0xcc4e00a72d871d6c328bcfe9025ad93d0a26df51\",\"amount\":\"753464\"}],\"blob_gas_used\":\"0\",\"excess_blob_gas\":\"0\"},\"bls_to_execution_changes\":[],\"blob_kzg_commitments\":[]}},\"signature\":\"0x949673f0256c06218c0002a56c2e555600a207aeea695093852691185c97a4b4b3b60827051646fbb2b66e2df8baed4d0332c897367fcacd0c6c80d9d8c25bef63255f784465860ead84e65c8a5ef5720acbce6c4b320d0416fbdd5446ca8df2\"},\"kzg_proofs\":[],\"blobs\":[]},\"DenebBlinded\":null}"

	vp := &eth2api.VersionedSignedProposal{}
	err := json.Unmarshal([]byte(proposalStr), vp)
	require.NoError(t, err)

	domain := mustParseHex(t, "000000009d33b6757386e7a551167938d6d7cfaaefbe0f9d7f8a35b24d8092c0")
	//blockHash, err := vp.Deneb.SignedBlock.Message.HashTreeRoot()
	//require.NoError(t, err)

	lodestarDataRoot := mustParseHex(t, "52a953ce63c0a37deb65fe481820b2bb97da91dd8b7c52734562fa249b312bf3")
	sigroot, err := (&eth2p0.SigningData{ObjectRoot: eth2p0.Root(lodestarDataRoot), Domain: eth2p0.Domain(domain)}).HashTreeRoot()
	require.NoError(t, err)

	log.Info(context.Background(), "sigroot", z.Str("sigroot", hex.EncodeToString(sigroot[:])))

	// sigRoot := mustParseHex(t, "d0588eb07b8764cdb40325e14d8a8c1091a3cc497827b5b75519f4788be246bf")
	// pubkey := mustParseHex(t, "8e218bb69300a13619a3148f233f2398fcc14ed6b092a681537f9fcf2740a35a5e2c9147e2c1509e3996fc2c212ae3e7")
	// sig := mustParseHex(t, "90899b08380ee083463c3c24960f723c05b50bb75a2ba40a57367db949eb0e7da91ad24887bec5847584862bdd5c67d519e932a914855d777f9e55f529a07f610a7ed2dcf0498bf412d8d5a2ce86d71a445bb3ba7d4374c3f8859bb70071ba62")

	// err := tbls.Verify(tbls.PublicKey(pubkey), sigRoot, tbls.Signature(sig))
	// require.NoError(t, err)

	//log.Info(context.Background(), "hash", z.Str("block", hex.EncodeToString(blockHash[:])))
}

/*
func TestChiadoSignature(t *testing.T) {
	var pk core.PubKey = "0x8b9b72b6680b6fe004fb0077023ebb0ab29268a78c74c658216abffcb552c13dae74a0da98857eb68dc2d0d4dd4dddc1"

	e2pk, err := pk.ToETH2()
	require.NoError(t, err)

	var tblspk tbls.PublicKey = tbls.PublicKey(e2pk)

	sig, err := hex.DecodeString("953f532ccd4861eb0279fd11099cfd5cb586fdd7b5f41e2a0284ca370176c2072d07d6b2439a6d9ea08ce3b029308e2317796de279371213836b11455a2f7de7102127475d9626c158eb85bd003855fef4b0d5f3d9db7007537d464de3a90da0")
	require.NoError(t, err)
	require.Len(t, sig, 96)

	var tblssig tbls.Signature
	copy(tblssig[:], sig)

	msg, err := hex.DecodeString("45c4e28e2b213a03a74a6ff984c704a0716235c15d89fa1ac489a31fe1e77aba")
	require.NoError(t, err)

	err = tbls.Verify(tblspk, msg, tblssig)
	require.NoError(t, err)
}

func TestEthereumSignature(t *testing.T) {
	var pk core.PubKey = "0xb9e1bec3f611b59aeef25a4ff2bb72137b76f967167139374bc36fab43b365160ce9a66d53cff140c494331c01daa294"

	e2pk, err := pk.ToETH2()
	require.NoError(t, err)

	var tblspk tbls.PublicKey = tbls.PublicKey(e2pk)

	sig, err := hex.DecodeString("a4d6d1c44452437382d95eae74c7de0e3b516ff5d6a5e4df255d03dd5f60b807d74fae1a23fad3c5e85b1bc758fae5f7077f7a0e0f32b64d6ac96dcbf979061ac15c7b45e53ad147970deb1a5c068d8eb3d07c9fc3a16f928f394c2c30cbc720")
	require.NoError(t, err)
	require.Len(t, sig, 96)

	var tblssig tbls.Signature
	copy(tblssig[:], sig)

	msg, err := hex.DecodeString("361c705d6d893be5c716c6e86b4a6e8921190f791ff2fffe8910cd6e1b093c9e")
	require.NoError(t, err)

	err = tbls.Verify(tblspk, msg, tblssig)
	require.NoError(t, err)
}
*/

/*
func TestChiadoTBLS(t *testing.T) {
	const keysTotal = 30
	const nodesTotal = 4

	// data is random, used for all keys
	data := mustParseHex(t, "b413ced71694c83b5ba54cea8a5ecd5485d88198d304523bb87cd3ce0fd1caf3727eb7cd3c3eae61c6a300e47a14cbce")
	allKeys := make([]map[int]tbls.PrivateKey, keysTotal)
	parsigs := make([]map[int]tbls.Signature, keysTotal)

	for i := 0; i < nodesTotal; i++ {
		path := fmt.Sprintf("/Users/pinebit/chiado/node%d/validator_keys", i)
		keyFiles, err := keystore.LoadFilesUnordered(path)
		require.NoError(t, err)
		require.Len(t, keyFiles, keysTotal)

		for _, kf := range keyFiles {
			if allKeys[kf.FileIndex] == nil {
				allKeys[kf.FileIndex] = make(map[int]tbls.PrivateKey)
			}
			allKeys[kf.FileIndex][i+1] = kf.PrivateKey

			sig, err := tbls.Sign(kf.PrivateKey, data)
			require.NoError(t, err)

			if parsigs[kf.FileIndex] == nil {
				parsigs[kf.FileIndex] = make(map[int]tbls.Signature)
			}
			parsigs[kf.FileIndex][i+1] = sig
		}
	}

	for i, ak := range allKeys {
		secret, err := tbls.RecoverSecret(ak, nodesTotal, nodesTotal)
		require.NoError(t, err)

		pubkey, err := tbls.SecretToPublicKey(secret)
		require.NoError(t, err)

		aggsig, err := tbls.ThresholdAggregate(parsigs[i])
		require.NoError(t, err)

		err = tbls.Verify(pubkey, data, aggsig)
		require.NoError(t, err)
	}
}
*/

func TestComponent_ValidSubmitAttestations(t *testing.T) {
	ctx := context.Background()
	eth2Cl, err := beaconmock.New()
	require.NoError(t, err)

	const (
		slot        = 123
		commIdx     = 456
		vIdxA       = 1
		vIdxB       = 2
		valCommIdxA = vIdxA
		valCommIdxB = vIdxB
		commLen     = 8
	)

	pubkeysByIdx := map[eth2p0.ValidatorIndex]core.PubKey{
		vIdxA: testutil.RandomCorePubKey(t),
		vIdxB: testutil.RandomCorePubKey(t),
	}

	component, err := validatorapi.NewComponentInsecure(t, eth2Cl, 0)
	require.NoError(t, err)

	aggBitsA := bitfield.NewBitlist(commLen)
	aggBitsA.SetBitAt(valCommIdxA, true)

	attA := &eth2p0.Attestation{
		AggregationBits: aggBitsA,
		Data: &eth2p0.AttestationData{
			Slot:   slot,
			Index:  commIdx,
			Source: &eth2p0.Checkpoint{},
			Target: &eth2p0.Checkpoint{},
		},
		Signature: eth2p0.BLSSignature{},
	}

	aggBitsB := bitfield.NewBitlist(commLen)
	aggBitsB.SetBitAt(valCommIdxB, true)

	attB := &eth2p0.Attestation{
		AggregationBits: aggBitsB,
		Data: &eth2p0.AttestationData{
			Slot:   slot,
			Index:  commIdx,
			Source: &eth2p0.Checkpoint{},
			Target: &eth2p0.Checkpoint{},
		},
		Signature: eth2p0.BLSSignature{},
	}

	atts := []*eth2p0.Attestation{attA, attB}

	component.RegisterPubKeyByAttestation(func(ctx context.Context, slot, commIdx, valCommIdx uint64) (core.PubKey, error) {
		return pubkeysByIdx[eth2p0.ValidatorIndex(valCommIdx)], nil
	})

	component.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		require.Equal(t, core.DutyAttester, duty.Type)
		require.Equal(t, uint64(slot), duty.Slot)

		parSignedDataA := set[pubkeysByIdx[vIdxA]]
		actAttA, ok := parSignedDataA.SignedData.(core.Attestation)
		require.True(t, ok)
		require.Equal(t, *attA, actAttA.Attestation)

		parSignedDataB := set[pubkeysByIdx[vIdxB]]
		actAttB, ok := parSignedDataB.SignedData.(core.Attestation)
		require.True(t, ok)
		require.Equal(t, *attB, actAttB.Attestation)

		return nil
	})

	err = component.SubmitAttestations(ctx, atts)
	require.NoError(t, err)
}

func TestComponent_InvalidSubmitAttestations(t *testing.T) {
	ctx := context.Background()
	eth2Cl, err := beaconmock.New()
	require.NoError(t, err)

	const (
		slot       = 123
		commIdx    = 456
		vIdx       = 1
		valCommIdx = vIdx
		commLen    = 8
	)

	component, err := validatorapi.NewComponentInsecure(t, eth2Cl, vIdx)
	require.NoError(t, err)

	aggBits := bitfield.NewBitlist(commLen)
	aggBits.SetBitAt(valCommIdx, true)
	aggBits.SetBitAt(valCommIdx+1, true)

	att := &eth2p0.Attestation{
		AggregationBits: aggBits,
		Data: &eth2p0.AttestationData{
			Slot:   slot,
			Index:  commIdx,
			Source: &eth2p0.Checkpoint{},
			Target: &eth2p0.Checkpoint{},
		},
		Signature: eth2p0.BLSSignature{},
	}

	atts := []*eth2p0.Attestation{att}

	err = component.SubmitAttestations(ctx, atts)
	require.Error(t, err)
}

func TestSubmitAttestations_Verify(t *testing.T) {
	ctx := context.Background()

	// Create keys (just use normal keys, not split tbls)
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	// Configure validator
	const (
		vIdx     = 1
		shareIdx = 1
	)

	validator := beaconmock.ValidatorSetA[vIdx]
	validator.Validator.PublicKey = eth2p0.BLSPubKey(pubkey)
	require.NoError(t, err)

	// Convert pubkey
	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)
	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New(
		beaconmock.WithValidatorSet(beaconmock.ValidatorSet{vIdx: validator}),
		beaconmock.WithDeterministicAttesterDuties(0), // All duties in first slot of epoch.
	)
	require.NoError(t, err)

	epochSlot, err := bmock.SlotsPerEpoch(ctx)
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
	require.NoError(t, err)

	vapi.RegisterPubKeyByAttestation(func(ctx context.Context, slot, commIdx, valCommIdx uint64) (core.PubKey, error) {
		require.EqualValues(t, slot, epochSlot)
		require.EqualValues(t, commIdx, vIdx)
		require.EqualValues(t, valCommIdx, 0)

		return corePubKey, nil
	})

	// Collect submitted partial signature.
	vapi.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		require.Len(t, set, 1)
		_, ok := set[corePubKey]
		require.True(t, ok)

		return nil
	})

	// Configure beacon mock to call validator API for submissions
	bmock.SubmitAttestationsFunc = vapi.SubmitAttestations

	signer, err := validatormock.NewSigner(secret)
	require.NoError(t, err)

	// Run attestation using validator mock
	attester := validatormock.NewSlotAttester(
		bmock,
		eth2p0.Slot(epochSlot),
		signer,
		[]eth2p0.BLSPubKey{validator.Validator.PublicKey},
	)

	require.NoError(t, attester.Prepare(ctx))
	require.NoError(t, attester.Attest(ctx))
}

// TestSignAndVerify signs and verifies the signature.
// Test input and output obtained from prysm/validator/client/attest_test.go#TestSignAttestation.
func TestSignAndVerify(t *testing.T) {
	ctx := context.Background()

	// Create key pair
	secretKey := *(*tbls.PrivateKey)(padTo([]byte{1}, 32))

	// Setup beaconmock
	forkSchedule := `{"data": [{
        	"previous_version": "0x61626364",
			"current_version": "0x64656666",
        	"epoch": "0"
      	}]}`
	bmock, err := beaconmock.New(
		beaconmock.WithEndpoint("/eth/v1/config/fork_schedule", forkSchedule),
		beaconmock.WithGenesisValidatorsRoot([32]byte{0x01, 0x02}))
	require.NoError(t, err)

	// Get and assert domain
	domain, err := signing.GetDomain(ctx, bmock, signing.DomainBeaconAttester, 0)
	require.NoError(t, err)
	require.Equal(t, "0x0100000011b4296f38fa573d05f00854d452e120725b4d24b5587a472c6c4258", fmt.Sprintf("%#x", domain))

	// Define attestation data to sign
	blockRoot := padTo([]byte("blockRoot"), 32)
	var eth2Root eth2p0.Root
	copy(eth2Root[:], blockRoot)
	attData := eth2p0.AttestationData{
		Slot:            999,
		Index:           0,
		BeaconBlockRoot: eth2Root,
		Source:          &eth2p0.Checkpoint{Epoch: 100},
		Target:          &eth2p0.Checkpoint{Epoch: 200},
	}

	// Assert attestation data
	attRoot, err := attData.HashTreeRoot()
	require.NoError(t, err)
	require.Equal(t, "0xeee68bd8e94662122695d04afa5fd5c30ae385c9f39d98aa840062f43221d0d0", fmt.Sprintf("%#x", attRoot))

	// Create and assert signing data
	sigData := eth2p0.SigningData{ObjectRoot: attRoot, Domain: domain}
	sigDataBytes, err := sigData.HashTreeRoot()
	require.NoError(t, err)
	require.Equal(t, "0x02bbdb88056d6cbafd6e94575540e74b8cf2c0f2c1b79b8e17e7b21ed1694305", fmt.Sprintf("%#x", sigDataBytes))

	// Get pubkey
	pubkey, err := tbls.SecretToPublicKey(secretKey)
	require.NoError(t, err)
	eth2Pubkey := eth2p0.BLSPubKey(pubkey)

	signer, err := validatormock.NewSigner(secretKey)
	require.NoError(t, err)

	// Sign
	sig, err := signer(eth2Pubkey, sigDataBytes[:])
	require.NoError(t, err)

	// Assert signature
	require.Equal(t, "0xb6a60f8497bd328908be83634d045dd7a32f5e246b2c4031fc2f316983f362e36fc27fd3d6d5a2b15b4dbff38804ffb10b1719b7ebc54e9cbf3293fd37082bc0fc91f79d70ce5b04ff13de3c8e10bb41305bfdbe921a43792c12624f225ee865",
		fmt.Sprintf("%#x", sig))

	// Convert pubkey
	shareIdx := 1
	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)
	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

	// Setup validatorapi component.
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
	require.NoError(t, err)
	vapi.RegisterPubKeyByAttestation(func(context.Context, uint64, uint64, uint64) (core.PubKey, error) {
		return core.PubKeyFromBytes(pubkey[:])
	})

	// Assert output
	var wg sync.WaitGroup
	wg.Add(1)
	vapi.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		require.Equal(t, core.DutyAttester, duty.Type)
		require.Len(t, set, 1)
		wg.Done()

		return nil
	})

	// Create and submit attestation.
	aggBits := bitfield.NewBitlist(1)
	aggBits.SetBitAt(0, true)
	att := eth2p0.Attestation{
		AggregationBits: aggBits,
		Data:            &attData,
		Signature:       sig,
	}
	err = vapi.SubmitAttestations(ctx, []*eth2p0.Attestation{&att})
	require.NoError(t, err)
	wg.Wait()
}

// padTo pads a byte slice to the given size.
// It was copied from prysm/encoding/bytesutil/bytes.go.
func padTo(b []byte, size int) []byte {
	if len(b) > size {
		return b
	}

	return append(b, make([]byte, size-len(b))...)
}

func TestComponent_Proposal(t *testing.T) {
	ctx := context.Background()
	eth2Cl, err := beaconmock.New()
	require.NoError(t, err)

	const (
		slot = 123
		vIdx = 1
	)

	slotsPerEpoch, err := eth2Cl.SlotsPerEpoch(context.Background())
	require.NoError(t, err)

	epoch := eth2p0.Epoch(uint64(slot) / slotsPerEpoch)

	component, err := validatorapi.NewComponentInsecure(t, eth2Cl, vIdx)
	require.NoError(t, err)

	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pk, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	msg := []byte("randao reveal")
	sig, err := tbls.Sign(secret, msg)
	require.NoError(t, err)

	randao := eth2p0.BLSSignature(sig)
	pubkey, err := core.PubKeyFromBytes(pk[:])
	require.NoError(t, err)

	block1 := &eth2api.VersionedProposal{
		Version: eth2spec.DataVersionPhase0,
		Phase0:  testutil.RandomPhase0BeaconBlock(),
	}
	block1.Phase0.Slot = slot
	block1.Phase0.ProposerIndex = vIdx
	block1.Phase0.Body.RANDAOReveal = randao

	component.RegisterGetDutyDefinition(func(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error) {
		return core.DutyDefinitionSet{pubkey: nil}, nil
	})

	component.RegisterAwaitProposal(func(ctx context.Context, slot uint64) (*eth2api.VersionedProposal, error) {
		return block1, nil
	})

	component.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		require.Equal(t, set, core.ParSignedDataSet{
			pubkey: core.NewPartialSignedRandao(epoch, randao, vIdx),
		})
		require.Equal(t, duty, core.NewRandaoDuty(slot))

		return nil
	})

	opts := &eth2api.ProposalOpts{
		Slot:         slot,
		RandaoReveal: randao,
		Graffiti:     [32]byte{},
	}
	eth2Resp2, err := component.Proposal(ctx, opts)
	require.NoError(t, err)
	block2 := eth2Resp2.Data

	require.Equal(t, block1, block2)
}

func TestComponent_SubmitProposal(t *testing.T) {
	ctx := context.Background()

	// Create keys (just use normal keys, not split tbls)
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	const (
		vIdx     = 1
		shareIdx = 1
		slot     = 123
		epoch    = eth2p0.Epoch(3)
	)

	// Convert pubkey
	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)
	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
	require.NoError(t, err)

	// Prepare unsigned beacon block
	msg := []byte("randao reveal")
	sig, err := tbls.Sign(secret, msg)
	require.NoError(t, err)

	randao := eth2p0.BLSSignature(sig)
	unsignedBlock := &eth2spec.VersionedBeaconBlock{
		Version: eth2spec.DataVersionCapella,
		Capella: testutil.RandomCapellaBeaconBlock(),
	}
	unsignedBlock.Capella.Body.RANDAOReveal = randao
	unsignedBlock.Capella.Slot = slot
	unsignedBlock.Capella.ProposerIndex = vIdx

	vapi.RegisterGetDutyDefinition(func(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error) {
		return core.DutyDefinitionSet{corePubKey: nil}, nil
	})

	// Sign beacon block
	sigRoot, err := unsignedBlock.Root()
	require.NoError(t, err)

	domain, err := signing.GetDomain(ctx, bmock, signing.DomainBeaconProposer, epoch)
	require.NoError(t, err)

	sigData, err := (&eth2p0.SigningData{ObjectRoot: sigRoot, Domain: domain}).HashTreeRoot()
	require.NoError(t, err)

	s, err := tbls.Sign(secret, sigData[:])
	require.NoError(t, err)

	signedBlock := &eth2api.VersionedSignedProposal{
		Version: eth2spec.DataVersionCapella,
		Capella: &capella.SignedBeaconBlock{
			Message:   unsignedBlock.Capella,
			Signature: eth2p0.BLSSignature(s),
		},
	}

	// Register subscriber
	vapi.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		block, ok := set[corePubKey].SignedData.(core.VersionedSignedProposal)
		require.True(t, ok)
		require.Equal(t, *signedBlock, block.VersionedSignedProposal)

		return nil
	})

	err = vapi.SubmitProposal(ctx, &eth2api.SubmitProposalOpts{
		Proposal: signedBlock,
	})
	require.NoError(t, err)
}

func TestComponent_SubmitProposalInvalidSignature(t *testing.T) {
	ctx := context.Background()

	// Create keys (just use normal keys, not split tbls)
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	const (
		vIdx     = 1
		shareIdx = 1
		slot     = 123
	)

	// Convert pubkey
	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)
	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
	require.NoError(t, err)

	// Prepare unsigned beacon block
	msg := []byte("randao reveal")
	sig, err := tbls.Sign(secret, msg)
	require.NoError(t, err)

	vapi.RegisterGetDutyDefinition(func(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error) {
		return core.DutyDefinitionSet{corePubKey: nil}, nil
	})

	// Add invalid Signature to beacon block
	s, err := tbls.Sign(secret, []byte("invalid msg"))
	require.NoError(t, err)

	unsignedBlock := testutil.RandomCapellaBeaconBlock()
	unsignedBlock.Body.RANDAOReveal = eth2p0.BLSSignature(sig)
	unsignedBlock.Slot = slot
	unsignedBlock.ProposerIndex = vIdx

	signedBlock := &eth2api.VersionedSignedProposal{
		Version: eth2spec.DataVersionCapella,
		Capella: &capella.SignedBeaconBlock{
			Message:   unsignedBlock,
			Signature: eth2p0.BLSSignature(s),
		},
	}

	// Register subscriber
	vapi.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		block, ok := set[corePubKey].SignedData.(core.VersionedSignedProposal)
		require.True(t, ok)
		require.Equal(t, signedBlock, block)

		return nil
	})

	err = vapi.SubmitProposal(ctx, &eth2api.SubmitProposalOpts{
		Proposal: signedBlock,
	})
	require.ErrorContains(t, err, "signature not verified")
}

func TestComponent_SubmitProposalInvalidBlock(t *testing.T) {
	ctx := context.Background()
	shareIdx := 1
	// Create keys (just use normal keys, not split tbls)
	pubkey := testutil.RandomCorePubKey(t)

	pkb, err := pubkey.Bytes()
	require.NoError(t, err)

	tblsPubkey := *(*tbls.PublicKey)(pkb)
	require.NoError(t, err)
	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{pubkey: {shareIdx: tblsPubkey}} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
	require.NoError(t, err)

	vapi.RegisterGetDutyDefinition(func(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error) {
		return core.DutyDefinitionSet{pubkey: nil}, nil
	})

	// invalid block scenarios
	tests := []struct {
		name   string
		block  *eth2api.VersionedSignedProposal
		errMsg string
	}{
		// phase0 and altair are not supported by attestantio
		{
			name:   "no bellatrix block",
			block:  &eth2api.VersionedSignedProposal{Version: eth2spec.DataVersionBellatrix},
			errMsg: "data missing",
		},
		{
			name:   "no capella block",
			block:  &eth2api.VersionedSignedProposal{Version: eth2spec.DataVersionCapella},
			errMsg: "data missing",
		},
		{
			name:   "no deneb block",
			block:  &eth2api.VersionedSignedProposal{Version: eth2spec.DataVersionDeneb},
			errMsg: "data missing",
		},
		{
			name:   "none",
			block:  &eth2api.VersionedSignedProposal{Version: eth2spec.DataVersion(6)},
			errMsg: "unsupported version",
		},
		{
			name: "no bellatrix sig",
			block: &eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBeaconBlock{
					Message:   &bellatrix.BeaconBlock{Slot: eth2p0.Slot(123), Body: testutil.RandomBellatrixBeaconBlockBody()},
					Signature: eth2p0.BLSSignature{},
				},
			},
			errMsg: "no signature found",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err = vapi.SubmitProposal(ctx, &eth2api.SubmitProposalOpts{
				Proposal: test.block,
			})
			require.ErrorContains(t, err, test.errMsg)
		})
	}
}

func TestComponent_SubmitBlindedProposal(t *testing.T) {
	ctx := context.Background()

	// Create keys (just use normal keys, not split tbls)
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	const (
		vIdx     = 1
		shareIdx = 1
		slot     = 123
		epoch    = eth2p0.Epoch(3)
	)

	// Convert pubkey
	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)
	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderTrue, nil)
	require.NoError(t, err)

	// Prepare unsigned beacon block
	msg := []byte("randao reveal")
	sig, err := tbls.Sign(secret, msg)
	require.NoError(t, err)

	unsignedBlindedBlock := testutil.RandomCapellaBlindedBeaconBlock()
	unsignedBlindedBlock.Body.RANDAOReveal = eth2p0.BLSSignature(sig)
	unsignedBlindedBlock.Slot = slot
	unsignedBlindedBlock.ProposerIndex = vIdx

	vapi.RegisterGetDutyDefinition(func(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error) {
		return core.DutyDefinitionSet{corePubKey: nil}, nil
	})

	// Sign blinded beacon block
	sigRoot, err := unsignedBlindedBlock.HashTreeRoot()
	require.NoError(t, err)

	domain, err := signing.GetDomain(ctx, bmock, signing.DomainBeaconProposer, epoch)
	require.NoError(t, err)

	sigData, err := (&eth2p0.SigningData{ObjectRoot: sigRoot, Domain: domain}).HashTreeRoot()
	require.NoError(t, err)

	s, err := tbls.Sign(secret, sigData[:])
	require.NoError(t, err)

	signedBlindedBlock := &eth2api.VersionedSignedBlindedProposal{
		Version: eth2spec.DataVersionCapella,
		Capella: &eth2capella.SignedBlindedBeaconBlock{
			Message:   unsignedBlindedBlock,
			Signature: eth2p0.BLSSignature(s),
		},
	}

	// Register subscriber
	vapi.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		block, ok := set[corePubKey].SignedData.(core.VersionedSignedProposal)
		require.True(t, ok)

		blindedBlock, err := block.ToBlinded()
		require.NoError(t, err)
		require.Equal(t, *signedBlindedBlock, blindedBlock)

		return nil
	})

	err = vapi.SubmitBlindedProposal(ctx, &eth2api.SubmitBlindedProposalOpts{
		Proposal: signedBlindedBlock,
	})
	require.NoError(t, err)
}

func TestComponent_SubmitBlindedProposalInvalidSignature(t *testing.T) {
	ctx := context.Background()

	// Create keys (just use normal keys, not split tbls)
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	const (
		vIdx     = 1
		shareIdx = 1
		slot     = 123
	)

	// Convert pubkey
	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)
	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderTrue, nil)
	require.NoError(t, err)

	// Prepare unsigned beacon block
	msg := []byte("randao reveal")
	sig, err := tbls.Sign(secret, msg)
	require.NoError(t, err)

	unsignedBlindedBlock := testutil.RandomCapellaBlindedBeaconBlock()
	unsignedBlindedBlock.Body.RANDAOReveal = eth2p0.BLSSignature(sig)
	unsignedBlindedBlock.Slot = slot
	unsignedBlindedBlock.ProposerIndex = vIdx

	vapi.RegisterGetDutyDefinition(func(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error) {
		return core.DutyDefinitionSet{corePubKey: nil}, nil
	})

	// Add invalid Signature to blinded beacon block

	s, err := tbls.Sign(secret, []byte("invalid msg"))
	require.NoError(t, err)

	signedBlindedBlock := &eth2api.VersionedSignedBlindedProposal{
		Version: eth2spec.DataVersionCapella,
		Capella: &eth2capella.SignedBlindedBeaconBlock{
			Message:   unsignedBlindedBlock,
			Signature: eth2p0.BLSSignature(s),
		},
	}

	// Register subscriber
	vapi.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		block, ok := set[corePubKey].SignedData.(core.VersionedSignedProposal)
		require.True(t, ok)
		require.Equal(t, signedBlindedBlock, block)

		blindedBlock, err := block.ToBlinded()
		require.NoError(t, err)
		require.Equal(t, signedBlindedBlock, blindedBlock)

		return nil
	})

	err = vapi.SubmitBlindedProposal(ctx, &eth2api.SubmitBlindedProposalOpts{
		Proposal: signedBlindedBlock,
	})
	require.ErrorContains(t, err, "signature not verified")
}

func TestComponent_SubmitBlindedProposalInvalidBlock(t *testing.T) {
	ctx := context.Background()
	shareIdx := 1
	// Create keys (just use normal keys, not split tbls)
	pubkey := testutil.RandomCorePubKey(t)

	// Convert pubkey
	pkb, err := pubkey.Bytes()
	require.NoError(t, err)

	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{pubkey: {shareIdx: *(*tbls.PublicKey)(pkb)}} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderTrue, nil)
	require.NoError(t, err)

	vapi.RegisterGetDutyDefinition(func(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error) {
		return core.DutyDefinitionSet{pubkey: nil}, nil
	})

	// invalid block scenarios
	tests := []struct {
		name   string
		block  *eth2api.VersionedSignedBlindedProposal
		errMsg string
	}{
		{
			name:   "no bellatrix block",
			block:  &eth2api.VersionedSignedBlindedProposal{Version: eth2spec.DataVersionBellatrix},
			errMsg: "data missing",
		},
		{
			name:   "no deneb block",
			block:  &eth2api.VersionedSignedBlindedProposal{Version: eth2spec.DataVersionDeneb},
			errMsg: "data missing",
		},
		{
			name:   "none",
			block:  &eth2api.VersionedSignedBlindedProposal{Version: eth2spec.DataVersion(6)},
			errMsg: "unsupported version",
		},
		{
			name: "no bellatrix sig",
			block: &eth2api.VersionedSignedBlindedProposal{
				Version: eth2spec.DataVersionBellatrix,
				Bellatrix: &eth2bellatrix.SignedBlindedBeaconBlock{
					Message:   &eth2bellatrix.BlindedBeaconBlock{Slot: eth2p0.Slot(123), Body: testutil.RandomBellatrixBlindedBeaconBlockBody()},
					Signature: eth2p0.BLSSignature{},
				},
			},
			errMsg: "no signature found",
		},
		{
			name: "no capella sig",
			block: &eth2api.VersionedSignedBlindedProposal{
				Version: eth2spec.DataVersionCapella,
				Capella: &eth2capella.SignedBlindedBeaconBlock{
					Message:   &eth2capella.BlindedBeaconBlock{Slot: eth2p0.Slot(123), Body: testutil.RandomCapellaBlindedBeaconBlockBody()},
					Signature: eth2p0.BLSSignature{},
				},
			},
			errMsg: "no signature found",
		},
		{
			name: "no deneb sig",
			block: &eth2api.VersionedSignedBlindedProposal{
				Version: eth2spec.DataVersionDeneb,
				Deneb: &eth2deneb.SignedBlindedBeaconBlock{
					Message: &eth2deneb.BlindedBeaconBlock{
						Slot: eth2p0.Slot(123),
						Body: testutil.RandomDenebBlindedBeaconBlockBody(),
					},
					Signature: eth2p0.BLSSignature{},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err = vapi.SubmitBlindedProposal(ctx, &eth2api.SubmitBlindedProposalOpts{
				Proposal: test.block,
			})
			require.ErrorContains(t, err, test.errMsg)
		})
	}
}

func TestComponent_SubmitVoluntaryExit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create keys (just use normal keys, not split tbls)
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	const (
		vIdx     = 2
		shareIdx = 1
		epoch    = 10
	)

	// Convert pubkey
	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)
	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

	// Prep beacon mock validators
	validator := beaconmock.ValidatorSetA[vIdx]
	validator.Validator.PublicKey = eth2p0.BLSPubKey(pubkey)
	require.NoError(t, err)

	// Configure beacon mock
	bmock, err := beaconmock.New(beaconmock.WithValidatorSet(beaconmock.ValidatorSetA))
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
	require.NoError(t, err)

	// Prepare unsigned voluntary exit
	exit := &eth2p0.VoluntaryExit{
		Epoch:          epoch,
		ValidatorIndex: vIdx,
	}

	// sign voluntary exit
	sigRoot, err := exit.HashTreeRoot()
	require.NoError(t, err)

	domain, err := signing.GetDomain(ctx, bmock, signing.DomainExit, epoch)
	require.NoError(t, err)

	sigData, err := (&eth2p0.SigningData{ObjectRoot: sigRoot, Domain: domain}).HashTreeRoot()
	require.NoError(t, err)

	sig, err := tbls.Sign(secret, sigData[:])
	require.NoError(t, err)

	signedExit := &eth2p0.SignedVoluntaryExit{
		Message:   exit,
		Signature: eth2p0.BLSSignature(sig),
	}

	// Register subscriber
	vapi.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		signedExit2, ok := set[corePubKey].SignedData.(core.SignedVoluntaryExit)
		require.True(t, ok)
		require.Equal(t, *signedExit, signedExit2.SignedVoluntaryExit)
		cancel()

		return ctx.Err()
	})

	err = vapi.SubmitVoluntaryExit(ctx, signedExit)
	require.ErrorIs(t, err, context.Canceled)
}

func TestComponent_SubmitVoluntaryExitInvalidSignature(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const (
		vIdx     = 2
		shareIdx = 1
	)

	// Create keys (just use normal keys, not split tbls)
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)
	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

	validator := beaconmock.ValidatorSetA[vIdx]
	validator.Validator.PublicKey = eth2p0.BLSPubKey(pubkey)
	require.NoError(t, err)

	// Configure beacon mock
	bmock, err := beaconmock.New(beaconmock.WithValidatorSet(beaconmock.ValidatorSetA))
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
	require.NoError(t, err)

	// Register subscriber
	vapi.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		cancel()
		return ctx.Err()
	})

	sig, err := tbls.Sign(secret, []byte("invalid message"))
	require.NoError(t, err)

	exit := testutil.RandomExit()
	exit.Message.ValidatorIndex = vIdx
	exit.Signature = eth2p0.BLSSignature(sig)

	err = vapi.SubmitVoluntaryExit(ctx, exit)
	require.ErrorContains(t, err, "signature not verified")
}

func TestComponent_Duties(t *testing.T) {
	ctx := context.Background()

	// Configure validator
	const (
		vIdx     = 123
		shareIdx = 1
		epch     = 456
	)

	// Create pubkey and pubshare
	eth2Pubkey := testutil.RandomEth2PubKey(t)
	eth2Share := testutil.RandomEth2PubKey(t)

	pubshare := tbls.PublicKey(eth2Share)
	pubkey := tbls.PublicKey(eth2Pubkey)
	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)

	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubshare}}
	// Configure beacon mock
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	t.Run("proposer_duties", func(t *testing.T) {
		bmock.ProposerDutiesFunc = func(ctx context.Context, epoch eth2p0.Epoch, indices []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
			require.Equal(t, epoch, eth2p0.Epoch(epch))
			require.Equal(t, []eth2p0.ValidatorIndex{eth2p0.ValidatorIndex(vIdx)}, indices)

			return []*eth2v1.ProposerDuty{{
				PubKey:         eth2Pubkey,
				ValidatorIndex: vIdx,
			}}, nil
		}

		// Construct the validator api component
		vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
		require.NoError(t, err)

		opts := &eth2api.ProposerDutiesOpts{
			Epoch:   eth2p0.Epoch(epch),
			Indices: []eth2p0.ValidatorIndex{eth2p0.ValidatorIndex(vIdx)},
		}
		eth2Resp, err := vapi.ProposerDuties(ctx, opts)
		require.NoError(t, err)
		duties := eth2Resp.Data
		require.Len(t, duties, 1)
		require.Equal(t, duties[0].PubKey, eth2Share)
	})

	t.Run("attester_duties", func(t *testing.T) {
		bmock.AttesterDutiesFunc = func(_ context.Context, epoch eth2p0.Epoch, indices []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error) {
			require.Equal(t, epoch, eth2p0.Epoch(epch))
			require.Equal(t, []eth2p0.ValidatorIndex{eth2p0.ValidatorIndex(vIdx)}, indices)

			return []*eth2v1.AttesterDuty{{
				PubKey:         eth2Pubkey,
				ValidatorIndex: vIdx,
			}}, nil
		}

		// Construct the validator api component
		vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
		require.NoError(t, err)

		opts := &eth2api.AttesterDutiesOpts{
			Epoch:   eth2p0.Epoch(epch),
			Indices: []eth2p0.ValidatorIndex{eth2p0.ValidatorIndex(vIdx)},
		}
		resp, err := vapi.AttesterDuties(ctx, opts)
		require.NoError(t, err)
		duties := resp.Data
		require.Len(t, duties, 1)
		require.Equal(t, duties[0].PubKey, eth2Share)
	})

	t.Run("sync_committee_duties", func(t *testing.T) {
		bmock.SyncCommitteeDutiesFunc = func(ctx context.Context, epoch eth2p0.Epoch, indices []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, error) {
			require.Equal(t, epoch, eth2p0.Epoch(epch))
			require.Equal(t, []eth2p0.ValidatorIndex{eth2p0.ValidatorIndex(vIdx)}, indices)

			return []*eth2v1.SyncCommitteeDuty{{
				PubKey:         eth2Pubkey,
				ValidatorIndex: vIdx,
			}}, nil
		}

		// Construct the validator api component
		vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
		require.NoError(t, err)

		opts := &eth2api.SyncCommitteeDutiesOpts{
			Epoch:   eth2p0.Epoch(epch),
			Indices: []eth2p0.ValidatorIndex{eth2p0.ValidatorIndex(vIdx)},
		}
		eth2Resp, err := vapi.SyncCommitteeDuties(ctx, opts)
		require.NoError(t, err)
		duties := eth2Resp.Data
		require.Len(t, duties, 1)
		require.Equal(t, duties[0].PubKey, eth2Share)
	})
}

func TestComponent_SubmitValidatorRegistration(t *testing.T) {
	ctx := context.Background()
	shareIdx := 1
	// Create keys (just use normal keys, not split tbls)
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	// Convert pubkey
	eth2Pubkey := eth2p0.BLSPubKey(pubkey)
	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)
	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderTrue, nil)
	require.NoError(t, err)

	unsigned := testutil.RandomValidatorRegistration(t)
	unsigned.Pubkey = eth2Pubkey
	unsigned.Timestamp, err = bmock.GenesisTime(ctx) // Set timestamp to genesis which should result in epoch 0 and slot 0.
	require.NoError(t, err)

	// Sign validator (builder) registration
	sigRoot, err := unsigned.HashTreeRoot()
	require.NoError(t, err)

	sigData, err := signing.GetDataRoot(ctx, bmock, signing.DomainApplicationBuilder, 0, sigRoot)
	require.NoError(t, err)

	s, err := tbls.Sign(secret, sigData[:])
	require.NoError(t, err)

	signed := &eth2api.VersionedSignedValidatorRegistration{
		Version: eth2spec.BuilderVersionV1,
		V1: &eth2v1.SignedValidatorRegistration{
			Message:   unsigned,
			Signature: eth2p0.BLSSignature(s),
		},
	}

	output := make(chan core.ParSignedDataSet, 1)

	// Register subscriber
	vapi.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		require.Equal(t, core.NewBuilderRegistrationDuty(0), duty)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case output <- set:
		}

		return nil
	})

	err = vapi.SubmitValidatorRegistrations(ctx, []*eth2api.VersionedSignedValidatorRegistration{signed})
	require.NoError(t, err)

	// Assert output
	actualData := <-output
	registration, ok := actualData[corePubKey].SignedData.(core.VersionedSignedValidatorRegistration)
	require.True(t, ok)
	require.Equal(t, *signed, registration.VersionedSignedValidatorRegistration)

	// Assert incorrect pubkey registration is swallowed
	close(output) // Panic if registration is not swallowed
	signed.V1.Message.Pubkey = testutil.RandomEth2PubKey(t)
	err = vapi.SubmitValidatorRegistrations(ctx, []*eth2api.VersionedSignedValidatorRegistration{signed})
	require.NoError(t, err)
}

func TestComponent_SubmitValidatorRegistrationInvalidSignature(t *testing.T) {
	ctx := context.Background()
	shareIdx := 1
	// Create keys (just use normal keys, not split tbls)
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	// Convert pubkey
	eth2Pubkey := eth2p0.BLSPubKey(pubkey)
	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)
	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderTrue, nil)
	require.NoError(t, err)

	unsigned := testutil.RandomValidatorRegistration(t)
	unsigned.Pubkey = eth2Pubkey
	unsigned.Timestamp, err = bmock.GenesisTime(ctx) // Set timestamp to genesis which should result in epoch 0 and slot 0.
	require.NoError(t, err)

	vapi.RegisterGetDutyDefinition(func(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error) {
		return core.DutyDefinitionSet{corePubKey: nil}, nil
	})

	// Add invalid Signature to validator (builder) registration

	s, err := tbls.Sign(secret, []byte("invalid msg"))
	require.NoError(t, err)

	signed := &eth2api.VersionedSignedValidatorRegistration{
		Version: eth2spec.BuilderVersionV1,
		V1: &eth2v1.SignedValidatorRegistration{
			Message:   unsigned,
			Signature: eth2p0.BLSSignature(s),
		},
	}

	err = vapi.SubmitValidatorRegistrations(ctx, []*eth2api.VersionedSignedValidatorRegistration{signed})
	require.ErrorContains(t, err, "signature not verified")
}

func TestComponent_TekuProposerConfig(t *testing.T) {
	ctx := context.Background()
	const (
		zeroAddr     = "0x0000000000000000000000000000000000000000"
		feeRecipient = "0x123456"
		shareIdx     = 1
	)
	// Create keys (just use normal keys, not split tbls)
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	// Convert pubkey
	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)
	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, func(core.PubKey) string {
		return feeRecipient
	}, testutil.BuilderTrue, nil)
	require.NoError(t, err)

	resp, err := vapi.ProposerConfig(ctx)
	require.NoError(t, err)

	pk, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)

	genesis, err := bmock.GenesisTime(ctx)
	require.NoError(t, err)
	slotDuration, err := bmock.SlotDuration(ctx)
	require.NoError(t, err)

	eth2pk, err := pk.ToETH2()
	require.NoError(t, err)

	require.Equal(t, &eth2exp.ProposerConfigResponse{
		Proposers: map[eth2p0.BLSPubKey]eth2exp.ProposerConfig{
			eth2pk: {
				FeeRecipient: feeRecipient,
				Builder: eth2exp.Builder{
					Enabled:  true,
					GasLimit: 30000000,
					Overrides: map[string]string{
						"timestamp":  fmt.Sprint(genesis.Add(slotDuration).Unix()),
						"public_key": string(pk),
					},
				},
			},
		},
		Default: eth2exp.ProposerConfig{
			FeeRecipient: zeroAddr,
			Builder: eth2exp.Builder{
				Enabled:  false,
				GasLimit: 30000000,
			},
		},
	}, resp)
}

func TestComponent_AggregateBeaconCommitteeSelections(t *testing.T) {
	ctx := context.Background()

	const slot = 99

	valSet := beaconmock.ValidatorSetA
	eth2Cl, err := beaconmock.New(beaconmock.WithValidatorSet(valSet))
	require.NoError(t, err)

	vapi, err := validatorapi.NewComponentInsecure(t, eth2Cl, 0)
	require.NoError(t, err)

	selections := []*eth2exp.BeaconCommitteeSelection{
		{
			ValidatorIndex: valSet[1].Index,
			Slot:           slot,
			SelectionProof: testutil.RandomEth2Signature(),
		}, {
			ValidatorIndex: valSet[2].Index,
			Slot:           slot,
			SelectionProof: testutil.RandomEth2Signature(),
		},
	}

	vapi.RegisterAwaitAggSigDB(func(_ context.Context, duty core.Duty, pk core.PubKey) (core.SignedData, error) {
		require.Equal(t, core.NewPrepareAggregatorDuty(slot), duty)
		for _, val := range valSet {
			pkEth2, err := pk.ToETH2()
			require.NoError(t, err)
			if pkEth2 != val.Validator.PublicKey {
				continue
			}
			for _, selection := range selections {
				if selection.ValidatorIndex == val.Index {
					return core.NewBeaconCommitteeSelection(selection), nil
				}
			}
		}

		return nil, errors.New("unknown public key")
	})

	actual, err := vapi.AggregateBeaconCommitteeSelections(ctx, selections)
	require.NoError(t, err)

	// Sort by VIdx before comparing
	sort.Slice(actual, func(i, j int) bool {
		return actual[i].ValidatorIndex < actual[j].ValidatorIndex
	})
	require.Equal(t, selections, actual)
}

func TestComponent_SubmitAggregateAttestations(t *testing.T) {
	ctx := context.Background()

	const vIdx = 1

	agg := &eth2p0.SignedAggregateAndProof{
		Message: &eth2p0.AggregateAndProof{
			AggregatorIndex: vIdx,
			Aggregate:       testutil.RandomAttestation(),
			SelectionProof:  testutil.RandomEth2Signature(),
		},
		Signature: testutil.RandomEth2Signature(),
	}

	slot := agg.Message.Aggregate.Data.Slot
	pubkey := beaconmock.ValidatorSetA[vIdx].Validator.PublicKey

	bmock, err := beaconmock.New(beaconmock.WithValidatorSet(beaconmock.ValidatorSetA))
	require.NoError(t, err)

	vapi, err := validatorapi.NewComponentInsecure(t, bmock, 0)
	require.NoError(t, err)

	vapi.Subscribe(func(_ context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		require.Equal(t, core.NewAggregatorDuty(uint64(slot)), duty)

		pk, err := core.PubKeyFromBytes(pubkey[:])
		require.NoError(t, err)

		data, ok := set[pk]
		require.True(t, ok)
		require.Equal(t, core.NewPartialSignedAggregateAndProof(agg, 0), data)

		return nil
	})

	require.NoError(t, vapi.SubmitAggregateAttestations(ctx, []*eth2p0.SignedAggregateAndProof{agg}))
}

func TestComponent_SubmitAggregateAttestationVerify(t *testing.T) {
	const shareIdx = 1
	var (
		ctx = context.Background()
		val = testutil.RandomValidator(t)
	)

	// Create keys (just use normal keys, not split tbls)
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)

	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

	val.Validator.PublicKey = eth2p0.BLSPubKey(pubkey)

	bmock, err := beaconmock.New(beaconmock.WithValidatorSet(beaconmock.ValidatorSet{val.Index: val}))
	require.NoError(t, err)

	slot := eth2p0.Slot(99)
	aggProof := &eth2p0.AggregateAndProof{
		AggregatorIndex: val.Index,
		Aggregate:       testutil.RandomAttestation(),
	}
	aggProof.Aggregate.Data.Slot = slot
	aggProof.SelectionProof = signBeaconSelection(t, bmock, secret, slot)
	signedAggProof := &eth2p0.SignedAggregateAndProof{
		Message:   aggProof,
		Signature: signAggregationAndProof(t, bmock, secret, aggProof),
	}

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
	require.NoError(t, err)

	done := make(chan struct{})
	// Collect submitted partial signature.
	vapi.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		require.Len(t, set, 1)
		_, ok := set[core.PubKeyFrom48Bytes(val.Validator.PublicKey)]
		require.True(t, ok)
		close(done)

		return nil
	})

	err = vapi.SubmitAggregateAttestations(ctx, []*eth2p0.SignedAggregateAndProof{signedAggProof})
	require.NoError(t, err)
	<-done
}

func TestComponent_SubmitSyncCommitteeMessages(t *testing.T) {
	const vIdx = 1

	var (
		ctx    = context.Background()
		msg    = testutil.RandomSyncCommitteeMessage()
		pubkey = beaconmock.ValidatorSetA[vIdx].Validator.PublicKey
		count  = 0 // No of times the subscription function is called.
	)

	msg.ValidatorIndex = vIdx

	bmock, err := beaconmock.New(beaconmock.WithValidatorSet(beaconmock.ValidatorSetA))
	require.NoError(t, err)

	vapi, err := validatorapi.NewComponentInsecure(t, bmock, 0)
	require.NoError(t, err)

	vapi.Subscribe(func(_ context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		require.Equal(t, core.NewSyncMessageDuty(uint64(msg.Slot)), duty)

		pk, err := core.PubKeyFromBytes(pubkey[:])
		require.NoError(t, err)

		data, ok := set[pk]
		require.True(t, ok)
		require.Equal(t, core.NewPartialSignedSyncMessage(msg, 0), data)
		count++

		return nil
	})

	require.NoError(t, vapi.SubmitSyncCommitteeMessages(ctx, []*altair.SyncCommitteeMessage{msg}))
	require.Equal(t, count, 1)
}

func TestComponent_SubmitSyncCommitteeContributions(t *testing.T) {
	const vIdx = 1

	var (
		count        = 0 // No of times the subscription function is called.
		ctx          = context.Background()
		contrib      = testutil.RandomSignedSyncContributionAndProof()
		pubkey       = beaconmock.ValidatorSetA[vIdx].Validator.PublicKey
		expectedDuty = core.NewSyncContributionDuty(uint64(contrib.Message.Contribution.Slot))
	)

	contrib.Message.AggregatorIndex = vIdx

	bmock, err := beaconmock.New(beaconmock.WithValidatorSet(beaconmock.ValidatorSetA))
	require.NoError(t, err)

	vapi, err := validatorapi.NewComponentInsecure(t, bmock, 0)
	require.NoError(t, err)

	vapi.Subscribe(func(_ context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		require.Equal(t, expectedDuty, duty)

		pk, err := core.PubKeyFromBytes(pubkey[:])
		require.NoError(t, err)

		data, ok := set[pk]
		require.True(t, ok)
		require.Equal(t, core.NewPartialSignedSyncContributionAndProof(contrib, 0), data)
		count++

		return nil
	})

	require.NoError(t, vapi.SubmitSyncCommitteeContributions(ctx, []*altair.SignedContributionAndProof{contrib}))
	require.Equal(t, count, 1)
}

func TestComponent_SubmitSyncCommitteeContributionsVerify(t *testing.T) {
	const shareIdx = 1
	var (
		ctx        = context.Background()
		val        = testutil.RandomValidator(t)
		slot       = eth2p0.Slot(50)
		subcommIdx = eth2p0.CommitteeIndex(1)
	)

	// Create keys (just use normal keys, not split tbls).
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)
	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

	val.Validator.PublicKey = eth2p0.BLSPubKey(pubkey)

	bmock, err := beaconmock.New(beaconmock.WithValidatorSet(beaconmock.ValidatorSet{val.Index: val}))
	require.NoError(t, err)

	// Create contribution and proof.
	contribAndProof := &altair.ContributionAndProof{
		AggregatorIndex: val.Index,
		Contribution:    testutil.RandomSyncCommitteeContribution(),
	}
	contribAndProof.Contribution.Slot = slot
	contribAndProof.Contribution.SubcommitteeIndex = uint64(subcommIdx)
	contribAndProof.SelectionProof = syncCommSelectionProof(t, bmock, secret, slot, subcommIdx)

	signedContribAndProof := &altair.SignedContributionAndProof{
		Message:   contribAndProof,
		Signature: signContributionAndProof(t, bmock, secret, contribAndProof),
	}

	// Construct validatorapi component.
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
	require.NoError(t, err)

	done := make(chan struct{})
	// Collect submitted partial signature.
	vapi.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		require.Len(t, set, 1)
		_, ok := set[core.PubKeyFrom48Bytes(val.Validator.PublicKey)]
		require.True(t, ok)
		close(done)

		return nil
	})

	err = vapi.SubmitSyncCommitteeContributions(ctx, []*altair.SignedContributionAndProof{signedContribAndProof})
	require.NoError(t, err)
	<-done
}

func TestComponent_ValidatorCache(t *testing.T) {
	baseValSet := testutil.RandomValidatorSet(t, 10)

	var (
		allPubSharesByKey = make(map[core.PubKey]map[int]tbls.PublicKey)
		keyByPubshare     = make(map[tbls.PublicKey]core.PubKey)
		valByPubkey       = make(map[eth2p0.BLSPubKey]*eth2v1.Validator)

		complete  = make(eth2wrap.CompleteValidators)
		pubshares []eth2p0.BLSPubKey
		singleVal eth2v1.Validator
	)

	for idx, val := range baseValSet {
		complete[idx] = val
		valByPubkey[val.Validator.PublicKey] = val
	}

	bmock, err := beaconmock.New(beaconmock.WithValidatorSet(baseValSet))
	require.NoError(t, err)

	bmock.CachedValidatorsFunc = func(ctx context.Context) (eth2wrap.ActiveValidators, eth2wrap.CompleteValidators, error) {
		cc := make(eth2wrap.CompleteValidators)
		maps.Copy(cc, complete)

		return nil, cc, nil
	}

	var valEndpointInvocations int
	bmock.ValidatorsFunc = func(ctx context.Context, opts *eth2api.ValidatorsOpts) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
		valEndpointInvocations += len(opts.PubKeys) + len(opts.Indices)

		ret := make(map[eth2p0.ValidatorIndex]*eth2v1.Validator)

		for _, pk := range opts.PubKeys {
			if val, ok := valByPubkey[pk]; ok {
				ret[val.Index] = val
			}
		}

		return ret, nil
	}

	i := 4
	for _, val := range baseValSet {
		i--

		pubshare, err := tblsconv.PubkeyFromCore(testutil.RandomCorePubKey(t))
		require.NoError(t, err)

		pubshares = append(pubshares, eth2p0.BLSPubKey(pubshare))

		corePubkey := core.PubKeyFrom48Bytes(val.Validator.PublicKey)
		allPubSharesByKey[corePubkey] = make(map[int]tbls.PublicKey)
		allPubSharesByKey[core.PubKeyFrom48Bytes(val.Validator.PublicKey)][1] = pubshare
		keyByPubshare[pubshare] = corePubkey

		if i == 0 {
			singleVal = *val
			break
		}
	}

	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, 1, nil, testutil.BuilderFalse, nil)
	require.NoError(t, err)

	// request validators that are completely cached
	ret, err := vapi.Validators(context.Background(), &eth2api.ValidatorsOpts{
		State:   "head",
		PubKeys: pubshares,
	})
	require.NoError(t, err)
	require.Equal(t, 0, valEndpointInvocations)
	require.Len(t, ret.Data, len(pubshares))

	// request validators that are not cached at all by removing singleVal from the cache
	delete(complete, singleVal.Index)

	share := allPubSharesByKey[core.PubKeyFrom48Bytes(singleVal.Validator.PublicKey)][1]

	ret, err = vapi.Validators(context.Background(), &eth2api.ValidatorsOpts{
		State:   "head",
		PubKeys: []eth2p0.BLSPubKey{eth2p0.BLSPubKey(share)},
	})
	require.NoError(t, err)
	require.Equal(t, 1, valEndpointInvocations)
	require.Len(t, ret.Data, 1)

	// request half-half validators
	ret, err = vapi.Validators(context.Background(), &eth2api.ValidatorsOpts{
		State:   "head",
		PubKeys: pubshares,
	})
	require.NoError(t, err)
	require.Equal(t, 2, valEndpointInvocations)
	require.Len(t, ret.Data, len(pubshares))
}

func TestComponent_GetAllValidators(t *testing.T) {
	const (
		totalVals      = 10
		numClusterVals = 4
		shareIdx       = 1
	)

	validatorSet := testutil.RandomValidatorSet(t, totalVals)

	// Pick numClusterVals from validator set.
	var (
		clusterVals       []*eth2v1.Validator
		allPubSharesByKey = make(map[core.PubKey]map[int]tbls.PublicKey)
		keyByPubshare     = make(map[tbls.PublicKey]core.PubKey)
	)
	i := numClusterVals
	for _, val := range validatorSet {
		i--

		clusterVals = append(clusterVals, val)
		pubshare, err := tblsconv.PubkeyFromCore(testutil.RandomCorePubKey(t))
		require.NoError(t, err)

		corePubkey := core.PubKeyFrom48Bytes(val.Validator.PublicKey)
		allPubSharesByKey[corePubkey] = make(map[int]tbls.PublicKey)
		allPubSharesByKey[core.PubKeyFrom48Bytes(val.Validator.PublicKey)][shareIdx] = pubshare
		keyByPubshare[pubshare] = corePubkey

		if i == 0 {
			break
		}
	}

	bmock, err := beaconmock.New(beaconmock.WithValidatorSet(validatorSet))
	require.NoError(t, err)

	// Construct validatorapi component.
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
	require.NoError(t, err)

	opts := &eth2api.ValidatorsOpts{
		State: "head",
	}
	resp, err := vapi.Validators(context.Background(), opts)
	require.NoError(t, err)
	vals := resp.Data
	require.Len(t, vals, totalVals)

	for _, val := range clusterVals {
		pubshare, err := tblsconv.PubkeyFromBytes(vals[val.Index].Validator.PublicKey[:])
		require.NoError(t, err)

		eth2Pubkey, err := keyByPubshare[pubshare].ToETH2()
		require.NoError(t, err)
		require.Equal(t, validatorSet[val.Index].Validator.PublicKey, eth2Pubkey)
	}
}

func TestComponent_GetClusterValidatorsWithError(t *testing.T) {
	const (
		numClusterVals = 4
		shareIdx       = 1
	)

	validatorSet := testutil.RandomValidatorSet(t, numClusterVals)
	var indices []eth2p0.ValidatorIndex
	for vidx := range validatorSet {
		indices = append(indices, vidx)
	}

	bmock, err := beaconmock.New(beaconmock.WithValidatorSet(validatorSet))
	require.NoError(t, err)

	// Construct validatorapi component.
	vapi, err := validatorapi.NewComponent(bmock, make(map[core.PubKey]map[int]tbls.PublicKey), shareIdx, nil, testutil.BuilderFalse, nil)
	require.NoError(t, err)

	opts := &eth2api.ValidatorsOpts{
		State:   "head",
		Indices: indices,
	}
	_, err = vapi.Validators(context.Background(), opts)
	require.ErrorContains(t, err, "pubshare not found")
}

func TestComponent_AggregateSyncCommitteeSelectionsVerify(t *testing.T) {
	const (
		slot     = 0
		shareIdx = 1
		vIdxA    = 1
		vIdxB    = 2
	)

	var (
		ctx    = context.Background()
		valSet = beaconmock.ValidatorSetA
	)

	// Sync committee selection 1.
	secret1, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey1, err := tbls.SecretToPublicKey(secret1)
	require.NoError(t, err)

	pk1, err := core.PubKeyFromBytes(pubkey1[:])
	require.NoError(t, err)

	valSet[vIdxA].Validator.PublicKey = eth2p0.BLSPubKey(pubkey1)

	selection1 := testutil.RandomSyncCommitteeSelection()
	selection1.ValidatorIndex = valSet[1].Index
	selection1.Slot = slot

	// Sync committee selection 2.
	secret2, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey2, err := tbls.SecretToPublicKey(secret2)
	require.NoError(t, err)

	pk2, err := core.PubKeyFromBytes(pubkey2[:])
	require.NoError(t, err)

	valSet[vIdxB].Validator.PublicKey = eth2p0.BLSPubKey(pubkey2)

	selection2 := testutil.RandomSyncCommitteeSelection()
	selection2.ValidatorIndex = valSet[2].Index
	selection2.Slot = slot

	// Construct beaconmock.
	bmock, err := beaconmock.New(beaconmock.WithValidatorSet(valSet))
	require.NoError(t, err)

	selection1.SelectionProof = syncCommSelectionProof(t, bmock, secret1, slot, selection1.SubcommitteeIndex)
	selection2.SelectionProof = syncCommSelectionProof(t, bmock, secret2, slot, selection2.SubcommitteeIndex)

	selections := []*eth2exp.SyncCommitteeSelection{selection1, selection2}

	// Populate all pubshares map.
	corePubKey1, err := core.PubKeyFromBytes(pubkey1[:])
	require.NoError(t, err)
	corePubKey2, err := core.PubKeyFromBytes(pubkey2[:])
	require.NoError(t, err)

	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{
		corePubKey1: {shareIdx: pubkey1},
		corePubKey2: {shareIdx: pubkey2},
	}

	// Construct the validator api component.
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
	require.NoError(t, err)

	vapi.RegisterAwaitAggSigDB(func(ctx context.Context, duty core.Duty, pubkey core.PubKey) (core.SignedData, error) {
		require.Equal(t, core.NewPrepareSyncContributionDuty(slot), duty)
		for _, val := range valSet {
			pkEth2, err := pubkey.ToETH2()
			require.NoError(t, err)
			if pkEth2 != val.Validator.PublicKey {
				continue
			}

			for _, selection := range selections {
				if selection.ValidatorIndex == val.Index {
					require.Equal(t, eth2p0.Slot(slot), selection.Slot)

					return core.NewSyncCommitteeSelection(selection), nil
				}
			}
		}

		return nil, errors.New("unknown public key")
	})

	vapi.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		require.Equal(t, duty, core.NewPrepareSyncContributionDuty(slot))

		expect := core.ParSignedDataSet{
			pk1: core.NewPartialSignedSyncCommitteeSelection(selection1, shareIdx),
			pk2: core.NewPartialSignedSyncCommitteeSelection(selection2, shareIdx),
		}

		require.Equal(t, expect, set)

		return nil
	})

	got, err := vapi.AggregateSyncCommitteeSelections(ctx, selections)
	require.NoError(t, err)

	// Sort by VIdx before comparing.
	sort.Slice(got, func(i, j int) bool {
		return got[i].ValidatorIndex < got[j].ValidatorIndex
	})

	require.Equal(t, selections, got)
}

func signAggregationAndProof(t *testing.T, eth2Cl eth2wrap.Client, secret tbls.PrivateKey, aggProof *eth2p0.AggregateAndProof) eth2p0.BLSSignature {
	t.Helper()

	epoch, err := eth2util.EpochFromSlot(context.Background(), eth2Cl, aggProof.Aggregate.Data.Slot)
	require.NoError(t, err)

	dataRoot, err := aggProof.HashTreeRoot()
	require.NoError(t, err)

	return sign(t, eth2Cl, secret, signing.DomainAggregateAndProof, epoch, dataRoot)
}

// syncCommSelectionProof returns the selection_proof corresponding to the provided altair.ContributionAndProof.
// Refer get_sync_committee_selection_proof from https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#aggregation-selection.
func syncCommSelectionProof(t *testing.T, eth2Cl eth2wrap.Client, secret tbls.PrivateKey, slot eth2p0.Slot, subcommIdx eth2p0.CommitteeIndex) eth2p0.BLSSignature {
	t.Helper()

	epoch, err := eth2util.EpochFromSlot(context.Background(), eth2Cl, slot)
	require.NoError(t, err)

	data := altair.SyncAggregatorSelectionData{
		Slot:              slot,
		SubcommitteeIndex: uint64(subcommIdx),
	}

	sigRoot, err := data.HashTreeRoot()
	require.NoError(t, err)

	return sign(t, eth2Cl, secret, signing.DomainSyncCommitteeSelectionProof, epoch, sigRoot)
}

// signContributionAndProof signs the provided altair.SignedContributionAndProof and returns the signature.
// Refer get_contribution_and_proof_signature from https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#broadcast-sync-committee-contribution
func signContributionAndProof(t *testing.T, eth2Cl eth2wrap.Client, secret tbls.PrivateKey, contrib *altair.ContributionAndProof) eth2p0.BLSSignature {
	t.Helper()

	epoch, err := eth2util.EpochFromSlot(context.Background(), eth2Cl, contrib.Contribution.Slot)
	require.NoError(t, err)

	sigRoot, err := contrib.HashTreeRoot()
	require.NoError(t, err)

	return sign(t, eth2Cl, secret, signing.DomainContributionAndProof, epoch, sigRoot)
}

func signBeaconSelection(t *testing.T, eth2Cl eth2wrap.Client, secret tbls.PrivateKey, slot eth2p0.Slot) eth2p0.BLSSignature {
	t.Helper()

	epoch, err := eth2util.EpochFromSlot(context.Background(), eth2Cl, slot)
	require.NoError(t, err)

	dataRoot, err := eth2util.SlotHashRoot(slot)
	require.NoError(t, err)

	return sign(t, eth2Cl, secret, signing.DomainSelectionProof, epoch, dataRoot)
}

func sign(t *testing.T, eth2Cl eth2wrap.Client, secret tbls.PrivateKey, domain signing.DomainName, epoch eth2p0.Epoch, dataRoot eth2p0.Root) eth2p0.BLSSignature {
	t.Helper()
	ctx := context.Background()

	signingRoot, err := signing.GetDataRoot(ctx, eth2Cl, domain, epoch, dataRoot)
	require.NoError(t, err)

	sig, err := tbls.Sign(secret, signingRoot[:])
	require.NoError(t, err)

	return eth2p0.BLSSignature(sig)
}

func TestSlotFromTimestamp(t *testing.T) {
	tests := []struct {
		name      string
		network   string
		timestamp time.Time
		genesis   time.Time
		want      eth2p0.Slot
		wantErr   bool
	}{
		{
			name:      "goerli_slot0",
			want:      0,
			network:   "goerli",
			timestamp: time.Unix(1616508000, 0).UTC(),
			wantErr:   false,
		},
		{
			name:      "goerli_slot1",
			want:      1,
			network:   "goerli",
			timestamp: time.Unix(1616508000, 0).UTC().Add(time.Second * 12),
			wantErr:   false,
		},
		{
			name:      "sepolia_slot0",
			want:      0,
			network:   "sepolia",
			timestamp: time.Unix(1655733600, 0).UTC(),
			wantErr:   false,
		},
		{
			name:      "sepolia_slot1",
			want:      1,
			network:   "sepolia",
			timestamp: time.Unix(1655733600, 0).UTC().Add(time.Second * 12),
			wantErr:   false,
		},
		{
			name:      "gnosis_slot0",
			want:      0,
			network:   "gnosis",
			timestamp: time.Unix(1638993340, 0).UTC(),
			wantErr:   false,
		},
		{
			name:      "gnosis_slot1",
			want:      1,
			network:   "gnosis",
			timestamp: time.Unix(1638993340, 0).UTC().Add(time.Second * 12),
			wantErr:   false,
		},
		{
			name:      "mainnet_slot0",
			want:      0,
			network:   "mainnet",
			timestamp: time.Unix(1606824023, 0).UTC(),
			wantErr:   false,
		},
		{
			name:      "mainnet_slot1",
			want:      1,
			network:   "mainnet",
			timestamp: time.Unix(1606824023, 0).UTC().Add(time.Second * 12),
			wantErr:   false,
		},
		{
			name:      "timestamp before genesis",
			want:      0,
			network:   "mainnet",
			timestamp: time.Unix(1606824023, 0).UTC().Add(time.Second * -12),
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			genesis, err := eth2util.NetworkToGenesisTime(tt.network)
			require.NoError(t, err)

			ctx := context.Background()
			eth2Cl, err := beaconmock.New(beaconmock.WithGenesisTime(genesis))
			require.NoError(t, err)

			got, err := validatorapi.SlotFromTimestamp(ctx, eth2Cl, tt.timestamp)
			if tt.wantErr {
				require.Error(t, err)
				require.Equal(t, 0, got)

				return
			}

			require.NoError(t, err)
			require.GreaterOrEqual(t, got, tt.want)
		})
	}
}
