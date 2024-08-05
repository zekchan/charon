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

func TestProposalHash(t *testing.T) {
	proposalStr := "{\"Version\":\"deneb\",\"Blinded\":false,\"ConsensusValue\":2317378000000000,\"ExecutionValue\":2215584996898181,\"Phase0\":null,\"Altair\":null,\"Bellatrix\":null,\"BellatrixBlinded\":null,\"Capella\":null,\"CapellaBlinded\":null,\"Deneb\":{\"block\":{\"slot\":\"11438033\",\"proposer_index\":\"7384\",\"parent_root\":\"0x3fcdd6b7f46290d9179aad6bc02034dd508b073b54dd736b9dbab240d1a7b8fc\",\"state_root\":\"0xde99012f89ee782b79575712d3d8b4cc49f8561ec82e27d7b385601c1e759122\",\"body\":{\"randao_reveal\":\"0x8fb7e3393857fc1b3db6f68a14dd1988b66331c90a7032bf6ab77fc066f91e7dc8c78f6022e86e39d3592291662dd070155ec1b4c6eb7708df7fe881cf33251c96600f5d9ac0c8b6b7f76ec5c0792c4117ecc4d1178bba2b9f376e3b28bc6391\",\"eth1_data\":{\"deposit_root\":\"0xa30ff0f357a12bab11ef6b4b93578fdb5e74555bee49fd4cd254e71a65f55304\",\"deposit_count\":\"1482\",\"block_hash\":\"0x1e1164ed5952d587e920646111b5d4e338b41bba5e35630a2b7d8397294b9575\"},\"graffiti\":\"0x636861726f6e2f76312e312e302d6465762d3462383439373500000000000000\",\"proposer_slashings\":[],\"attester_slashings\":[],\"attestations\":[{\"aggregation_bits\":\"0xbbfbdfff6dfbfbfffeafffffffffbff7eebdbd7dfdffff01\",\"data\":{\"slot\":\"11438032\",\"index\":\"1\",\"beacon_block_root\":\"0x3fcdd6b7f46290d9179aad6bc02034dd508b073b54dd736b9dbab240d1a7b8fc\",\"source\":{\"epoch\":\"714876\",\"root\":\"0xbe5b734518bdc1356a62f7fd8de79ff43ab0e72b8c4fccc325ea8a09f209f361\"},\"target\":{\"epoch\":\"714877\",\"root\":\"0x3fcdd6b7f46290d9179aad6bc02034dd508b073b54dd736b9dbab240d1a7b8fc\"}},\"signature\":\"0x94935974086ca9f4b0835c0e576777aba878299476633da84d1f60541165bfd5c09a9fece974892b1dc496e6c809279316fa7a93a644fe1d62b17df8133bf838e00b4b0b1b4bf654f5ba7214f6223975e731590670a1f788f6312a94a36fd573\"},{\"aggregation_bits\":\"0xf7ff3fffff7fd9ffedfdefffdbd7ef5fffd7ffff6effef01\",\"data\":{\"slot\":\"11438032\",\"index\":\"0\",\"beacon_block_root\":\"0x3fcdd6b7f46290d9179aad6bc02034dd508b073b54dd736b9dbab240d1a7b8fc\",\"source\":{\"epoch\":\"714876\",\"root\":\"0xbe5b734518bdc1356a62f7fd8de79ff43ab0e72b8c4fccc325ea8a09f209f361\"},\"target\":{\"epoch\":\"714877\",\"root\":\"0x3fcdd6b7f46290d9179aad6bc02034dd508b073b54dd736b9dbab240d1a7b8fc\"}},\"signature\":\"0xb2649e1ca1f6e1a08fa5dff68e9e056baf24a9bfd31ad5dd2e95218841b5d87ea7d0ff4d2eab076bccd047392b985f69020429e7d063d7f1039bb2d4114166ad753a328a20939dfa1a7d75dafac822c0f6ac58a5b52c352f9d5552a22ccba49f\"}],\"deposits\":[],\"voluntary_exits\":[],\"sync_aggregate\":{\"sync_committee_bits\":\"0xf7bdebffbf7fa77ffffffdfd3bffafeebfefffbff7feffeffffceefbff9f9fffcff7f7fffdffefbaff9fb37f7ffffbf6ff9efffbdfe3fffdffffffefdf7f7f75\",\"sync_committee_signature\":\"0x8d0441955b16922ed87512b3159f1de498a656df4f702eb2a634b7d53dfa64989bae3c3782015719c22300f2774751050b47c201de1e2ea9ce91ec279ca92d0ad8f23dd7592f5034a02857cc1cf5680fa471506300c45a9de0221db2d169720a\"},\"execution_payload\":{\"parent_hash\":\"0xc681768e15d7bdf97950f11aa5064bf8469b81f2777e2a8aa32c3fc39b5ae3b5\",\"fee_recipient\":\"0x7cE7390C41Ce3416c4A0a297761C71763d89Ca3B\",\"state_root\":\"0xd0e9d932919e92604a255612e5913c7c521ae4e7c8e8d4d0b60c5d5e61ac1dab\",\"receipts_root\":\"0x7251abf026b15da91775c5dad983e7489acf8a6893e5197983ffc3ef570f623d\",\"logs_bloom\":\"0x00000000000000000000000000000000000000000108000000000000000000000000000000000000000000000000004000020000000000000040000002000000000000000000000000000000000000000100000000100100000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000040000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000200000000000000000000000000000000\",\"prev_randao\":\"0x611baa3da5dc919c653142b9f947b4608608880747766d65be8cefb56be4d581\",\"block_number\":\"11101661\",\"gas_limit\":\"17000000\",\"gas_used\":\"443117\",\"timestamp\":\"1722586465\",\"extra_data\":\"0x4e65746865726d696e64\",\"base_fee_per_gas\":\"7\",\"block_hash\":\"0xbbd3b0c8e9061b916a8ee8aef7897ecfbd0042660752b63090aefdb62d75b07f\",\"transactions\":[\"0x01f902918227d8820b1985012a05f2008306e6029494f34bc8e795421d19042077faa16698f3eb900380b902244b0af2ba3fb6ad3d8118887b2df55cf5851d77d0b1128dab8d090c07a8fd4b37c5402b3500000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001a000000000000000000000000042b3f1313ec16d1f400fa07604ff2bdb7ec88e7a000000000000000000000000000000000000000000000000000000000000001bd201337b449c085e04ef951b6750768fb507f3724dff43357c9bb81c12c90b9a632c473329197d242c3b7988697840061008ee11065b51c8b9dfca313319aac400000000000000000000000000000000000000000000000000000000000000853078336662366164336438313138383837623264663535636635383531643737643062313132386461623864303930633037613866643462333763353430326233352f3078663531303965336435376436386266333034353865316532363066316233633534323762346637616333326131343331656430326234306661353833393635380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000042307866353130396533643537643638626633303435386531653236306631623363353432376234663761633332613134333165643032623430666135383339363538000000000000000000000000000000000000000000000000000000000000c080a0f4ec52d049bd46f0ccb234475e753d716da71dec49ddc27b7d8017b9186c83afa023e2eab64237e59fdce9f0f2dba61a45f4e8c8a9beb520fd883020628e49f32a\"],\"withdrawals\":[{\"index\":\"49294462\",\"validator_index\":\"2394\",\"address\":\"0xcc4e00a72d871d6c328bcfe9025ad93d0a26df51\",\"amount\":\"316591\"},{\"index\":\"49294463\",\"validator_index\":\"2395\",\"address\":\"0xcc4e00a72d871d6c328bcfe9025ad93d0a26df51\",\"amount\":\"459405\"},{\"index\":\"49294464\",\"validator_index\":\"2396\",\"address\":\"0xcc4e00a72d871d6c328bcfe9025ad93d0a26df51\",\"amount\":\"315894\"},{\"index\":\"49294465\",\"validator_index\":\"2397\",\"address\":\"0xcc4e00a72d871d6c328bcfe9025ad93d0a26df51\",\"amount\":\"326425\"},{\"index\":\"49294466\",\"validator_index\":\"2398\",\"address\":\"0xcc4e00a72d871d6c328bcfe9025ad93d0a26df51\",\"amount\":\"306729\"},{\"index\":\"49294467\",\"validator_index\":\"2399\",\"address\":\"0xcc4e00a72d871d6c328bcfe9025ad93d0a26df51\",\"amount\":\"467290\"},{\"index\":\"49294468\",\"validator_index\":\"2813\",\"address\":\"0xcc4e00a72d871d6c328bcfe9025ad93d0a26df51\",\"amount\":\"306740\"},{\"index\":\"49294469\",\"validator_index\":\"2868\",\"address\":\"0xcc4e00a72d871d6c328bcfe9025ad93d0a26df51\",\"amount\":\"317940\"}],\"blob_gas_used\":\"0\",\"excess_blob_gas\":\"0\"},\"bls_to_execution_changes\":[],\"blob_kzg_commitments\":[]}},\"kzg_proofs\":[],\"blobs\":[]},\"DenebBlinded\":null}"

	vp := &eth2api.VersionedProposal{}
	err := json.Unmarshal([]byte(proposalStr), vp)
	require.NoError(t, err)

	denebHash, err := vp.Deneb.HashTreeRoot() // 26259b848e6d64bdf1fab9e719218bb2f0f670c075c89c74163387ad0466db7c
	require.NoError(t, err)
	blockHash, err := vp.Deneb.Block.HashTreeRoot()
	require.NoError(t, err)

	log.Info(context.Background(), "hash", z.Str("deneb", hex.EncodeToString(denebHash[:])), z.Str("block", hex.EncodeToString(blockHash[:])))
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
