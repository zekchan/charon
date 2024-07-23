// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core

import (
	"context"
	"encoding/hex"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/tbls"
)

var (
	_ Eth2SignedData = VersionedSignedProposal{}
	_ Eth2SignedData = Attestation{}
	_ Eth2SignedData = SignedVoluntaryExit{}
	_ Eth2SignedData = VersionedSignedValidatorRegistration{}
	_ Eth2SignedData = SignedRandao{}
	_ Eth2SignedData = BeaconCommitteeSelection{}
	_ Eth2SignedData = SignedAggregateAndProof{}
	_ Eth2SignedData = SignedSyncMessage{}
	_ Eth2SignedData = SignedSyncContributionAndProof{}
	_ Eth2SignedData = SyncCommitteeSelection{}
)

// VerifyEth2SignedData verifies signature associated with the given Eth2SignedData.
func VerifyEth2SignedData(ctx context.Context, eth2Cl eth2wrap.Client, data Eth2SignedData, pubkey tbls.PublicKey) error {
	epoch, err := data.Epoch(ctx, eth2Cl)
	if err != nil {
		return err
	}

	sigRoot, err := data.MessageRoot()
	if err != nil {
		return err
	}

	jsdata, _ := data.MarshalJSON()

	domainName := data.DomainName()
	sig := data.Signature().ToETH2()

	time.Sleep(100 * time.Millisecond)

	log.Debug(ctx, "[chiado] VerifyEth2SignedData",
		z.Str("pubkey", hex.EncodeToString(pubkey[:])),
		z.Str("sigRoot", hex.EncodeToString(sigRoot[:])),
		z.Str("domainName", string(domainName)),
		z.Str("sig", sig.String()),
		z.Any("epoch", epoch),
		z.Any("jsdata", jsdata))

	time.Sleep(100 * time.Millisecond)

	return signing.Verify(ctx, eth2Cl, domainName, epoch, sigRoot, sig, pubkey)
}

// Implement Eth2SignedData for VersionedSignedProposal.

func (VersionedSignedProposal) DomainName() signing.DomainName {
	return signing.DomainBeaconProposer
}

func (p VersionedSignedProposal) Epoch(ctx context.Context, eth2Cl eth2wrap.Client) (eth2p0.Epoch, error) {
	slot, err := p.Slot()
	if err != nil {
		return 0, err
	}

	return eth2util.EpochFromSlot(ctx, eth2Cl, slot)
}

// Implement Eth2SignedData for Attestation.

func (Attestation) DomainName() signing.DomainName {
	return signing.DomainBeaconAttester
}

func (a Attestation) Epoch(_ context.Context, _ eth2wrap.Client) (eth2p0.Epoch, error) {
	return a.Attestation.Data.Target.Epoch, nil
}

// Implement Eth2SignedData for SignedVoluntaryExit.

func (SignedVoluntaryExit) DomainName() signing.DomainName {
	return signing.DomainExit
}

func (e SignedVoluntaryExit) Epoch(_ context.Context, _ eth2wrap.Client) (eth2p0.Epoch, error) {
	return e.Message.Epoch, nil
}

// Implement Eth2SignedData for VersionedSignedValidatorRegistration.

func (VersionedSignedValidatorRegistration) DomainName() signing.DomainName {
	return signing.DomainApplicationBuilder
}

func (VersionedSignedValidatorRegistration) Epoch(context.Context, eth2wrap.Client) (eth2p0.Epoch, error) {
	// Always use epoch 0 for DomainApplicationBuilder.
	return 0, nil
}

// Implement Eth2SignedData for SignedRandao.

func (SignedRandao) DomainName() signing.DomainName {
	return signing.DomainRandao
}

func (s SignedRandao) Epoch(_ context.Context, _ eth2wrap.Client) (eth2p0.Epoch, error) {
	return s.SignedEpoch.Epoch, nil
}

// Implement Eth2SignedData for BeaconCommitteeSelection.

func (BeaconCommitteeSelection) DomainName() signing.DomainName {
	return signing.DomainSelectionProof
}

func (s BeaconCommitteeSelection) Epoch(ctx context.Context, eth2Cl eth2wrap.Client) (eth2p0.Epoch, error) {
	return eth2util.EpochFromSlot(ctx, eth2Cl, s.Slot)
}

// Implement Eth2SignedData for SignedAggregateAndProof.

func (SignedAggregateAndProof) DomainName() signing.DomainName {
	return signing.DomainAggregateAndProof
}

func (s SignedAggregateAndProof) Epoch(ctx context.Context, eth2Cl eth2wrap.Client) (eth2p0.Epoch, error) {
	return eth2util.EpochFromSlot(ctx, eth2Cl, s.Message.Aggregate.Data.Slot)
}

// Implement Eth2SignedData for SignedSyncMessage.

func (SignedSyncMessage) DomainName() signing.DomainName {
	return signing.DomainSyncCommittee
}

func (s SignedSyncMessage) Epoch(ctx context.Context, eth2Cl eth2wrap.Client) (eth2p0.Epoch, error) {
	return eth2util.EpochFromSlot(ctx, eth2Cl, s.Slot)
}

// Implement Eth2SignedData for SignedSyncContributionAndProof.

func (SignedSyncContributionAndProof) DomainName() signing.DomainName {
	return signing.DomainContributionAndProof
}

func (s SignedSyncContributionAndProof) Epoch(ctx context.Context, eth2Cl eth2wrap.Client) (eth2p0.Epoch, error) {
	return eth2util.EpochFromSlot(ctx, eth2Cl, s.Message.Contribution.Slot)
}

// Implement Eth2SignedData for SyncCommitteeSelection.

func (SyncCommitteeSelection) DomainName() signing.DomainName {
	return signing.DomainSyncCommitteeSelectionProof
}

func (s SyncCommitteeSelection) Epoch(ctx context.Context, eth2Cl eth2wrap.Client) (eth2p0.Epoch, error) {
	return eth2util.EpochFromSlot(ctx, eth2Cl, s.Slot)
}
