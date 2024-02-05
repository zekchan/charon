// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Code generated by "stringer -type=OrderStart -trimprefix=Start"; DO NOT EDIT.

package lifecycle

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[StartTracker-0]
	_ = x[StartPrivkeyLock-1]
	_ = x[StartAggSigDB-2]
	_ = x[StartRelay-3]
	_ = x[StartMonitoringAPI-4]
	_ = x[StartDebugAPI-5]
	_ = x[StartValidatorAPI-6]
	_ = x[StartGenericSignature-7]
	_ = x[StartP2PPing-8]
	_ = x[StartP2PRouters-9]
	_ = x[StartForceDirectConns-10]
	_ = x[StartP2PConsensus-11]
	_ = x[StartSimulator-12]
	_ = x[StartScheduler-13]
	_ = x[StartP2PEventCollector-14]
	_ = x[StartPeerInfo-15]
	_ = x[StartParSigDB-16]
}

const _OrderStart_name = "TrackerPrivkeyLockAggSigDBRelayMonitoringAPIDebugAPIValidatorAPIGenericSignatureP2PPingP2PRoutersForceDirectConnsP2PConsensusSimulatorSchedulerP2PEventCollectorPeerInfoParSigDB"

var _OrderStart_index = [...]uint8{0, 7, 18, 26, 31, 44, 52, 64, 80, 87, 97, 113, 125, 134, 143, 160, 168, 176}

func (i OrderStart) String() string {
	if i < 0 || i >= OrderStart(len(_OrderStart_index)-1) {
		return "OrderStart(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _OrderStart_name[_OrderStart_index[i]:_OrderStart_index[i+1]]
}
