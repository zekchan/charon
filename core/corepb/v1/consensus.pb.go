// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        (unknown)
// source: core/corepb/v1/consensus.proto

package v1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	anypb "google.golang.org/protobuf/types/known/anypb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type QBFTMsg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type              int64  `protobuf:"varint,1,opt,name=type,proto3" json:"type,omitempty"`
	Duty              *Duty  `protobuf:"bytes,2,opt,name=duty,proto3" json:"duty,omitempty"`
	PeerIdx           int64  `protobuf:"varint,3,opt,name=peer_idx,json=peerIdx,proto3" json:"peer_idx,omitempty"`
	Round             int64  `protobuf:"varint,4,opt,name=round,proto3" json:"round,omitempty"`
	PreparedRound     int64  `protobuf:"varint,6,opt,name=prepared_round,json=preparedRound,proto3" json:"prepared_round,omitempty"`
	Signature         []byte `protobuf:"bytes,8,opt,name=signature,proto3" json:"signature,omitempty"`
	ValueHash         []byte `protobuf:"bytes,11,opt,name=value_hash,json=valueHash,proto3" json:"value_hash,omitempty"`
	PreparedValueHash []byte `protobuf:"bytes,12,opt,name=prepared_value_hash,json=preparedValueHash,proto3" json:"prepared_value_hash,omitempty"`
}

func (x *QBFTMsg) Reset() {
	*x = QBFTMsg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_core_corepb_v1_consensus_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QBFTMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QBFTMsg) ProtoMessage() {}

func (x *QBFTMsg) ProtoReflect() protoreflect.Message {
	mi := &file_core_corepb_v1_consensus_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QBFTMsg.ProtoReflect.Descriptor instead.
func (*QBFTMsg) Descriptor() ([]byte, []int) {
	return file_core_corepb_v1_consensus_proto_rawDescGZIP(), []int{0}
}

func (x *QBFTMsg) GetType() int64 {
	if x != nil {
		return x.Type
	}
	return 0
}

func (x *QBFTMsg) GetDuty() *Duty {
	if x != nil {
		return x.Duty
	}
	return nil
}

func (x *QBFTMsg) GetPeerIdx() int64 {
	if x != nil {
		return x.PeerIdx
	}
	return 0
}

func (x *QBFTMsg) GetRound() int64 {
	if x != nil {
		return x.Round
	}
	return 0
}

func (x *QBFTMsg) GetPreparedRound() int64 {
	if x != nil {
		return x.PreparedRound
	}
	return 0
}

func (x *QBFTMsg) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

func (x *QBFTMsg) GetValueHash() []byte {
	if x != nil {
		return x.ValueHash
	}
	return nil
}

func (x *QBFTMsg) GetPreparedValueHash() []byte {
	if x != nil {
		return x.PreparedValueHash
	}
	return nil
}

type ConsensusMsg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Msg           *QBFTMsg     `protobuf:"bytes,1,opt,name=msg,proto3" json:"msg,omitempty"`                     // msg is the message that we send
	Justification []*QBFTMsg   `protobuf:"bytes,2,rep,name=justification,proto3" json:"justification,omitempty"` // justification is the justifications from others for the message
	Values        []*anypb.Any `protobuf:"bytes,3,rep,name=values,proto3" json:"values,omitempty"`               // values of the hashes in the messages
}

func (x *ConsensusMsg) Reset() {
	*x = ConsensusMsg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_core_corepb_v1_consensus_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConsensusMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConsensusMsg) ProtoMessage() {}

func (x *ConsensusMsg) ProtoReflect() protoreflect.Message {
	mi := &file_core_corepb_v1_consensus_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConsensusMsg.ProtoReflect.Descriptor instead.
func (*ConsensusMsg) Descriptor() ([]byte, []int) {
	return file_core_corepb_v1_consensus_proto_rawDescGZIP(), []int{1}
}

func (x *ConsensusMsg) GetMsg() *QBFTMsg {
	if x != nil {
		return x.Msg
	}
	return nil
}

func (x *ConsensusMsg) GetJustification() []*QBFTMsg {
	if x != nil {
		return x.Justification
	}
	return nil
}

func (x *ConsensusMsg) GetValues() []*anypb.Any {
	if x != nil {
		return x.Values
	}
	return nil
}

type SniffedConsensusMsg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Timestamp *timestamppb.Timestamp `protobuf:"bytes,1,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	Msg       *ConsensusMsg          `protobuf:"bytes,2,opt,name=msg,proto3" json:"msg,omitempty"`
}

func (x *SniffedConsensusMsg) Reset() {
	*x = SniffedConsensusMsg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_core_corepb_v1_consensus_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SniffedConsensusMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SniffedConsensusMsg) ProtoMessage() {}

func (x *SniffedConsensusMsg) ProtoReflect() protoreflect.Message {
	mi := &file_core_corepb_v1_consensus_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SniffedConsensusMsg.ProtoReflect.Descriptor instead.
func (*SniffedConsensusMsg) Descriptor() ([]byte, []int) {
	return file_core_corepb_v1_consensus_proto_rawDescGZIP(), []int{2}
}

func (x *SniffedConsensusMsg) GetTimestamp() *timestamppb.Timestamp {
	if x != nil {
		return x.Timestamp
	}
	return nil
}

func (x *SniffedConsensusMsg) GetMsg() *ConsensusMsg {
	if x != nil {
		return x.Msg
	}
	return nil
}

type SniffedConsensusInstance struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	StartedAt *timestamppb.Timestamp `protobuf:"bytes,1,opt,name=started_at,json=startedAt,proto3" json:"started_at,omitempty"`
	Nodes     int64                  `protobuf:"varint,2,opt,name=nodes,proto3" json:"nodes,omitempty"`
	PeerIdx   int64                  `protobuf:"varint,3,opt,name=peer_idx,json=peerIdx,proto3" json:"peer_idx,omitempty"`
	Msgs      []*SniffedConsensusMsg `protobuf:"bytes,4,rep,name=msgs,proto3" json:"msgs,omitempty"`
}

func (x *SniffedConsensusInstance) Reset() {
	*x = SniffedConsensusInstance{}
	if protoimpl.UnsafeEnabled {
		mi := &file_core_corepb_v1_consensus_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SniffedConsensusInstance) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SniffedConsensusInstance) ProtoMessage() {}

func (x *SniffedConsensusInstance) ProtoReflect() protoreflect.Message {
	mi := &file_core_corepb_v1_consensus_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SniffedConsensusInstance.ProtoReflect.Descriptor instead.
func (*SniffedConsensusInstance) Descriptor() ([]byte, []int) {
	return file_core_corepb_v1_consensus_proto_rawDescGZIP(), []int{3}
}

func (x *SniffedConsensusInstance) GetStartedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.StartedAt
	}
	return nil
}

func (x *SniffedConsensusInstance) GetNodes() int64 {
	if x != nil {
		return x.Nodes
	}
	return 0
}

func (x *SniffedConsensusInstance) GetPeerIdx() int64 {
	if x != nil {
		return x.PeerIdx
	}
	return 0
}

func (x *SniffedConsensusInstance) GetMsgs() []*SniffedConsensusMsg {
	if x != nil {
		return x.Msgs
	}
	return nil
}

type SniffedConsensusInstances struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Instances []*SniffedConsensusInstance `protobuf:"bytes,1,rep,name=instances,proto3" json:"instances,omitempty"`
	GitHash   string                      `protobuf:"bytes,2,opt,name=git_hash,json=gitHash,proto3" json:"git_hash,omitempty"`
}

func (x *SniffedConsensusInstances) Reset() {
	*x = SniffedConsensusInstances{}
	if protoimpl.UnsafeEnabled {
		mi := &file_core_corepb_v1_consensus_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SniffedConsensusInstances) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SniffedConsensusInstances) ProtoMessage() {}

func (x *SniffedConsensusInstances) ProtoReflect() protoreflect.Message {
	mi := &file_core_corepb_v1_consensus_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SniffedConsensusInstances.ProtoReflect.Descriptor instead.
func (*SniffedConsensusInstances) Descriptor() ([]byte, []int) {
	return file_core_corepb_v1_consensus_proto_rawDescGZIP(), []int{4}
}

func (x *SniffedConsensusInstances) GetInstances() []*SniffedConsensusInstance {
	if x != nil {
		return x.Instances
	}
	return nil
}

func (x *SniffedConsensusInstances) GetGitHash() string {
	if x != nil {
		return x.GitHash
	}
	return ""
}

var File_core_corepb_v1_consensus_proto protoreflect.FileDescriptor

var file_core_corepb_v1_consensus_proto_rawDesc = []byte{
	0x0a, 0x1e, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2f, 0x76, 0x31,
	0x2f, 0x63, 0x6f, 0x6e, 0x73, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x0e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2e, 0x76, 0x31,
	0x1a, 0x19, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2f, 0x76, 0x31,
	0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x19, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x61, 0x6e, 0x79,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
	0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xa4, 0x02, 0x0a, 0x07, 0x51, 0x42, 0x46, 0x54,
	0x4d, 0x73, 0x67, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x03, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x28, 0x0a, 0x04, 0x64, 0x75, 0x74, 0x79, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x72,
	0x65, 0x70, 0x62, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x75, 0x74, 0x79, 0x52, 0x04, 0x64, 0x75, 0x74,
	0x79, 0x12, 0x19, 0x0a, 0x08, 0x70, 0x65, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x78, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x03, 0x52, 0x07, 0x70, 0x65, 0x65, 0x72, 0x49, 0x64, 0x78, 0x12, 0x14, 0x0a, 0x05,
	0x72, 0x6f, 0x75, 0x6e, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x03, 0x52, 0x05, 0x72, 0x6f, 0x75,
	0x6e, 0x64, 0x12, 0x25, 0x0a, 0x0e, 0x70, 0x72, 0x65, 0x70, 0x61, 0x72, 0x65, 0x64, 0x5f, 0x72,
	0x6f, 0x75, 0x6e, 0x64, 0x18, 0x06, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0d, 0x70, 0x72, 0x65, 0x70,
	0x61, 0x72, 0x65, 0x64, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67,
	0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69,
	0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x5f, 0x68, 0x61, 0x73, 0x68, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x48, 0x61, 0x73, 0x68, 0x12, 0x2e, 0x0a, 0x13, 0x70, 0x72, 0x65, 0x70, 0x61, 0x72,
	0x65, 0x64, 0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x5f, 0x68, 0x61, 0x73, 0x68, 0x18, 0x0c, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x11, 0x70, 0x72, 0x65, 0x70, 0x61, 0x72, 0x65, 0x64, 0x56, 0x61, 0x6c,
	0x75, 0x65, 0x48, 0x61, 0x73, 0x68, 0x4a, 0x04, 0x08, 0x05, 0x10, 0x06, 0x4a, 0x04, 0x08, 0x07,
	0x10, 0x08, 0x4a, 0x04, 0x08, 0x09, 0x10, 0x0a, 0x4a, 0x04, 0x08, 0x0a, 0x10, 0x0b, 0x22, 0xa6,
	0x01, 0x0a, 0x0c, 0x43, 0x6f, 0x6e, 0x73, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x4d, 0x73, 0x67, 0x12,
	0x29, 0x0a, 0x03, 0x6d, 0x73, 0x67, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x63,
	0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2e, 0x76, 0x31, 0x2e, 0x51, 0x42,
	0x46, 0x54, 0x4d, 0x73, 0x67, 0x52, 0x03, 0x6d, 0x73, 0x67, 0x12, 0x3d, 0x0a, 0x0d, 0x6a, 0x75,
	0x73, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x17, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2e,
	0x76, 0x31, 0x2e, 0x51, 0x42, 0x46, 0x54, 0x4d, 0x73, 0x67, 0x52, 0x0d, 0x6a, 0x75, 0x73, 0x74,
	0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x2c, 0x0a, 0x06, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x41, 0x6e, 0x79, 0x52,
	0x06, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x22, 0x7f, 0x0a, 0x13, 0x53, 0x6e, 0x69, 0x66, 0x66,
	0x65, 0x64, 0x43, 0x6f, 0x6e, 0x73, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x4d, 0x73, 0x67, 0x12, 0x38,
	0x0a, 0x09, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x74,
	0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x12, 0x2e, 0x0a, 0x03, 0x6d, 0x73, 0x67, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x72,
	0x65, 0x70, 0x62, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x6f, 0x6e, 0x73, 0x65, 0x6e, 0x73, 0x75, 0x73,
	0x4d, 0x73, 0x67, 0x52, 0x03, 0x6d, 0x73, 0x67, 0x22, 0xbf, 0x01, 0x0a, 0x18, 0x53, 0x6e, 0x69,
	0x66, 0x66, 0x65, 0x64, 0x43, 0x6f, 0x6e, 0x73, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x49, 0x6e, 0x73,
	0x74, 0x61, 0x6e, 0x63, 0x65, 0x12, 0x39, 0x0a, 0x0a, 0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x64,
	0x5f, 0x61, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x64, 0x41, 0x74,
	0x12, 0x14, 0x0a, 0x05, 0x6e, 0x6f, 0x64, 0x65, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52,
	0x05, 0x6e, 0x6f, 0x64, 0x65, 0x73, 0x12, 0x19, 0x0a, 0x08, 0x70, 0x65, 0x65, 0x72, 0x5f, 0x69,
	0x64, 0x78, 0x18, 0x03, 0x20, 0x01, 0x28, 0x03, 0x52, 0x07, 0x70, 0x65, 0x65, 0x72, 0x49, 0x64,
	0x78, 0x12, 0x37, 0x0a, 0x04, 0x6d, 0x73, 0x67, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x23, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2e, 0x76, 0x31,
	0x2e, 0x53, 0x6e, 0x69, 0x66, 0x66, 0x65, 0x64, 0x43, 0x6f, 0x6e, 0x73, 0x65, 0x6e, 0x73, 0x75,
	0x73, 0x4d, 0x73, 0x67, 0x52, 0x04, 0x6d, 0x73, 0x67, 0x73, 0x22, 0x7e, 0x0a, 0x19, 0x53, 0x6e,
	0x69, 0x66, 0x66, 0x65, 0x64, 0x43, 0x6f, 0x6e, 0x73, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x49, 0x6e,
	0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x73, 0x12, 0x46, 0x0a, 0x09, 0x69, 0x6e, 0x73, 0x74, 0x61,
	0x6e, 0x63, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x28, 0x2e, 0x63, 0x6f, 0x72,
	0x65, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x6e, 0x69, 0x66,
	0x66, 0x65, 0x64, 0x43, 0x6f, 0x6e, 0x73, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x49, 0x6e, 0x73, 0x74,
	0x61, 0x6e, 0x63, 0x65, 0x52, 0x09, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x73, 0x12,
	0x19, 0x0a, 0x08, 0x67, 0x69, 0x74, 0x5f, 0x68, 0x61, 0x73, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x07, 0x67, 0x69, 0x74, 0x48, 0x61, 0x73, 0x68, 0x42, 0x2e, 0x5a, 0x2c, 0x67, 0x69,
	0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x62, 0x6f, 0x6c, 0x6e, 0x65, 0x74,
	0x77, 0x6f, 0x72, 0x6b, 0x2f, 0x63, 0x68, 0x61, 0x72, 0x6f, 0x6e, 0x2f, 0x63, 0x6f, 0x72, 0x65,
	0x2f, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2f, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_core_corepb_v1_consensus_proto_rawDescOnce sync.Once
	file_core_corepb_v1_consensus_proto_rawDescData = file_core_corepb_v1_consensus_proto_rawDesc
)

func file_core_corepb_v1_consensus_proto_rawDescGZIP() []byte {
	file_core_corepb_v1_consensus_proto_rawDescOnce.Do(func() {
		file_core_corepb_v1_consensus_proto_rawDescData = protoimpl.X.CompressGZIP(file_core_corepb_v1_consensus_proto_rawDescData)
	})
	return file_core_corepb_v1_consensus_proto_rawDescData
}

var file_core_corepb_v1_consensus_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_core_corepb_v1_consensus_proto_goTypes = []interface{}{
	(*QBFTMsg)(nil),                   // 0: core.corepb.v1.QBFTMsg
	(*ConsensusMsg)(nil),              // 1: core.corepb.v1.ConsensusMsg
	(*SniffedConsensusMsg)(nil),       // 2: core.corepb.v1.SniffedConsensusMsg
	(*SniffedConsensusInstance)(nil),  // 3: core.corepb.v1.SniffedConsensusInstance
	(*SniffedConsensusInstances)(nil), // 4: core.corepb.v1.SniffedConsensusInstances
	(*Duty)(nil),                      // 5: core.corepb.v1.Duty
	(*anypb.Any)(nil),                 // 6: google.protobuf.Any
	(*timestamppb.Timestamp)(nil),     // 7: google.protobuf.Timestamp
}
var file_core_corepb_v1_consensus_proto_depIdxs = []int32{
	5, // 0: core.corepb.v1.QBFTMsg.duty:type_name -> core.corepb.v1.Duty
	0, // 1: core.corepb.v1.ConsensusMsg.msg:type_name -> core.corepb.v1.QBFTMsg
	0, // 2: core.corepb.v1.ConsensusMsg.justification:type_name -> core.corepb.v1.QBFTMsg
	6, // 3: core.corepb.v1.ConsensusMsg.values:type_name -> google.protobuf.Any
	7, // 4: core.corepb.v1.SniffedConsensusMsg.timestamp:type_name -> google.protobuf.Timestamp
	1, // 5: core.corepb.v1.SniffedConsensusMsg.msg:type_name -> core.corepb.v1.ConsensusMsg
	7, // 6: core.corepb.v1.SniffedConsensusInstance.started_at:type_name -> google.protobuf.Timestamp
	2, // 7: core.corepb.v1.SniffedConsensusInstance.msgs:type_name -> core.corepb.v1.SniffedConsensusMsg
	3, // 8: core.corepb.v1.SniffedConsensusInstances.instances:type_name -> core.corepb.v1.SniffedConsensusInstance
	9, // [9:9] is the sub-list for method output_type
	9, // [9:9] is the sub-list for method input_type
	9, // [9:9] is the sub-list for extension type_name
	9, // [9:9] is the sub-list for extension extendee
	0, // [0:9] is the sub-list for field type_name
}

func init() { file_core_corepb_v1_consensus_proto_init() }
func file_core_corepb_v1_consensus_proto_init() {
	if File_core_corepb_v1_consensus_proto != nil {
		return
	}
	file_core_corepb_v1_core_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_core_corepb_v1_consensus_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QBFTMsg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_core_corepb_v1_consensus_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConsensusMsg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_core_corepb_v1_consensus_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SniffedConsensusMsg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_core_corepb_v1_consensus_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SniffedConsensusInstance); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_core_corepb_v1_consensus_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SniffedConsensusInstances); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_core_corepb_v1_consensus_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_core_corepb_v1_consensus_proto_goTypes,
		DependencyIndexes: file_core_corepb_v1_consensus_proto_depIdxs,
		MessageInfos:      file_core_corepb_v1_consensus_proto_msgTypes,
	}.Build()
	File_core_corepb_v1_consensus_proto = out.File
	file_core_corepb_v1_consensus_proto_rawDesc = nil
	file_core_corepb_v1_consensus_proto_goTypes = nil
	file_core_corepb_v1_consensus_proto_depIdxs = nil
}
