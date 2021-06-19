package metadata

import (
	"github.com/0xkraken/incognito-wasm/incognito/common"
	rCommon "github.com/ethereum/go-ethereum/common"
)

// whoever can send this type of tx
type IssuingEVMRequest struct {
	BlockHash  rCommon.Hash
	TxIndex    uint
	ProofStrs  []string
	IncTokenID common.Hash
	MetadataBase
}

func NewIssuingEVMRequest(
	blockHash rCommon.Hash,
	txIndex uint,
	proofStrs []string,
	incTokenID common.Hash,
	metaType int,
) (*IssuingEVMRequest, error) {
	metadataBase := MetadataBase{
		Type: metaType,
	}
	issuingEthReq := &IssuingEVMRequest{
		BlockHash:    blockHash,
		TxIndex:      txIndex,
		ProofStrs:    proofStrs,
		IncTokenID:   incTokenID,
		MetadataBase: metadataBase,
	}
	return issuingEthReq, nil
}

func (iReq IssuingEVMRequest) Hash() *common.Hash {
	record := iReq.BlockHash.String()
	record += string(iReq.TxIndex)
	proofStrs := iReq.ProofStrs
	for _, proofStr := range proofStrs {
		record += proofStr
	}
	record += iReq.MetadataBase.Hash().String()
	record += iReq.IncTokenID.String()

	// final hash
	hash := common.HashH([]byte(record))
	return &hash
}

func (iReq *IssuingEVMRequest) CalculateSize() uint64 {
	return calculateSize(iReq)
}
