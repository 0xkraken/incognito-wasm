package metadata

import (
	zkp "github.com/0xkraken/incognito-wasm/incognito/privacy/zeroknowledge"
	"github.com/0xkraken/incognito-wasm/incognito/common"
)

// Interface for all types of metadata in tx
type Metadata interface {
	GetType() int
	Hash() *common.Hash
	CalculateSize() uint64
}

// This is tx struct which is really saved in tx mempool
type TxDesc struct {
	// Tx is the transaction associated with the entry.
	Tx Transaction

	// Height is the best block's height when the entry was added to the the source pool.
	Height uint64

	// Fee is the total fee the transaction associated with the entry pays.
	Fee uint64

	// FeeToken is the total token fee the transaction associated with the entry pays.
	// FeeToken is zero if tx is PRV transaction
	FeeToken uint64

	// FeePerKB is the fee the transaction pays in coin per 1000 bytes.
	FeePerKB int32
}

// Interface for mempool which is used in metadata
type MempoolRetriever interface {
	GetSerialNumbersHashH() map[common.Hash][]common.Hash
	GetTxsInMem() map[common.Hash]TxDesc
	GetSNDOutputsHashH() map[common.Hash][]common.Hash
}

// Interface for all type of transaction
type Transaction interface {
	// GET/SET FUNC
	GetMetadataType() int
	GetType() string
	GetLockTime() int64
	GetTxActualSize() uint64
	GetSenderAddrLastByte() byte
	GetTxFee() uint64
	GetTxFeeToken() uint64
	GetMetadata() Metadata
	SetMetadata(Metadata)
	GetInfo() []byte
	GetSender() []byte
	GetSigPubKey() []byte
	GetProof() *zkp.PaymentProof
	// Get receivers' data for tx
	GetReceivers() ([][]byte, []uint64)
	GetUniqueReceiver() (bool, []byte, uint64)
	GetTransferData() (bool, []byte, uint64, *common.Hash)
	// Get receivers' data for custom token tx (nil for normal tx)
	GetTokenReceivers() ([][]byte, []uint64)
	GetTokenUniqueReceiver() (bool, []byte, uint64)
	//GetMetadataFromVinsTx(ChainRetriever, ShardViewRetriever, BeaconViewRetriever) (Metadata, error)
	GetTokenID() *common.Hash
	ListSerialNumbersHashH() []common.Hash
	ListSNDOutputsHashH() []common.Hash
	Hash() *common.Hash
}
