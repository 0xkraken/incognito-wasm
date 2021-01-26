package common

const (
	MaxShardNumber = 8

	TxVersion                        = 1
	MaxTxSize    = uint64(100)  // unit KB = 100KB
)

const (
	CustomTokenInit = iota
	CustomTokenTransfer
	CustomTokenCrossShard
)

// For all Transaction information
const (
	TxNormalType        = "n"  // normal tx(send and receive coin)
	TxRewardType        = "s"  // reward tx
	TxReturnStakingType = "rs" //
	//TxCustomTokenType        = "t"  // token  tx with no supporting privacy
	TxCustomTokenPrivacyType = "tp" // token  tx with supporting privacy
)

// for common
const (
	EmptyString       = ""
	ZeroByte          = byte(0x00)
	DateOutputFormat  = "2006-01-02T15:04:05.999999"
	BigIntSize        = 32 // bytes
	CheckSumLen       = 4  // bytes
	AESKeySize        = 32 // bytes
	Int32Size         = 4  // bytes
	Uint32Size        = 4  // bytes
	Uint64Size        = 8  // bytes
	HashSize          = 32 // bytes
	MaxHashStringSize = HashSize * 2
	Base58Version     = 0
)

// special token ids (aka. PropertyID in custom token)
var (
	PRVCoinID   = Hash{4} // To send PRV in custom token
	PRVCoinName = "PRV"   // To send PRV in custom token
)

// size data for incognito key and signature
const (
	// for key size
	PrivateKeySize      = 32  // bytes
	PublicKeySize       = 32  // bytes
	BLSPublicKeySize    = 128 // bytes
	BriPublicKeySize    = 33  // bytes
	TransmissionKeySize = 32  //bytes
	ReceivingKeySize    = 32  // bytes
	PaymentAddressSize  = 64  // bytes
	// for signature size
	// it is used for both privacy and no privacy
	SigPubKeySize    = 32
	SigNoPrivacySize = 64
	SigPrivacySize   = 96
	IncPubKeyB58Size = 51

	MaxPSMsgSize = 1 << 22 //4Mb
)

//statking
const (
	ShardStakingMeta    = 63
	StopAutoStakingMeta = 127
	BeaconStakingMeta   = 64
)

const (
	BlsConsensus    = "bls"
	BridgeConsensus = "dsa"
	IncKeyType      = "inc"
)

