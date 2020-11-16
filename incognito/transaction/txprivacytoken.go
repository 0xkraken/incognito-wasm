package transaction

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/0xkraken/incognito-wasm/incognito/common"
	"github.com/0xkraken/incognito-wasm/incognito/metadata"
	"github.com/0xkraken/incognito-wasm/incognito/privacy"
	zkp "github.com/0xkraken/incognito-wasm/incognito/privacy/zeroknowledge"
	"strconv"
)

/*
TxPrivacyTokenData
 */
type TxPrivacyTokenData struct {
	TxNormal       Tx          // used for privacy functionality
	PropertyID     common.Hash // = hash of TxCustomTokenprivacy data
	PropertyName   string
	PropertySymbol string

	Type     int    // action type
	Mintable bool   // default false
	Amount   uint64 // init amount
}

func (txTokenPrivacyData TxPrivacyTokenData) String() string {
	record := txTokenPrivacyData.PropertyName
	record += txTokenPrivacyData.PropertySymbol
	record += fmt.Sprintf("%d", txTokenPrivacyData.Amount)
	if txTokenPrivacyData.TxNormal.Proof != nil {
		for _, out := range txTokenPrivacyData.TxNormal.Proof.GetOutputCoins() {
			record += string(out.CoinDetails.GetPublicKey().ToBytesS())
			record += strconv.FormatUint(out.CoinDetails.GetValue(), 10)
		}
		for _, in := range txTokenPrivacyData.TxNormal.Proof.GetInputCoins() {
			if in.CoinDetails.GetPublicKey() != nil {
				record += string(in.CoinDetails.GetPublicKey().ToBytesS())
			}
			if in.CoinDetails.GetValue() > 0 {
				record += strconv.FormatUint(in.CoinDetails.GetValue(), 10)
			}
		}
	}
	return record
}

func (txTokenPrivacyData TxPrivacyTokenData) JSONString() string {
	data, err := json.MarshalIndent(txTokenPrivacyData, "", "\t")
	if err != nil {
		return ""
	}
	return string(data)
}

// Hash - return hash of custom token data, be used as Token ID
func (txTokenPrivacyData TxPrivacyTokenData) Hash() (*common.Hash, error) {
	point := privacy.HashToPoint([]byte(txTokenPrivacyData.String()))
	hash := new(common.Hash)
	err := hash.SetBytes(point.ToBytesS())
	if err != nil {
		return nil, err
	}
	return hash, nil
}

// CustomTokenParamTx - use for rpc request json body
type CustomTokenPrivacyParamTx struct {
	PropertyID     string                 `json:"TokenID"`
	PropertyName   string                 `json:"TokenName"`
	PropertySymbol string                 `json:"TokenSymbol"`
	Amount         uint64                 `json:"TokenAmount"`
	TokenTxType    int                    `json:"TokenTxType"`
	Receiver       []*privacy.PaymentInfo `json:"TokenReceiver"`
	TokenInput     []*privacy.InputCoin   `json:"TokenInput"`
	Mintable       bool                   `json:"TokenMintable"`
	Fee            uint64                 `json:"TokenFee"`
}



/*
Privacy token transaction
 */


type TxPrivacyTokenInitParams struct {
	senderKey          *privacy.PrivateKey
	paymentInfo        []*privacy.PaymentInfo
	inputCoin          []*privacy.InputCoin
	feeNativeCoin      uint64
	tokenParams        *CustomTokenPrivacyParamTx
	metaData           metadata.Metadata
	hasPrivacyCoin     bool
	hasPrivacyToken    bool
	shardID            byte
	info               []byte
}

type TxPrivacyTokenInitParamsForASM struct {
	txParam                           TxPrivacyTokenInitParams
	commitmentIndicesForNativeToken   []uint64
	commitmentBytesForNativeToken     [][]byte
	myCommitmentIndicesForNativeToken []uint64
	sndOutputsForNativeToken          []*privacy.Scalar

	commitmentIndicesForPToken   []uint64
	commitmentBytesForPToken     [][]byte
	myCommitmentIndicesForPToken []uint64
	sndOutputsForPToken          []*privacy.Scalar
}

func (param *TxPrivacyTokenInitParamsForASM) SetMetaData(meta metadata.Metadata) {
	param.txParam.metaData = meta
}

func NewTxPrivacyTokenInitParams(senderKey *privacy.PrivateKey,
	paymentInfo []*privacy.PaymentInfo,
	inputCoin []*privacy.InputCoin,
	feeNativeCoin uint64,
	tokenParams *CustomTokenPrivacyParamTx,
	metaData metadata.Metadata,
	hasPrivacyCoin bool,
	hasPrivacyToken bool,
	shardID byte,
	info []byte) *TxPrivacyTokenInitParams {
	params := &TxPrivacyTokenInitParams{
		shardID:            shardID,
		paymentInfo:        paymentInfo,
		metaData:           metaData,
		feeNativeCoin:      feeNativeCoin,
		hasPrivacyCoin:     hasPrivacyCoin,
		hasPrivacyToken:    hasPrivacyToken,
		inputCoin:          inputCoin,
		senderKey:          senderKey,
		tokenParams:        tokenParams,
		info:               info,
	}
	return params
}

func NewTxPrivacyTokenInitParamsForASM(
	senderKey *privacy.PrivateKey,
	paymentInfo []*privacy.PaymentInfo,
	inputCoin []*privacy.InputCoin,
	feeNativeCoin uint64,
	tokenParams *CustomTokenPrivacyParamTx,
	metaData metadata.Metadata,
	hasPrivacyCoin bool,
	hasPrivacyToken bool,
	shardID byte,
	info []byte,
	commitmentIndicesForNativeToken []uint64,
	commitmentBytesForNativeToken [][]byte,
	myCommitmentIndicesForNativeToken []uint64,
	sndOutputsForNativeToken []*privacy.Scalar,

	commitmentIndicesForPToken []uint64,
	commitmentBytesForPToken [][]byte,
	myCommitmentIndicesForPToken []uint64,
	sndOutputsForPToken []*privacy.Scalar) *TxPrivacyTokenInitParamsForASM {

	txParam := NewTxPrivacyTokenInitParams(senderKey, paymentInfo, inputCoin, feeNativeCoin, tokenParams,  metaData, hasPrivacyCoin, hasPrivacyToken, shardID, info)
	params := &TxPrivacyTokenInitParamsForASM{
		txParam:                           *txParam,
		commitmentIndicesForNativeToken:   commitmentIndicesForNativeToken,
		commitmentBytesForNativeToken:     commitmentBytesForNativeToken,
		myCommitmentIndicesForNativeToken: myCommitmentIndicesForNativeToken,
		sndOutputsForNativeToken:          sndOutputsForNativeToken,

		commitmentIndicesForPToken:   commitmentIndicesForPToken,
		commitmentBytesForPToken:     commitmentBytesForPToken,
		myCommitmentIndicesForPToken: myCommitmentIndicesForPToken,
		sndOutputsForPToken:          sndOutputsForPToken,
	}
	return params
}

// TxCustomTokenPrivacy is class tx which is inherited from P tx(supporting privacy) for fee
// and contain data(with supporting privacy format) to support issuing and transfer a custom token(token from end-user, look like erc-20)
// Dev or end-user can use this class tx to create an token type which use personal purpose
// TxCustomTokenPrivacy is an advance format of TxNormalToken
// so that user need to spend a lot fee to create this class tx
type TxCustomTokenPrivacy struct {
	Tx                                    // inherit from normal tx of P(supporting privacy) with a high fee to ensure that tx could contain a big data of privacy for token
	TxPrivacyTokenData TxPrivacyTokenData `json:"TxTokenPrivacyData"` // supporting privacy format
	// private field, not use for json parser, only use as temp variable
	cachedHash *common.Hash // cached hash data of tx
}

func (txCustomTokenPrivacy *TxCustomTokenPrivacy) UnmarshalJSON(data []byte) error {
	tx := Tx{}
	err := json.Unmarshal(data, &tx)
	if err != nil {
		return err
	}
	temp := &struct {
		TxTokenPrivacyData TxPrivacyTokenData
	}{}
	err = json.Unmarshal(data, &temp)
	if err != nil {
		return err
	}
	TxTokenPrivacyDataJson, err := json.MarshalIndent(temp.TxTokenPrivacyData, "", "\t")
	if err != nil {
		return err
	}
	err = json.Unmarshal(TxTokenPrivacyDataJson, &txCustomTokenPrivacy.TxPrivacyTokenData)
	if err != nil {
		return err
	}
	txCustomTokenPrivacy.Tx = tx

	// TODO: hotfix, remove when fixed this issue
	if tx.Metadata != nil && tx.Metadata.GetType() == 81 {
		if txCustomTokenPrivacy.TxPrivacyTokenData.Amount == 37772966455153490 {
			txCustomTokenPrivacy.TxPrivacyTokenData.Amount = 37772966455153487
		}
	}

	return nil
}

func (txCustomTokenPrivacy TxCustomTokenPrivacy) String() string {
	// get hash of tx
	record := txCustomTokenPrivacy.Tx.Hash().String()
	// add more hash of tx custom token data privacy
	tokenPrivacyDataHash, _ := txCustomTokenPrivacy.TxPrivacyTokenData.Hash()
	record += tokenPrivacyDataHash.String()
	if txCustomTokenPrivacy.Metadata != nil {
		record += string(txCustomTokenPrivacy.Metadata.Hash()[:])
	}
	return record
}

func (txCustomTokenPrivacy TxCustomTokenPrivacy) JSONString() string {
	data, err := json.MarshalIndent(txCustomTokenPrivacy, "", "\t")
	if err != nil {
		return ""
	}
	return string(data)
}

// Hash returns the hash of all fields of the transaction
func (txCustomTokenPrivacy *TxCustomTokenPrivacy) Hash() *common.Hash {
	if txCustomTokenPrivacy.cachedHash != nil {
		return txCustomTokenPrivacy.cachedHash
	}
	// final hash
	hash := common.HashH([]byte(txCustomTokenPrivacy.String()))
	return &hash
}


// Init -  build normal tx component and privacy custom token data
func (txCustomTokenPrivacy *TxCustomTokenPrivacy) InitForASM(params *TxPrivacyTokenInitParamsForASM, serverTime int64) error {
	var err error
	// init data for tx PRV for fee
	normalTx := Tx{}
	err = normalTx.InitForASM(NewTxPrivacyInitParamsForASM(
		params.txParam.senderKey,
		params.txParam.paymentInfo,
		params.txParam.inputCoin,
		params.txParam.feeNativeCoin,
		params.txParam.hasPrivacyCoin,
		nil,
		params.txParam.metaData,
		params.txParam.info,
		params.commitmentIndicesForNativeToken,
		params.commitmentBytesForNativeToken,
		params.myCommitmentIndicesForNativeToken,
		params.sndOutputsForNativeToken,
	), serverTime)
	if err != nil {
		return err
	}

	// override TxCustomTokenPrivacyType type
	normalTx.Type = common.TxCustomTokenPrivacyType
	txCustomTokenPrivacy.Tx = normalTx

	// check action type and create privacy custom toke data
	var handled = false
	// Add token data component
	switch params.txParam.tokenParams.TokenTxType {
	case common.CustomTokenInit:
		// case init a new privacy custom token
		{
			handled = true
			txCustomTokenPrivacy.TxPrivacyTokenData = TxPrivacyTokenData{
				Type:           params.txParam.tokenParams.TokenTxType,
				PropertyName:   params.txParam.tokenParams.PropertyName,
				PropertySymbol: params.txParam.tokenParams.PropertySymbol,
				Amount:         params.txParam.tokenParams.Amount,
			}

			// issue token with data of privacy
			temp := Tx{}
			temp.Type = common.TxNormalType
			temp.Proof = new(zkp.PaymentProof)
			tempOutputCoin := make([]*privacy.OutputCoin, 1)
			tempOutputCoin[0] = new(privacy.OutputCoin)
			tempOutputCoin[0].CoinDetails = new(privacy.Coin)
			tempOutputCoin[0].CoinDetails.SetValue(params.txParam.tokenParams.Amount)
			PK, err := new(privacy.Point).FromBytesS(params.txParam.tokenParams.Receiver[0].PaymentAddress.Pk)
			if err != nil {
				return err
			}
			tempOutputCoin[0].CoinDetails.SetPublicKey(PK)
			tempOutputCoin[0].CoinDetails.SetRandomness(privacy.RandomScalar())

			// set info coin for output coin
			if len(params.txParam.tokenParams.Receiver[0].Message) > 0 {
				if len(params.txParam.tokenParams.Receiver[0].Message) > privacy.MaxSizeInfoCoin {
					return errors.New(fmt.Sprintf("Size of message %v should be less than %v",
						len(params.txParam.tokenParams.Receiver[0].Message), privacy.MaxSizeInfoCoin))
				}
				tempOutputCoin[0].CoinDetails.SetInfo(params.txParam.tokenParams.Receiver[0].Message)
			}

			sndOut := privacy.RandomScalar()
			tempOutputCoin[0].CoinDetails.SetSNDerivator(sndOut)
			temp.Proof.SetOutputCoins(tempOutputCoin)

			// create coin commitment
			err = temp.Proof.GetOutputCoins()[0].CoinDetails.CommitAll()
			if err != nil {
				return err
			}
			// get last byte
			lastByteSender := params.txParam.tokenParams.Receiver[0].PaymentAddress.Pk[len(params.txParam.tokenParams.Receiver[0].PaymentAddress.Pk)-1]
			temp.PubKeyLastByteSender = common.GetShardIDFromLastByte(lastByteSender)

			// sign Tx
			temp.SigPubKey = params.txParam.tokenParams.Receiver[0].PaymentAddress.Pk
			temp.sigPrivKey = *params.txParam.senderKey
			err = temp.signTx()
			if err != nil {
				return err
			}

			txCustomTokenPrivacy.TxPrivacyTokenData.TxNormal = temp
			hashInitToken, err := txCustomTokenPrivacy.TxPrivacyTokenData.Hash()
			if err != nil {
				return err
			}

			if params.txParam.tokenParams.Mintable {
				propertyID, err := common.Hash{}.NewHashFromStr(params.txParam.tokenParams.PropertyID)
				if err != nil {
					return err
				}
				txCustomTokenPrivacy.TxPrivacyTokenData.PropertyID = *propertyID
				txCustomTokenPrivacy.TxPrivacyTokenData.Mintable = true
			} else {
				//NOTICE: @merman update PropertyID calculated from hash of tokendata and shardID
				newHashInitToken := common.HashH(append(hashInitToken.GetBytes(), params.txParam.shardID))
				txCustomTokenPrivacy.TxPrivacyTokenData.PropertyID = newHashInitToken
			}
		}
	case common.CustomTokenTransfer:
		{
			handled = true
			// make a transfering for privacy custom token
			// fee always 0 and reuse function of normal tx for custom token ID
			temp := Tx{}
			propertyID, _ := common.Hash{}.NewHashFromStr(params.txParam.tokenParams.PropertyID)
			txCustomTokenPrivacy.TxPrivacyTokenData = TxPrivacyTokenData{
				Type:           params.txParam.tokenParams.TokenTxType,
				PropertyName:   params.txParam.tokenParams.PropertyName,
				PropertySymbol: params.txParam.tokenParams.PropertySymbol,
				PropertyID:     *propertyID,
				Mintable:       params.txParam.tokenParams.Mintable,
			}
			err := temp.InitForASM(NewTxPrivacyInitParamsForASM(
				params.txParam.senderKey,
				params.txParam.tokenParams.Receiver,
				params.txParam.tokenParams.TokenInput,
				params.txParam.tokenParams.Fee,
				params.txParam.hasPrivacyToken,
				propertyID,
				nil,
				params.txParam.info,
				params.commitmentIndicesForPToken,
				params.commitmentBytesForPToken,
				params.myCommitmentIndicesForPToken,
				params.sndOutputsForPToken,
			), serverTime)
			if err != nil {
				return err
			}
			txCustomTokenPrivacy.TxPrivacyTokenData.TxNormal = temp
		}
	}

	if !handled {
		return errors.New("can't handle this TokenTxType")
	}
	return nil
}

