package transaction

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/0xkraken/incognito-wasm/incognito/incognitokey"
	"github.com/0xkraken/incognito-wasm/incognito/privacy"
	zkp "github.com/0xkraken/incognito-wasm/incognito/privacy/zeroknowledge"
	"github.com/0xkraken/incognito-wasm/incognito/privacy/zeroknowledge/utils"
	"github.com/0xkraken/incognito-wasm/incognito/common"
	"github.com/0xkraken/incognito-wasm/incognito/metadata"
	"math"
	"math/big"
	"strconv"
)

type Tx struct {
	// Basic data, required
	Version  int8   `json:"Version"`
	Type     string `json:"Type"` // Transaction type
	LockTime int64  `json:"LockTime"`
	Fee      uint64 `json:"Fee"` // Fee applies: always consant
	Info     []byte // 512 bytes
	// Sign and Privacy proof, required
	SigPubKey            []byte `json:"SigPubKey, omitempty"` // 33 bytes
	Sig                  []byte `json:"Sig, omitempty"`       //
	Proof                *zkp.PaymentProof
	PubKeyLastByteSender byte
	// Metadata, optional
	Metadata metadata.Metadata
	// private field, not use for json parser, only use as temp variable
	sigPrivKey       []byte       // is ALWAYS private property of struct, if privacy: 64 bytes, and otherwise, 32 bytes
	cachedHash       *common.Hash // cached hash data of tx
	cachedActualSize *uint64      // cached actualsize data for tx
}

func (tx *Tx) UnmarshalJSON(data []byte) error {
	type Alias Tx
	temp := &struct {
		Metadata *json.RawMessage
		*Alias
	}{
		Alias: (*Alias)(tx),
	}
	err := json.Unmarshal(data, &temp)
	if err != nil {
		println("UnmarshalJSON tx error: ", err)
		return fmt.Errorf("UnmarshalJSON tx error: ", err)
	}

	if temp.Metadata == nil {
		tx.Metadata = nil

	} else {
		meta, parseErr := metadata.ParseMetadata(temp.Metadata)
		if parseErr != nil {
			return parseErr
		}
		tx.Metadata = meta
	}
	return nil
}

type TxPrivacyInitParams struct {
	senderSK    *privacy.PrivateKey
	paymentInfo []*privacy.PaymentInfo
	inputCoins  []*privacy.InputCoin
	fee         uint64
	hasPrivacy  bool
	tokenID     *common.Hash // default is nil -> use for prv coin
	metaData    metadata.Metadata
	info        []byte // 512 bytes
}

type TxPrivacyInitParamsForASM struct {
	txParam             TxPrivacyInitParams
	commitmentIndices   []uint64
	commitmentBytes     [][]byte
	myCommitmentIndices []uint64
	sndOutputs          []*privacy.Scalar
}

func NewTxPrivacyInitParamsForASM(
	senderSK *privacy.PrivateKey,
	paymentInfo []*privacy.PaymentInfo,
	inputCoins []*privacy.InputCoin,
	fee uint64,
	hasPrivacy bool,
	tokenID *common.Hash, // default is nil -> use for prv coin
	metaData metadata.Metadata,
	info []byte,
	commitmentIndices []uint64,
	commitmentBytes [][]byte,
	myCommitmentIndices []uint64,
	sndOutputs []*privacy.Scalar) *TxPrivacyInitParamsForASM {

	txParam := TxPrivacyInitParams{
		senderSK:    senderSK,
		paymentInfo: paymentInfo,
		inputCoins:  inputCoins,
		fee:         fee,
		hasPrivacy:  hasPrivacy,
		tokenID:     tokenID,
		metaData:    metaData,
		info:        info,
	}
	params := &TxPrivacyInitParamsForASM{
		txParam:             txParam,
		commitmentIndices:   commitmentIndices,
		commitmentBytes:     commitmentBytes,
		myCommitmentIndices: myCommitmentIndices,
		sndOutputs:          sndOutputs,
	}
	return params
}

func (param *TxPrivacyInitParamsForASM) SetMetaData(meta metadata.Metadata) {
	param.txParam.metaData = meta
}

func (tx *Tx) InitForASM(params *TxPrivacyInitParamsForASM, serverTime int64) error {
	//Logger.log.Debugf("CREATING TX........\n")
	tx.Version = common.TxVersion
	var err error

	if len(params.txParam.inputCoins) > 255 {
		return fmt.Errorf("Number of input coins %v should be less than 255", strconv.Itoa(len(params.txParam.inputCoins)))
	}

	if len(params.txParam.paymentInfo) > 254 {
		return fmt.Errorf("Number of payment infos %v should be less than 254", strconv.Itoa(len(params.txParam.paymentInfo)))
	}

	limitFee := uint64(0)
	estimateTxSizeParam := NewEstimateTxSizeParam(len(params.txParam.inputCoins), len(params.txParam.paymentInfo),
		params.txParam.hasPrivacy, nil, nil, limitFee)
	if txSize := EstimateTxSize(estimateTxSizeParam); txSize > common.MaxTxSize {
		return fmt.Errorf("Tx's size %v should be less than %v", strconv.Itoa(int(txSize)), strconv.Itoa(int(common.MaxTxSize)))
	}

	if params.txParam.tokenID == nil {
		// using default PRV
		params.txParam.tokenID = &common.Hash{}
		err := params.txParam.tokenID.SetBytes(common.PRVCoinID[:])
		if err != nil {
			return fmt.Errorf("TokenID is invalid %v", params.txParam.tokenID.String())
		}
	}

	// Calculate execution time
	//start := time.Now()

	if tx.LockTime == 0 {
		tx.LockTime = serverTime
	}

	// create sender's key set from sender's spending key
	senderFullKey := incognitokey.KeySet{}
	err = senderFullKey.InitFromPrivateKey(params.txParam.senderSK)
	if err != nil {
		return errors.New(fmt.Sprintf("Can not import Private key for sender keyset from %+v", params.txParam.senderSK))
	}
	// get public key last byte of sender
	pkLastByteSender := senderFullKey.PaymentAddress.Pk[len(senderFullKey.PaymentAddress.Pk)-1]

	// init info of tx
	tx.Info = []byte{}
	if len(params.txParam.info) > 0 {
		tx.Info = params.txParam.info
	}

	// set metadata
	tx.Metadata = params.txParam.metaData

	// set tx type
	tx.Type = common.TxNormalType
	//Logger.log.Debugf("len(inputCoins), fee, hasPrivacy: %d, %d, %v\n", len(params.inputCoins), params.fee, params.hasPrivacy)

	if len(params.txParam.inputCoins) == 0 && params.txParam.fee == 0 && !params.txParam.hasPrivacy {
		//Logger.log.Debugf("len(inputCoins) == 0 && fee == 0 && !hasPrivacy\n")
		tx.Fee = params.txParam.fee
		tx.sigPrivKey = *params.txParam.senderSK
		tx.PubKeyLastByteSender = common.GetShardIDFromLastByte(pkLastByteSender)
		err := tx.signTx()
		if err != nil {
			return errors.New(fmt.Sprintf("Cannot sign tx %v\n", err))
		}
		return nil
	}

	shardID := common.GetShardIDFromLastByte(pkLastByteSender)

	if params.txParam.hasPrivacy {
		// Check number of list of random commitments, list of random commitment indices
		if len(params.commitmentIndices) != len(params.txParam.inputCoins)*privacy.CommitmentRingSize {
			return errors.New(fmt.Sprintf("Invalid len commitmentIndices, expect %v, got %v",
				len(params.txParam.inputCoins)*privacy.CommitmentRingSize, len(params.commitmentIndices)))
		}

		if len(params.myCommitmentIndices) != len(params.txParam.inputCoins) {
			return errors.New(fmt.Sprintf("Invalid len myCommitmentIndices, expect %v, got %v",
				len(params.txParam.inputCoins), len(params.myCommitmentIndices)))
		}
	}

	// Calculate execution time for creating payment proof
	//startPrivacy := time.Now()

	// Calculate sum of all output coins' value
	sumOutputValue := uint64(0)
	for _, p := range params.txParam.paymentInfo {
		sumOutputValue += p.Amount
	}

	// Calculate sum of all input coins' value
	sumInputValue := uint64(0)
	for _, coin := range params.txParam.inputCoins {
		sumInputValue += coin.CoinDetails.GetValue()
	}
	//Logger.log.Debugf("sumInputValue: %d\n", sumInputValue)

	// Calculate over balance, it will be returned to sender
	overBalance := int64(sumInputValue - sumOutputValue - params.txParam.fee)

	// Check if sum of input coins' value is at least sum of output coins' value and tx fee
	if overBalance < 0 {
		return errors.New(fmt.Sprintf("input value less than output value. sumInputValue=%d sumOutputValue=%d fee=%d",
			sumInputValue, sumOutputValue, params.txParam.fee))
	}

	// if overBalance > 0, create a new payment info with pk is sender's pk and amount is overBalance
	if overBalance > 0 {
		changePaymentInfo := new(privacy.PaymentInfo)
		changePaymentInfo.Amount = uint64(overBalance)
		changePaymentInfo.PaymentAddress = senderFullKey.PaymentAddress
		params.txParam.paymentInfo = append(params.txParam.paymentInfo, changePaymentInfo)
	}

	// create new output coins
	outputCoins := make([]*privacy.OutputCoin, len(params.txParam.paymentInfo))

	// create SNDs for output coins
	sndOuts := params.sndOutputs

	// create new output coins with info: Pk, value, last byte of pk, snd
	for i, pInfo := range params.txParam.paymentInfo {
		outputCoins[i] = new(privacy.OutputCoin)
		outputCoins[i].CoinDetails = new(privacy.Coin)
		outputCoins[i].CoinDetails.SetValue(pInfo.Amount)
		if len(pInfo.Message) > 0 {
			if len(pInfo.Message) > privacy.MaxSizeInfoCoin {
				return errors.New(fmt.Sprintf("Size of message %v should be less than %+v", len(pInfo.Message), privacy.MaxSizeInfoCoin))
			}
			outputCoins[i].CoinDetails.SetInfo(pInfo.Message)
		}

		PK, err := new(privacy.Point).FromBytesS(pInfo.PaymentAddress.Pk)
		if err != nil {
			return errors.New(fmt.Sprintf("can not decompress public key from %+v", pInfo.PaymentAddress))
		}
		outputCoins[i].CoinDetails.SetPublicKey(PK)
		outputCoins[i].CoinDetails.SetSNDerivator(sndOuts[i])
	}

	// assign fee tx
	tx.Fee = params.txParam.fee

	// create zero knowledge proof of payment
	tx.Proof = &zkp.PaymentProof{}

	// get list of commitments for proving one-out-of-many from commitmentIndexs
	commitmentProving := make([]*privacy.Point, len(params.commitmentBytes))
	for i, cmBytes := range params.commitmentBytes {
		commitmentProving[i] = new(privacy.Point)
		commitmentProving[i], err = commitmentProving[i].FromBytesS(cmBytes)
		if err != nil {
			return errors.New(fmt.Sprintf("Decode commitment error %v with index: %v - shardID %v - commitment bytes",
				err, params.commitmentIndices[i], shardID, cmBytes))
		}
	}

	// prepare witness for proving
	witness := new(zkp.PaymentWitness)
	paymentWitnessParam := zkp.PaymentWitnessParam{
		HasPrivacy:              params.txParam.hasPrivacy,
		PrivateKey:              new(privacy.Scalar).FromBytesS(*params.txParam.senderSK),
		InputCoins:              params.txParam.inputCoins,
		OutputCoins:             outputCoins,
		PublicKeyLastByteSender: pkLastByteSender,
		Commitments:             commitmentProving,
		CommitmentIndices:       params.commitmentIndices,
		MyCommitmentIndices:     params.myCommitmentIndices,
		Fee:                     params.txParam.fee,
	}
	err = witness.Init(paymentWitnessParam)
	if err.(*privacy.PrivacyError) != nil {
		jsonParam, _ := json.MarshalIndent(paymentWitnessParam, common.EmptyString, "  ")
		return errors.New(fmt.Sprintf("Can not init payment witness with err: %v - param %v", err, string(jsonParam)))
	}

	tx.Proof, err = witness.Prove(params.txParam.hasPrivacy)
	if err.(*privacy.PrivacyError) != nil {
		jsonParam, _ := json.MarshalIndent(paymentWitnessParam, common.EmptyString, "  ")
		return errors.New(fmt.Sprintf("Can not create zkp with err: %v - param %v", err, string(jsonParam)))
	}

	//Logger.log.Debugf("DONE PROVING........\n")

	// set private key for signing tx
	if params.txParam.hasPrivacy {
		randSK := witness.GetRandSecretKey()
		tx.sigPrivKey = append(*params.txParam.senderSK, randSK.ToBytesS()...)

		// encrypt coin details (Randomness)
		// hide information of output coins except coin commitments, public key, snDerivators
		for i := 0; i < len(tx.Proof.GetOutputCoins()); i++ {
			err = tx.Proof.GetOutputCoins()[i].Encrypt(params.txParam.paymentInfo[i].PaymentAddress.Tk)
			if err.(*privacy.PrivacyError) != nil {
				return err
			}
			tx.Proof.GetOutputCoins()[i].CoinDetails.SetSerialNumber(nil)
			tx.Proof.GetOutputCoins()[i].CoinDetails.SetValue(0)
			tx.Proof.GetOutputCoins()[i].CoinDetails.SetRandomness(nil)
		}

		// hide information of input coins except serial number of input coins
		for i := 0; i < len(tx.Proof.GetInputCoins()); i++ {
			tx.Proof.GetInputCoins()[i].CoinDetails.SetCoinCommitment(nil)
			tx.Proof.GetInputCoins()[i].CoinDetails.SetValue(0)
			tx.Proof.GetInputCoins()[i].CoinDetails.SetSNDerivator(nil)
			tx.Proof.GetInputCoins()[i].CoinDetails.SetPublicKey(nil)
			tx.Proof.GetInputCoins()[i].CoinDetails.SetRandomness(nil)
		}

	} else {
		tx.sigPrivKey = []byte{}
		randSK := big.NewInt(0)
		tx.sigPrivKey = append(*params.txParam.senderSK, randSK.Bytes()...)
	}

	// sign tx
	tx.PubKeyLastByteSender = common.GetShardIDFromLastByte(pkLastByteSender)
	err = tx.signTx()
	if err != nil {
		return err
	}

	snProof := tx.Proof.GetSerialNumberProof()
	for i := 0; i < len(snProof); i++ {
		res, _ := snProof[i].Verify(nil)
		println("Verify serial number proof: ", i, ": ", res)
	}

	//elapsedPrivacy := time.Since(startPrivacy)
	//elapsed := time.Since(start)
	//Logger.log.Debugf("Creating payment proof time %s", elapsedPrivacy)
	//Logger.log.Debugf("Successfully Creating normal tx %+v in %s time", *tx.Hash(), elapsed)
	return nil
}

func (tx Tx) String() string {
	record := strconv.Itoa(int(tx.Version))

	record += strconv.FormatInt(tx.LockTime, 10)
	record += strconv.FormatUint(tx.Fee, 10)
	if tx.Proof != nil {
		tmp := base64.StdEncoding.EncodeToString(tx.Proof.Bytes())
		//tmp := base58.Base58Check{}.Encode(tx.Proof.Bytes(), 0x00)
		record += tmp
		// fmt.Printf("Proof check base 58: %v\n",tmp)
	}
	if tx.Metadata != nil {
		metadataHash := tx.Metadata.Hash()
		//Logger.log.Debugf("\n\n\n\n test metadata after hashing: %v\n", metadataHash.GetBytes())
		metadataStr := metadataHash.String()
		record += metadataStr
	}

	//TODO: To be uncomment
	// record += string(tx.Info)
	return record
}

func (tx *Tx) Hash() *common.Hash {
	if tx.cachedHash != nil {
		return tx.cachedHash
	}
	inBytes := []byte(tx.String())
	hash := common.HashH(inBytes)
	tx.cachedHash = &hash
	return &hash
}

// signTx - signs tx
func (tx *Tx) signTx() error {
	//Check input transaction
	if tx.Sig != nil {
		return errors.New("input transaction must be an unsigned one")
	}

	/****** using Schnorr signature *******/
	// sign with sigPrivKey
	// prepare private key for Schnorr
	sk := new(privacy.Scalar).FromBytesS(tx.sigPrivKey[:common.BigIntSize])
	r := new(privacy.Scalar).FromBytesS(tx.sigPrivKey[common.BigIntSize:])
	sigKey := new(privacy.SchnorrPrivateKey)
	sigKey.Set(sk, r)

	// save public key for verification signature tx
	tx.SigPubKey = sigKey.GetPublicKey().GetPublicKey().ToBytesS()

	// signing
	signature, err := sigKey.Sign(tx.Hash()[:])
	if err != nil {
		return err
	}

	// convert signature to byte array
	tx.Sig = signature.Bytes()

	return nil
}

/*
Estimate tx's size
*/
type EstimateTxSizeParam struct {
	numInputCoins            int
	numPayments              int
	hasPrivacy               bool
	metadata                 metadata.Metadata
	privacyCustomTokenParams *CustomTokenPrivacyParamTx
	limitFee                 uint64
}

func NewEstimateTxSizeParam(numInputCoins, numPayments int,
	hasPrivacy bool, metadata metadata.Metadata,
	privacyCustomTokenParams *CustomTokenPrivacyParamTx,
	limitFee uint64) *EstimateTxSizeParam {
	estimateTxSizeParam := &EstimateTxSizeParam{
		numInputCoins:            numInputCoins,
		numPayments:              numPayments,
		hasPrivacy:               hasPrivacy,
		limitFee:                 limitFee,
		metadata:                 metadata,
		privacyCustomTokenParams: privacyCustomTokenParams,
	}
	return estimateTxSizeParam
}

// EstimateTxSize returns the estimated size of the tx in kilobyte
func EstimateTxSize(estimateTxSizeParam *EstimateTxSizeParam) uint64 {

	sizeVersion := uint64(1)  // int8
	sizeType := uint64(5)     // string, max : 5
	sizeLockTime := uint64(8) // int64
	sizeFee := uint64(8)      // uint64

	sizeInfo := uint64(512)

	sizeSigPubKey := uint64(common.SigPubKeySize)
	sizeSig := uint64(common.SigNoPrivacySize)
	if estimateTxSizeParam.hasPrivacy {
		sizeSig = uint64(common.SigPrivacySize)
	}

	sizeProof := uint64(0)
	if estimateTxSizeParam.numInputCoins != 0 || estimateTxSizeParam.numPayments != 0 {
		sizeProof = utils.EstimateProofSize(estimateTxSizeParam.numInputCoins, estimateTxSizeParam.numPayments, estimateTxSizeParam.hasPrivacy)
	} else {
		if estimateTxSizeParam.limitFee > 0 {
			sizeProof = utils.EstimateProofSize(1, 1, estimateTxSizeParam.hasPrivacy)
		}
	}

	sizePubKeyLastByte := uint64(1)

	sizeMetadata := uint64(0)
	if estimateTxSizeParam.metadata != nil {
		sizeMetadata += estimateTxSizeParam.metadata.CalculateSize()
	}

	sizeTx := sizeVersion + sizeType + sizeLockTime + sizeFee + sizeInfo + sizeSigPubKey + sizeSig + sizeProof + sizePubKeyLastByte + sizeMetadata

	// size of privacy custom token  data
	if estimateTxSizeParam.privacyCustomTokenParams != nil {
		customTokenDataSize := uint64(0)

		customTokenDataSize += uint64(len(estimateTxSizeParam.privacyCustomTokenParams.PropertyID))
		customTokenDataSize += uint64(len(estimateTxSizeParam.privacyCustomTokenParams.PropertySymbol))
		customTokenDataSize += uint64(len(estimateTxSizeParam.privacyCustomTokenParams.PropertyName))

		customTokenDataSize += 8 // for amount
		customTokenDataSize += 4 // for TokenTxType

		customTokenDataSize += uint64(1) // int8 version
		customTokenDataSize += uint64(5) // string, max : 5 type
		customTokenDataSize += uint64(8) // int64 locktime
		customTokenDataSize += uint64(8) // uint64 fee

		customTokenDataSize += uint64(64) // info

		customTokenDataSize += uint64(common.SigPubKeySize)  // sig pubkey
		customTokenDataSize += uint64(common.SigPrivacySize) // sig

		// Proof
		customTokenDataSize += utils.EstimateProofSize(len(estimateTxSizeParam.privacyCustomTokenParams.TokenInput), len(estimateTxSizeParam.privacyCustomTokenParams.Receiver), true)

		customTokenDataSize += uint64(1) //PubKeyLastByte

		sizeTx += customTokenDataSize
	}

	return uint64(math.Ceil(float64(sizeTx) / 1024))
}
