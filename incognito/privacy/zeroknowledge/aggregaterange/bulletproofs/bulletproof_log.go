package bulletproofs

import "github.com/0xkraken/incognito-wasm/incognito/common"

type BulletproofsLogger struct {
	Log common.Logger
}

func (logger *BulletproofsLogger) Init(inst common.Logger) {
	logger.Log = inst
}

// Global instant to use
var Logger = BulletproofsLogger{}
