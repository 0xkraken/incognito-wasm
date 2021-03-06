package privacy_util

import "github.com/0xkraken/incognito-wasm/incognito/common"

type PrivacyUtilLogger struct {
	Log common.Logger
}

func (logger *PrivacyUtilLogger) Init(inst common.Logger) {
	logger.Log = inst
}

// Global instant to use
var Logger = PrivacyUtilLogger{}
