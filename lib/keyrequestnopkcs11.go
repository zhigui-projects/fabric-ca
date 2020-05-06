// +build !pkcs11

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/gm"
)

// GetKeyRequest constructs and returns api.BasicKeyRequest object based on the bccsp
// configuration options
func GetKeyRequest(cfg *CAConfig) *api.BasicKeyRequest {
	if cfg.CSP.SwOpts != nil {
		if gm.IsGM(){
			return &api.BasicKeyRequest{Algo: "gmsm2", Size: cfg.CSP.SwOpts.SecLevel}
		} else {
		    return &api.BasicKeyRequest{Algo: "ecdsa", Size: cfg.CSP.SwOpts.SecLevel}
		}
	}
	return api.NewBasicKeyRequest()
}
