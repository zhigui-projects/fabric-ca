/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package sw

import (
	"crypto/rand"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/zhigui-projects/gmsm/sm2"
)

func signGMSM2(k *sm2.PrivateKey, msg []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	signature, err = k.Sign(rand.Reader, msg, opts)
	return
}

func verifyGMSM2(k *sm2.PublicKey, signature, msg []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	valid = k.Verify(msg, signature)
	return
}

type gmsm2Signer struct{}

func (s *gmsm2Signer) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	return signGMSM2(k.(*gmsm2PrivateKey).privKey, digest, opts)
}

type gmsm2PrivateKeySigner struct{}

func (s *gmsm2PrivateKeySigner) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	puk := k.(*gmsm2PrivateKey).privKey.PublicKey
	sm2pk := sm2.PublicKey{
		Curve: puk.Curve,
		X:     puk.X,
		Y:     puk.Y,
	}

	privKey := k.(*gmsm2PrivateKey).privKey
	sm2privKey := sm2.PrivateKey{
		D:         privKey.D,
		PublicKey: sm2pk,
	}

	return signGMSM2(&sm2privKey, digest, opts)
}

type gmsm2PrivateKeyVerifier struct{}

func (v *gmsm2PrivateKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	return verifyGMSM2(&(k.(*gmsm2PrivateKey).privKey.PublicKey), signature, digest, opts)
}

type gmsm2PublicKeyKeyVerifier struct{}

func (v *gmsm2PublicKeyKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	return verifyGMSM2(k.(*gmsm2PublicKey).pubKey, signature, digest, opts)
}
