/*
Copyright IBM Corp. 2016 All Rights Reserved.

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

package utils

import (
	"crypto/x509"

	"github.com/pkg/errors"
	x "github.com/zhigui-projects/x509"
)

// DERToX509Certificate converts der to x509
func DERToX509Certificate(asn1Data []byte) (*x509.Certificate, error) {
	var cert *x509.Certificate
	var err1, err2 error
	if cert, err1 = x509.ParseCertificate(asn1Data); err1 == nil {
		return cert, nil
	}
	if cert, err2 = x.X509(x.SM2).ParseCertificate(asn1Data); err2 == nil {
		return cert, nil
	}
	return nil, errors.Errorf("DERToX509Certificate failed, err1: %v, err2: %v", err1, err2)
}
