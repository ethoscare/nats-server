// Copyright 2019-2022 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"crypto"
	"io"
)

type CertStoreType int

const _CERTMATCHBYEMPTY_ = 0
const _CERTSTOREEMPTY_ = 0

var _, _ = _CERTMATCHBYEMPTY_, _CERTSTOREEMPTY_

const (
	WindowsCurrentUser CertStoreType = iota + 1
	WindowsLocalMachine
)

var CertStoreMap = map[string]CertStoreType{
	"windowscurrentuser":  WindowsCurrentUser,
	"windowslocalmachine": WindowsLocalMachine,
}

var CertStoreOSMap = map[CertStoreType]string{
	WindowsCurrentUser:  "windows",
	WindowsLocalMachine: "windows",
}

type CertMatchByType int

const (
	MatchByIssuer CertMatchByType = iota + 1
	MatchBySubject
)

var CertMatchByMap = map[string]CertMatchByType{
	"issuer":  MatchByIssuer,
	"subject": MatchBySubject,
}

// CertStore is an abstract placeholder for an operating system cert repo or facade
type CertStore interface{}

// Credential provides access to a public key and is a crypto.Signer.
type Credential interface {
	// Public returns the public key corresponding to the leaf certificate.
	Public() crypto.PublicKey
	// Sign signs digest with the private key.
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)
}
