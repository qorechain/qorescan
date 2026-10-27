// SPDX-License-Identifier: Apache-2.0

package nodehome

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// maxKeyFileSize bounds the key files QoreScan opens. Real key files are a
// few hundred bytes.
const maxKeyFileSize = 64 * 1024

// ValidatorKeyFile is everything QoreScan decodes from priv_validator_key.json.
//
// The struct deliberately has no field for the private key value: the JSON
// decoder skips members that have no matching field, so the private key
// bytes are never decoded into a Go value, stored, logged or written out.
// Only the private key's type name is kept. TestKeyStructsHaveNoPrivateValue
// enforces this shape.
type ValidatorKeyFile struct {
	Address string        `json:"address"`
	PubKey  PublicKeyJSON `json:"pub_key"`
	PrivKey KeyTypeOnly   `json:"priv_key"`
}

// NodeKeyFile is everything QoreScan decodes from node_key.json. The file
// holds only a private key, so only its type name is read; the node ID, which
// would require the key bytes, is not derived.
type NodeKeyFile struct {
	PrivKey KeyTypeOnly `json:"priv_key"`
}

// PublicKeyJSON is a typed public key as the consensus engine writes it.
type PublicKeyJSON struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// KeyTypeOnly holds the type name of a key and nothing else.
type KeyTypeOnly struct {
	Type string `json:"type"`
}

// readKeyFile reads a key file into v and then overwrites the raw buffer, so
// the file content (which includes the private key) does not outlive the
// call. v must be one of the key-file structs above.
func readKeyFile(path string, v any) error {
	switch v.(type) {
	case *ValidatorKeyFile, *NodeKeyFile:
	default:
		return fmt.Errorf("nodehome: refusing to decode a key file into %T", v)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	if st.Size() > maxKeyFileSize {
		return fmt.Errorf("larger than %d bytes, not a key file", maxKeyFileSize)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxKeyFileSize))
	if err != nil {
		return err
	}
	defer clear(raw)
	if err := json.Unmarshal(raw, v); err != nil {
		// The decoder's error can quote input; never return it.
		return errors.New("not valid JSON")
	}
	return nil
}

// publicKeyBytes decodes a base64 public key value. It returns nil for a
// value that does not decode.
func publicKeyBytes(v string) []byte {
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil
	}
	return b
}
