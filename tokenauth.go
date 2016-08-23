// Copyright 2016 Jacques Supcik, BlueMasters
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This package provides a function to easily check for a valid authentication
// token in Google App Engine requests. The list of valid UUID must be stored
// in the Google Datastore under the kind "DatastoreKind". To improve the
// performances, this module uses memcache. The public key parameters for the
// validation are passed using environment variables.

package tokenauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"google.golang.org/appengine"
	"google.golang.org/appengine/datastore"
	"google.golang.org/appengine/memcache"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

type TokenAuth struct {
	PublicKeyXVar  string
	PublicKeyYVar  string
	DatastoreKind  string // e.g. "ValidTokens"
	MemcachePrefix string // e.g. "valid-token-"
}

const (
	headerKey          = "Authorization"
	headerValuePrefix  = "Bearer "
	uuidClaim          = "jti"
	memcacheExpiration = 1 * time.Hour
)

func (t TokenAuth) CheckAuth(r *http.Request) error {
	// retrieve authorization header
	auth := r.Header.Get(headerKey)
	if auth == "" {
		return errors.New("Missing Authorization header")
	}

	ctx := appengine.NewContext(r)
	// check if the token is in the memcache
	item, err := memcache.Get(ctx, t.MemcachePrefix+auth)
	if err == nil && item != nil {
		return nil
	}

	// check if the authorization header is valid
	if !strings.HasPrefix(auth, headerValuePrefix) {
		return errors.New("Bad Authorization header")
	}
	ss := strings.Trim(strings.TrimPrefix(auth, headerValuePrefix), " ")

	// retrieve the public key parameters from the environment
	x := os.Getenv(t.PublicKeyXVar)
	if x == "" {
		return errors.New("Public Key X undefined")
	}

	y := os.Getenv(t.PublicKeyYVar)
	if y == "" {
		return errors.New("Public Key Y undefined")
	}

	keyX := new(big.Int)
	keyY := new(big.Int)

	keyX.SetString(x, 16)
	keyY.SetString(y, 16)

	// make the ECDSA public key
	publicKey := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     keyX,
		Y:     keyY,
	}

	// check the signature
	token, err := jwt.Parse(ss, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return &publicKey, nil
	})

	if err != nil {
		return err
	}

	// extract the UUID from the claim (field jti)
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		uuid, ok := claims[uuidClaim]
		if !ok {
			return errors.New("Token does not contain a UUID")
		}
		// check if the UUID is in the datastore
		result := struct {
			Present bool
		}{}
		key := datastore.NewKey(ctx, t.DatastoreKind, uuid.(string), 0, nil)
		err := datastore.Get(ctx, key, &result)

		if err == nil { // add the Authorization header to the memcache
			memcache.Add(ctx, &memcache.Item{
				Key:        t.MemcachePrefix + auth,
				Value:      []byte{1},
				Expiration: memcacheExpiration,
			})
		}
		return err

	} else {
		return errors.New("Invalid token")
	}

}
