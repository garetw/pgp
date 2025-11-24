package pgp

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	pmopenpgp "github.com/ProtonMail/go-crypto/openpgp"
	pmarmor "github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/gopenpgp/v3/constants"
	gopgp "github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
)

type UserID string
type Domain string
type Suffix string

// Email is user@domain.suffix.
type Email struct {
	UserID UserID
	Domain Domain
	Suffix Suffix
}

type KeyType string

const (
	RSA    KeyType = "rsa"
	X25519 KeyType = "x25519"
)

// KeyProps describes how to generate a key.
type KeyProps struct {
	Name       string
	Email      string
	Passphrase string
	KeyType    KeyType
	// KeyBits specifies the length for RSA keys (e.g., 4096).
	// This field is ignored for X25519 keys, which have a fixed security strength.
	KeyBits int
}

// Keys holds the public and private keys in armored form.
type Keys struct {
	PublicKey  string
	PrivateKey string
}

// GenerateKey creates a new key pair using the v3 KeyGeneration API.
// For RSA it uses the RFC4880 profile; for X25519 it uses the default profile.
// The kp.KeyBits parameter is only used for RSA key generation.
func GenerateKey(kp KeyProps) (*Keys, error) {
	if kp.Name == "" {
		return nil, errors.New("name must not be empty")
	}
	if kp.Email == "" {
		return nil, errors.New("email must not be empty")
	}

	var pgpHandle *gopgp.PGPHandle

	switch kp.KeyType {
	case RSA:
		// RFC4880 profile → RSA (3072 by default, 4096 with HighSecurity).
		pgpHandle = gopgp.PGPWithProfile(profile.RFC4880())
	case X25519:
		// Default profile → Curve25519 EC key.
		pgpHandle = gopgp.PGPWithProfile(profile.Default())
	default:
		// Default to modern EC keys.
		pgpHandle = gopgp.PGPWithProfile(profile.Default())
	}

	keyGenHandle := pgpHandle.
		KeyGeneration().
		AddUserId(kp.Name, kp.Email).
		New()

	var (
		privateKey *gopgp.Key
		err        error
	)

	// For RSA we can honour “stronger” requests by using HighSecurity.
	if kp.KeyType == RSA && kp.KeyBits >= 4096 {
		privateKey, err = keyGenHandle.GenerateKeyWithSecurity(constants.HighSecurity)
	} else {
		privateKey, err = keyGenHandle.GenerateKey()
	}
	if err != nil {
		return nil, err
	}

	// Derive public key from the freshly generated private key.
	publicKey, err := privateKey.ToPublic()
	if err != nil {
		return nil, err
	}

	// Lock the private key if a passphrase was provided.
	if kp.Passphrase != "" {
		privateKey, err = pgpHandle.LockKey(privateKey, []byte(kp.Passphrase))
		if err != nil {
			return nil, err
		}
	}

	armoredPriv, err := privateKey.Armor()
	if err != nil {
		return nil, err
	}

	armoredPub, err := publicKey.Armor()
	if err != nil {
		return nil, err
	}

	return &Keys{
		PublicKey:  armoredPub,
		PrivateKey: armoredPriv,
	}, nil
}

// ReadKey parses an armored key into a gopenpgp Key.
func ReadKey(armoredKey string) (*gopgp.Key, error) {
	key, err := gopgp.NewKeyFromArmored(armoredKey)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// ReadKeyRing parses an armored key into a gopenpgp KeyRing.
func ReadKeyRing(armoredKey string) (*gopgp.KeyRing, error) {
	key, err := gopgp.NewKeyFromArmored(armoredKey)
	if err != nil {
		return nil, err
	}
	keyRing, err := gopgp.NewKeyRing(key)
	if err != nil {
		return nil, err
	}
	return keyRing, nil
}

// DecryptKey unlocks a password-protected private key using Key.Unlock.
func DecryptKey(key *gopgp.Key, passphrase string) (*gopgp.Key, error) {
	if passphrase == "" {
		return nil, errors.New("passphrase must not be empty")
	}

	unlocked, err := key.IsUnlocked()
	if err != nil {
		return nil, err
	}
	if unlocked {
		return key, nil
	}

	unlockedKey, err := key.Unlock([]byte(passphrase))
	if err != nil {
		return nil, err
	}
	return unlockedKey, nil
}

// EncryptKey (re)locks an unlocked private key using PGP().LockKey.
func EncryptKey(key *gopgp.Key, passphrase string) (*gopgp.Key, error) {
	if passphrase == "" {
		return nil, errors.New("passphrase must not be empty")
	}

	locked, err := key.IsLocked()
	if err != nil {
		return nil, err
	}
	if locked {
		return key, nil
	}

	pgpHandle := gopgp.PGP()
	lockedKey, err := pgpHandle.LockKey(key, []byte(passphrase))
	if err != nil {
		return nil, err
	}
	return lockedKey, nil
}

// signDetached is an internal helper that creates a detached armored
// signature over arbitrary data using the v3 Sign() API.
func signDetached(privateKey *gopgp.Key, data []byte) (string, error) {
	if privateKey == nil {
		return "", errors.New("private key is nil")
	}

	pgpHandle := gopgp.PGP()
	signer, err := pgpHandle.
		Sign().
		SigningKey(privateKey).
		Detached().
		New()
	if err != nil {
		return "", err
	}
	defer signer.ClearPrivateParams()

	sigBytes, err := signer.Sign(data, gopgp.Armor)
	if err != nil {
		return "", err
	}

	return string(sigBytes), nil
}

// verifyDetached is an internal helper that verifies a detached armored
// signature with the v3 Verify() API.
func verifyDetached(publicKey *gopgp.Key, data []byte, signature string) (bool, error) {
	if publicKey == nil {
		return false, errors.New("public key is nil")
	}
	if signature == "" {
		return false, errors.New("signature must not be empty")
	}

	pgpHandle := gopgp.PGP()
	verifier, err := pgpHandle.
		Verify().
		VerificationKey(publicKey).
		New()
	if err != nil {
		return false, err
	}

	verifyResult, err := verifier.VerifyDetached(
		data,
		[]byte(signature),
		gopgp.Armor,
	)
	if err != nil {
		// Non-signature error (parsing, etc.).
		return false, err
	}
	if sigErr := verifyResult.SignatureError(); sigErr != nil {
		return false, sigErr
	}

	return true, nil
}

// SignMessage creates a detached armored signature for the given message
// using the v3 Sign() API.
func SignMessage(privateKey *gopgp.Key, message string) (string, error) {
	return signDetached(privateKey, []byte(message))
}

// VerifyMessage verifies a detached armored signature over a message
// using the v3 Verify() API.
func VerifyMessage(publicKey *gopgp.Key, message string, signature string) (bool, error) {
	return verifyDetached(publicKey, []byte(message), signature)
}

// SignArmoredKeyDetached creates a detached armored signature over an
// arbitrary armored key string using the v3 Sign() API. This is the
// generic "sign keys and other things" entry point.
func SignArmoredKeyDetached(privateKey *gopgp.Key, armoredKey string) (string, error) {
	if armoredKey == "" {
		return "", errors.New("armored key must not be empty")
	}
	return signDetached(privateKey, []byte(armoredKey))
}

// VerifyArmoredKeyDetached verifies a detached armored signature over an
// armored key string using the v3 Verify() API.
func VerifyArmoredKeyDetached(publicKey *gopgp.Key, armoredKey string, signature string) (bool, error) {
	if armoredKey == "" {
		return false, errors.New("armored key must not be empty")
	}
	return verifyDetached(publicKey, []byte(armoredKey), signature)
}

// SignOnlineArmoredKeyDetached is a convenience wrapper for the
// offline-key-signs-online-key use-case. offlinePriv is the offline
// private key (unlocked), onlinePublicArmored is the armored online
// public key.
func SignOnlineArmoredKeyDetached(offlinePriv *gopgp.Key, onlinePublicArmored string) (string, error) {
	return SignArmoredKeyDetached(offlinePriv, onlinePublicArmored)
}

// VerifyOnlineArmoredKeyDetached verifies that a detached signature over
// the armored online public key was created by the offline public key.
func VerifyOnlineArmoredKeyDetached(offlinePub *gopgp.Key, onlinePublicArmored string, signature string) (bool, error) {
	return VerifyArmoredKeyDetached(offlinePub, onlinePublicArmored, signature)
}

// EncryptMessage encrypts a plaintext string to a public key and returns an armored message.
func EncryptMessage(publicKey *gopgp.Key, message string) (string, error) {
	if publicKey == nil {
		return "", errors.New("public key is nil")
	}

	pgpHandle := gopgp.PGP()
	encHandle, err := pgpHandle.
		Encryption().
		Recipient(publicKey).
		New()
	if err != nil {
		return "", err
	}

	pgpMessage, err := encHandle.Encrypt([]byte(message))
	if err != nil {
		return "", err
	}

	armored, err := pgpMessage.Armor()
	if err != nil {
		return "", err
	}

	return armored, nil
}

// DecryptMessage decrypts an armored PGP message using an unlocked private key.
func DecryptMessage(privateKey *gopgp.Key, encryptedMessage string) (string, error) {
	if privateKey == nil {
		return "", errors.New("private key is nil")
	}
	if encryptedMessage == "" {
		return "", errors.New("encrypted message must not be empty")
	}

	pgpHandle := gopgp.PGP()
	decHandle, err := pgpHandle.
		Decryption().
		DecryptionKey(privateKey).
		New()
	if err != nil {
		return "", err
	}

	decrypted, err := decHandle.Decrypt([]byte(encryptedMessage), gopgp.Armor)
	if err != nil {
		return "", err
	}

	return decrypted.String(), nil
}

// CertifyOnlineWithOffline uses the offline key to add OpenPGP
// certification signatures over all identities on onlineKey.PublicKey.
// The returned Keys value has the same private key as onlineKey, but its
// public key includes the new third-party certifications from the offline key.
//
// offlineKey.PrivateKey is the offline private key (armored).
// onlineKey.PublicKey is the online public key to be certified.
// passphrase decrypts the offline private key.
func CertifyOnlineWithOffline(offlineKey, onlineKey *Keys, passphrase string) (*Keys, error) {
	if offlineKey == nil || onlineKey == nil {
		return nil, fmt.Errorf("offlineKey and onlineKey must not be nil")
	}
	if passphrase == "" {
		return nil, fmt.Errorf("passphrase must not be empty")
	}

	// 1. Read the offline private key (signer) into an EntityList.
	offlineEntityList, err := pmopenpgp.ReadArmoredKeyRing(strings.NewReader(offlineKey.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("failed to read offline key ring: %w", err)
	}
	if len(offlineEntityList) != 1 {
		return nil, fmt.Errorf("expected 1 entity in offline key ring, got %d", len(offlineEntityList))
	}
	signer := offlineEntityList[0]

	// 2. Decrypt all private keys in the signer entity.
	if err := signer.DecryptPrivateKeys([]byte(passphrase)); err != nil {
		return nil, fmt.Errorf("failed to decrypt offline private key(s): %w", err)
	}

	// 3. Read the online public key into an EntityList.
	onlineEntityList, err := pmopenpgp.ReadArmoredKeyRing(strings.NewReader(onlineKey.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("failed to read online key ring: %w", err)
	}
	if len(onlineEntityList) != 1 {
		return nil, fmt.Errorf("expected 1 entity in online key ring, got %d", len(onlineEntityList))
	}
	target := onlineEntityList[0]

	// 4. Have the offline entity certify every identity on the online key.
	for identityName := range target.Identities {
		if err := target.SignIdentity(identityName, signer, nil); err != nil {
			return nil, fmt.Errorf("error signing identity %q: %w", identityName, err)
		}
	}

	// 5. Serialize the newly certified online public key back to armor.
	var buf bytes.Buffer
	w, err := pmarmor.Encode(&buf, pmopenpgp.PublicKeyType, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create armor encoder: %w", err)
	}
	if err := target.Serialize(w); err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("failed to serialize certified key: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("failed to close armor encoder: %w", err)
	}

	// 6. Return the new key object: same private key, updated public key.
	return &Keys{
		PublicKey:  buf.String(),
		PrivateKey: onlineKey.PrivateKey,
	}, nil
}
