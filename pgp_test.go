package pgp_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"signet/internal/pgp"
)

const (
	testNameOffline     = "Offline User"
	testEmailOffline    = "offline@example.com"
	testNameOnline      = "Online User"
	testEmailOnline     = "online@example.com"
	testMessage         = "This is a test message."
	testPasswordOffline = "offlinepassword"
	testPasswordOnline  = "onlinepassword"
)

func newOfflineKeyProps() pgp.KeyProps {
	return pgp.KeyProps{
		Name:       testNameOffline,
		Email:      testEmailOffline,
		Passphrase: testPasswordOffline,
		KeyType:    pgp.X25519,
		KeyBits:    2048,
	}
}

func newOnlineKeyProps() pgp.KeyProps {
	return pgp.KeyProps{
		Name:       testNameOnline,
		Email:      testEmailOnline,
		Passphrase: testPasswordOnline,
		KeyType:    pgp.X25519,
		KeyBits:    2048,
	}
}

func TestGenerateKey(t *testing.T) {
	kp := newOnlineKeyProps()

	keys, err := pgp.GenerateKey(kp)
	require.NoError(t, err, "GenerateKey should not return an error")
	require.NotNil(t, keys, "GenerateKey should not return nil")

	assert.NotEmpty(t, keys.PublicKey, "public key should not be empty")
	assert.NotEmpty(t, keys.PrivateKey, "private key should not be empty")
}

func TestEncryptAndDecrypt(t *testing.T) {
	kp := newOnlineKeyProps()

	keys, err := pgp.GenerateKey(kp)
	require.NoError(t, err, "GenerateKey should not return an error")
	require.NotNil(t, keys, "GenerateKey should not return nil")

	publicKey, err := pgp.ReadKey(keys.PublicKey)
	require.NoError(t, err, "ReadKey for public key should not return an error")
	require.NotNil(t, publicKey, "public key should not be nil")

	encryptedMessage, err := pgp.EncryptMessage(publicKey, testMessage)
	require.NoError(t, err, "EncryptMessage should not return an error")
	assert.NotEmpty(t, encryptedMessage, "encrypted message should not be empty")

	privateKey, err := pgp.ReadKey(keys.PrivateKey)
	require.NoError(t, err, "ReadKey for private key should not return an error")
	require.NotNil(t, privateKey, "private key should not be nil")

	decryptedPrivateKey, err := pgp.DecryptKey(privateKey, testPasswordOnline)
	require.NoError(t, err, "DecryptKey should not return an error")
	require.NotNil(t, decryptedPrivateKey, "unlocked private key should not be nil")

	decryptedMessage, err := pgp.DecryptMessage(decryptedPrivateKey, encryptedMessage)
	require.NoError(t, err, "DecryptMessage should not return an error")
	assert.Equal(t, testMessage, decryptedMessage, "decrypted message should equal original")
}

func TestSignAndVerifyMessage(t *testing.T) {
	kp := newOnlineKeyProps()

	keys, err := pgp.GenerateKey(kp)
	require.NoError(t, err, "GenerateKey should not return an error")
	require.NotNil(t, keys, "GenerateKey should not return nil")

	privateKey, err := pgp.ReadKey(keys.PrivateKey)
	require.NoError(t, err, "ReadKey for private key should not return an error")
	require.NotNil(t, privateKey, "private key should not be nil")

	unlockedPrivateKey, err := pgp.DecryptKey(privateKey, testPasswordOnline)
	require.NoError(t, err, "DecryptKey should not return an error")
	require.NotNil(t, unlockedPrivateKey, "unlocked private key should not be nil")

	signature, err := pgp.SignMessage(unlockedPrivateKey, testMessage)
	require.NoError(t, err, "SignMessage should not return an error")
	assert.NotEmpty(t, signature, "signature should not be empty")

	publicKey, err := pgp.ReadKey(keys.PublicKey)
	require.NoError(t, err, "ReadKey for public key should not return an error")
	require.NotNil(t, publicKey, "public key should not be nil")

	ok, err := pgp.VerifyMessage(publicKey, testMessage, signature)
	require.NoError(t, err, "VerifyMessage should not return an error when signature is valid")
	assert.True(t, ok, "VerifyMessage should return true for a valid signature")

	// Negative check: same signature must fail on a different message.
	ok, err = pgp.VerifyMessage(publicKey, testMessage+" tampered", signature)
	if err == nil {
		assert.False(t, ok, "VerifyMessage should return false for invalid signature")
	}
}

func TestOfflineAndOnlineKeyGeneration(t *testing.T) {
	offlineProps := newOfflineKeyProps()
	onlineProps := newOnlineKeyProps()

	offlineKeys, err := pgp.GenerateKey(offlineProps)
	require.NoError(t, err, "GenerateKey for offline should not return an error")
	require.NotNil(t, offlineKeys, "GenerateKey for offline should not return nil")
	assert.NotEmpty(t, offlineKeys.PublicKey, "offline public key should not be empty")
	assert.NotEmpty(t, offlineKeys.PrivateKey, "offline private key should not be empty")

	onlineKeys, err := pgp.GenerateKey(onlineProps)
	require.NoError(t, err, "GenerateKey for online should not return an error")
	require.NotNil(t, onlineKeys, "GenerateKey for online should not return nil")
	assert.NotEmpty(t, onlineKeys.PublicKey, "online public key should not be empty")
	assert.NotEmpty(t, onlineKeys.PrivateKey, "online private key should not be empty")

	// Sanity: the two key pairs should not be identical.
	assert.NotEqual(t, offlineKeys.PublicKey, onlineKeys.PublicKey, "offline and online public keys should differ")
	assert.NotEqual(t, offlineKeys.PrivateKey, onlineKeys.PrivateKey, "offline and online private keys should differ")
}

func TestOfflineSignsOnlineArmoredKeyDetached(t *testing.T) {
	// Generate offline key.
	offlineProps := newOfflineKeyProps()
	offlineKeys, err := pgp.GenerateKey(offlineProps)
	require.NoError(t, err, "GenerateKey for offline should not return an error")
	require.NotNil(t, offlineKeys, "GenerateKey for offline should not return nil")

	// Generate online key.
	onlineProps := newOnlineKeyProps()
	onlineKeys, err := pgp.GenerateKey(onlineProps)
	require.NoError(t, err, "GenerateKey for online should not return an error")
	require.NotNil(t, onlineKeys, "GenerateKey for online should not return nil")

	// Unlock the offline private key for signing.
	offlinePrivKey, err := pgp.ReadKey(offlineKeys.PrivateKey)
	require.NoError(t, err, "ReadKey for offline private key should not return an error")
	require.NotNil(t, offlinePrivKey, "offline private key should not be nil")

	unlockedOfflinePrivKey, err := pgp.DecryptKey(offlinePrivKey, testPasswordOffline)
	require.NoError(t, err, "DecryptKey for offline should not return an error")
	require.NotNil(t, unlockedOfflinePrivKey, "unlocked offline private key should not be nil")

	// Offline signs the online public key armor using the v3 Sign() API.
	signature, err := pgp.SignOnlineArmoredKeyDetached(unlockedOfflinePrivKey, onlineKeys.PublicKey)
	require.NoError(t, err, "SignOnlineArmoredKeyDetached should not return an error")
	assert.NotEmpty(t, signature, "detached signature over online key should not be empty")

	// Verify with the offline public key.
	offlinePubKey, err := pgp.ReadKey(offlineKeys.PublicKey)
	require.NoError(t, err, "ReadKey for offline public key should not return an error")
	require.NotNil(t, offlinePubKey, "offline public key should not be nil")

	ok, err := pgp.VerifyOnlineArmoredKeyDetached(offlinePubKey, onlineKeys.PublicKey, signature)
	require.NoError(t, err, "VerifyOnlineArmoredKeyDetached should not return an error for valid signature")
	assert.True(t, ok, "VerifyOnlineArmoredKeyDetached should return true for a valid signature")

	// Negative: verification must fail if we change the online public key armor.
	ok, err = pgp.VerifyOnlineArmoredKeyDetached(offlinePubKey, onlineKeys.PublicKey+"tampered", signature)
	if err == nil {
		assert.False(t, ok, "VerifyOnlineArmoredKeyDetached should return false for tampered key data")
	}
}

func TestOfflineCertifiesOnlineKey(t *testing.T) {
	// Generate offline and online keys.
	offlineProps := newOfflineKeyProps()
	offlineKeys, err := pgp.GenerateKey(offlineProps)
	require.NoError(t, err, "GenerateKey for offline should not return an error")
	require.NotNil(t, offlineKeys, "GenerateKey for offline should not return nil")

	onlineProps := newOnlineKeyProps()
	onlineKeys, err := pgp.GenerateKey(onlineProps)
	require.NoError(t, err, "GenerateKey for online should not return an error")
	require.NotNil(t, onlineKeys, "GenerateKey for online should not return nil")

	// Offline certifies the online key (OpenPGP-style key certification).
	certifiedOnline, err := pgp.CertifyOnlineWithOffline(offlineKeys, onlineKeys, testPasswordOffline)
	require.NoError(t, err, "CertifyOnlineWithOffline should not return an error")
	require.NotNil(t, certifiedOnline, "CertifyOnlineWithOffline should not return nil")

	assert.NotEmpty(t, certifiedOnline.PublicKey, "certified online public key should not be empty")
	assert.Equal(t, onlineKeys.PrivateKey, certifiedOnline.PrivateKey, "online private key should remain unchanged")

	// In many cases the public key armor will change due to new certification packets.
	assert.NotEqual(t, onlineKeys.PublicKey, certifiedOnline.PublicKey, "certified online public key is expected to differ from original")
}
