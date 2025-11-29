package pgp_test

import (
	"testing"

	gopgp "github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/garetw/pgp"
)

const (
	testName1     = "User One"
	testEmail1    = "user1@example.com"
	testName2     = "User Two"
	testEmail2    = "user2@example.com"
	testName3     = "User Three"
	testEmail3    = "user3@example.com"
	testMessage   = "This is a test message."
	testPassword1 = "password-one"
	testPassword2 = "password-two"
	testPassword3 = "password-three"
)

func newKeyProps1() pgp.KeyProps {
	return pgp.KeyProps{
		Name:       testName1,
		Email:      testEmail1,
		Passphrase: testPassword1,
		KeyType:    pgp.X25519,
		KeyBits:    2048,
	}
}

func newKeyProps2() pgp.KeyProps {
	return pgp.KeyProps{
		Name:       testName2,
		Email:      testEmail2,
		Passphrase: testPassword2,
		KeyType:    pgp.X25519,
		KeyBits:    2048,
	}
}

func newKeyProps3() pgp.KeyProps {
	return pgp.KeyProps{
		Name:       testName3,
		Email:      testEmail3,
		Passphrase: testPassword3,
		KeyType:    pgp.X25519,
		KeyBits:    2048,
	}
}

// -----------------------------------------------------------------------------
// Single-key tests
// -----------------------------------------------------------------------------

func TestGenerateKey(t *testing.T) {
	kp := newKeyProps1()

	keys, err := pgp.GenerateKey(kp)
	require.NoError(t, err, "GenerateKey should not return an error")
	require.NotNil(t, keys, "GenerateKey should not return nil")

	assert.NotEmpty(t, keys.PublicKey, "public key should not be empty")
	assert.NotEmpty(t, keys.PrivateKey, "private key should not be empty")
}

func TestEncryptAndDecrypt(t *testing.T) {
	kp := newKeyProps1()

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

	decryptedPrivateKey, err := pgp.DecryptKey(privateKey, testPassword1)
	require.NoError(t, err, "DecryptKey should not return an error")
	require.NotNil(t, decryptedPrivateKey, "unlocked private key should not be nil")

	decryptedMessage, err := pgp.DecryptMessage(decryptedPrivateKey, encryptedMessage)
	require.NoError(t, err, "DecryptMessage should not return an error")
	assert.Equal(t, testMessage, decryptedMessage, "decrypted message should equal original")
}

func TestSignAndVerifyMessage(t *testing.T) {
	kp := newKeyProps1()

	keys, err := pgp.GenerateKey(kp)
	require.NoError(t, err, "GenerateKey should not return an error")
	require.NotNil(t, keys, "GenerateKey should not return nil")

	privateKey, err := pgp.ReadKey(keys.PrivateKey)
	require.NoError(t, err, "ReadKey for private key should not return an error")
	require.NotNil(t, privateKey, "private key should not be nil")

	unlockedPrivateKey, err := pgp.DecryptKey(privateKey, testPassword1)
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

func TestMultipleKeyPairsDistinct(t *testing.T) {
	props1 := newKeyProps1()
	props2 := newKeyProps2()

	keys1, err := pgp.GenerateKey(props1)
	require.NoError(t, err, "GenerateKey for first keypair should not return an error")
	require.NotNil(t, keys1, "GenerateKey for first keypair should not return nil")

	keys2, err := pgp.GenerateKey(props2)
	require.NoError(t, err, "GenerateKey for second keypair should not return an error")
	require.NotNil(t, keys2, "GenerateKey for second keypair should not return nil")

	assert.NotEmpty(t, keys1.PublicKey, "first public key should not be empty")
	assert.NotEmpty(t, keys1.PrivateKey, "first private key should not be empty")
	assert.NotEmpty(t, keys2.PublicKey, "second public key should not be empty")
	assert.NotEmpty(t, keys2.PrivateKey, "second private key should not be empty")

	// Sanity: the two key pairs should not be identical.
	assert.NotEqual(t, keys1.PublicKey, keys2.PublicKey, "public keys should differ")
	assert.NotEqual(t, keys1.PrivateKey, keys2.PrivateKey, "private keys should differ")
}

// -----------------------------------------------------------------------------
// Armored key signing + certification
// -----------------------------------------------------------------------------

func TestKeySignsOtherArmoredKeyDetached(t *testing.T) {
	// Signer key.
	propsSigner := newKeyProps1()
	signerKeys, err := pgp.GenerateKey(propsSigner)
	require.NoError(t, err)
	require.NotNil(t, signerKeys)

	// Target key to be signed.
	propsTarget := newKeyProps2()
	targetKeys, err := pgp.GenerateKey(propsTarget)
	require.NoError(t, err)
	require.NotNil(t, targetKeys)

	// Unlock signer private key.
	signerPriv, err := pgp.ReadKey(signerKeys.PrivateKey)
	require.NoError(t, err)
	require.NotNil(t, signerPriv)

	unlockedSignerPriv, err := pgp.DecryptKey(signerPriv, testPassword1)
	require.NoError(t, err)
	require.NotNil(t, unlockedSignerPriv)

	// Sign the target public key armor.
	signature, err := pgp.SignOnlineArmoredKeyDetached(unlockedSignerPriv, targetKeys.PublicKey)
	require.NoError(t, err)
	assert.NotEmpty(t, signature, "detached signature over key armor should not be empty")

	// Verify with signer public key.
	signerPub, err := pgp.ReadKey(signerKeys.PublicKey)
	require.NoError(t, err)
	require.NotNil(t, signerPub)

	ok, err := pgp.VerifyOnlineArmoredKeyDetached(signerPub, targetKeys.PublicKey, signature)
	require.NoError(t, err, "VerifyOnlineArmoredKeyDetached should not return error for valid signature")
	assert.True(t, ok, "VerifyOnlineArmoredKeyDetached should return true for a valid signature")

	// Negative: verification must fail if we change the target public key armor.
	ok, err = pgp.VerifyOnlineArmoredKeyDetached(signerPub, targetKeys.PublicKey+"tampered", signature)
	if err == nil {
		assert.False(t, ok, "VerifyOnlineArmoredKeyDetached should return false for tampered key data")
	}
}

func TestKeyCertificationUpdatesPublicKey(t *testing.T) {
	// Certifier key.
	propsCertifier := newKeyProps1()
	certifierKeys, err := pgp.GenerateKey(propsCertifier)
	require.NoError(t, err)
	require.NotNil(t, certifierKeys)

	// Target key to be certified.
	propsTarget := newKeyProps2()
	targetKeys, err := pgp.GenerateKey(propsTarget)
	require.NoError(t, err)
	require.NotNil(t, targetKeys)

	// Certifier adds certification signatures over target identities.
	certified, err := pgp.CertifyOnlineWithOffline(certifierKeys, targetKeys, testPassword1)
	require.NoError(t, err, "CertifyOnlineWithOffline should not return an error")
	require.NotNil(t, certified, "CertifyOnlineWithOffline should not return nil")

	assert.NotEmpty(t, certified.PublicKey, "certified public key should not be empty")
	assert.Equal(t, targetKeys.PrivateKey, certified.PrivateKey, "target private key should remain unchanged")

	// Public key armor is expected to change due to added certifications.
	assert.NotEqual(t, targetKeys.PublicKey, certified.PublicKey, "certified public key is expected to differ from original")
}

// -----------------------------------------------------------------------------
// Multi-recipient / multi-key operations
// -----------------------------------------------------------------------------

func TestEncryptAndDecryptWithMultipleRecipients(t *testing.T) {
	// Two recipients.
	props1 := newKeyProps1()
	props2 := newKeyProps2()

	keys1, err := pgp.GenerateKey(props1)
	require.NoError(t, err)
	require.NotNil(t, keys1)

	keys2, err := pgp.GenerateKey(props2)
	require.NoError(t, err)
	require.NotNil(t, keys2)

	pub1, err := pgp.ReadKey(keys1.PublicKey)
	require.NoError(t, err)
	require.NotNil(t, pub1)

	pub2, err := pgp.ReadKey(keys2.PublicKey)
	require.NoError(t, err)
	require.NotNil(t, pub2)

	const msg = "multi-recipient test message"

	// Encrypt to both recipients at once.
	encrypted, err := pgp.EncryptMessageForRecipients(
		[]*gopgp.Key{pub1, pub2},
		msg,
	)
	require.NoError(t, err, "EncryptMessageForRecipients should not return error")
	assert.NotEmpty(t, encrypted, "encrypted message should not be empty")

	// Recipient 1 decrypts with their private key.
	priv1, err := pgp.ReadKey(keys1.PrivateKey)
	require.NoError(t, err)
	require.NotNil(t, priv1)

	unlockedPriv1, err := pgp.DecryptKey(priv1, testPassword1)
	require.NoError(t, err)
	require.NotNil(t, unlockedPriv1)

	decrypted1, err := pgp.DecryptMessageWithMultipleKeys(
		[]*gopgp.Key{unlockedPriv1},
		encrypted,
	)
	require.NoError(t, err, "DecryptMessageWithMultipleKeys for recipient1 should not return error")
	assert.Equal(t, msg, decrypted1, "recipient1 decrypted message should match original")

	// Recipient 2 decrypts with their private key.
	priv2, err := pgp.ReadKey(keys2.PrivateKey)
	require.NoError(t, err)
	require.NotNil(t, priv2)

	unlockedPriv2, err := pgp.DecryptKey(priv2, testPassword2)
	require.NoError(t, err)
	require.NotNil(t, unlockedPriv2)

	decrypted2, err := pgp.DecryptMessageWithMultipleKeys(
		[]*gopgp.Key{unlockedPriv2},
		encrypted,
	)
	require.NoError(t, err, "DecryptMessageWithMultipleKeys for recipient2 should not return error")
	assert.Equal(t, msg, decrypted2, "recipient2 decrypted message should match original")

	// Decrypting with both keys in the same set should also work.
	decryptedCombined, err := pgp.DecryptMessageWithMultipleKeys(
		[]*gopgp.Key{unlockedPriv1, unlockedPriv2},
		encrypted,
	)
	require.NoError(t, err, "DecryptMessageWithMultipleKeys with both keys should not return error")
	assert.Equal(t, msg, decryptedCombined, "combined decrypted message should match original")
}

func TestSignAndVerifyWithMultipleKeys(t *testing.T) {
	// Two signers.
	props1 := newKeyProps1()
	props2 := newKeyProps2()

	keys1, err := pgp.GenerateKey(props1)
	require.NoError(t, err)
	require.NotNil(t, keys1)

	keys2, err := pgp.GenerateKey(props2)
	require.NoError(t, err)
	require.NotNil(t, keys2)

	priv1, err := pgp.ReadKey(keys1.PrivateKey)
	require.NoError(t, err)
	require.NotNil(t, priv1)

	priv2, err := pgp.ReadKey(keys2.PrivateKey)
	require.NoError(t, err)
	require.NotNil(t, priv2)

	unlockedPriv1, err := pgp.DecryptKey(priv1, testPassword1)
	require.NoError(t, err)
	require.NotNil(t, unlockedPriv1)

	unlockedPriv2, err := pgp.DecryptKey(priv2, testPassword2)
	require.NoError(t, err)
	require.NotNil(t, unlockedPriv2)

	const msg = "multi-signature test message"

	// Create a detached signature that is produced by both keys at once.
	signature, err := pgp.SignMessageWithMultipleKeys(
		[]*gopgp.Key{unlockedPriv1, unlockedPriv2},
		msg,
	)
	require.NoError(t, err, "SignMessageWithMultipleKeys should not return error")
	assert.NotEmpty(t, signature, "multi-signature blob should not be empty")

	pub1, err := pgp.ReadKey(keys1.PublicKey)
	require.NoError(t, err)
	require.NotNil(t, pub1)

	pub2, err := pgp.ReadKey(keys2.PublicKey)
	require.NoError(t, err)
	require.NotNil(t, pub2)

	// Verify with both public keys in the verification set.
	ok, err := pgp.VerifyMessageWithMultipleKeys(
		[]*gopgp.Key{pub1, pub2},
		msg,
		signature,
	)
	require.NoError(t, err, "VerifyMessageWithMultipleKeys should not return error for valid signatures")
	assert.True(t, ok, "multi-key verification should succeed with matching keys")

	// Negative: verification with an unrelated key only should fail.
	props3 := newKeyProps3()
	keys3, err := pgp.GenerateKey(props3)
	require.NoError(t, err)
	require.NotNil(t, keys3)

	pub3, err := pgp.ReadKey(keys3.PublicKey)
	require.NoError(t, err)
	require.NotNil(t, pub3)

	ok, err = pgp.VerifyMessageWithMultipleKeys(
		[]*gopgp.Key{pub3},
		msg,
		signature,
	)
	require.NoError(t, err, "VerifyMessageWithMultipleKeys should not return error for non-matching key")
	assert.False(t, ok, "verification should fail with non-matching public key")
}

func TestEncryptAndSignMessageForMultiple(t *testing.T) {
	// Two recipients who are also signers.
	props1 := newKeyProps1()
	props2 := newKeyProps2()

	keys1, err := pgp.GenerateKey(props1)
	require.NoError(t, err)
	require.NotNil(t, keys1)

	keys2, err := pgp.GenerateKey(props2)
	require.NoError(t, err)
	require.NotNil(t, keys2)

	pub1, err := pgp.ReadKey(keys1.PublicKey)
	require.NoError(t, err)
	require.NotNil(t, pub1)

	pub2, err := pgp.ReadKey(keys2.PublicKey)
	require.NoError(t, err)
	require.NotNil(t, pub2)

	// Unlock signing keys (these will be scrubbed by ClearPrivateParams).
	signPriv1, err := pgp.ReadKey(keys1.PrivateKey)
	require.NoError(t, err)
	require.NotNil(t, signPriv1)

	signPriv2, err := pgp.ReadKey(keys2.PrivateKey)
	require.NoError(t, err)
	require.NotNil(t, signPriv2)

	unlockedSignPriv1, err := pgp.DecryptKey(signPriv1, testPassword1)
	require.NoError(t, err)
	require.NotNil(t, unlockedSignPriv1)

	unlockedSignPriv2, err := pgp.DecryptKey(signPriv2, testPassword2)
	require.NoError(t, err)
	require.NotNil(t, unlockedSignPriv2)

	const msg = "encrypt+sign multi test"

	// Encrypt to both and sign with both.
	armored, err := pgp.EncryptAndSignMessageForMultiple(
		[]*gopgp.Key{pub1, pub2},
		[]*gopgp.Key{unlockedSignPriv1, unlockedSignPriv2},
		msg,
	)
	require.NoError(t, err, "EncryptAndSignMessageForMultiple should not return error")
	assert.NotEmpty(t, armored, "encrypted+signed message should not be empty")

	// IMPORTANT: Do NOT reuse unlockedSignPriv1/2 for decryption,
	// because ClearPrivateParams wipes them inside EncryptAndSignMessageForMultiple.
	// Instead, read and unlock fresh private key objects for decryption.

	decPriv1, err := pgp.ReadKey(keys1.PrivateKey)
	require.NoError(t, err)
	require.NotNil(t, decPriv1)

	decPriv2, err := pgp.ReadKey(keys2.PrivateKey)
	require.NoError(t, err)
	require.NotNil(t, decPriv2)

	unlockedDecPriv1, err := pgp.DecryptKey(decPriv1, testPassword1)
	require.NoError(t, err)
	require.NotNil(t, unlockedDecPriv1)

	unlockedDecPriv2, err := pgp.DecryptKey(decPriv2, testPassword2)
	require.NoError(t, err)
	require.NotNil(t, unlockedDecPriv2)

	// Decrypt with both private keys in the decryption set.
	decrypted, err := pgp.DecryptMessageWithMultipleKeys(
		[]*gopgp.Key{unlockedDecPriv1, unlockedDecPriv2},
		armored,
	)
	require.NoError(t, err, "DecryptMessageWithMultipleKeys should succeed on multi-recipient message")
	assert.Equal(t, msg, decrypted, "round-trip encrypt+sign+decrypt should preserve message")
}
