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
	require.NoError(t, err)
	require.NotNil(t, keys)

	pub, err := pgp.ReadKey(keys.PublicKey)
	require.NoError(t, err)
	require.NotNil(t, pub)

	encrypted, err := pgp.EncryptMessage(pub, testMessage)
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	priv, err := pgp.ReadKey(keys.PrivateKey)
	require.NoError(t, err)
	require.NotNil(t, priv)

	unlockedPriv, err := pgp.DecryptKey(priv, testPassword1)
	require.NoError(t, err)
	require.NotNil(t, unlockedPriv)

	decrypted, err := pgp.DecryptMessage(unlockedPriv, encrypted)
	require.NoError(t, err)
	assert.Equal(t, testMessage, decrypted)
}

func TestSignAndVerifyMessage(t *testing.T) {
	kp := newKeyProps1()

	keys, err := pgp.GenerateKey(kp)
	require.NoError(t, err)
	require.NotNil(t, keys)

	priv, err := pgp.ReadKey(keys.PrivateKey)
	require.NoError(t, err)
	require.NotNil(t, priv)

	unlockedPriv, err := pgp.DecryptKey(priv, testPassword1)
	require.NoError(t, err)
	require.NotNil(t, unlockedPriv)

	sig, err := pgp.SignMessage(unlockedPriv, testMessage)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)

	pub, err := pgp.ReadKey(keys.PublicKey)
	require.NoError(t, err)
	require.NotNil(t, pub)

	ok, err := pgp.VerifyMessage(pub, testMessage, sig)
	require.NoError(t, err)
	assert.True(t, ok)

	// Negative: same signature must fail on a different message.
	ok, err = pgp.VerifyMessage(pub, testMessage+" tampered", sig)
	if err == nil {
		assert.False(t, ok)
	}
}

func TestDistinctKeyPairs(t *testing.T) {
	props1 := newKeyProps1()
	props2 := newKeyProps2()

	keys1, err := pgp.GenerateKey(props1)
	require.NoError(t, err)
	require.NotNil(t, keys1)

	keys2, err := pgp.GenerateKey(props2)
	require.NoError(t, err)
	require.NotNil(t, keys2)

	assert.NotEmpty(t, keys1.PublicKey)
	assert.NotEmpty(t, keys1.PrivateKey)
	assert.NotEmpty(t, keys2.PublicKey)
	assert.NotEmpty(t, keys2.PrivateKey)

	assert.NotEqual(t, keys1.PublicKey, keys2.PublicKey)
	assert.NotEqual(t, keys1.PrivateKey, keys2.PrivateKey)
}

// -----------------------------------------------------------------------------
// Multi-recipient encryption/decryption
// -----------------------------------------------------------------------------

func TestMultiRecipientEncryption(t *testing.T) {
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

	encrypted, err := pgp.EncryptMessageForRecipients(
		[]*gopgp.Key{pub1, pub2},
		msg,
	)
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	// Recipient 1
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
	require.NoError(t, err)
	assert.Equal(t, msg, decrypted1)

	// Recipient 2
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
	require.NoError(t, err)
	assert.Equal(t, msg, decrypted2)

	// Both keys together
	decryptedCombined, err := pgp.DecryptMessageWithMultipleKeys(
		[]*gopgp.Key{unlockedPriv1, unlockedPriv2},
		encrypted,
	)
	require.NoError(t, err)
	assert.Equal(t, msg, decryptedCombined)
}

// -----------------------------------------------------------------------------
// Multi-key signing / verification
// -----------------------------------------------------------------------------

func TestMultiKeySigningAndVerification(t *testing.T) {
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

	sig, err := pgp.SignMessageWithMultipleKeys(
		[]*gopgp.Key{unlockedPriv1, unlockedPriv2},
		msg,
	)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)

	pub1, err := pgp.ReadKey(keys1.PublicKey)
	require.NoError(t, err)
	require.NotNil(t, pub1)

	pub2, err := pgp.ReadKey(keys2.PublicKey)
	require.NoError(t, err)
	require.NotNil(t, pub2)

	ok, err := pgp.VerifyMessageWithMultipleKeys(
		[]*gopgp.Key{pub1, pub2},
		msg,
		sig,
	)
	require.NoError(t, err)
	assert.True(t, ok)

	// Negative: a third unrelated key should not verify.
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
		sig,
	)
	require.NoError(t, err)
	assert.False(t, ok)
}

// -----------------------------------------------------------------------------
// Encrypt + sign + decrypt with multiple recipients/signers
// -----------------------------------------------------------------------------

func TestEncryptAndSignForMultipleRecipients(t *testing.T) {
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

	// Signing keys (these will be scrubbed by ClearPrivateParams).
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

	armored, err := pgp.EncryptAndSignMessageForMultiple(
		[]*gopgp.Key{pub1, pub2},
		[]*gopgp.Key{unlockedSignPriv1, unlockedSignPriv2},
		msg,
	)
	require.NoError(t, err)
	assert.NotEmpty(t, armored)

	// Do NOT reuse unlockedSignPriv1/2 for decryption; they have been scrubbed.
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

	decrypted, err := pgp.DecryptMessageWithMultipleKeys(
		[]*gopgp.Key{unlockedDecPriv1, unlockedDecPriv2},
		armored,
	)
	require.NoError(t, err)
	assert.Equal(t, msg, decrypted)
}
