import * as assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { EDWARDS25519SHA512BATCH, CURVE25519XSALSA20POLY1305, XSALSA20POLY1305, keygen, deriveKeyFromPassword, generateSalt, serializeKey, deserializeKey, encrypt, decrypt, sign, verifySignature } from './index.js'

describe('Crypto suite', () => {
  it('should deserialize to the same contents as when serializing', () => {
    for (const type of [EDWARDS25519SHA512BATCH, CURVE25519XSALSA20POLY1305, XSALSA20POLY1305]) {
      const key = keygen(type)
      const serializedKey = serializeKey(key, true)
      const deserializedKey = deserializeKey(serializedKey)
      assert.deepEqual(deserializedKey, key)
    }
  })

  it('should deserialize to the same contents as when serializing (public)', () => {
    for (const type of [EDWARDS25519SHA512BATCH, CURVE25519XSALSA20POLY1305]) {
      const key = keygen(type)
      const serializedKey = serializeKey(key, false)
      const publicKey = { type: key.type, publicKey: key.publicKey }
      const deserializedKey = deserializeKey(serializedKey)
      assert.deepEqual(deserializedKey, publicKey)
    }
  })

  it('should derive the same key for the same password/salt combination', async () => {
    for (const type of [EDWARDS25519SHA512BATCH, CURVE25519XSALSA20POLY1305, XSALSA20POLY1305]) {
      const salt = generateSalt()

      assert.notEqual(salt, '')

      const invocation1 = await deriveKeyFromPassword(type, 'password123', salt)
      const invocation2 = await deriveKeyFromPassword(type, 'password123', salt)

      assert.deepEqual(invocation2, invocation1)
    }
  })

  it('should derive different keys for the different password/salt combination', async () => {
    const salt1 = 'salt1'
    const salt2 = 'salt2'

    for (const type of [EDWARDS25519SHA512BATCH, CURVE25519XSALSA20POLY1305, XSALSA20POLY1305]) {
      const invocation1 = await deriveKeyFromPassword(type, 'password123', salt1)
      const invocation2 = await deriveKeyFromPassword(type, 'password123', salt2)
      const invocation3 = await deriveKeyFromPassword(type, 'p4ssw0rd321', salt1)

      assert.notDeepEqual(invocation2, invocation1)
      assert.notDeepEqual(invocation3, invocation2)
      assert.notDeepEqual(invocation3, invocation1)
    }
  })

  it('should correctly sign and verify messages', () => {
    const key = keygen(EDWARDS25519SHA512BATCH)
    const data = 'data'

    const signature = sign(key, data)

    assert.doesNotThrow(() => verifySignature(key, data, signature))
  })

  it('should not verify signatures made with a different key', () => {
    const key1 = keygen(EDWARDS25519SHA512BATCH)
    const key2 = keygen(EDWARDS25519SHA512BATCH)
    const data = 'data'

    const signature = sign(key1, data)

    assert.throws(() => verifySignature(key2, data, signature))
  })

  it('should not verify signatures made with different data', () => {
    const key = keygen(EDWARDS25519SHA512BATCH)
    const data1 = 'data1'
    const data2 = 'data2'

    const signature = sign(key, data1)

    assert.throws(() => verifySignature(key, data2, signature))
  })

  it('should not verify invalid signatures', () => {
    const key = keygen(EDWARDS25519SHA512BATCH)
    const data = 'data'

    assert.throws(() => verifySignature(key, data, 'INVALID SIGNATURE'))
  })

  it('should correctly encrypt and decrypt messages', () => {
    const data = 'data'

    for (const type of [CURVE25519XSALSA20POLY1305, XSALSA20POLY1305]) {
      const key = keygen(type)
      const encryptedMessage = encrypt(key, data)

      assert.notEqual(encryptedMessage, data)

      const result = decrypt(key, encryptedMessage)

      assert.equal(result, data)
    }
  })

  it('should not decrypt messages encrypted with a different key', () => {
    const data = 'data'

    for (const type of [CURVE25519XSALSA20POLY1305, XSALSA20POLY1305]) {
      const key1 = keygen(type)
      const key2 = keygen(type)
      const encryptedMessage = encrypt(key1, data)

      assert.notEqual(encryptedMessage, data)

      assert.throws(() => decrypt(key2, encryptedMessage))
    }
  })

  it('should not decrypt invalid messages', () => {
    for (const type of [CURVE25519XSALSA20POLY1305, XSALSA20POLY1305]) {
      const key = keygen(type)
      assert.throws(() => decrypt(key, 'Invalid message'))
    }
  })
})
