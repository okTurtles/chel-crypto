import * as assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { EDWARDS25519SHA512BATCH, CURVE25519XSALSA20POLY1305, XSALSA20POLY1305, HMACSHA512, keygen, deriveKeyFromPassword, generateSalt, serializeKey, deserializeKey, encrypt, decrypt, sign, verifySignature } from './index.js'

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

  it('can compute and verify HMACSHA512 signatures', () => {
    const key = keygen(HMACSHA512)
    const data1 = 'test msg 1'
    const data2 = 'test msg 2'
    const result1 = sign(key, data1)
    const result2 = sign(key, data2)
    verifySignature(key, data1, result1)
    verifySignature(key, data2, result2)
    assert.throws(() => verifySignature(key, data1, result2))
    assert.throws(() => verifySignature(key, data2, result1))
  })

  it('Passes RFC 4231 test vectors for HMACSHA512', () => {
    // From <https://datatracker.ietf.org/doc/html/rfc4231>
    const testVectors = [
      {
        key: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
        message: 'Hi There',
        result: '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854'
      },
      {
        key: '4a656665',
        message: 'what do ya want for nothing?',
        result: '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737'
      },
      /*
      // The following two messages will fail due to UTF-8 encoding
      {
        key: 'aa'.repeat(20),
        message: '\xdd'.repeat(50),
        result: 'fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb'
      },
      {
        key: '0102030405060708090a0b0c0d0e0f10111213141516171819',
        message: '\xcd'.repeat(50),
        result: 'b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd'
      },
      */
      {
        key: 'aa'.repeat(131),
        message: 'Test Using Larger Than Block-Size Key - Hash Key First',
        result: '80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598'
      },
      {
        key: 'aa'.repeat(131),
        message: 'This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.',
        result: 'e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58'
      }
    ]

    for (const vec of testVectors) {
      const key = {
        type: HMACSHA512,
        secretKey: Buffer.from(vec.key, 'hex')
      }
      const result = sign(key, vec.message)
      const expected = Buffer.from(vec.result, 'hex').toString('base64')
      assert.equal(result, expected)
      verifySignature(key, vec.message, expected)
      assert.throws(() => verifySignature(key, vec.message, 'AAA' + expected.slice(3)))
    }
  })
})
