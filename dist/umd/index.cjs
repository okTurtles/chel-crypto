var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
(function (factory) {
    if (typeof module === "object" && typeof module.exports === "object") {
        var v = factory(require, exports);
        if (v !== undefined) module.exports = v;
    }
    else if (typeof define === "function" && define.amd) {
        define(["require", "exports", "@chelonia/multiformats", "scrypt-async", "tweetnacl"], factory);
    }
})(function (require, exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.decrypt = exports.encrypt = exports.verifySignature = exports.sign = exports.keyId = exports.keygenOfSameType = exports.deserializeKey = exports.serializeKey = exports.deriveKeyFromPassword = exports.generateSalt = exports.keygen = exports.EXTERNALKM32 = exports.XSALSA20POLY1305 = exports.CURVE25519XSALSA20POLY1305 = exports.EDWARDS25519SHA512BATCH = exports.SNULL = exports.ENULL = void 0;
    const multiformats_1 = require("@chelonia/multiformats");
    const scrypt_async_1 = __importDefault(require("scrypt-async"));
    const tweetnacl_1 = __importDefault(require("tweetnacl"));
    const bufToStr = (() => {
        const textDecoder = new TextDecoder();
        return (buf) => {
            return textDecoder.decode(buf);
        };
    })();
    const strToBuf = (() => {
        const textEncoder = new TextEncoder();
        return (str) => {
            return textEncoder.encode(str);
        };
    })();
    const blake32Hash = (data) => {
        const uint8array = typeof data === 'string' ? strToBuf(data) : data;
        const digest = multiformats_1.blake2b256.digest(uint8array);
        // While `digest.digest` is only 32 bytes long in this case,
        // `digest.bytes` is 36 bytes because it includes a multiformat prefix.
        return multiformats_1.base58btc.encode(digest.bytes);
    };
    const b64ToBuf = (data) => new Uint8Array(atob(data)
        .split('')
        .map((b) => b.charCodeAt(0)));
    // ENULL and SNULL are 'null' algorithms for asymmetric encryption and
    // signatures, respectively. They are useful for development and testing because
    // their values can easily be inspected by hand but they offer ABSOLUTELY NO
    // PROTECTION and should *NEVER* be used in production.
    exports.ENULL = 'eNULL';
    exports.SNULL = 'sNULL';
    exports.EDWARDS25519SHA512BATCH = 'edwards25519sha512batch';
    exports.CURVE25519XSALSA20POLY1305 = 'curve25519xsalsa20poly1305';
    exports.XSALSA20POLY1305 = 'xsalsa20poly1305';
    // 32 bytes of keying material, used for external keys (such as files)
    exports.EXTERNALKM32 = 'externalkm32';
    if (process.env.NODE_ENV === 'production' && process.env.ENABLE_UNSAFE_NULL_CRYPTO === 'true') {
        throw new Error('ENABLE_UNSAFE_NULL_CRYPTO cannot be enabled in production mode');
    }
    const bytesOrObjectToB64 = (ary) => {
        if (!(ary instanceof Uint8Array)) {
            throw TypeError('Unsupported type');
        }
        return btoa(Array.from(ary)
            .map((c) => String.fromCharCode(c))
            .join(''));
    };
    const keygen = (type) => {
        if (process.env.ENABLE_UNSAFE_NULL_CRYPTO === 'true' && (type === exports.ENULL || type === exports.SNULL)) {
            const res = {
                type,
                publicKey: bytesOrObjectToB64(tweetnacl_1.default.randomBytes(18))
            };
            Object.defineProperty(res, 'secretKey', { value: res.publicKey });
            return res;
        }
        if (type === exports.EDWARDS25519SHA512BATCH) {
            const key = tweetnacl_1.default.sign.keyPair();
            const res = {
                type,
                publicKey: key.publicKey
            };
            // prevents 'secretKey' from being enumerated or appearing in JSON
            Object.defineProperty(res, 'secretKey', { value: key.secretKey });
            return res;
        }
        else if (type === exports.CURVE25519XSALSA20POLY1305) {
            const key = tweetnacl_1.default.box.keyPair();
            const res = {
                type,
                publicKey: key.publicKey
            };
            Object.defineProperty(res, 'secretKey', { value: key.secretKey });
            return res;
        }
        else if (type === exports.XSALSA20POLY1305) {
            const res = {
                type
            };
            Object.defineProperty(res, 'secretKey', { value: tweetnacl_1.default.randomBytes(tweetnacl_1.default.secretbox.keyLength) });
            return res;
        }
        else if (type === exports.EXTERNALKM32) {
            const res = {
                type
            };
            Object.defineProperty(res, 'secretKey', { value: tweetnacl_1.default.randomBytes(32) });
            return res;
        }
        throw new Error('Unsupported key type');
    };
    exports.keygen = keygen;
    const generateSalt = () => {
        return bytesOrObjectToB64(tweetnacl_1.default.randomBytes(18));
    };
    exports.generateSalt = generateSalt;
    const deriveKeyFromPassword = (type, password, salt) => {
        if (process.env.ENABLE_UNSAFE_NULL_CRYPTO === 'true' && (type === exports.ENULL || type === exports.SNULL)) {
            const v = blake32Hash(blake32Hash(salt) + blake32Hash(password));
            return Promise.resolve({
                type,
                secretKey: v,
                publicKey: v
            });
        }
        if (![exports.EDWARDS25519SHA512BATCH, exports.CURVE25519XSALSA20POLY1305, exports.XSALSA20POLY1305].includes(type)) {
            return Promise.reject(new Error('Unsupported type'));
        }
        return new Promise((resolve) => {
            (0, scrypt_async_1.default)(password, salt, {
                N: 16384,
                r: 8,
                p: 1,
                dkLen: type === exports.EDWARDS25519SHA512BATCH ? tweetnacl_1.default.sign.seedLength : type === exports.CURVE25519XSALSA20POLY1305 ? tweetnacl_1.default.box.secretKeyLength : type === exports.XSALSA20POLY1305 ? tweetnacl_1.default.secretbox.keyLength : 0,
                encoding: 'binary'
            }, (derivedKey) => {
                const buffer = new Uint8Array(derivedKey);
                if (type === exports.EDWARDS25519SHA512BATCH) {
                    const key = tweetnacl_1.default.sign.keyPair.fromSeed(buffer);
                    resolve({
                        type,
                        secretKey: key.secretKey,
                        publicKey: key.publicKey
                    });
                }
                else if (type === exports.CURVE25519XSALSA20POLY1305) {
                    const key = tweetnacl_1.default.box.keyPair.fromSecretKey(buffer);
                    resolve({
                        type,
                        secretKey: key.secretKey,
                        publicKey: key.publicKey
                    });
                }
                else if (type === exports.XSALSA20POLY1305) {
                    resolve({
                        type,
                        secretKey: buffer
                    });
                }
            });
        });
    };
    exports.deriveKeyFromPassword = deriveKeyFromPassword;
    // Format: [type, publicKey, secretKey]: [string, string, null] | [string, null, string]
    // Using an array instead of an object ensures that the object is serialized in order since the JSON specification does not define the order for object keys
    // and therefore different it could vary across implementations
    const serializeKey = (key, saveSecretKey) => {
        if (process.env.ENABLE_UNSAFE_NULL_CRYPTO === 'true' && (key.type === exports.ENULL || key.type === exports.SNULL)) {
            return JSON.stringify([
                key.type,
                saveSecretKey ? null : key.publicKey,
                saveSecretKey ? key.secretKey : null
            ], undefined, 0);
        }
        if (key.type === exports.EDWARDS25519SHA512BATCH || key.type === exports.CURVE25519XSALSA20POLY1305) {
            if (!saveSecretKey) {
                if (!key.publicKey) {
                    throw new Error('Unsupported operation: no public key to export');
                }
                return JSON.stringify([
                    key.type,
                    bytesOrObjectToB64(key.publicKey),
                    null
                ], undefined, 0);
            }
            if (!key.secretKey) {
                throw new Error('Unsupported operation: no secret key to export');
            }
            return JSON.stringify([
                key.type,
                null,
                bytesOrObjectToB64(key.secretKey)
            ], undefined, 0);
        }
        else if (key.type === exports.XSALSA20POLY1305) {
            if (!saveSecretKey) {
                throw new Error('Unsupported operation: no public key to export');
            }
            if (!key.secretKey) {
                throw new Error('Unsupported operation: no secret key to export');
            }
            return JSON.stringify([
                key.type,
                null,
                bytesOrObjectToB64(key.secretKey)
            ], undefined, 0);
        }
        throw new Error('Unsupported key type');
    };
    exports.serializeKey = serializeKey;
    const deserializeKey = (data) => {
        const keyData = JSON.parse(data);
        if (!keyData || keyData.length !== 3) {
            throw new Error('Invalid key object');
        }
        if (process.env.ENABLE_UNSAFE_NULL_CRYPTO === 'true' && (keyData[0] === exports.ENULL || keyData[0] === exports.SNULL)) {
            const res = {
                type: keyData[0]
            };
            if (keyData[2]) {
                Object.defineProperty(res, 'secretKey', { value: keyData[2] });
                res.publicKey = keyData[2];
            }
            else {
                res.publicKey = keyData[1];
            }
            return res;
        }
        if (keyData[0] === exports.EDWARDS25519SHA512BATCH) {
            if (keyData[2]) {
                const key = tweetnacl_1.default.sign.keyPair.fromSecretKey(b64ToBuf(keyData[2]));
                const res = {
                    type: keyData[0],
                    publicKey: key.publicKey
                };
                Object.defineProperty(res, 'secretKey', { value: key.secretKey });
                return res;
            }
            else if (keyData[1]) {
                return {
                    type: keyData[0],
                    publicKey: new Uint8Array(b64ToBuf(keyData[1]))
                };
            }
            throw new Error('Missing secret or public key');
        }
        else if (keyData[0] === exports.CURVE25519XSALSA20POLY1305) {
            if (keyData[2]) {
                const key = tweetnacl_1.default.box.keyPair.fromSecretKey(b64ToBuf(keyData[2]));
                const res = {
                    type: keyData[0],
                    publicKey: key.publicKey
                };
                Object.defineProperty(res, 'secretKey', { value: key.secretKey });
                return res;
            }
            else if (keyData[1]) {
                return {
                    type: keyData[0],
                    publicKey: new Uint8Array(b64ToBuf(keyData[1]))
                };
            }
            throw new Error('Missing secret or public key');
        }
        else if (keyData[0] === exports.XSALSA20POLY1305) {
            if (!keyData[2]) {
                throw new Error('Secret key missing');
            }
            const res = {
                type: keyData[0]
            };
            Object.defineProperty(res, 'secretKey', { value: new Uint8Array(b64ToBuf(keyData[2])) });
            return res;
        }
        throw new Error('Unsupported key type');
    };
    exports.deserializeKey = deserializeKey;
    const keygenOfSameType = (inKey) => {
        const key = typeof inKey === 'string' ? (0, exports.deserializeKey)(inKey) : inKey;
        return (0, exports.keygen)(key.type);
    };
    exports.keygenOfSameType = keygenOfSameType;
    const keyId = (inKey) => {
        const key = typeof inKey === 'string' ? (0, exports.deserializeKey)(inKey) : inKey;
        const serializedKey = (0, exports.serializeKey)(key, !key.publicKey);
        return blake32Hash(serializedKey);
    };
    exports.keyId = keyId;
    const sign = (inKey, data) => {
        const key = typeof inKey === 'string' ? (0, exports.deserializeKey)(inKey) : inKey;
        if (process.env.ENABLE_UNSAFE_NULL_CRYPTO === 'true' && key.type === exports.SNULL) {
            if (!key.secretKey) {
                throw new Error('Secret key missing');
            }
            return key.secretKey + ';' + blake32Hash(data);
        }
        if (key.type !== exports.EDWARDS25519SHA512BATCH) {
            throw new Error('Unsupported algorithm');
        }
        if (!key.secretKey) {
            throw new Error('Secret key missing');
        }
        const messageUint8 = strToBuf(data);
        const signature = tweetnacl_1.default.sign.detached(messageUint8, key.secretKey);
        const base64Signature = bytesOrObjectToB64(signature);
        return base64Signature;
    };
    exports.sign = sign;
    const verifySignature = (inKey, data, signature) => {
        const key = typeof inKey === 'string' ? (0, exports.deserializeKey)(inKey) : inKey;
        if (process.env.ENABLE_UNSAFE_NULL_CRYPTO === 'true' && key.type === exports.SNULL) {
            if (!key.publicKey) {
                throw new Error('Public key missing');
            }
            if ((key.publicKey + ';' + blake32Hash(data)) !== signature) {
                throw new Error('Invalid signature');
            }
            return;
        }
        if (key.type !== exports.EDWARDS25519SHA512BATCH) {
            throw new Error('Unsupported algorithm');
        }
        if (!key.publicKey) {
            throw new Error('Public key missing');
        }
        const decodedSignature = b64ToBuf(signature);
        const messageUint8 = strToBuf(data);
        const result = tweetnacl_1.default.sign.detached.verify(messageUint8, decodedSignature, key.publicKey);
        if (!result) {
            throw new Error('Invalid signature');
        }
    };
    exports.verifySignature = verifySignature;
    /**
     * @param inKey - Encryption key to use
     * @param data - Data to encrypt
     * @param ad - Additional data (the AD in AEAD), used for validation
     */
    const encrypt = (inKey, data, ad) => {
        const key = typeof inKey === 'string' ? (0, exports.deserializeKey)(inKey) : inKey;
        if (process.env.ENABLE_UNSAFE_NULL_CRYPTO === 'true' && key.type === exports.ENULL) {
            if (!key.publicKey) {
                throw new Error('Public key missing');
            }
            return `${key.publicKey};${data};${ad !== null && ad !== void 0 ? ad : ''}`;
        }
        if (key.type === exports.XSALSA20POLY1305) {
            if (!key.secretKey) {
                throw new Error('Secret key missing');
            }
            const nonce = tweetnacl_1.default.randomBytes(tweetnacl_1.default.secretbox.nonceLength);
            let encryptionNonce;
            if (ad) {
                encryptionNonce = new Uint8Array(nonce);
                const adHash = tweetnacl_1.default.hash(strToBuf(ad));
                const len = Math.min(adHash.length, nonce.length);
                for (let i = 0; i < len; i++) {
                    encryptionNonce[i] ^= adHash[i];
                }
            }
            else {
                encryptionNonce = nonce;
            }
            const messageUint8 = strToBuf(data);
            const box = tweetnacl_1.default.secretbox(messageUint8, encryptionNonce, key.secretKey);
            const fullMessage = new Uint8Array(nonce.length + box.length);
            fullMessage.set(nonce);
            fullMessage.set(box, nonce.length);
            const base64FullMessage = bytesOrObjectToB64(fullMessage);
            return base64FullMessage;
        }
        else if (key.type === exports.CURVE25519XSALSA20POLY1305) {
            if (!key.publicKey) {
                throw new Error('Public key missing');
            }
            const nonce = tweetnacl_1.default.randomBytes(tweetnacl_1.default.box.nonceLength);
            let encryptionNonce;
            if (ad) {
                encryptionNonce = new Uint8Array(nonce);
                const adHash = tweetnacl_1.default.hash(strToBuf(ad));
                const len = Math.min(adHash.length, nonce.length);
                for (let i = 0; i < len; i++) {
                    encryptionNonce[i] ^= adHash[i];
                }
            }
            else {
                encryptionNonce = nonce;
            }
            const messageUint8 = strToBuf(data);
            const ephemeralKey = tweetnacl_1.default.box.keyPair();
            const box = tweetnacl_1.default.box(messageUint8, encryptionNonce, key.publicKey, ephemeralKey.secretKey);
            // Attempt to discard the data in memory for ephemeralKey.secretKey
            crypto.getRandomValues(ephemeralKey.secretKey);
            ephemeralKey.secretKey.fill(0);
            const fullMessage = new Uint8Array(tweetnacl_1.default.box.publicKeyLength + nonce.length + box.length);
            fullMessage.set(ephemeralKey.publicKey);
            fullMessage.set(nonce, tweetnacl_1.default.box.publicKeyLength);
            fullMessage.set(box, tweetnacl_1.default.box.publicKeyLength + nonce.length);
            const base64FullMessage = bytesOrObjectToB64(fullMessage);
            return base64FullMessage;
        }
        throw new Error('Unsupported algorithm');
    };
    exports.encrypt = encrypt;
    const decrypt = (inKey, data, ad) => {
        const key = typeof inKey === 'string' ? (0, exports.deserializeKey)(inKey) : inKey;
        if (process.env.ENABLE_UNSAFE_NULL_CRYPTO === 'true' && key.type === exports.ENULL) {
            if (!key.secretKey) {
                throw new Error('Secret key missing');
            }
            if (!data.startsWith(key.secretKey + ';') || !data.endsWith(';' + (ad !== null && ad !== void 0 ? ad : ''))) {
                throw new Error('Additional data mismatch');
            }
            return data.slice(String(key.secretKey).length + 1, data.length - 1 - (ad !== null && ad !== void 0 ? ad : '').length);
        }
        if (key.type === exports.XSALSA20POLY1305) {
            if (!key.secretKey) {
                throw new Error('Secret key missing');
            }
            const messageWithNonceAsUint8Array = b64ToBuf(data);
            const nonce = messageWithNonceAsUint8Array.slice(0, tweetnacl_1.default.secretbox.nonceLength);
            const message = messageWithNonceAsUint8Array.slice(tweetnacl_1.default.secretbox.nonceLength, messageWithNonceAsUint8Array.length);
            if (ad) {
                const adHash = tweetnacl_1.default.hash(strToBuf(ad));
                const len = Math.min(adHash.length, nonce.length);
                for (let i = 0; i < len; i++) {
                    nonce[i] ^= adHash[i];
                }
            }
            const decrypted = tweetnacl_1.default.secretbox.open(message, nonce, key.secretKey);
            if (!decrypted) {
                throw new Error('Could not decrypt message');
            }
            return bufToStr(decrypted);
        }
        else if (key.type === exports.CURVE25519XSALSA20POLY1305) {
            if (!key.secretKey) {
                throw new Error('Secret key missing');
            }
            const messageWithNonceAsUint8Array = b64ToBuf(data);
            const ephemeralPublicKey = messageWithNonceAsUint8Array.slice(0, tweetnacl_1.default.box.publicKeyLength);
            const nonce = messageWithNonceAsUint8Array.slice(tweetnacl_1.default.box.publicKeyLength, tweetnacl_1.default.box.publicKeyLength + tweetnacl_1.default.box.nonceLength);
            const message = messageWithNonceAsUint8Array.slice(tweetnacl_1.default.box.publicKeyLength + tweetnacl_1.default.box.nonceLength);
            if (ad) {
                const adHash = tweetnacl_1.default.hash(strToBuf(ad));
                const len = Math.min(adHash.length, nonce.length);
                for (let i = 0; i < len; i++) {
                    nonce[i] ^= adHash[i];
                }
            }
            const decrypted = tweetnacl_1.default.box.open(message, nonce, ephemeralPublicKey, key.secretKey);
            if (!decrypted) {
                throw new Error('Could not decrypt message');
            }
            return bufToStr(decrypted);
        }
        throw new Error('Unsupported algorithm');
    };
    exports.decrypt = decrypt;
});
