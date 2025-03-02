export declare const ENULL = "eNULL";
export declare const SNULL = "sNULL";
export declare const EDWARDS25519SHA512BATCH = "edwards25519sha512batch";
export declare const CURVE25519XSALSA20POLY1305 = "curve25519xsalsa20poly1305";
export declare const XSALSA20POLY1305 = "xsalsa20poly1305";
export declare const EXTERNALKM32 = "externalkm32";
export type Key = {
    type: string;
    secretKey?: unknown;
    publicKey?: unknown;
};
export declare const keygen: (type: string) => Key;
export declare const generateSalt: () => string;
export declare const deriveKeyFromPassword: (type: string, password: string, salt: string) => Promise<Key>;
export declare const serializeKey: (key: Key, saveSecretKey: boolean) => string;
export declare const deserializeKey: (data: string) => Key;
export declare const keygenOfSameType: (inKey: Key | string) => Key;
export declare const keyId: (inKey: Key | string) => string;
export declare const sign: (inKey: Key | string, data: string) => string;
export declare const verifySignature: (inKey: Key | string, data: string, signature: string) => void;
/**
 * @param inKey - Encryption key to use
 * @param data - Data to encrypt
 * @param ad - Additional data (the AD in AEAD), used for validation
 */
export declare const encrypt: (inKey: Key | string, data: string, ad?: string) => string;
export declare const decrypt: (inKey: Key | string, data: string, ad?: string) => string;
