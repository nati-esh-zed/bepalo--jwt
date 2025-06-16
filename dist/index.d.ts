import { RelativeTime } from "@bepalo/time";
export type SURecord = Record<string, unknown>;
/**
 * JsonWebToken Error class
 */
export declare class JwtError extends Error {
    constructor(message?: string);
}
export type JwtSymmetricAlgorithm = "HS256" | "HS384" | "HS512";
export type JwtAsymmetricAlgorithm = "RS256" | "RS384" | "RS512" | "ES256" | "ES384" | "ES512" | "PS256" | "PS384" | "PS512";
/**
 * All JWT-supported algorithms including symmetric, asymmetric, and none.
 *
 * - **HMAC-Based (Symmetric, Fast)**: Used for shared-key authentication.
 *   - HS256: Most common and secure.
 *   - HS384: Slightly stronger but less common.
 *   - HS512: High-security option for robust applications.
 *
 * - **RSA-Based (Asymmetric, Public-Private Key)**: Used for OAuth, OpenID, and other key-based authentication.
 *   - RS256: Widely used.
 *   - RS384: Stronger but heavier.
 *   - RS512: Computationally expensive but highly secure.
 *   - PS256: RSA-PSS variant with SHA-256.
 *   - PS384: RSA-PSS variant with SHA-384.
 *   - PS512: RSA-PSS variant with SHA-512.
 *
 * - **ECDSA-Based (Asymmetric, Efficient)**: Faster than RSA, great for modern applications.
 *   - ES256: Recommended alternative to RSA.
 *   - ES384: Stronger cryptographic security.
 *   - ES512: Best for ultra-secure environments.
 */
export type JwtAlgorithm = JwtSymmetricAlgorithm | JwtAsymmetricAlgorithm | "none";
/**
 * Internal mapping of algorithms to Node.js crypto identifiers.
 */
declare enum JwtAlgorithmEnum {
    HS256 = "sha256",
    HS384 = "sha384",
    HS512 = "sha512",
    RS256 = "RSA-SHA256",
    RS384 = "RSA-SHA384",
    RS512 = "RSA-SHA512",
    PS256 = "RSA-PSS-SHA256",
    PS384 = "RSA-PSS-SHA384",
    PS512 = "RSA-PSS-SHA512",
    ES256 = "sha256",
    ES384 = "sha384",
    ES512 = "sha512",
    none = "none"
}
/**
 * JWT header standard fields.
 */
export type JwtHeader = {
    alg: JwtAlgorithm;
    typ?: string | "JWT";
    cty?: string;
    crit?: Array<string | Exclude<keyof JwtHeader, "crit">>;
    kid?: string;
    jku?: string;
    x5u?: string | string[];
    "x5t#S256"?: string;
    x5t?: string;
    x5c?: string | string[];
};
/**
 * JWT payload including standard claims and any custom fields.
 */
export type JwtPayload<CustomData extends SURecord> = {
    [key: string]: unknown;
    iss?: string;
    sub?: string;
    aud?: string | string[];
    exp?: number;
    nbf?: number;
    iat?: number;
    jti?: string;
} & CustomData;
/**
 * A fully parsed JWT token.
 */
export type Jwt<Payload extends SURecord> = {
    header: JwtHeader;
    payload: JwtPayload<Payload> | string;
    signature: string;
};
export type JwtResult<Payload extends SURecord> = {
    valid: boolean;
    payload?: JwtPayload<Payload>;
    reason?: string;
};
/**
 * Key pair type. for symmetric algorithms set both private and public keys to the key.
 */
export type KeyPair = {
    publicKey: string;
    privateKey: string;
};
/**
 * Optional parameters for verifying a JWT.
 */
export type JWTVerifyOptions = {
    /**
     * Decoded algorithm must match the stored algorithm. **(default: true)**
     */
    strict?: boolean;
    /**
     * Expected issuer
     */
    iss?: string;
    /**
     * Expected audience/s
     */
    aud?: string | string[];
    /**
     * Expected subject
     */
    sub?: string;
    /**
     * Expected token id
     */
    jti?: string;
    /**
     * Enable/disable expiration time check **(default: true)**
     */
    exp?: boolean;
    /**
     * Enable/disable not-before time check **(default: true)**
     */
    nbf?: boolean;
    /**
     * Leeway in seconds for expiration time
     */
    expLeeway?: number;
    /**
     * Leeway in seconds for not-before time
     */
    nbfLeeway?: number;
};
/**
 * JWT class providing utility function and methods to sign, verify and decode tokens.
 */
export declare class JWT<Payload extends SURecord> {
    #private;
    get alg(): JwtAlgorithm;
    get algorithm(): JwtAlgorithmEnum;
    get isAsymmetric(): boolean;
    /**
     * Get the current time in seconds
     */
    static now(): number;
    /**
     * Get the future time in seconds. eg. `JWT.for(10).Minutes`
     */
    static for(time: number): RelativeTime;
    /**
     * Get the future time in seconds. eg. `exp: JWT.in(10).Minutes`
     */
    static in(time: number): RelativeTime;
    /**
     * Get the future time in seconds. eg. `nbf: JWT.after(5).Minutes`
     */
    static after(time: number): RelativeTime;
    /**
     * Get the past time in seconds. eg. `JWT.before(5).Minutes`
     */
    static before(time: number): RelativeTime;
    /**
     * Generate a rando HMAC key for HS256 (32 bytes), HS384 (36 bytes), or HS512 (64 bytes) encoded in base64url format.
     * Default: 256 bits (32 bytes), which is good for HS256.
     */
    static genHmacKey(alg: JwtSymmetricAlgorithm): string;
    /**
     * Generate key pair based on algorithm and optional parameters.
     * Default: modulus lengths of RS256|PS256 (2048), RS384|PS384 (3072), RS512|PS512 (4096).
     */
    static genKeyPair(alg: JwtAsymmetricAlgorithm, options?: {
        modulusLength?: number;
    }): KeyPair;
    /**
     * Generate a rando HMAC key for HS256 (32 bytes), HS384 (36 bytes), or HS512 (64 bytes) encoded in base64url format.
     * Default: modulus lengths of RS256|PS256 (2048), RS384|PS384 (3072), RS512|PS512 (4096).
     */
    static genKey(alg: JwtAlgorithm, options?: {
        /**
         * Used only for RSA and RSA-PSS
         */
        modulusLength?: number;
    }): KeyPair | string;
    /**
     * Create a JWT instance using a symmetric algorithm.
     */
    static createSymmetric<Payload extends SURecord>(key: string | undefined, alg: JwtSymmetricAlgorithm): JWT<Payload>;
    /**
     * Create a JWT instance using an asymmetric algorithm.
     */
    static createAsymmetric<Payload extends SURecord>(key: KeyPair, alg: JwtAsymmetricAlgorithm): JWT<Payload>;
    /**
     * Create a JWT instance using a symmetric or asymmetric algorithm.
     */
    static create<Payload extends SURecord>(key: KeyPair | string, alg: JwtAlgorithm): JWT<Payload>;
    private constructor();
    /**
     * Sign a payload and return a JWT token string.
     */
    sign(payload: JwtPayload<Payload>): string;
    /**
     * Verify only the signature of the token (no claims checked).
     */
    verifySignature(token: string, verifyJwt?: Pick<JWTVerifyOptions, "strict">): JwtResult<Payload>;
    /**
     * Verify a token including signature and claims.
     * Returns a JwtResult with a valid payload on success.
     */
    verify(token: string, verifyJwt?: JWTVerifyOptions): JwtResult<Payload>;
}
export {};
