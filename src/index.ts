/**
 *
 * JsonWebToken utility class and helpers for signing, verifying, and decoding JWT payloads.
 *
 * USAGE:
 *  ```ts
 *
 *  ```
 *
 *
 * @module
 * @exports JwtError class
 * @exports JwtSymmetricAlgorithm type
 * @exports JwtAsymmetricAlgorithm type
 * @exports JwtAlgorithm type
 * @exports JwtAlgorithmEnum enum
 * @exports JwtHeader type
 * @exports JwtPayload type
 * @exports Jwt type
 * @exports JWTVerifyOptions type
 * @exports Time
 * @exports JWT class
 *
 */

// import { Buffer } from "node";
import {
  createHmac,
  createSign,
  createVerify,
  generateKeyPairSync,
  sign,
  verify,
  constants,
  randomBytes,
} from "crypto";
import { RelativeTime } from "@bepalo/time";

export type SURecord = Record<string, unknown>;

/**
 * JsonWebToken Error class
 */
export class JwtError extends Error {
  constructor(message?: string) {
    super(message);
  }
}

// Supported symmetric algorithms
export type JwtSymmetricAlgorithm = "HS256" | "HS384" | "HS512";

// Supported asymmetric algorithms
export type JwtAsymmetricAlgorithm =
  | "RS256"
  | "RS384"
  | "RS512"
  | "ES256"
  | "ES384"
  | "ES512"
  | "PS256"
  | "PS384"
  | "PS512";

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
export type JwtAlgorithm =
  | JwtSymmetricAlgorithm
  | JwtAsymmetricAlgorithm
  | "none";

/**
 * Internal mapping of algorithms to Node.js crypto identifiers.
 */
enum JwtAlgorithmEnum {
  HS256 = "sha256",
  HS384 = "sha384",
  HS512 = "sha512",
  RS256 = "RSA-SHA256",
  RS384 = "RSA-SHA384",
  RS512 = "RSA-SHA512",
  PS256 = "RSA-PSS-SHA256",
  PS384 = "RSA-PSS-SHA384",
  PS512 = "RSA-PSS-SHA512",
  ES256 = "sha3-256",
  ES384 = "sha3-384",
  ES512 = "sha3-512",
  none = "none",
}

/**
 * Internal mapping of algorithms to Node.js crypto hash algorithms.
 */
enum JwtAlgorithmHashEnum {
  HS256 = "sha256",
  HS384 = "sha384",
  HS512 = "sha512",
  RS256 = "sha256",
  RS384 = "sha384",
  RS512 = "sha512",
  PS256 = "sha256",
  PS384 = "sha384",
  PS512 = "sha512",
  ES256 = "sha256",
  ES384 = "sha384",
  ES512 = "sha512",
  none = "none",
}

/**
 * Internal mapping of algorithms to modulus length.
 */
enum JwtAlgorithmModulusLenEnum {
  RS256 = 2048,
  RS384 = 3072,
  RS512 = 4096,
  PS256 = 2048,
  PS384 = 3072,
  PS512 = 4096,
}

/**
 * Valid symmetric jwt algorithm sets for quick lookup
 */
const ValidJwtSymmetricAlgorithms: Set<JwtSymmetricAlgorithm> =
  new Set<JwtSymmetricAlgorithm>(["HS256", "HS384", "HS512"]);

/**
 * Valid asymmetric jwt algorithm set for quick lookup
 */
const ValidJwtAsymmetricAlgorithms: Set<JwtAsymmetricAlgorithm> =
  new Set<JwtAsymmetricAlgorithm>([
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
  ]);

const JwtAsymmetricPSAlgorithms: Set<JwtAsymmetricAlgorithm> =
  new Set<JwtAsymmetricAlgorithm>(["PS256", "PS384", "PS512"]);

/**
 * Valid jwt algorithm set for quick lookup
 */
const ValidJwtAlgorithms: Set<JwtAlgorithm> = new Set<JwtAlgorithm>([
  "HS256",
  "HS384",
  "HS512",
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
  "ES512",
]);

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
export type Jwt<CustomPayload extends SURecord> = {
  header: JwtHeader;
  payload: JwtPayload<CustomPayload> | string;
  signature: string;
};

export type JwtResult<CustomPayload extends SURecord> =
  | { valid: true; payload?: JwtPayload<CustomPayload> }
  | { valid: false; reason: string };

/**
 * Key pair type. for symmetric algorithms set both private and public keys to the key.
 */
export type KeyPair = { publicKey: string; privateKey: string };

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
export class JWT<CustomPayload extends SURecord> {
  #alg: JwtAlgorithm;
  #algorithm: JwtAlgorithmEnum;
  #privateKey: string;
  #publicKey: string;
  #isAsymmetric: boolean = false;
  #isRsaPss: boolean = false;

  get alg(): JwtAlgorithm {
    return this.#alg;
  }

  get algorithm(): JwtAlgorithmEnum {
    return this.#algorithm;
  }

  get isAsymmetric(): boolean {
    return this.#isAsymmetric;
  }

  /**
   * Get the current time in seconds
   */
  static now(): number {
    return Math.floor(Date.now() / 1000);
  }

  /**
   * Get the future time in seconds. eg. `JWT.for(10).Minutes`
   */
  static for(time: number): RelativeTime {
    return new RelativeTime(time, JWT.now());
  }

  /**
   * Get the future time in seconds. eg. `exp: JWT.in(10).Minutes`
   */
  static in(time: number): RelativeTime {
    return new RelativeTime(time, JWT.now());
  }

  /**
   * Get the future time in seconds. eg. `nbf: JWT.after(5).Minutes`
   */
  static after(time: number): RelativeTime {
    return new RelativeTime(time, JWT.now());
  }

  /**
   * Get the past time in seconds. eg. `JWT.before(5).Minutes`
   */
  static before(time: number): RelativeTime {
    return new RelativeTime(-time, JWT.now());
  }

  /**
   * Generate a secure HMAC key for HS256 (32 bytes), HS384 (36 bytes), or HS512 (64 bytes) encoded in base64url format.
   * Default: 256 bits (32 bytes), which is good for HS256.
   */
  static genHmacKey(alg: JwtSymmetricAlgorithm): string {
    switch (alg) {
      case "HS256":
        return randomBytes(32).toString("base64url");
      case "HS384":
        return randomBytes(48).toString("base64url");
      case "HS512":
        return randomBytes(64).toString("base64url");
    }
  }

  /**
   * Generate key pair based on algorithm and optional parameters.
   * Default: modulus lengths of RS256|PS256 (2048), RS384|PS384 (3072), RS512|PS512 (4096).
   */
  static genKeyPair(
    alg: JwtAsymmetricAlgorithm = "ES384",
    options?: {
      modulusLength?: number;
    }
  ): KeyPair {
    switch (alg) {
      case "ES256":
        return generateKeyPairSync("ec", {
          namedCurve: "P-256",
          publicKeyEncoding: {
            type: "spki",
            format: "pem",
          },
          privateKeyEncoding: {
            type: "pkcs8",
            format: "pem",
          },
        });
      case "ES384":
        return generateKeyPairSync("ec", {
          namedCurve: "P-384",
          publicKeyEncoding: {
            type: "spki",
            format: "pem",
          },
          privateKeyEncoding: {
            type: "pkcs8",
            format: "pem",
          },
        });
      case "ES512":
        return generateKeyPairSync("ec", {
          namedCurve: "P-521",
          publicKeyEncoding: {
            type: "spki",
            format: "pem",
          },
          privateKeyEncoding: {
            type: "pkcs8",
            format: "pem",
          },
        });
      case "RS256":
      case "RS384":
      case "RS512":
      case "PS256":
      case "PS384":
      case "PS512":
        return generateKeyPairSync("rsa", {
          modulusLength:
            options?.modulusLength ?? JwtAlgorithmModulusLenEnum[alg],
          publicKeyEncoding: {
            type: "spki",
            format: "pem",
          },
          privateKeyEncoding: {
            type: "pkcs8",
            format: "pem",
          },
        });
    }
  }

  /**
   * Generate a secure HMAC key for HS256 (32 bytes), HS384 (36 bytes), or HS512 (64 bytes) encoded in base64url format.
   * Default: modulus lengths of RS256|PS256 (2048), RS384|PS384 (3072), RS512|PS512 (4096).
   */
  static genKey(
    alg: JwtAlgorithm = "HS256",
    options?: {
      /**
       * Used only for RSA and RSA-PSS
       */
      modulusLength?: number;
    }
  ): KeyPair | string {
    if (ValidJwtSymmetricAlgorithms.has(alg as JwtSymmetricAlgorithm)) {
      const key = JWT.genHmacKey(alg as JwtSymmetricAlgorithm);
      return key;
    } else {
      return JWT.genKeyPair(alg as JwtAsymmetricAlgorithm, options);
    }
  }

  /**
   * Create a JWT instance using a symmetric algorithm.
   */
  static createSymmetric<CustomPayload extends SURecord>(
    key: string | undefined,
    alg: JwtSymmetricAlgorithm = "HS256"
  ): JWT<CustomPayload> {
    if (!key || !ValidJwtSymmetricAlgorithms.has(alg)) {
      throw new JwtError("Invalid or unsupported symmetric JWT algorithm");
    }
    return new JWT<CustomPayload>(
      { privateKey: key, publicKey: key },
      alg,
      false,
      false
    );
  }

  /**
   * Create a JWT instance using an asymmetric algorithm.
   */
  static createAsymmetric<CustomPayload extends SURecord>(
    key: KeyPair,
    alg: JwtAsymmetricAlgorithm = "ES384"
  ): JWT<CustomPayload> {
    if (!ValidJwtAsymmetricAlgorithms.has(alg)) {
      throw new JwtError("Invalid or unsupported asymmetric JWT algorithm");
    }
    return new JWT<CustomPayload>(
      key,
      alg,
      true,
      JwtAsymmetricPSAlgorithms.has(alg)
    );
  }

  /**
   * Create a JWT instance using a symmetric or asymmetric algorithm.
   */
  static create<CustomPayload extends SURecord>(
    key: KeyPair | string,
    alg: JwtAlgorithm = "HS256"
  ): JWT<CustomPayload> {
    if (typeof key === "string") {
      if (!ValidJwtSymmetricAlgorithms.has(alg as JwtSymmetricAlgorithm)) {
        throw new JwtError("Invalid or unsupported symmetric JWT algorithm");
      } else if (
        !ValidJwtAsymmetricAlgorithms.has(alg as JwtAsymmetricAlgorithm)
      ) {
        throw new JwtError("Invalid or unsupported asymmetric JWT algorithm");
      }
    }
    return typeof key === "string"
      ? new JWT<CustomPayload>(
          { privateKey: key, publicKey: key },
          alg,
          false,
          false
        )
      : new JWT<CustomPayload>(
          key,
          alg,
          true,
          JwtAsymmetricPSAlgorithms.has(alg as JwtAsymmetricAlgorithm)
        );
  }

  private constructor(
    key: KeyPair,
    alg: JwtAlgorithm,
    isAsymmetric: boolean,
    isRsaPss: boolean
  ) {
    if (!key.privateKey) throw new JwtError("null JWT private key");
    if (!key.publicKey) throw new JwtError("null JWT public key");
    this.#alg = alg;
    this.#algorithm = JwtAlgorithmEnum[alg];
    this.#privateKey = key.privateKey;
    this.#publicKey = key.publicKey;
    this.#isAsymmetric = isAsymmetric;
    this.#isRsaPss = isRsaPss;
  }

  #signData(
    alg: JwtAlgorithm,
    algorithm: JwtAlgorithmEnum,
    dataToSign: string
  ): string {
    return this.#isAsymmetric
      ? this.#isRsaPss
        ? sign(JwtAlgorithmHashEnum[alg], Buffer.from(dataToSign), {
            key: this.#privateKey,
            padding: constants.RSA_PKCS1_PSS_PADDING,
            saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
          }).toString("base64url")
        : createSign(algorithm)
            .update(dataToSign)
            .sign(this.#privateKey, "base64url")
      : createHmac(algorithm, this.#privateKey, { encoding: "base64url" })
          .update(dataToSign)
          .digest("base64url");
  }

  #verifySignature(
    alg: JwtAlgorithm,
    algorithm: JwtAlgorithmEnum,
    dataToVerify: string,
    signature: string
  ): boolean {
    return this.#isAsymmetric
      ? this.#isRsaPss
        ? verify(
            JwtAlgorithmHashEnum[alg],
            Buffer.from(dataToVerify),
            {
              key: this.#privateKey,
              padding: constants.RSA_PKCS1_PSS_PADDING,
              saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
            },
            Buffer.from(signature, "base64url")
          )
        : createVerify(algorithm)
            .update(dataToVerify)
            .verify(this.#publicKey, signature, "base64url")
      : createHmac(algorithm, this.#publicKey, { encoding: "base64url" })
          .update(dataToVerify)
          .digest("base64url") === signature;
  }

  /**
   * Validates that the token's `aud` (audience) claim matches the expected audience.
   * Supports strings or arrays for both expected and actual values.
   */
  #validateAudience(
    expectedAudience: string | string[],
    audience: string | string[] | undefined
  ): boolean {
    if (!audience) return false;
    if (Array.isArray(audience)) {
      if (Array.isArray(expectedAudience)) {
        return audience.some((actual) => expectedAudience.includes(actual));
      }
      return audience.includes(expectedAudience);
    }
    if (Array.isArray(expectedAudience)) {
      return expectedAudience.includes(audience);
    }
    return audience === expectedAudience;
  }

  #validateClaims(
    payload: JwtPayload<CustomPayload> & { exp: number; nbf: number },
    verifyJwt: JWTVerifyOptions,
    now: number = JWT.now()
  ): JwtResult<CustomPayload> {
    if (verifyJwt.jti && payload.jti !== verifyJwt.jti) {
      return { valid: false, reason: "jti (jwt id) mismatch" };
    }

    if (verifyJwt.iss && payload.iss !== verifyJwt.iss) {
      return { valid: false, reason: "iss (issuer) mismatch" };
    }

    if (verifyJwt.sub && payload.sub !== verifyJwt.sub) {
      return { valid: false, reason: "sub (subject) mismatch" };
    }

    if (verifyJwt.aud && !this.#validateAudience(verifyJwt.aud, payload.aud)) {
      return { valid: false, reason: "aud (audience) mismatch" };
    }

    if (verifyJwt.exp && now > payload.exp + (verifyJwt.expLeeway ?? 0)) {
      return { valid: false, reason: "token expired" };
    }

    if (verifyJwt.nbf && payload.nbf - (verifyJwt.nbfLeeway ?? 0) > now) {
      return { valid: false, reason: "token not yet valid (nbf)" };
    }

    return { valid: true, payload };
  }

  #safelyParseJson<ObjType extends SURecord>(
    jsonStr: string
  ): ObjType | undefined {
    try {
      const result = JSON.parse(jsonStr);
      return result;
    } catch (_err) {
      return undefined;
    }
  }

  /**
   * Sign a payload and return a JWT token string.
   */
  sign(payload: JwtPayload<CustomPayload>): string {
    const alg = this.#alg;
    const algorithm = this.#algorithm;
    const header = Buffer.from(JSON.stringify({ typ: "JWT", alg })).toString(
      "base64url"
    );
    const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const dataToSign = `${header}.${body}`;
    const signature = this.#signData(alg, algorithm, dataToSign);
    return `${dataToSign}.${signature}`;
  }

  /**
   * Verify only the signature of the token (no claims checked).
   */
  verifySignature(
    token: string,
    verifyJwt?: Pick<JWTVerifyOptions, "strict">
  ): JwtResult<CustomPayload> {
    verifyJwt = { strict: true, ...verifyJwt };
    const [header, body, signature] = token.split(".");
    if (!(header && body && signature)) {
      return { valid: false, reason: "invalid token" };
    }

    const jwtHeader = this.#safelyParseJson<JwtHeader>(
      Buffer.from(header, "base64url").toString()
    );
    if (!jwtHeader) {
      return { valid: false, reason: "invalid token header" };
    }
    const { typ, alg } = jwtHeader;
    if (typ !== "JWT") {
      return { valid: false, reason: "invalid token type" };
    } else if (verifyJwt.strict && this.#alg !== alg) {
      return { valid: false, reason: "algorithm mismatch" };
    } else if (!alg || !ValidJwtAlgorithms.has(alg)) {
      return { valid: false, reason: "invalid algorithm" };
    }

    const algorithm = JwtAlgorithmEnum[alg as JwtAlgorithm];
    const dataToVerify = `${header}.${body}`;
    const signaturesMatch = this.#verifySignature(
      alg,
      algorithm,
      dataToVerify,
      signature
    );
    if (!signaturesMatch) {
      return { valid: false, reason: "invalid signature" };
    }
    return { valid: true };
  }

  /**
   * Fully verify a token including signature and claims.
   * Returns a JwtResult with a valid payload on success.
   */
  verify(
    token: string,
    verifyJwt?: JWTVerifyOptions
  ): JwtResult<CustomPayload> {
    verifyJwt = { strict: true, exp: true, nbf: true, ...verifyJwt };
    const [header, body, signature] = token.split(".");
    if (!(header && body && signature)) {
      return { valid: false, reason: "invalid token" };
    }
    const jwtHeader = this.#safelyParseJson<JwtHeader>(
      Buffer.from(header, "base64url").toString()
    );
    if (!jwtHeader) {
      return { valid: false, reason: "invalid token header" };
    }
    const { typ, alg } = jwtHeader;
    if (typ !== "JWT") {
      return { valid: false, reason: "invalid token type" };
    } else if (verifyJwt.strict && this.#alg !== alg) {
      return { valid: false, reason: "algorithm mismatch" };
    } else if (!alg || !ValidJwtAlgorithms.has(alg)) {
      return { valid: false, reason: "invalid algorithm" };
    }

    const algorithm = JwtAlgorithmEnum[alg as JwtAlgorithm];
    const dataToVerify = `${header}.${body}`;
    const signaturesMatch = this.#verifySignature(
      alg,
      algorithm,
      dataToVerify,
      signature
    );

    if (!signaturesMatch) {
      return { valid: false, reason: "invalid signature" };
    }

    const payload = JSON.parse(Buffer.from(body, "base64url").toString());

    return this.#validateClaims(payload, verifyJwt);
  }
}
