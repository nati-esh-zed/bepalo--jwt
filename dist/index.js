"use strict";
var __classPrivateFieldGet = (this && this.__classPrivateFieldGet) || function (receiver, state, kind, f) {
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
    return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var __classPrivateFieldSet = (this && this.__classPrivateFieldSet) || function (receiver, state, value, kind, f) {
    if (kind === "m") throw new TypeError("Private method is not writable");
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a setter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
    return (kind === "a" ? f.call(receiver, value) : f ? f.value = value : state.set(receiver, value)), value;
};
var _JWT_instances, _a, _JWT_alg, _JWT_algorithm, _JWT_privateKey, _JWT_publicKey, _JWT_isAsymmetric, _JWT_isRsaPss, _JWT_signData, _JWT_verifySignature, _JWT_validateAudience, _JWT_validateClaims, _JWT_safelyParseJson;
Object.defineProperty(exports, "__esModule", { value: true });
exports.JWT = exports.JwtError = void 0;
/**
 *
 * JsonWebToken utility class and helpers for signing, verifying, and decoding JWT payloads.
 *
 * USAGE:
 *  ```ts
 *  import { JWT, JwtError } from "@bepalo/jwt";
 *
 *  const payload = { userId: 123, role: "admin" };
 *  const alg = "HS256";
 *  const key = JWT.genKey(alg);
 *  const jwt = JWT.create<typeof payload>(key, alg);
 *  const token = jwt.sign({
 *    ...payload,
 *    exp: JWT.in(1).Minutes,
 *    iat: JWT.now(),
 *    jti: "jti-1234",
 *    iss: "auth-server",
 *    sub: "session",
 *    aud: ["auth-client-a", "auth-client-b"],
 *  });
 *  // verify signature only
 *  const { valid: signatureValid } = jwt.verifySignature(token);
 *  // verify signature and claims and return payload
 *  const { valid, payload: decoded, reason } = jwt.verify(token);
 *  if (!valid) {
 *    throw new JwtError(reason);
 *  }
 *  typeof key === "string"
 *    ? console.log(key)
 *    : console.log(key.publicKey, key.privateKey);
 *  console.log({
 *    alg,
 *    token,
 *    len: token.length,
 *    signatureValid,
 *    valid,
 *    decoded,
 *  });
 *  ```
 *
 *
 * @module @bepalo/jwt
 * @exports JWT class -- main class
 * @exports SURecord type
 * @exports JwtError class
 * @exports JwtSymmetricAlgorithm type
 * @exports JwtAsymmetricAlgorithm type
 * @exports JwtAlgorithm type
 * @exports JwtHeader type
 * @exports JwtPayload type
 * @exports Jwt type
 * @exports JwtResult type
 * @exports KeyPair type
 * @exports JWTVerifyOptions type
 *
 */
const crypto_1 = require("crypto");
const time_1 = require("@bepalo/time");
/**
 * JsonWebToken Error class
 */
class JwtError extends Error {
    constructor(message) {
        super(message);
    }
}
exports.JwtError = JwtError;
/**
 * Internal mapping of algorithms to Node.js crypto identifiers.
 */
var JwtAlgorithmEnum;
(function (JwtAlgorithmEnum) {
    JwtAlgorithmEnum["HS256"] = "sha256";
    JwtAlgorithmEnum["HS384"] = "sha384";
    JwtAlgorithmEnum["HS512"] = "sha512";
    JwtAlgorithmEnum["RS256"] = "RSA-SHA256";
    JwtAlgorithmEnum["RS384"] = "RSA-SHA384";
    JwtAlgorithmEnum["RS512"] = "RSA-SHA512";
    JwtAlgorithmEnum["PS256"] = "RSA-PSS-SHA256";
    JwtAlgorithmEnum["PS384"] = "RSA-PSS-SHA384";
    JwtAlgorithmEnum["PS512"] = "RSA-PSS-SHA512";
    JwtAlgorithmEnum["ES256"] = "sha256";
    JwtAlgorithmEnum["ES384"] = "sha384";
    JwtAlgorithmEnum["ES512"] = "sha512";
    JwtAlgorithmEnum["none"] = "none";
})(JwtAlgorithmEnum || (JwtAlgorithmEnum = {}));
/**
 * Internal mapping of algorithms to Node.js crypto hash algorithms.
 */
var JwtAlgorithmHashEnum;
(function (JwtAlgorithmHashEnum) {
    JwtAlgorithmHashEnum["HS256"] = "sha256";
    JwtAlgorithmHashEnum["HS384"] = "sha384";
    JwtAlgorithmHashEnum["HS512"] = "sha512";
    JwtAlgorithmHashEnum["RS256"] = "sha256";
    JwtAlgorithmHashEnum["RS384"] = "sha384";
    JwtAlgorithmHashEnum["RS512"] = "sha512";
    JwtAlgorithmHashEnum["PS256"] = "sha256";
    JwtAlgorithmHashEnum["PS384"] = "sha384";
    JwtAlgorithmHashEnum["PS512"] = "sha512";
    JwtAlgorithmHashEnum["ES256"] = "sha256";
    JwtAlgorithmHashEnum["ES384"] = "sha384";
    JwtAlgorithmHashEnum["ES512"] = "sha512";
    JwtAlgorithmHashEnum["none"] = "none";
})(JwtAlgorithmHashEnum || (JwtAlgorithmHashEnum = {}));
/**
 * Internal mapping of algorithms to modulus length.
 */
var JwtAlgorithmModulusLenEnum;
(function (JwtAlgorithmModulusLenEnum) {
    JwtAlgorithmModulusLenEnum[JwtAlgorithmModulusLenEnum["RS256"] = 2048] = "RS256";
    JwtAlgorithmModulusLenEnum[JwtAlgorithmModulusLenEnum["RS384"] = 3072] = "RS384";
    JwtAlgorithmModulusLenEnum[JwtAlgorithmModulusLenEnum["RS512"] = 4096] = "RS512";
    JwtAlgorithmModulusLenEnum[JwtAlgorithmModulusLenEnum["PS256"] = 2048] = "PS256";
    JwtAlgorithmModulusLenEnum[JwtAlgorithmModulusLenEnum["PS384"] = 3072] = "PS384";
    JwtAlgorithmModulusLenEnum[JwtAlgorithmModulusLenEnum["PS512"] = 4096] = "PS512";
})(JwtAlgorithmModulusLenEnum || (JwtAlgorithmModulusLenEnum = {}));
/**
 * Valid symmetric jwt algorithm sets for quick lookup
 */
const ValidJwtSymmetricAlgorithms = new Set(["HS256", "HS384", "HS512"]);
/**
 * Valid asymmetric jwt algorithm set for quick lookup
 */
const ValidJwtAsymmetricAlgorithms = new Set([
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
const JwtAsymmetricPSAlgorithms = new Set(["PS256", "PS384", "PS512"]);
/**
 * Valid jwt algorithm set for quick lookup
 */
const ValidJwtAlgorithms = new Set([
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
 * JWT class providing utility function and methods to sign, verify and decode tokens.
 */
class JWT {
    get alg() {
        return __classPrivateFieldGet(this, _JWT_alg, "f");
    }
    get algorithm() {
        return __classPrivateFieldGet(this, _JWT_algorithm, "f");
    }
    get isAsymmetric() {
        return __classPrivateFieldGet(this, _JWT_isAsymmetric, "f");
    }
    /**
     * Get the current time in seconds
     */
    static now() {
        return Math.floor(Date.now() / 1000);
    }
    /**
     * Get the future time in seconds. eg. `JWT.for(10).Minutes`
     */
    static for(time) {
        return new time_1.RelativeTime(time, _a.now());
    }
    /**
     * Get the future time in seconds. eg. `exp: JWT.in(10).Minutes`
     */
    static in(time) {
        return new time_1.RelativeTime(time, _a.now());
    }
    /**
     * Get the future time in seconds. eg. `nbf: JWT.after(5).Minutes`
     */
    static after(time) {
        return new time_1.RelativeTime(time, _a.now());
    }
    /**
     * Get the past time in seconds. eg. `JWT.before(5).Minutes`
     */
    static before(time) {
        return new time_1.RelativeTime(-time, _a.now());
    }
    /**
     * Generate a rando HMAC key for HS256 (32 bytes), HS384 (36 bytes), or HS512 (64 bytes) encoded in base64url format.
     * Default: 256 bits (32 bytes), which is good for HS256.
     */
    static genHmacKey(alg) {
        switch (alg) {
            case "HS256":
                return (0, crypto_1.randomBytes)(32).toString("base64url");
            case "HS384":
                return (0, crypto_1.randomBytes)(48).toString("base64url");
            case "HS512":
                return (0, crypto_1.randomBytes)(64).toString("base64url");
        }
    }
    /**
     * Generate key pair based on algorithm and optional parameters.
     * Default: modulus lengths of RS256|PS256 (2048), RS384|PS384 (3072), RS512|PS512 (4096).
     */
    static genKeyPair(alg, options) {
        var _b;
        switch (alg) {
            case "ES256":
                return (0, crypto_1.generateKeyPairSync)("ec", {
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
                return (0, crypto_1.generateKeyPairSync)("ec", {
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
                return (0, crypto_1.generateKeyPairSync)("ec", {
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
                return (0, crypto_1.generateKeyPairSync)("rsa", {
                    modulusLength: (_b = options === null || options === void 0 ? void 0 : options.modulusLength) !== null && _b !== void 0 ? _b : JwtAlgorithmModulusLenEnum[alg],
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
     * Generate a rando HMAC key for HS256 (32 bytes), HS384 (36 bytes), or HS512 (64 bytes) encoded in base64url format.
     * Default: modulus lengths of RS256|PS256 (2048), RS384|PS384 (3072), RS512|PS512 (4096).
     */
    static genKey(alg, options) {
        if (ValidJwtSymmetricAlgorithms.has(alg)) {
            const key = _a.genHmacKey(alg);
            return key;
        }
        else {
            return _a.genKeyPair(alg, options);
        }
    }
    /**
     * Create a JWT instance using a symmetric algorithm.
     */
    static createSymmetric(key, alg) {
        if (!key || !ValidJwtSymmetricAlgorithms.has(alg)) {
            throw new JwtError("Invalid or unsupported symmetric JWT algorithm");
        }
        return new _a({ privateKey: key, publicKey: key }, alg, false, false);
    }
    /**
     * Create a JWT instance using an asymmetric algorithm.
     */
    static createAsymmetric(key, alg) {
        if (!ValidJwtAsymmetricAlgorithms.has(alg)) {
            throw new JwtError("Invalid or unsupported asymmetric JWT algorithm");
        }
        return new _a(key, alg, true, JwtAsymmetricPSAlgorithms.has(alg));
    }
    /**
     * Create a JWT instance using a symmetric or asymmetric algorithm.
     */
    static create(key, alg) {
        if (typeof key === "string") {
            if (!ValidJwtSymmetricAlgorithms.has(alg)) {
                throw new JwtError("Invalid or unsupported symmetric JWT algorithm");
            }
        }
        else if (!ValidJwtAsymmetricAlgorithms.has(alg)) {
            throw new JwtError("Invalid or unsupported asymmetric JWT algorithm");
        }
        return typeof key === "string"
            ? new _a({ privateKey: key, publicKey: key }, alg, false, false)
            : new _a(key, alg, true, JwtAsymmetricPSAlgorithms.has(alg));
    }
    constructor(key, alg, isAsymmetric, isRsaPss) {
        _JWT_instances.add(this);
        _JWT_alg.set(this, void 0);
        _JWT_algorithm.set(this, void 0);
        _JWT_privateKey.set(this, void 0);
        _JWT_publicKey.set(this, void 0);
        _JWT_isAsymmetric.set(this, false);
        _JWT_isRsaPss.set(this, false);
        if (!key.privateKey)
            throw new JwtError("null JWT private key");
        if (!key.publicKey)
            throw new JwtError("null JWT public key");
        __classPrivateFieldSet(this, _JWT_alg, alg, "f");
        __classPrivateFieldSet(this, _JWT_algorithm, JwtAlgorithmEnum[alg], "f");
        __classPrivateFieldSet(this, _JWT_privateKey, key.privateKey, "f");
        __classPrivateFieldSet(this, _JWT_publicKey, key.publicKey, "f");
        __classPrivateFieldSet(this, _JWT_isAsymmetric, isAsymmetric, "f");
        __classPrivateFieldSet(this, _JWT_isRsaPss, isRsaPss, "f");
    }
    /**
     * Sign a payload and return a JWT token string.
     */
    sign(payload) {
        const alg = __classPrivateFieldGet(this, _JWT_alg, "f");
        const algorithm = __classPrivateFieldGet(this, _JWT_algorithm, "f");
        const header = Buffer.from(JSON.stringify({ typ: "JWT", alg })).toString("base64url");
        const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
        const dataToSign = `${header}.${body}`;
        const signature = __classPrivateFieldGet(this, _JWT_instances, "m", _JWT_signData).call(this, alg, algorithm, dataToSign);
        return `${dataToSign}.${signature}`;
    }
    /**
     * Verify only the signature of the token (no claims checked).
     */
    verifySignature(token, verifyJwt) {
        verifyJwt = Object.assign({ strict: true }, verifyJwt);
        const [header, body, signature] = token.split(".");
        if (!(header && body && signature)) {
            return { valid: false, reason: "invalid token" };
        }
        const jwtHeader = __classPrivateFieldGet(this, _JWT_instances, "m", _JWT_safelyParseJson).call(this, Buffer.from(header, "base64url").toString());
        if (!jwtHeader) {
            return { valid: false, reason: "invalid token header" };
        }
        const { typ, alg } = jwtHeader;
        if (typ !== "JWT") {
            return { valid: false, reason: "invalid token type" };
        }
        else if (verifyJwt.strict && __classPrivateFieldGet(this, _JWT_alg, "f") !== alg) {
            return { valid: false, reason: "algorithm mismatch" };
        }
        else if (!alg || !ValidJwtAlgorithms.has(alg)) {
            return { valid: false, reason: "invalid algorithm" };
        }
        const algorithm = JwtAlgorithmEnum[alg];
        const dataToVerify = `${header}.${body}`;
        const signaturesMatch = __classPrivateFieldGet(this, _JWT_instances, "m", _JWT_verifySignature).call(this, alg, algorithm, dataToVerify, signature);
        if (!signaturesMatch) {
            return { valid: false, reason: "invalid signature" };
        }
        return { valid: true };
    }
    /**
     * Verify a token including signature and claims.
     * Returns a JwtResult with a valid payload on success.
     */
    verify(token, verifyJwt) {
        verifyJwt = Object.assign({ strict: true, exp: true, nbf: true }, verifyJwt);
        const [header, body, signature] = token.split(".");
        if (!(header && body && signature)) {
            return { valid: false, reason: "invalid token" };
        }
        const jwtHeader = __classPrivateFieldGet(this, _JWT_instances, "m", _JWT_safelyParseJson).call(this, Buffer.from(header, "base64url").toString());
        if (!jwtHeader) {
            return { valid: false, reason: "invalid token header" };
        }
        const { typ, alg } = jwtHeader;
        if (typ !== "JWT") {
            return { valid: false, reason: "invalid token type" };
        }
        else if (verifyJwt.strict && __classPrivateFieldGet(this, _JWT_alg, "f") !== alg) {
            return { valid: false, reason: "algorithm mismatch" };
        }
        else if (!alg || !ValidJwtAlgorithms.has(alg)) {
            return { valid: false, reason: "invalid algorithm" };
        }
        const algorithm = JwtAlgorithmEnum[alg];
        const dataToVerify = `${header}.${body}`;
        const signaturesMatch = __classPrivateFieldGet(this, _JWT_instances, "m", _JWT_verifySignature).call(this, alg, algorithm, dataToVerify, signature);
        if (!signaturesMatch) {
            return { valid: false, reason: "invalid signature" };
        }
        const jwtPayload = __classPrivateFieldGet(this, _JWT_instances, "m", _JWT_safelyParseJson).call(this, Buffer.from(body, "base64url").toString());
        if (!jwtPayload) {
            return { valid: false, reason: "invalid payload" };
        }
        return __classPrivateFieldGet(this, _JWT_instances, "m", _JWT_validateClaims).call(this, jwtPayload, verifyJwt);
    }
}
exports.JWT = JWT;
_a = JWT, _JWT_alg = new WeakMap(), _JWT_algorithm = new WeakMap(), _JWT_privateKey = new WeakMap(), _JWT_publicKey = new WeakMap(), _JWT_isAsymmetric = new WeakMap(), _JWT_isRsaPss = new WeakMap(), _JWT_instances = new WeakSet(), _JWT_signData = function _JWT_signData(alg, algorithm, dataToSign) {
    return __classPrivateFieldGet(this, _JWT_isAsymmetric, "f")
        ? __classPrivateFieldGet(this, _JWT_isRsaPss, "f")
            ? (0, crypto_1.sign)(JwtAlgorithmHashEnum[alg], Buffer.from(dataToSign), {
                key: __classPrivateFieldGet(this, _JWT_privateKey, "f"),
                padding: crypto_1.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: crypto_1.constants.RSA_PSS_SALTLEN_DIGEST,
            }).toString("base64url")
            : (0, crypto_1.createSign)(algorithm)
                .update(dataToSign)
                .sign(__classPrivateFieldGet(this, _JWT_privateKey, "f"), "base64url")
        : (0, crypto_1.createHmac)(algorithm, __classPrivateFieldGet(this, _JWT_privateKey, "f"), { encoding: "base64url" })
            .update(dataToSign)
            .digest("base64url");
}, _JWT_verifySignature = function _JWT_verifySignature(alg, algorithm, dataToVerify, signature) {
    return __classPrivateFieldGet(this, _JWT_isAsymmetric, "f")
        ? __classPrivateFieldGet(this, _JWT_isRsaPss, "f")
            ? (0, crypto_1.verify)(JwtAlgorithmHashEnum[alg], Buffer.from(dataToVerify), {
                key: __classPrivateFieldGet(this, _JWT_privateKey, "f"),
                padding: crypto_1.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: crypto_1.constants.RSA_PSS_SALTLEN_DIGEST,
            }, Buffer.from(signature, "base64url"))
            : (0, crypto_1.createVerify)(algorithm)
                .update(dataToVerify)
                .verify(__classPrivateFieldGet(this, _JWT_publicKey, "f"), signature, "base64url")
        : (0, crypto_1.createHmac)(algorithm, __classPrivateFieldGet(this, _JWT_publicKey, "f"), { encoding: "base64url" })
            .update(dataToVerify)
            .digest("base64url") === signature;
}, _JWT_validateAudience = function _JWT_validateAudience(expectedAudience, audience) {
    if (!audience)
        return false;
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
}, _JWT_validateClaims = function _JWT_validateClaims(payload, verifyJwt, now = _a.now()) {
    var _b, _c;
    if (verifyJwt.jti && payload.jti !== verifyJwt.jti) {
        return { valid: false, reason: "jti (jwt id) mismatch" };
    }
    if (verifyJwt.iss && payload.iss !== verifyJwt.iss) {
        return { valid: false, reason: "iss (issuer) mismatch" };
    }
    if (verifyJwt.sub && payload.sub !== verifyJwt.sub) {
        return { valid: false, reason: "sub (subject) mismatch" };
    }
    if (verifyJwt.aud && !__classPrivateFieldGet(this, _JWT_instances, "m", _JWT_validateAudience).call(this, verifyJwt.aud, payload.aud)) {
        return { valid: false, reason: "aud (audience) mismatch" };
    }
    if (verifyJwt.exp && now > payload.exp + ((_b = verifyJwt.expLeeway) !== null && _b !== void 0 ? _b : 0)) {
        return { valid: false, reason: "token expired" };
    }
    if (verifyJwt.nbf && payload.nbf - ((_c = verifyJwt.nbfLeeway) !== null && _c !== void 0 ? _c : 0) > now) {
        return { valid: false, reason: "token not yet valid (nbf)" };
    }
    return { valid: true, payload };
}, _JWT_safelyParseJson = function _JWT_safelyParseJson(jsonStr) {
    try {
        const result = JSON.parse(jsonStr);
        return result;
    }
    catch (_err) {
        return undefined;
    }
};
//# sourceMappingURL=index.js.map