import { describe, test, expect } from "vitest";
import { JWT } from "@bepalo/jwt";

const payload = { userId: 123, role: "admin" };

describe("JWT Utility", () => {

  test("genHmacKey with HS256", () => {
    const secret = JWT.genHmacKey("HS256");
    expect(secret).toBeTypeOf("string");
  });

  test("genHmacKey with HS384", () => {
    const secret = JWT.genHmacKey("HS384");
    expect(secret).toBeTypeOf("string");
  });

  test("genHmacKey with HS384", () => {
    const secret = JWT.genHmacKey("HS384");
    expect(secret).toBeTypeOf("string");
  });

  test("genKey with HS256", () => {
    const secret = JWT.genKey("HS256");
    expect(secret).toBeTypeOf("string");
  });

  test("genKey with HS384", () => {
    const secret = JWT.genKey("HS384");
    expect(secret).toBeTypeOf("string");
  });

  test("genKey with HS384", () => {
    const secret = JWT.genKey("HS384");
    expect(secret).toBeTypeOf("string");
  });


  test("genKeyPair with ES256", () => {
    const secret = JWT.genKeyPair("ES256");
    expect(secret).toBeTypeOf("object");
    expect(secret.publicKey).toBeTypeOf("string");
    expect(secret.privateKey).toBeTypeOf("string");
  });

  test("genKeyPair with ES384", () => {
    const secret = JWT.genKeyPair("ES384");
    expect(secret).toBeTypeOf("object");
    expect(secret.publicKey).toBeTypeOf("string");
    expect(secret.privateKey).toBeTypeOf("string");
  });

  test("genKeyPair with ES384", () => {
    const secret = JWT.genKeyPair("ES384");
    expect(secret).toBeTypeOf("object");
    expect(secret.publicKey).toBeTypeOf("string");
    expect(secret.privateKey).toBeTypeOf("string");
  });


  test("genKeyPair with RS256", () => {
    const secret = JWT.genKeyPair("RS256");
    expect(secret).toBeTypeOf("object");
    expect(secret.publicKey).toBeTypeOf("string");
    expect(secret.privateKey).toBeTypeOf("string");
  });

  test("genKeyPair with RS384", () => {
    const secret = JWT.genKeyPair("RS384");
    expect(secret).toBeTypeOf("object");
    expect(secret.publicKey).toBeTypeOf("string");
    expect(secret.privateKey).toBeTypeOf("string");
  });

  test("genKeyPair with RS384", () => {
    const secret = JWT.genKeyPair("RS384");
    expect(secret).toBeTypeOf("object");
    expect(secret.publicKey).toBeTypeOf("string");
    expect(secret.privateKey).toBeTypeOf("string");
  });


  test("genKeyPair with PS256", () => {
    const secret = JWT.genKeyPair("PS256");
    expect(secret).toBeTypeOf("object");
    expect(secret.publicKey).toBeTypeOf("string");
    expect(secret.privateKey).toBeTypeOf("string");
  });

  test("genKeyPair with PS384", () => {
    const secret = JWT.genKeyPair("PS384");
    expect(secret).toBeTypeOf("object");
    expect(secret.publicKey).toBeTypeOf("string");
    expect(secret.privateKey).toBeTypeOf("string");
  });

  test("genKeyPair with PS384", () => {
    const secret = JWT.genKeyPair("PS384");
    expect(secret).toBeTypeOf("object");
    expect(secret.publicKey).toBeTypeOf("string");
    expect(secret.privateKey).toBeTypeOf("string");
  });


  test("sign and verify with HS256", () => {
    const secret = JWT.genHmacKey("HS256");
    const jwt = JWT.createSymmetric(secret, "HS256");
    const token = jwt.sign({ ...payload, exp: JWT.in(1).Minutes });
    expect(token).toBeTypeOf("string");
    const result = jwt.verify(token);
    expect(result).toBeTypeOf("object");
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
    expect(result.payload).toBeTypeOf("object");
  });

  test("verify returns full payload if valid", () => {
    const secret = JWT.genHmacKey("HS256");
    const jwt = JWT.createSymmetric(secret, "HS256");
    const token = jwt.sign({ ...payload, exp: JWT.in(1).Minutes });
    expect(token).toBeTypeOf("string");
    const result = jwt.verify(token);
    expect(result).toBeTypeOf("object");
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
    expect(result.payload).toBeTypeOf("object");
    expect(result.payload?.userId).toBe(123);
  });

  test("expired token fails verification", () => {
    const secret = JWT.genHmacKey("HS256");
    const jwt = JWT.createSymmetric(secret, "HS256");
    const token = jwt.sign({ ...payload, exp: JWT.in(-1).Minutes });
    expect(token).toBeTypeOf("string");
    const result = jwt.verify(token);
    expect(result).toBeTypeOf("object");
    expect(result.valid).toBe(false);
    expect(result.reason).toBeTypeOf("string");
    expect(result.payload).toBeUndefined();
  });

  test("nbf (not before) blocks early use", () => {
    const secret = JWT.genHmacKey("HS256");
    const jwt = JWT.createSymmetric(secret, "HS256");
    const token = jwt.sign({ ...payload, nbf: JWT.in(1).Minutes });
    expect(token).toBeTypeOf("string");
    const result = jwt.verify(token);
    expect(result).toBeTypeOf("object");
    expect(result.valid).toBe(false);
    expect(result.reason).toBeTypeOf("string");
    expect(result.payload).toBeUndefined();

  });

  test("issuer check works", () => {
    const secret = JWT.genHmacKey("HS256");
    const jwt = JWT.createSymmetric(secret, "HS256");
    const token = jwt.sign({
      ...payload,
      iss: "auth-server",
      exp: JWT.in(1).Minutes,
    });
    expect(token).toBeTypeOf("string");
    const result = jwt.verify(token, { iss: "auth-server" });
    expect(result).toBeTypeOf("object");
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
    expect(result.payload).toBeTypeOf("object");
  });

  test("subject check fails if mismatched", () => {
    const secret = JWT.genHmacKey("HS256");
    const jwt = JWT.createSymmetric(secret, "HS256");
    const token = jwt.sign({
      ...payload,
      sub: "user:123",
      exp: JWT.in(1).Minutes,
    });
    expect(token).toBeTypeOf("string");
    const result = jwt.verify(token, { sub: "user:999" });
    expect(result).toBeTypeOf("object");
    expect(result.valid).toBe(false);
    expect(result.reason).toBeTypeOf("string");
    expect(result.payload).toBeUndefined();
  });

  test("tampered payload invalidates signature", () => {
    const secret = JWT.genHmacKey("HS256");
    const jwt = JWT.createSymmetric(secret, "HS256");
    const token = jwt.sign({ ...payload, exp: JWT.in(1).Minutes });
    expect(token).toBeTypeOf("string");
    const parts = token.split(".");
    parts[1] = Buffer.from(JSON.stringify({ tampered: true })).toString(
      "base64url"
    );
    const tampered = parts.join(".");
    const result = jwt.verify(tampered);
    expect(result).toBeTypeOf("object");
    expect(result.valid).toBe(false);
    expect(result.reason).toBeTypeOf("string");
    expect(result.payload).toBeUndefined();
  });

  test("strict mode detects alg mismatch", () => {
    const keyPair = JWT.genKeyPair("RS256");
    const jwtA = JWT.createAsymmetric(keyPair, "RS256");
    const jwtB = JWT.createAsymmetric(keyPair, "RS512");
    const token = jwtA.sign({ ...payload, exp: JWT.in(1).Minutes });
    expect(token).toBeTypeOf("string");
    const result = jwtB.verify(token, { strict: true });
    expect(result).toBeTypeOf("object");
    expect(result.valid).toBe(false);
    expect(result.reason).toBeTypeOf("string");
    expect(result.payload).toBeUndefined();
  });

  test("verify with RS256 keypair works", () => {
    const keyPair = JWT.genKeyPair("RS256");
    const jwt = JWT.createAsymmetric(keyPair, "RS256");
    const token = jwt.sign({ ...payload, exp: JWT.in(1).Minutes });
    expect(token).toBeTypeOf("string");
    const result = jwt.verify(token);
    expect(result).toBeTypeOf("object");
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
    expect(result.payload).toBeTypeOf("object");
  });

  test("verify with RS384 keypair works", () => {
    const keyPair = JWT.genKeyPair("RS384");
    const jwt = JWT.createAsymmetric(keyPair, "RS384");
    const token = jwt.sign({ ...payload, exp: JWT.in(1).Minutes });
    expect(token).toBeTypeOf("string");
    const result = jwt.verify(token);
    expect(result).toBeTypeOf("object");
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
    expect(result.payload).toBeTypeOf("object");
  });

  test("verify with RS512 works", () => {
    const keyPair = JWT.genKeyPair("RS512");
    const jwt = JWT.createAsymmetric(keyPair, "RS512");
    const token = jwt.sign({ ...payload, exp: JWT.in(1).Minutes });
    expect(token).toBeTypeOf("string");
    const result = jwt.verify(token);
    expect(result).toBeTypeOf("object");
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
    expect(result.payload).toBeTypeOf("object");
  });

  test("verify with PS256 works", () => {
    const keyPair = JWT.genKeyPair("PS256");
    const jwt = JWT.createAsymmetric(keyPair, "PS256");
    const token = jwt.sign({ ...payload, exp: JWT.in(1).Minutes });
    expect(token).toBeTypeOf("string");
    const result = jwt.verify(token);
    expect(result).toBeTypeOf("object");
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
    expect(result.payload).toBeTypeOf("object");
  });

  test("verify with PS384 works", () => {
    const keyPair = JWT.genKeyPair("PS384");
    const jwt = JWT.createAsymmetric(keyPair, "PS384");
    const token = jwt.sign({ ...payload, exp: JWT.in(1).Minutes });
    expect(token).toBeTypeOf("string");
    const result = jwt.verify(token);
    expect(result).toBeTypeOf("object");
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
    expect(result.payload).toBeTypeOf("object");
  });

  test("verify with PS512 works", () => {
    const keyPair = JWT.genKeyPair("PS512");
    const jwt = JWT.createAsymmetric(keyPair, "PS512");
    const token = jwt.sign({ ...payload, exp: JWT.in(1).Minutes });
    expect(token).toBeTypeOf("string");
    const result = jwt.verify(token);
    expect(result).toBeTypeOf("object");
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
    expect(result.payload).toBeTypeOf("object");
  });

  test("verify with ES256 works", () => {
    const keyPair = JWT.genKeyPair("ES256");
    const jwt = JWT.createAsymmetric(keyPair, "ES256");
    const token = jwt.sign({ ...payload, exp: JWT.in(1).Minutes });
    expect(token).toBeTypeOf("string");
    const result = jwt.verify(token);
    expect(result).toBeTypeOf("object");
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
    expect(result.payload).toBeTypeOf("object");
  });

  test("verify with ES384 works", () => {
    const keyPair = JWT.genKeyPair("ES384");
    const jwt = JWT.createAsymmetric(keyPair, "ES384");
    const token = jwt.sign({ ...payload, exp: JWT.in(1).Minutes });
    expect(token).toBeTypeOf("string");
    const result = jwt.verify(token);
    expect(result).toBeTypeOf("object");
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
    expect(result.payload).toBeTypeOf("object");
  });

  test("verify with ES512 works", () => {
    const keyPair = JWT.genKeyPair("ES512");
    const jwt = JWT.createAsymmetric(keyPair, "ES512");
    const token = jwt.sign({ ...payload, exp: JWT.in(1).Minutes });
    expect(token).toBeTypeOf("string");
    const result = jwt.verify(token);
    expect(result).toBeTypeOf("object");
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
    expect(result.payload).toBeTypeOf("object");
  });

  test("verify fails with bad signature", () => {
    const secret = JWT.genHmacKey("HS256");
    const jwt = JWT.createSymmetric(secret, "HS256");
    const token = jwt.sign({ ...payload, exp: JWT.in(1).Minutes });
    expect(token).toBeTypeOf("string");
    const parts = token.split(".");
    parts[2] = "tampered_signature";
    const tampered = parts.join(".");
    const result = jwt.verify(tampered);
    expect(result).toBeTypeOf("object");
    expect(result.valid).toBe(false);
    expect(result.reason).toBeTypeOf("string");
    expect(result.payload).toBeUndefined();
  });

  test("verify respects verifyJwt options (sub check)", () => {
    const secret = JWT.genHmacKey("HS256");
    const jwt = JWT.createSymmetric(secret, "HS256");
    const token = jwt.sign({
      ...payload,
      sub: "expected",
      exp: JWT.in(1).Minutes,
    });
    expect(token).toBeTypeOf("string");
    const result = jwt.verify(token, { sub: "wrong" });
    expect(result).toBeTypeOf("object");
    expect(result.valid).toBe(false);
    expect(result.reason).toBeTypeOf("string");
    expect(result.payload).toBeUndefined();
  });

  test("verify fails if aud does not match expected", () => {
    const secret = JWT.genHmacKey("HS256");
    const jwt = JWT.createSymmetric(secret, "HS256");
    const token = jwt.sign({
      ...payload,
      aud: "client-123",
      exp: JWT.in(1).Minutes,
    });
    expect(token).toBeTypeOf("string");
    const result = jwt.verify(token, { aud: "other-client" });
    expect(result).toBeTypeOf("object");
    expect(result.valid).toBe(false);
    expect(result.reason).toBeTypeOf("string");
    expect(result.payload).toBeUndefined();
  });

  test("verify passes if aud matches expected", () => {
    const secret = JWT.genHmacKey("HS256");
    const jwt = JWT.createSymmetric(secret, "HS256");
    const token = jwt.sign({
      ...payload,
      aud: "client-123",
      exp: JWT.in(1).Minutes,
    });
    expect(token).toBeTypeOf("string");
    const result = jwt.verify(token, { aud: "client-123" });
    expect(result).toBeTypeOf("object");
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
    expect(result.payload).toBeTypeOf("object");
  });

  test("verify fails with aud as array on payload", () => {
    const secret = JWT.genHmacKey("HS256");
    const jwt = JWT.createSymmetric(secret, "HS256");
    const token = jwt.sign({
      ...payload,
      aud: ["client-a", "client-b"],
      exp: JWT.in(1).Minutes,
    });
    expect(token).toBeTypeOf("string");
    const result = jwt.verify(token, { aud: "client-c" });
    expect(result).toBeTypeOf("object");
    expect(result.valid).toBe(false);
    expect(result.reason).toBeTypeOf("string");
    expect(result.payload).toBeUndefined();
  });

  test("verify passes with aud as array on payload", () => {
    const secret = JWT.genHmacKey("HS256");
    const jwt = JWT.createSymmetric(secret, "HS256");
    const token = jwt.sign({
      ...payload,
      aud: ["client-a", "client-b"],
      exp: JWT.in(1).Minutes,
    });
    expect(token).toBeTypeOf("string");
    const result = jwt.verify(token, { aud: "client-b" });
    expect(result).toBeTypeOf("object");
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
    expect(result.payload).toBeTypeOf("object");
  });

  test("verify fails with aud as array", () => {
    const secret = JWT.genHmacKey("HS256");
    const jwt = JWT.createSymmetric(secret, "HS256");
    const token = jwt.sign({
      ...payload,
      aud: "client-c",
      exp: JWT.in(1).Minutes,
    });
    expect(token).toBeTypeOf("string");
    const result = jwt.verify(token, { aud: ["client-a", "client-b"] });
    expect(result).toBeTypeOf("object");
    expect(result.valid).toBe(false);
    expect(result.reason).toBeTypeOf("string");
    expect(result.payload).toBeUndefined();
  });

  test("verify passes with aud as array", () => {
    const secret = JWT.genHmacKey("HS256");
    const jwt = JWT.createSymmetric(secret, "HS256");
    const token = jwt.sign({
      ...payload,
      aud: "client-b",
      exp: JWT.in(1).Minutes,
    });
    expect(token).toBeTypeOf("string");
    const result = jwt.verify(token, { aud: ["client-a", "client-b"] });
    expect(result).toBeTypeOf("object");
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
    expect(result.payload).toBeTypeOf("object");
  });

  test("verify fails with aud as both arrays", () => {
    const secret = JWT.genHmacKey("HS256");
    const jwt = JWT.createSymmetric(secret, "HS256");
    const token = jwt.sign({
      ...payload,
      aud: ["client-a", "client-b"],
      exp: JWT.in(1).Minutes,
    });
    expect(token).toBeTypeOf("string");
    const result = jwt.verify(token, { aud: ["client-c", "client-d"] });
    expect(result).toBeTypeOf("object");
    expect(result.valid).toBe(false);
    expect(result.reason).toBeTypeOf("string");
    expect(result.payload).toBeUndefined();
  });

  test("verify passes with aud as both arrays", () => {
    const secret = JWT.genHmacKey("HS256");
    const jwt = JWT.createSymmetric(secret, "HS256");
    const token = jwt.sign({
      ...payload,
      aud: ["client-a", "client-b"],
      exp: JWT.in(1).Minutes,
    });
    expect(token).toBeTypeOf("string");
    const result = jwt.verify(token, { aud: ["client-a", "client-c"] });
    expect(result).toBeTypeOf("object");
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
    expect(result.payload).toBeTypeOf("object");
  });
});
