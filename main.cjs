// import { JWT } from "@bepalo/jwt";
const { JWT } = require("@bepalo/jwt");

const payload = { userId: 123, role: "admin" };
// const alg = "HS256"
// const key = JWT.genHmacKey(alg);
// const jwt = JWT.create(key, alg);
// for (const alg of ["HS256", "HS384", "HS512", "ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]) {
for (const alg of ["ES256", "ES384", "ES512"]) {
  const key = JWT.genKey(alg);
  const jwt = JWT.create(key, alg);
  const token = jwt.sign({
    ...payload,
    exp: JWT.in(1).Minutes,
    iat: JWT.now(),
    jti: "jti-1234",
    iss: "auth-server",
    sub: "session",
    aud: ["auth-client-a", "auth-client-b"]
  })
  const verified = jwt.verifySignature(token);
  const decoded = jwt.verify(token);
  console.log(key.publicKey, key.privateKey)
  console.log({ alg, token, len: token.length, verified, decoded });
}
// console.log({ token, valid, decoded });