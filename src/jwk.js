'use strict';

function parseJwk(jwk) {
  if (typeof jwk !== 'object' || jwk === null) {
    throw new TypeError('parseJwk expects a JSON object');
  }
  if (!('kty' in jwk) || jwk.kty === undefined) {
    throw new TypeError('parseJwk expects a kty field');
  }
  const kty = jwk.kty;
  if (kty === 'RSA') {
    return {
      type: 'rsa',
      alg: jwk.alg,
      kty: jwk.kty,
    };
  }
  if (kty === 'EC') {
    return {
      type: 'ec',
      alg: jwk.alg,
      crv: jwk.crv,
      kty: jwk.kty,
    };
  }
  if (kty === 'OKP') {
    return {
      type: 'okp',
      alg: jwk.alg,
      crv: jwk.crv,
      kty: jwk.kty,
    };
  }
  if (kty === 'SYMMETRIC') {
    return {
      type: 'symmetric',
      alg: jwk.alg,
      k: jwk.k,
      kty: jwk.kty,
    };
  }
  return { type: 'unknown', kty };
}

module.exports = { parseJwk };