const { parseDer, InvalidAssetError, DecompressionError } = require('./der');
const { OID_TABLE, CLASSICAL_OIDS } = require('./constants');

// decodeOid is already in lib/spki.js, let me verify its signature
function decodeOid(buf) {
  if (buf.length === 0) throw new InvalidAssetError('empty OID');
  const first = buf[0];
  const arcs = [Math.floor(first / 40), first % 40];
  let value = 0;
  for (let i = 1; i < buf.length; i++) {
    const b = buf[i];
    value = (value << 7) | (b & 0x7f);
    if ((b & 0x80) === 0) {
      arcs.push(value);
      value = 0;
    }
  }
  if (buf[buf.length - 1] & 0x80) throw new InvalidAssetError('truncated OID arc');
  return arcs.join('.');
}

function decodeBitString(node) {
  if (node.tag !== 0x03) throw new InvalidAssetError('expected BIT STRING');
  if (node.content.length === 0) throw new InvalidAssetError('empty BIT STRING');
  return Buffer.from(node.content.subarray(1));
}

// EC namedCurve OIDs carried in AlgorithmIdentifier.parameters -> paramSet name.
const NAMED_CURVE_TO_PARAMSET = {
  '1.2.840.10045.3.1.7': 'P-256',
  '1.3.132.0.34': 'P-384',
};

// RSA public key DER length -> paramSet name (includes leading 0x00 + INTEGER tag/len).
const RSA_KEY_BYTES_TO_PARAMSET = {
  270: 'RSA-2048',
  398: 'RSA-3072',
  526: 'RSA-4096',
};

function familyAndParamSet(oid, parameters, keyBytes) {
  const pq = OID_TABLE[oid];
  if (pq) {
    let family;
    if (pq.primitive === 'kem') {
      family = 'ML-KEM';
    } else if (pq.parameterSetIdentifier.startsWith('ML-DSA')) {
      family = 'ML-DSA';
    } else if (pq.parameterSetIdentifier.startsWith('SLH-DSA')) {
      family = 'SLH-DSA';
    } else {
      family = pq.primitive;
    }
    return { family, paramSet: pq.parameterSetIdentifier };
  }

  const classical = CLASSICAL_OIDS[oid];
  if (!classical) throw new InvalidAssetError(`unknown OID ${oid}`);

  if (oid === '1.2.840.10045.2.1') {
    // id-ecPublicKey: parameters carry the namedCurve OID
    const curveOid = decodeOid(parameters);
    const paramSet = NAMED_CURVE_TO_PARAMSET[curveOid];
    if (!paramSet) throw new InvalidAssetError(`unsupported EC curve ${curveOid}`);
    return { family: 'EC', paramSet };
  }

  if (oid === '1.2.840.113549.1.1.1') {
    // rsaEncryption: paramSet derived from key length
    const paramSet = RSA_KEY_BYTES_TO_PARAMSET[keyBytes.length];
    if (!paramSet) throw new InvalidAssetError(`unsupported RSA key size ${keyBytes.length} bytes`);
    return { family: 'RSA', paramSet };
  }

  if (oid === '1.3.101.112') return { family: 'EdDSA', paramSet: 'Ed25519' };
  if (oid === '1.3.101.113') return { family: 'EdDSA', paramSet: 'Ed448' };

  throw new InvalidAssetError(`unsupported classical OID ${oid}`);
}

function parseSpki(der) {
  if (!Buffer.isBuffer(der) && typeof der !== 'string' && !(der instanceof Uint8Array) && !Array.isArray(der)) {
    const shown = der === null ? 'null' : typeof der;
    throw new InvalidAssetError(`parseSpki expects Buffer/Uint8Array/string DER input, got ${shown}`);
  }
  const buf = Buffer.isBuffer(der) ? der : Buffer.from(der);
  const root = parseDer(buf);
  if (root.tag !== 0x30) throw new InvalidAssetError('SubjectPublicKeyInfo must be a SEQUENCE');

  const children = root.children || [];
  if (children.length < 2) throw new InvalidAssetError('SubjectPublicKeyInfo needs algorithm + subjectPublicKey');

  const algNode = children[0];
  if (algNode.tag !== 0x30) throw new InvalidAssetError('algorithm must be AlgorithmIdentifier SEQUENCE');

  const algChildren = algNode.children || [];
  if (algChildren.length < 1) throw new InvalidAssetError('empty AlgorithmIdentifier');
  const oidNode = algChildren[0];
  if (oidNode.tag !== 0x06) throw new InvalidAssetError('expected algorithm OID');
  const oid = decodeOid(oidNode.content);

  let parameters = Buffer.alloc(0);
  if (algChildren.length >= 2) {
    parameters = Buffer.from(algChildren[1].content || Buffer.alloc(0));
  }

  const spkiNode = children[1];
  const keyBytes = decodeBitString(spkiNode);
  if (keyBytes.length === 0) throw new InvalidAssetError('empty subjectPublicKey BIT STRING');

  const { family, paramSet } = familyAndParamSet(oid, parameters, keyBytes);

  return { oid, keyBytes, family, paramSet };
}

module.exports = { parseSpki, InvalidAssetError };