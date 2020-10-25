var $P = secp256r1(), $C = $P._curve;

var sha256 = function(data, callback) {
  let crypto, subtle;
  if (typeof window === "object"
  && typeof (crypto = window.crypto) === "object"
  && typeof (subtle = crypto.subtle || cypto.webkitSubtle) === "object") {
    // Set up Web Crypto API handler.
    sha256 = function(data, callback) {
      subtle.digest({name:'SHA-256'},data).then(callback);
    };
  } else if (typeof require === "function"
  && typeof (crypto = require("crypto")) === "object"
  && typeof crypto.createHash === "function") {
    // Set up Node.js handler.
    sha256 = function(data, callback) {
      const buf = crypto.createHash('sha256').update(data).digest();
      setImmediate(function(){callback((new Uint8Array(buf)).buffer)});
    };
  } else {
    throw new Error("Couldn't find SHA256 implementation");
  }
  sha256(data, callback);
}

function biToU256(bi) {
  var bytes = bi._toByteArray();
  if (!bytes[0]) { bytes.shift(); }
  while (bytes.length < 32) { bytes.unshift(0); }
  return bytes;
}

function u256ToBi(u256) {
  //return new BigInteger((u256[0] > 127 ? [0] : []).concat(u256));
  return new BigInteger([0].concat(toByteArray(u256)));
}

function toByteArray(x) {
  if (x instanceof ArrayBuffer) { x = new Uint8Array(x); }
  return Array.prototype.slice.call(x);
}

function decompress(x, yEven) {
  var beta = x._multiply(x._square()._add($C.a))._add($C.b)._sqrt();
  if (beta == null) throw new Error("Invalid point compression");
  x = beta.x;
  if (x._testBit(0) != yEven) { // Use the other root
    beta = $C._fromBigInteger($C.q._subtract(x));
  }
  return beta;
}

function encodePublic(p, formatter) {
  var ary = toByteArray(p), type = ary.shift(), n = ary.length, x, y;
  if (n !== 32 && n !== 64) { return null; }
  x = $C._fromBigInteger(new BigInteger([0].concat(ary.slice(0,32))));
  if ((type & 0xfc) === 4 && n === 64) {
    y = $C._fromBigInteger(new BigInteger([0].concat(ary.slice(32))));
  } else if ((type & 0xfe) === 2 && n === 32) {
    y = decompress(x, !!(type & 1));
  } else {
    return null;
  }
  return formatter(x.x, y.x);
}

function encodePrivate(d, formatter) {
  var k = u256ToBi(d);
  p = $P.g._multiply(k);
  return formatter(k, p._getX().x, p._getY().x);
};

if (WITH_JWK) {
  //*
  function _map(c) {
    return ({
      '+': '-',
      '-': '+',
      '/': '_',
      '_': '/'
    })[c] || c;
  }

  function encBi256(bi) {
    return btoa(String.fromCharCode.apply(0, biToU256(bi)))
           .replace(/./g, _map)
           .substr(0, 43);
  }

  function decJwk256(st) {
    return atob(st.replace(/./g, _map)+'=')
           .split('')
           .map(function(c){return c.charCodeAt()});
  }
  /*///
  function uint6ToB64(nUint6) {
    return nUint6 < 26 ? nUint6 + 65
         : nUint6 < 52 ? nUint6 + 71
         : nUint6 < 62 ? nUint6 - 4
         : nUint6 === 62 ? 45
         : nUint6 === 63 ? 95
         : -1;
  }

  function d2c(d) { return lut[d]; };
  function c2d(c) { return (c > 44 && c < 123) ? lut[c+20] : -1 }

  function encBi256(bi) {
    var aBytes = biToU256(bi), sB64Enc = "";
    for (var nMod3, nLen = aBytes.length, nUint24 = 0, nIdx = 0; nIdx < nLen; nIdx++) {
      nMod3 = nIdx % 3;
      nUint24 |= aBytes[nIdx] << (16 >> nMod3 & 24);
      if (nMod3 === 2 || aBytes.length - nIdx === 1) {
        sB64Enc += String.fromCharCode(
          d2c(nUint24 >> 18 & 63),
          d2c(nUint24 >> 12 & 63),
          d2c(nUint24 >> 6 & 63),
          d2c(nUint24 & 63)
        );
        nUint24 = 0;
      }
    }

    return sB64Enc.substring(0,43);
  }

  function decJwk256(st) {
    var ary = new Array(32), p = 0, n = 0, i;
    for (i = 0; i < 43; ++i) {
      n = (n << 6) + c2d(st.charCodeAt(i));
      if (i % 4 == 3) {
        ary[p++] = n >> 16;
        ary[p++] = (n >> 8) & 255;
        ary[p++] = n & 255;
        n = 0;
      }
    }
    ary[p++] = n >> 10;
    ary[p++] = (n >> 2) & 255;
    return ary;
  }

  var lut = (function(lut, i) {
    for (i = 0; i < 143; ++i) { lut[i] = uint6ToB64(i); }
    for (i = 0; i <  64; ++i) { lut[lut[i] + 20] = i; }
    return lut;
  })(new Int8Array(143));
  //*/

  if (WITH_PRIVATE && WITH_EXPORT) {
    exports['jwkToPrivate'] = function(jwk) {
      return new Uint8Array(decJwk256(jwk["d"]));
    };
  }

  if (WITH_PUBLIC && WITH_EXPORT) {
    exports['jwkToPublic'] = function(jwk) {
      var bytes = decJwk256(jwk["x"]);
      bytes.unshift(2 ^ (decJwk256(jwk["y"])[31] & 1));
      return new Uint8Array(bytes);
    };
  }

  if (WITH_PRIVATE && WITH_IMPORT) {
    exports['privateToJwk'] = function(d) {
      return encodePrivate(d, function(d, x, y) {
        return {
          "crv":"P-256","kty":"EC","ext":true,
          "d":encBi256(d),
          "x":encBi256(x),
          "y":encBi256(y)
        };
      });
    };
  }

  if (WITH_PUBLIC && WITH_IMPORT) {
    exports['publicToJwk'] = function(p) {
      return encodePublic(p, function(x, y) {
        return {
          "crv":"P-256","kty":"EC","ext":true,
          "x":encBi256(x),
          "y":encBi256(y)
        };
      });
    };
  }
}//WITH_JWK

if (WITH_ASN1) {

  var $asn1pub = [
    // SEQUENCE (19 bytes)
    48, 19,
    // OBJECT (id-ecPublicKey)
    6, 7,
    42, 134, 72, 206, 61, 2, 1,
    // OBJECT (prime256v1)
    6, 8,
    42, 134, 72, 206, 61, 3, 1, 7
  ];

  if (WITH_PRIVATE && WITH_EXPORT) {
    exports['pkcs8ToPrivate'] = function(ab) {
      return (new Uint8Array(ab)).slice(36, 68);
    }
  }

  if (WITH_PUBLIC && WITH_EXPORT) {
    exports['spkiToPublic'] = function(ab) {
      var pub = (new Uint8Array(ab)).slice(26);
      //pub[0] = pub[64] & 1 ? 3 : 2;
      pub[0] = (pub[64] & 1) ^ 2;
      return pub.slice(0, 33);
    }
  }

  if (WITH_PRIVATE && WITH_IMPORT) {
    exports['privateToPkcs8'] = function(d) {
      return encodePrivate(d, function(d, x, y) {
        return (new Uint8Array([
          // SEQUENCE (135 bytes)
          48, 129, 135,
          // INTEGER (0)
          2, 1, 0
        ]
        .concat($asn1pub)
        .concat([
          // OCTET STRING (109 bytes)
          4, 109,
          // SEQUENCE (107 bytes)
          48, 107,
          // INTEGER (1)
          2, 1,
          // OCTET STRING (32 bytes)
          1, 4, 32
        ])
        .concat(biToU256(d))
        .concat([
          // cont (1)
          161, 68,
          // BIT STRING (66 bytes)
          3, 66,
          // ???
          0,
          // public key
          4
        ])
        .concat(biToU256(x))
        .concat(biToU256(y)))).buffer;
      });
    };
  }

  if (WITH_PUBLIC && WITH_IMPORT) {
    exports['publicToSpki'] = function(p) {
      return encodePublic(p, function(x, y) {
        return (new Uint8Array([
            // SEQUENCE (89 bytes)
            48, 89
          ]
          .concat($asn1pub)
          .concat([
            // BIT STRING (66 bytes)
            3, 66,
            // ???
            0,
            // public key
            4
          ])
          .concat(biToU256(x))
          .concat(biToU256(y))
        )).buffer;
      });
    };
  }
}//WITH_ASN1

if (WITH_PRIVATE) {
  exports['invertPrivate'] = function(d) {
    var k = u256ToBi(d);
    k = $P.n._subtract(k);
    return biToU256(k);
  }
}

if (WITH_PRIVATE && WITH_IMPORT) {
  function checkPrivate(d) {
    var k = u256ToBi(d);
    if (k._compareTo($P.n) >= 0 || k._equals(BigInteger._ZERO)) {
      return false;
    } else {
      return true;
    }
  }
  exports['checkPrivate'] = checkPrivate;
}

if (WITH_PRIVATE && WITH_IMPORT && WITH_SEED) {
  function seedToPrivate(seed, callback) {
    sha256(seed, function(ab) {
      if (checkPrivate(ab)) {
        callback(ab);
      } else { // example seed: Q-1MC%07aIIM7**G63hVu40]dt1CPefl
        seedToPrivate(new Uint8Array(toByteArray(ab).concat(toByteArray(seed))), callback);
      }
    });
  }
  exports['seedToPrivate'] = seedToPrivate;
}

function tracePrototype(label, _class) {
  const proto = _class.prototype;
  const called = new Map();
  const size = new Map();
  let hook = function(o, p) {
    let ref = o[p];
    if (typeof ref === 'function') {
      called.set(p, 0);
      size.set(p, ref.toString().length);
      o[p] = function() {
          called.set(p, called.get(p) + 1);
        if (called.get(p) >= 1000) {
          o[p] = ref;
        }
        var E = Array.from(called.entries());
        E.sort((a, b) => a[1] - b[1]);
        console.log(label, E.map(x => x[0]+':'+size.get(x[0])+':'+x[1]).join(' '));
        return ref.apply(this, arguments);
      }
    }
  };
  for (const p of Object.getOwnPropertyNames(proto)) {
    if (p[0] == '_') hook(proto, p);
  }
}

//tracePrototype('BigInteger', BigInteger);
