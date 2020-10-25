require('./b64poly.js');

const testData = [
  {"rawPrivate":[216,144,175,22,179,211,124,201,11,157,226,2,154,240,232,250,1,68,202,148,113,181,63,146,52,100,209,163,92,76,166,43],"jwk":{"crv":"P-256","d":"2JCvFrPTfMkLneICmvDo-gFEypRxtT-SNGTRo1xMpis","ext":true,"kty":"EC","x":"RUnYAOiJnLw4KaZ6kvxrRkTIvkdEiUWMv9UmmrvO7vM","y":"_9IrGfeWnsJkAKg0iwuywcmbqc3qhWgRHVnXVcd_P8Y"}},
  {"rawPrivate":[117,107,1,38,180,88,111,199,109,201,61,187,97,89,63,151,152,51,211,204,165,140,246,235,238,254,224,89,129,107,57,170],"jwk":{"crv":"P-256","d":"dWsBJrRYb8dtyT27YVk_l5gz08yljPbr7v7gWYFrOao","ext":true,"kty":"EC","x":"I-TUge_aFQ3esPMLnnRBw9T9rsVhP4xIGLkLifqNfwc","y":"8ooOEOpjZwjZ86Gpz_qEGShZE7_MTifSBkHeN6Hg_oo"}},
  {"rawPrivate":[139,35,114,131,40,173,17,199,135,85,49,53,132,139,83,0,54,155,178,130,142,198,28,182,200,164,69,81,145,189,3,99],"jwk":{"crv":"P-256","d":"iyNygyitEceHVTE1hItTADabsoKOxhy2yKRFUZG9A2M","ext":true,"kty":"EC","x":"_iU-HyEtj-E6Sp7eoyhPIESDJTRrV_4mJ4R7QnIR2y0","y":"stTcHj_1Xi9s7zPkV_xjqm7aSugAE4KEGqwSJNzpn1c"}},
  {"rawPrivate":[230,172,122,19,143,188,85,2,248,52,217,12,108,181,79,25,191,189,247,207,214,153,30,37,9,201,25,252,183,74,170,222],"jwk":{"crv":"P-256","d":"5qx6E4-8VQL4NNkMbLVPGb-998_WmR4lCckZ_LdKqt4","ext":true,"kty":"EC","x":"sBSn8CvBYlIo1qABpilZLUc0MtaVyRkHNkNxTPStsN0","y":"Wu6qsgonsUHzopmt4NJ-jixZDEtW9xFe7HozUHgmFkM"}},
  {"rawPrivate":[255,255,255,255,0,0,0,0,255,255,255,255,255,255,255,255,188,230,250,173,167,23,158,132,243,185,202,194,252,99,37,80],"jwk":{"crv":"P-256","kty":"EC","ext":true,"d":"_____wAAAAD__________7zm-q2nF56E87nKwvxjJVA","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"sBy9HAHlgGVxGBS1g_Bh6dQxzKmUzqExNEm_l8hArgo"}},
//  {"rawPrivate":[255,255,255,255,0,0,0,0,255,255,255,255,255,255,255,255,188,230,250,173,167,23,158,132,243,185,202,194,252,99,37,90],"jwk":{"crv":"P-256","kty":"EC","ext":true,"d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAk","x":"6mjXtv7fC3GHiTjVHXH4cp4Ky4wsbfiz156KS5CUnuA","y":"KidEyXLJ_OeHAUqWSo6gyE1xT-qk3oI_6FoiSk3QSPo"}},
  {"rawPrivate":[128,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1],"jwk":{"crv":"P-256","kty":"EC","ext":true,"d":"gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE","x":"-AgDPBwGDEDbS3b4xi3I8WqjFpUto9VM-sQ2-fgVFho","y":"TPTnkjyPzDVeu67dryZh0ag8v4NqZ1o_6XnMhkaov3I"}},
  {"rawPrivate":[1],"jwk":{"crv":"P-256","kty":"EC","ext":true,"d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"}},
  {"rawPrivate":[2],"jwk":{"crv":"P-256","kty":"EC","ext":true,"d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI","x":"fPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI_EdmmXg","y":"B3dVENuO0EApPZrGn3Qw27p9reY86YIpngS3nSJ4c9E"}},
  {"rawPrivate":[3],"jwk":{"crv":"P-256","kty":"EC","ext":true,"d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM","x":"Xsvk0aYzCkTI9--VHUvxZebGtyHvramF-0FmG8bn_Ww","y":"hzRkDEmY_343SwbOGmSi7NgqsDY4T7g9mnmxJ6J9UDI"}},
];

const vectors = (function(){
  const fs = require('fs');
  const zlib = require('zlib');
  const readline = require('readline');

  const vectors = [];

  function loadVectors(file) {
    const br = fs.readFileSync(file);
    const ndjson = zlib.brotliDecompressSync(br).toString();
    for (const line of ndjson.split(/\n/)) {
      if (line) {
        let vector = JSON.parse(line);
        vectors.push(vector);
      }
    }
  }

  loadVectors('testvectors.ndjson.br');

  return vectors;
})();

const files = (function(){
  const fs = require('fs');
  const dir = fs.opendirSync('.');
  const files = [];
  let file = null;
  while (file = dir.readSync()) {
    if (file.name.match(/^p256([.].+)?[.]js$/)) {
      files.push(file.name);
    }
  }
  dir.close();
  return files.sort((a, b) => a === 'p256.js' ? -1 : b === 'p256.js' ? 1 : a.localeCompare(b));
})();

for (const file of files) {
  const P256 = require('./'+file);

  console.log('===== ' + file + ' =====');

  const passed = {};

  function runVectors(name, fn) {
    if (P256[name]) {
      passed[name] = true;

      for (let i = 0; i < vectors.length; ++i) {
        const vector = vectors[i];
        const result = fn(vector, i);
        if (typeof result !== 'boolean') {
          throw new Error(`Test function for {name} did not return a boolean!`);
        }
        passed[name] = result && passed[name];
      }
      console.log((passed[name] ? '\x1b[32;1mPASS\x1b[0m' : '\x1b[31;1mFAIL\x1b[0m') + ' ' + name);
    }
  }

  runVectors('privateToJwk', function(V, I) {
    let okay = true;
    const ref = V.private.jwk;
    const jwk = P256.privateToJwk(V.private.raw);
    for (const p of Object.getOwnPropertyNames(ref)) {
      if (jwk[p] != ref[p]) {
        okay = false;
        console.log(I, p, jwk[p], ref[p]);
      }
    }
    return okay;
  });

  runVectors('privateToPkcs8', function(V, I) {
    let okay = true;
    const ref = Buffer.from(V.private.pkcs8).toString('hex');
    const pkcs8 = Buffer.from(P256.privateToPkcs8(V.private.raw)).toString('hex');
    if (pkcs8 != ref) {
      okay = false;
      console.log(Buffer.from(V.private.raw).toString('hex'));
      console.log(I, pkcs8, ref);
    }
    return okay;
  });

  runVectors('publicToJwk', function(V, I) {
    let okay = true
    const ref = V.public.jwk;
    const jwk1 = P256.publicToJwk(V.public.uncompressed);
    const jwk2 = P256.publicToJwk(V.public.raw);
    for (const p of Object.getOwnPropertyNames(ref)) {
      if (jwk1[p] != ref[p]) {
        okay = false;
        console.log(I, '(uncompressed)', p, jwk1[p], ref[p]);
      }
      if (jwk2[p] != ref[p]) {
        okay = false;
        console.log(I, '(compressed)  ', p, jwk2[p], ref[p]);
      }
    }
    return okay;
  });

  runVectors('publicToSpki', function(V, I) {
    let okay = true
    const ref = Buffer.from(V.public.spki).toString('hex');
    const spki1 = Buffer.from(P256.publicToSpki(V.public.uncompressed)).toString('hex');
    const spki2 = Buffer.from(P256.publicToSpki(V.public.raw)).toString('hex');
    if (spki1 != ref) {
      okay = false;
      console.log(I, '(uncompressed)', spki1, ref);
    }
    if (spki2 != ref) {
      okay = false;
      console.log(I, '(compressed)  ', spki2, ref);
    }
    return okay;
  });

  runVectors('jwkToPrivate', function(V, I) {
    let okay = true;
    const ref = Buffer.from(V.private.raw).toString('hex');
    const raw = Buffer.from(P256.jwkToPrivate(V.private.jwk)).toString('hex');
    if (raw != ref) {
      okay = false;
      console.log(I, raw, ref);
    }
    return okay;
  });

  runVectors('jwkToPublic', function(V, I) {
    let okay = true;
    const ref = Buffer.from(V.public.raw).toString('hex');
    const raw = Buffer.from(P256.jwkToPublic(V.public.jwk)).toString('hex');
    if (raw != ref) {
      okay = false;
      console.log(I, raw, ref);
    }
    return okay;
  });

  runVectors('pkcs8ToPrivate', function(V, I) {
    let okay = true;
    const ref = Buffer.from(V.private.raw).toString('hex');
    const raw = Buffer.from(P256.pkcs8ToPrivate(V.private.pkcs8)).toString('hex');
    if (raw != ref) {
      okay = false;
      console.log(I, raw, ref);
    }
    return okay;
  });

  runVectors('spkiToPublic', function(V, I) {
    let okay = true;
    const ref = Buffer.from(V.public.raw).toString('hex');
    const raw = Buffer.from(P256.spkiToPublic(V.public.spki)).toString('hex');
    if (raw != ref) {
      okay = false;
      console.log(I, raw, ref);
    }
    return okay;
  });

  runVectors('invertPrivate', function(V, I) {
    let okay = true;
    const ref = Buffer.from(V.private.invert).toString('hex');
    const invert = Buffer.from(P256.invertPrivate(V.private.raw)).toString('hex');
    if (invert != ref) {
      okay = false;
      console.log(I, invert, ref);
    }
    return okay;
  });

  for (const p of Object.getOwnPropertyNames(P256).sort()) {
    if (typeof P256[p] === "function" && !passed.hasOwnProperty(p)) {
      console.log('\x1b[33;1mSKIP\x1b[0m', p);
    }
  }
  console.log();
}
