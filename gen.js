const crypto = require('crypto');

const N = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551')

function genTestData() {
  const ec = crypto.generateKeyPairSync('ec', {namedCurve:'prime256v1'});
  const ecPublic = ec.publicKey;
  const ecPrivate = ec.privateKey;

  const ecdh = crypto.createECDH('prime256v1');

  ecdh.setPrivateKey(ecPrivate.export({type:'pkcs8',format:'der'}).slice(36, 68));

  let pubUnc = ecdh.getPublicKey();
  let pubUncArray = [].slice.call(pubUnc);

  let pubCmp = crypto.ECDH.convertKey(pubUnc, 'prime256v1', null, null, 'compressed');
  let pubCmpArray = [].slice.call(pubCmp);

  let pubInvArray = [].slice.call(pubCmp); pubInvArray[0] ^= 1;

  let priv = ecdh.getPrivateKey();
  let privArray = [].slice.call(priv);
  while (privArray.length < 32) privArray.unshift(0);

  let pkcs8 = ecPrivate.export({type:'pkcs8',format:'der'});
  let pkcs8Array = [].slice.call(pkcs8);

  let spki = ecPublic.export({type:'spki',format:'der'});
  let spkiArray = [].slice.call(spki);

  let jwk = {
    "crv":"P-256","kty":"EC","ext":true,
    "d":Buffer.from(privArray).toString('base64').substr(0,43).replace(/[/]/g,'_').replace(/[+]/g,'-'),
    "x":pubUnc.slice(1,33).toString('base64').substr(0,43).replace(/[/]/g,'_').replace(/[+]/g,'-'),
    "y":pubUnc.slice(33).toString('base64').substr(0,43).replace(/[/]/g,'_').replace(/[+]/g,'-'),
  };

  let biPrivate = BigInt('0x'+privArray.map(b => b.toString(16).padStart(2,'0')).join(''));
  let biPrivateInv = N - biPrivate;
  let privInvArray = [];
  while (biPrivateInv > 0n) {
    privInvArray.unshift(parseInt(biPrivateInv % 256n));
    biPrivateInv = biPrivateInv / 256n;
  }
  while (privInvArray.length < 32) privInvArray.unshift(0);

  const obj = {"public":{},"private":{}};

  obj.private.raw = privArray;
  obj.private.invert = privInvArray;
  obj.private.pkcs8 = pkcs8Array;
  obj.private.jwk = jwk;

  obj.public.raw = pubCmpArray;
  obj.public.uncompressed = pubUncArray;
  obj.public.invert = pubInvArray;
  obj.public.spki = spkiArray;
  obj.public.jwk = JSON.parse(JSON.stringify(jwk));
  delete obj.public.jwk.d;

  console.log(JSON.stringify(obj));
}

for (let i = 0; i < 500; ++i) {
  genTestData();
}
