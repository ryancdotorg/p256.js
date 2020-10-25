// Named EC curves

// Requires ec.js, jsbn.js, and jsbn2.js

// ----------------
// X9ECParameters

// constructor
function X9ECParameters(curve,g,n,h) {
    this._curve = curve;
    this.g = g;
    this.n = n;
    this.h = h;
}

function x9getCurve() {
    return this._curve;
}

function x9getG() {
    return this.g;
}

function x9getN() {
    return this.n;
}

function x9getH() {
    return this.h;
}

//X9ECParameters.prototype._getCurve = x9getCurve;
//X9ECParameters.prototype._getG = x9getG;
//X9ECParameters.prototype._getN = x9getN;
//X9ECParameters.prototype._getH = x9getH;

// ----------------
// SECNamedCurves

//function fromHex(s) { return new BigInteger(s, 16); }

function secp256r1() {
    // p = 2^224 (2^32 - 1) + 2^192 + 2^96 - 1
//    var p = fromHex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
//    var a = fromHex("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc");
//    var b = fromHex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");
//    var n = fromHex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    var p = new BigInteger([0,255,255,255,255,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,255,255,255,255,255,255,255,255,255,255,255,255]);
    var a = new BigInteger([0,255,255,255,255,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,255,255,255,255,255,255,255,255,255,255,255,252]);
    var b = new BigInteger([90,198,53,216,170,58,147,231,179,235,189,85,118,152,134,188,101,29,6,176,204,83,176,246,59,206,60,62,39,210,96,75]);
    var n = new BigInteger([0,255,255,255,255,0,0,0,0,255,255,255,255,255,255,255,255,188,230,250,173,167,23,158,132,243,185,202,194,252,99,37,81]);
    var h = BigInteger._ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = new ECPointFp(curve,
//        curve._fromBigInteger(fromHex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")),
//        curve._fromBigInteger(fromHex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"))
        curve._fromBigInteger(new BigInteger([107,23,209,242,225,44,66,71,248,188,230,229,99,164,64,242,119,3,125,129,45,235,51,160,244,161,57,69,216,152,194,150])),
        curve._fromBigInteger(new BigInteger([79,227,66,226,254,26,127,155,142,231,235,74,124,15,158,22,43,206,51,87,107,49,94,206,203,182,64,104,55,191,81,245]))
    );
    //return new X9ECParameters(curve, G, n, h);
    return {_curve: curve, g: G, n: n, h: h};
}
