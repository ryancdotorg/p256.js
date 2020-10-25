// Basic Javascript Elliptic Curve implementation
// Ported loosely from BouncyCastle's Java EC code
// Only Fp curves implemented for now

// Requires jsbn.js and jsbn2.js

// ----------------
// ECFieldElementFp

// constructor
function ECFieldElementFp(q,x) {
    this.x = x;
    // TODO if(x._compareTo(q) >= 0) error
    this.q = q;
}

function feFpEquals(other) {
    if(other == this) return true;
    return (this.q._equals(other.q) && this.x._equals(other.x));
}

function feFpToBigInteger() {
    return this.x;
}

function feFpNegate() {
    return new ECFieldElementFp(this.q, this.x._negate()._mod(this.q));
}

function feFpAdd(b) {
    return new ECFieldElementFp(this.q, this.x._add(b.x)._mod(this.q));
}

function feFpSubtract(b) {
    return new ECFieldElementFp(this.q, this.x._subtract(b.x)._mod(this.q));
}

function feFpMultiply(b) {
    return new ECFieldElementFp(this.q, this.x._multiply(b.x)._mod(this.q));
}

function feFpSquare() {
    return new ECFieldElementFp(this.q, this.x._square()._mod(this.q));
}

function feFpDivide(b) {
    return new ECFieldElementFp(this.q, this.x._multiply(b.x._modInverse(this.q))._mod(this.q));
}

// From Kai Elvin's ec2.js https://github.com/kaielvin/jsbn-ec-point-compression
function feFpSqrt() {
    var z = new ECFieldElementFp(this.q,this.x._modPow(this.q._shiftLeft(-2)._add(BigInteger._ONE),this.q));
    return z._square()._equals(this) ? z : null;
}

/*
ECFieldElementFp.prototype = {
  _equals: feFpEquals,
  _toBigInteger: feFpToBigInteger,
  _negate: feFpNegate,
  _add: feFpAdd,
  _multiply: feFpMultiply,
  _square: feFpSquare,
  _sqrt: feFpSqrt
};
*/

ECFieldElementFp.prototype._equals = feFpEquals;
//ECFieldElementFp.prototype._toBigInteger = feFpToBigInteger;
ECFieldElementFp.prototype._negate = feFpNegate;
ECFieldElementFp.prototype._add = feFpAdd;
//ECFieldElementFp.prototype._subtract = feFpSubtract;
ECFieldElementFp.prototype._multiply = feFpMultiply;
ECFieldElementFp.prototype._square = feFpSquare;
//ECFieldElementFp.prototype._divide = feFpDivide;
ECFieldElementFp.prototype._sqrt = feFpSqrt;

// ----------------
// ECPointFp

// constructor
function ECPointFp(curve,x,y,z) {
    this._curve = curve;
    this.x = x;
    this.y = y;
    // Projective coordinates: either zinv == null or z * zinv == 1
    // z and zinv are just BigIntegers, not fieldElements
    if(z == null) {
      this.z = BigInteger._ONE;
    }
    else {
      this.z = z;
    }
    this.zinv = null;
    //TODO: compression flag
}

function pointFpGetX() {
    if(this.zinv == null) {
      this.zinv = this.z._modInverse(this._curve.q);
    }
    var r = this.x.x._multiply(this.zinv);
    this._curve._reduce(r);
    return this._curve._fromBigInteger(r);
}

function pointFpGetY() {
    if(this.zinv == null) {
      this.zinv = this.z._modInverse(this._curve.q);
    }
    var r = this.y.x._multiply(this.zinv);
    this._curve._reduce(r);
    return this._curve._fromBigInteger(r);
}

function pointFpEquals(other) {
    if(other == this) return true;
    if(this._isInfinity()) return other._isInfinity();
    if(other._isInfinity()) return this._isInfinity();
    var u, v;
    // u = Y2 * Z1 - Y1 * Z2
    u = other.y.x._multiply(this.z)._subtract(this.y.x._multiply(other.z))._mod(this._curve.q);
    if(!u._equals(BigInteger._ZERO)) return false;
    // v = X2 * Z1 - X1 * Z2
    v = other.x.x._multiply(this.z)._subtract(this.x.x._multiply(other.z))._mod(this._curve.q);
    return v._equals(BigInteger._ZERO);
}

function pointFpIsInfinity() {
    if((this.x == null) && (this.y == null)) return true;
    return this.z._equals(BigInteger._ZERO) && !this.y.x._equals(BigInteger._ZERO);
}

function pointFpNegate() {
    return new ECPointFp(this._curve, this.x, this.y._negate(), this.z);
}

function pointFpAdd(b) {
    /* NEVER HIT
    if(this._isInfinity()) return b;
    if(b._isInfinity()) return this;
    */

    // u = Y2 * Z1 - Y1 * Z2
    var u = b.y.x._multiply(this.z)._subtract(this.y.x._multiply(b.z))._mod(this._curve.q);
    // v = X2 * Z1 - X1 * Z2
    var v = b.x.x._multiply(this.z)._subtract(this.x.x._multiply(b.z))._mod(this._curve.q);

    /* NEVER HIT
    if(BigInteger._ZERO._equals(v)) {
        if(BigInteger._ZERO._equals(u)) {
            return this._twice(); // this == b, so double
        }
        return this._curve._getInfinity(); // this = -b, so infinity
    }
    */

    var x1 = this.x.x;
    var y1 = this.y.x;
    var x2 = b.x.x;
    var y2 = b.y.x;

    var v2 = v._square();
    var v3 = v2._multiply(v);
    var x1v2 = x1._multiply(v2);
    var zu2 = u._square()._multiply(this.z);

    // x3 = v * (z2 * (z1 * u^2 - 2 * x1 * v^2) - v^3)
    var x3 = zu2._subtract(x1v2._shiftLeft(1))._multiply(b.z)._subtract(v3)._multiply(v)._mod(this._curve.q);
    // y3 = z2 * (3 * x1 * u * v^2 - y1 * v^3 - z1 * u^3) + u * v^3
    var y3 = x1v2._multiply(BigInteger._THREE)._multiply(u)._subtract(y1._multiply(v3))._subtract(zu2._multiply(u))._multiply(b.z)._add(u._multiply(v3))._mod(this._curve.q);
    // z3 = v^3 * z1 * z2
    var z3 = v3._multiply(this.z)._multiply(b.z)._mod(this._curve.q);

    return new ECPointFp(this._curve, this._curve._fromBigInteger(x3), this._curve._fromBigInteger(y3), z3);
}

function pointFpTwice() {
    /* NEVER HIT
    if(this._isInfinity()) return this;
    if(this.y.x._signum() == 0) return this._curve._getInfinity();
    */

    // TODO: optimized handling of constants
    var x1 = this.x.x;
    var y1 = this.y.x;

    var y1z1 = y1._multiply(this.z);
    var y1sqz1 = y1z1._multiply(y1)._mod(this._curve.q);
    var a = this._curve.a.x;

    // w = 3 * x1^2 + a * z1^2
    var w = x1._square()._multiply(BigInteger._THREE);
    if(!BigInteger._ZERO._equals(a)) {
      w = w._add(this.z._square()._multiply(a));
    }
    w = w._mod(this._curve.q);
    //this._curve._reduce(w);
    // x3 = 2 * y1 * z1 * (w^2 - 8 * x1 * y1^2 * z1)
    var x3 = w._square()._subtract(x1._shiftLeft(3)._multiply(y1sqz1))._shiftLeft(1)._multiply(y1z1)._mod(this._curve.q);
    // y3 = 4 * y1^2 * z1 * (3 * w * x1 - 2 * y1^2 * z1) - w^3
    var y3 = w._multiply(BigInteger._THREE)._multiply(x1)._subtract(y1sqz1._shiftLeft(1))._shiftLeft(2)._multiply(y1sqz1)._subtract(w._square()._multiply(w))._mod(this._curve.q);
    // z3 = 8 * (y1 * z1)^3
    var z3 = y1z1._square()._multiply(y1z1)._shiftLeft(3)._mod(this._curve.q);

    return new ECPointFp(this._curve, this._curve._fromBigInteger(x3), this._curve._fromBigInteger(y3), z3);
}

// Simple NAF (Non-Adjacent Form) multiplication algorithm
// TODO: modularize the multiplication algorithm
function pointFpMultiply(k) {
  /* NEVER HIT
  if(this._isInfinity()) return this;
  if(k._signum() == 0) return this._curve._getInfinity();
  */

  var e = k;
  var h = e._multiply(BigInteger._THREE);

  var neg = this._negate();
  var R = this;

  var i;
  for(i = h._bitLength() - 2; i > 0; --i) {
    R = R._twice();

    var hBit = h._testBit(i);
    var eBit = e._testBit(i);

    if (hBit != eBit) {
      R = R._add(hBit ? this : neg);
    }
  }

  return R;
}

// Compute this*j + x*k (simultaneous multiplication)
function pointFpMultiplyTwo(j,x,k) {
  var i;
  if(j._bitLength() > k._bitLength())
    i = j._bitLength() - 1;
  else
    i = k._bitLength() - 1;

  var R = this._curve._getInfinity();
  var both = this._add(x);
  while(i >= 0) {
    R = R._twice();
    if(j._testBit(i)) {
      if(k._testBit(i)) {
        R = R._add(both);
      }
      else {
        R = R._add(this);
      }
    }
    else {
      if(k._testBit(i)) {
        R = R._add(x);
      }
    }
    --i;
  }

  return R;
}

/*
ECPointFp.prototype = {
  _getX: pointFpGetX,
  _getY: pointFpGetY,
  _isInfinity: pointFpIsInfinity,
  _negate: pointFpNegate,
  _add: pointFpAdd,
  _twice: pointFpTwice,
  _multiply: pointFpMultiply
};
*/

ECPointFp.prototype._getX = pointFpGetX;
ECPointFp.prototype._getY = pointFpGetY;
//ECPointFp.prototype._equals = pointFpEquals;
//ECPointFp.prototype._isInfinity = pointFpIsInfinity;
ECPointFp.prototype._negate = pointFpNegate;
ECPointFp.prototype._add = pointFpAdd;
ECPointFp.prototype._twice = pointFpTwice;
ECPointFp.prototype._multiply = pointFpMultiply;
//ECPointFp.prototype._multiplyTwo = pointFpMultiplyTwo;

// ----------------
// ECCurveFp

// constructor
function ECCurveFp(q,a,b) {
    this.q = q;
    this.a = this._fromBigInteger(a);
    this.b = this._fromBigInteger(b);
    this._infinity = new ECPointFp(this, null, null);
    this._reducer = new Barrett(this.q);
}

function curveFpGetQ() {
    return this.q;
}

function curveFpGetA() {
    return this.a;
}

function curveFpGetB() {
    return this.b;
}

function curveFpEquals(other) {
    if(other == this) return true;
    return(this.q._equals(other.q) && this.a._equals(other.a) && this.b._equals(other.b));
}

function curveFpGetInfinity() {
    return this._infinity;
}

function curveFpFromBigInteger(x) {
    return new ECFieldElementFp(this.q, x);
}

function curveReduce(x) {
    this._reducer._reduce(x);
}

// for now, work with hex strings because they're easier in JS
function curveFpDecodePointHex(s) {
    switch(parseInt(s.substr(0,2), 16)) { // first byte
    case 0:
	return this._infinity;
    case 2:
    case 3:
	// point compression not supported yet
	return null;
    case 4:
    case 6:
    case 7:
	var len = (s.length - 2) / 2;
	var xHex = s.substr(2, len);
	var yHex = s.substr(len+2, len);

	return new ECPointFp(this,
			     this._fromBigInteger(new BigInteger(xHex, 16)),
			     this._fromBigInteger(new BigInteger(yHex, 16)));

    default: // unsupported
	return null;
    }
}

function curveFpEncodePointHex(p) {
	if (p._isInfinity()) return "00";
	var xHex = p._getX().x._toString(16);
	var yHex = p._getY().x._toString(16);
	var oLen = this.q._toString(16).length;
	if ((oLen % 2) != 0) oLen++;
	while (xHex.length < oLen) {
		xHex = "0" + xHex;
	}
	while (yHex.length < oLen) {
		yHex = "0" + yHex;
	}
	return "04" + xHex + yHex;
}

//ECCurveFp.prototype._getQ = curveFpGetQ;
//ECCurveFp.prototype._getA = curveFpGetA;
//ECCurveFp.prototype._getB = curveFpGetB;
//ECCurveFp.prototype._equals = curveFpEquals;
//ECCurveFp.prototype._getInfinity = curveFpGetInfinity;
ECCurveFp.prototype._fromBigInteger = curveFpFromBigInteger;
ECCurveFp.prototype._reduce = curveReduce;
//ECCurveFp.prototype._decodePointHex = curveFpDecodePointHex;
//ECCurveFp.prototype._encodePointHex = curveFpEncodePointHex;
