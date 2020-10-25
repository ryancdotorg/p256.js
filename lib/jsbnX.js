// Copyright (c) 2005  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Basic JavaScript BN library - subset useful for RSA encryption.

// Bits per digit
var dbits;

// JavaScript engine analysis
var canary = 0xdeadbeefcafe;
var j_lm = ((canary&0xffffff)==0xefcafe);

// (public) Constructor
function BigInteger(a) {
  if (a != null) this._fromBytes(a);
/*
  if(a != null)
    if("number" == typeof a) this._fromNumber(a,b,c);
    else if(b == null && "string" != typeof a) this._fromString(a,256);
    else this._fromString(a,b);
//*/
}

// return new, unset BigInteger
function nbi() { return new BigInteger(null); }

// am: Compute w_j += (x*this_i), propagate carries,
// c is initial carry, returns final carry.
// c < 3*dvalue, x < 2*dvalue, this_i < dvalue
// We need to select the fastest one that works in this environment.

// am1: use a single mult and divide to get the high bits,
// max digit bits should be 26 because
// max internal value = 2*dvalue^2-2*dvalue (< 2^53)
function am1(i,x,w,j,c,n) {
  while(--n >= 0) {
    var v = x*this[i++]+w[j]+c;
    c = Math.floor(v/0x4000000);
    w[j++] = v&0x3ffffff;
  }
  return c;
}
/*
// am2 avoids a big mult-and-extract completely.
// Max digit bits should be <= 30 because we do bitwise ops
// on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
function am2(i,x,w,j,c,n) {
  var xl = x&0x7fff, xh = x>>15;
  while(--n >= 0) {
    var l = this[i]&0x7fff;
    var h = this[i++]>>15;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x7fff)<<15)+w[j]+(c&0x3fffffff);
    c = (l>>>30)+(m>>>15)+xh*h+(c>>>30);
    w[j++] = l&0x3fffffff;
  }
  return c;
}
// Alternately, set max digit bits to 28 since some
// browsers slow down when dealing with 32-bit numbers.
function am3(i,x,w,j,c,n) {
  var xl = x&0x3fff, xh = x>>14;
  while(--n >= 0) {
    var l = this[i]&0x3fff;
    var h = this[i++]>>14;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x3fff)<<14)+w[j]+c;
    c = (l>>28)+(m>>14)+xh*h;
    w[j++] = l&0xfffffff;
  }
  return c;
}

if(j_lm && (typeof navigator == "object" && navigator.appName == "Microsoft Internet Explorer")) {
  BigInteger.prototype._am = am2;
  dbits = 30;
}
else if(j_lm && (typeof navigator == "object" && navigator.appName != "Netscape")) {
  BigInteger.prototype._am = am1;
  dbits = 26;
}
else { // Mozilla/Netscape seems to prefer am3
  BigInteger.prototype._am = am3;
  dbits = 28;
}
*/

BigInteger.prototype._am = am1;
dbits = 26;

BigInteger.prototype._DB = dbits;
BigInteger.prototype._DM = ((1<<dbits)-1);
BigInteger.prototype._DV = (1<<dbits);

var BI_FP = 52;
BigInteger.prototype._FV = Math.pow(2,BI_FP);
BigInteger.prototype._F1 = BI_FP-dbits;
BigInteger.prototype._F2 = 2*dbits-BI_FP;

/*
// Digit conversions
var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
var BI_RC = new Array();
var rr,vv;
rr = "0".charCodeAt(0);
for(vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
rr = "a".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
rr = "A".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

function int2char(n) { return BI_RM.charAt(n); }
function intAt(s,i) {
  var c = BI_RC[s.charCodeAt(i)];
  return (c==null)?-1:c;
}
//*/

// (protected) copy this to r
function bnpCopyTo(r) {
  for(var i = this.t-1; i >= 0; --i) r[i] = this[i];
  r.t = this.t;
  r.s = this.s;
}

// (protected) set from integer value x, -DV <= x < DV
function bnpFromInt(x) {
  // only ever called with 0, 1, and 3
  this.t = x & 1;
  this.s = 0;
  this[0] = x;
/*
  this.t = 1;
  this.s = (x<0)?-1:0;
  if(x > 0) this[0] = x;
  else if(x < -1) this[0] = x+this._DV;
  else this.t = 0;
//*/
}

// return bigint initialized to value
function nbv(i) { var r = nbi(); r._fromInt(i); return r; }

// (protected) convert from byte array
function bnpFromBytes(s) {
  this.t = 0;
  this.s = 0;
  var i = s.length, mi = false, sh = 0;
  while(--i >= 0) {
    var x = s[i] & 0xff;
    mi = false;
    if(sh == 0)
      this[this.t++] = x;
    else if(sh+8 > this._DB) {
      this[this.t-1] |= (x&((1<<(this._DB-sh))-1))<<sh;
      this[this.t++] = (x>>(this._DB-sh));
    }
    else
      this[this.t-1] |= x<<sh;
    sh += 8;
    if(sh >= this._DB) sh -= this._DB;
  }
  if((s[0]&0x80) != 0) {
    this.s = -1;
    if(sh > 0) this[this.t-1] |= ((1<<(this._DB-sh))-1)<<sh;
  }
  this._clamp();
  if(mi) BigInteger._ZERO._subTo(this,this);
}

// (protected) set from string and radix
function bnpFromString(s,b) {
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 256) k = 8; // byte array
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else { this._fromRadix(s,b); return; }
  this.t = 0;
  this.s = 0;
  var i = s.length, mi = false, sh = 0;
  while(--i >= 0) {
    var x = (k==8)?s[i]&0xff:intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-") mi = true;
      continue;
    }
    mi = false;
    if(sh == 0)
      this[this.t++] = x;
    else if(sh+k > this._DB) {
      this[this.t-1] |= (x&((1<<(this._DB-sh))-1))<<sh;
      this[this.t++] = (x>>(this._DB-sh));
    }
    else
      this[this.t-1] |= x<<sh;
    sh += k;
    if(sh >= this._DB) sh -= this._DB;
  }
  if(k == 8 && (s[0]&0x80) != 0) {
    this.s = -1;
    if(sh > 0) this[this.t-1] |= ((1<<(this._DB-sh))-1)<<sh;
  }
  this._clamp();
  if(mi) BigInteger._ZERO._subTo(this,this);
}

// (protected) clamp off excess high words
function bnpClamp() {
  var c = this.s&this._DM;
  while(this.t > 0 && this[this.t-1] == c) --this.t;
}

// (public) return string representation in given radix
function bnToString(b) {
  if(this.s < 0) return "-"+this._negate()._toString(b);
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else return this._toRadix(b);
  var km = (1<<k)-1, d, m = false, r = "", i = this.t;
  var p = this._DB-(i*this._DB)%k;
  if(i-- > 0) {
    if(p < this._DB && (d = this[i]>>p) > 0) { m = true; r = int2char(d); }
    while(i >= 0) {
      if(p < k) {
        d = (this[i]&((1<<p)-1))<<(k-p);
        d |= this[--i]>>(p+=this._DB-k);
      }
      else {
        d = (this[i]>>(p-=k))&km;
        if(p <= 0) { p += this._DB; --i; }
      }
      if(d > 0) m = true;
      if(m) r += int2char(d);
    }
  }
  return m?r:"0";
}

// (public) -this
function bnNegate() { var r = nbi(); BigInteger._ZERO._subTo(this,r); return r; }

// (public) |this|
function bnAbs() { return (this.s<0)?this._negate():this; }

// (public) return + if this > a, - if this < a, 0 if equal
function bnCompareTo(a) {
  var r = this.s-a.s;
  if(r != 0) return r;
  var i = this.t;
  r = i-a.t;
  if(r != 0) return (this.s<0)?-r:r;
  while(--i >= 0) if((r=this[i]-a[i]) != 0) return r;
  return 0;
}

// returns bit length of the integer x
function nbits(x) {
  var r = 1, t;
  if((t=x>>>16) != 0) { x = t; r += 16; }
  if((t=x>>8) != 0) { x = t; r += 8; }
  if((t=x>>4) != 0) { x = t; r += 4; }
  if((t=x>>2) != 0) { x = t; r += 2; }
  if((t=x>>1) != 0) { x = t; r += 1; }
  return r;
}

// (public) return the number of bits in "this"
function bnBitLength() {
  if(this.t <= 0) return 0;
  return this._DB*(this.t-1)+nbits(this[this.t-1]^(this.s&this._DM));
}

// (protected) r = this << n*DB
function bnpDLShiftTo(n,r) {
  var i;
  for(i = this.t-1; i >= 0; --i) r[i+n] = this[i];
  for(i = n-1; i >= 0; --i) r[i] = 0;
  r.t = this.t+n;
  r.s = this.s;
}

// (protected) r = this >> n*DB
function bnpDRShiftTo(n,r) {
  for(var i = n; i < this.t; ++i) r[i-n] = this[i];
  r.t = Math.max(this.t-n,0);
  r.s = this.s;
}

// (protected) r = this << n
function bnpLShiftTo(n,r) {
  var bs = n%this._DB;
  var cbs = this._DB-bs;
  var bm = (1<<cbs)-1;
  var ds = Math.floor(n/this._DB), c = (this.s<<bs)&this._DM, i;
  for(i = this.t-1; i >= 0; --i) {
    r[i+ds+1] = (this[i]>>cbs)|c;
    c = (this[i]&bm)<<bs;
  }
  for(i = ds-1; i >= 0; --i) r[i] = 0;
  r[ds] = c;
  r.t = this.t+ds+1;
  r.s = this.s;
  r._clamp();
}

// (protected) r = this >> n
function bnpRShiftTo(n,r) {
  r.s = this.s;
  var ds = Math.floor(n/this._DB);
  if(ds >= this.t) { r.t = 0; return; }
  var bs = n%this._DB;
  var cbs = this._DB-bs;
  var bm = (1<<bs)-1;
  r[0] = this[ds]>>bs;
  for(var i = ds+1; i < this.t; ++i) {
    r[i-ds-1] |= (this[i]&bm)<<cbs;
    r[i-ds] = this[i]>>bs;
  }
  if(bs > 0) r[this.t-ds-1] |= (this.s&bm)<<cbs;
  r.t = this.t-ds;
  r._clamp();
}

// (protected) r = this - a
function bnpSubTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]-a[i];
    r[i++] = c&this._DM;
    c >>= this._DB;
  }
  if(a.t < this.t) {
    c -= a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this._DM;
      c >>= this._DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c -= a[i];
      r[i++] = c&this._DM;
      c >>= this._DB;
    }
    c -= a.s;
  }
  r.s = (c<0)?-1:0;
  if(c < -1) r[i++] = this._DV+c;
  else if(c > 0) r[i++] = c;
  r.t = i;
  r._clamp();
}

// (protected) r = this * a, r != this,a (HAC 14.12)
// "this" should be the larger one if appropriate.
function bnpMultiplyTo(a,r) {
  var x = this._abs(), y = a._abs();
  var i = x.t;
  r.t = i+y.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < y.t; ++i) r[i+x.t] = x._am(0,y[i],r,i,0,x.t);
  r.s = 0;
  r._clamp();
  if(this.s != a.s) BigInteger._ZERO._subTo(r,r);
}

// (protected) r = this^2, r != this (HAC 14.16)
function bnpSquareTo(r) {
  var x = this._abs();
  var i = r.t = 2*x.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < x.t-1; ++i) {
    var c = x._am(i,x[i],r,2*i,0,1);
    if((r[i+x.t]+=x._am(i+1,2*x[i],r,2*i+1,c,x.t-i-1)) >= x._DV) {
      r[i+x.t] -= x._DV;
      r[i+x.t+1] = 1;
    }
  }
  if(r.t > 0) r[r.t-1] += x._am(i,x[i],r,2*i,0,1);
  r.s = 0;
  r._clamp();
}

// (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
// r != q, this != m.  q or r may be null.
function bnpDivRemTo(m,q,r) {
  var pm = m._abs();
  if(pm.t <= 0) return;
  var pt = this._abs();
  if(pt.t < pm.t) {
    if(q != null) q._fromInt(0);
    if(r != null) this._copyTo(r);
    return;
  }
  if(r == null) r = nbi();
  var y = nbi(), ts = this.s, ms = m.s;
  var nsh = this._DB-nbits(pm[pm.t-1]);	// normalize modulus
  if(nsh > 0) { pm._lShiftTo(nsh,y); pt._lShiftTo(nsh,r); }
  else { pm._copyTo(y); pt._copyTo(r); }
  var ys = y.t;
  var y0 = y[ys-1];
  if(y0 == 0) return;
  var yt = y0*(1<<this._F1)+((ys>1)?y[ys-2]>>this._F2:0);
  var d1 = this._FV/yt, d2 = (1<<this._F1)/yt, e = 1<<this._F2;
  var i = r.t, j = i-ys, t = (q==null)?nbi():q;
  y._dlShiftTo(j,t);
  if(r._compareTo(t) >= 0) {
    r[r.t++] = 1;
    r._subTo(t,r);
  }
  BigInteger._ONE._dlShiftTo(ys,t);
  t._subTo(y,y);	// "negative" y so we can replace sub with am later
  while(y.t < ys) y[y.t++] = 0;
  while(--j >= 0) {
    // Estimate quotient digit
    var qd = (r[--i]==y0)?this._DM:Math.floor(r[i]*d1+(r[i-1]+e)*d2);
    if((r[i]+=y._am(0,qd,r,j,0,ys)) < qd) {	// Try it out
      y._dlShiftTo(j,t);
      r._subTo(t,r);
      while(r[i] < --qd) r._subTo(t,r);
    }
  }
  if(q != null) {
    r._drShiftTo(ys,q);
    if(ts != ms) BigInteger._ZERO._subTo(q,q);
  }
  r.t = ys;
  r._clamp();
  if(nsh > 0) r._rShiftTo(nsh,r);	// Denormalize remainder
  if(ts < 0) BigInteger._ZERO._subTo(r,r);
}

// (public) this mod a
function bnMod(a) {
  var r = nbi();
  this._abs()._divRemTo(a,null,r);
  if(this.s < 0 && r._compareTo(BigInteger._ZERO) > 0) a._subTo(r,r);
  return r;
}

// (protected) return "-1/this % 2^DB"; useful for Mont. reduction
// justification:
//         xy == 1 (mod m)
//         xy =  1+km
//   xy(2-xy) = (1+km)(1-km)
// x[y(2-xy)] = 1-k^2m^2
// x[y(2-xy)] == 1 (mod m^2)
// if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
// should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
// JS multiply "overflows" differently from C/C++, so care is needed here.
function bnpInvDigit() {
  if(this.t < 1) return 0;
  var x = this[0];
  if((x&1) == 0) return 0;
  var y = x&3;		// y == 1/x mod 2^2
  y = (y*(2-(x&0xf)*y))&0xf;	// y == 1/x mod 2^4
  y = (y*(2-(x&0xff)*y))&0xff;	// y == 1/x mod 2^8
  y = (y*(2-(((x&0xffff)*y)&0xffff)))&0xffff;	// y == 1/x mod 2^16
  // last step - calculate inverse mod DV directly;
  // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
  y = (y*(2-x*y%this._DV))%this._DV;		// y == 1/x mod 2^dbits
  // we really want the negative inverse, and -DV < y < DV
  return (y>0)?this._DV-y:-y;
}

// Montgomery reduction
function Montgomery(m) {
  this.m = m;
  this.mp = m._invDigit();
  this.mpl = this.mp&0x7fff;
  this.mph = this.mp>>15;
  this.um = (1<<(m._DB-15))-1;
  this.mt2 = 2*m.t;
}

// xR mod m
function montConvert(x) {
  var r = nbi();
  x._abs()._dlShiftTo(this.m.t,r);
  r._divRemTo(this.m,null,r);
  if(x.s < 0 && r._compareTo(BigInteger._ZERO) > 0) this.m._subTo(r,r);
  return r;
}

// x/R mod m
function montRevert(x) {
  var r = nbi();
  x._copyTo(r);
  this._reduce(r);
  return r;
}

// x = x/R mod m (HAC 14.32)
function montReduce(x) {
  while(x.t <= this.mt2)	// pad x so am has enough room later
    x[x.t++] = 0;
  for(var i = 0; i < this.m.t; ++i) {
    // faster way of calculating u0 = x[i]*mp mod DV
    var j = x[i]&0x7fff;
    var u0 = (j*this.mpl+(((j*this.mph+(x[i]>>15)*this.mpl)&this.um)<<15))&x._DM;
    // use am to combine the multiply-shift-add into one call
    j = i+this.m.t;
    x[j] += this.m._am(0,u0,x,i,0,this.m.t);
    // propagate carry
    while(x[j] >= x._DV) { x[j] -= x._DV; x[++j]++; }
  }
  x._clamp();
  x._drShiftTo(this.m.t,x);
  if(x._compareTo(this.m) >= 0) x._subTo(this.m,x);
}

// r = "x^2/R mod m"; x != r
function montSqrTo(x,r) { x._squareTo(r); this._reduce(r); }

// r = "xy/R mod m"; x,y != r
function montMulTo(x,y,r) { x._multiplyTo(y,r); this._reduce(r); }

/*
Montgomery.prototype = {
  _convert: montConvert,
  _revert: montRevert,
  _reduce: montReduce,
  _mulTo: montMulTo,
  _sqrTo: montSqrTo
};
*/

Montgomery.prototype._convert = montConvert;
Montgomery.prototype._revert = montRevert;
Montgomery.prototype._reduce = montReduce;
Montgomery.prototype._mulTo = montMulTo;
Montgomery.prototype._sqrTo = montSqrTo;


// (protected) true iff this is even
function bnpIsEven() { return ((this.t>0)?(this[0]&1):this.s) == 0; }

// (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
function bnpExp(e,z) {
  if(e > 0xffffffff || e < 1) return BigInteger._ONE;
  var r = nbi(), r2 = nbi(), g = z._convert(this), i = nbits(e)-1;
  g._copyTo(r);
  while(--i >= 0) {
    z._sqrTo(r,r2);
    if((e&(1<<i)) > 0) z._mulTo(r2,g,r);
    else { var t = r; r = r2; r2 = t; }
  }
  return z._revert(r);
}

// (public) this^e % m, 0 <= e < 2^32
function bnModPowInt(e,m) {
  var z;
  if(e < 256 || m._isEven()) z = new Classic(m); else z = new Montgomery(m);
  return this._exp(e,z);
}

// protected
BigInteger.prototype._copyTo = bnpCopyTo;
BigInteger.prototype._fromInt = bnpFromInt;
//BigInteger.prototype._fromString = bnpFromString;
BigInteger.prototype._fromBytes = bnpFromBytes;
BigInteger.prototype._clamp = bnpClamp;
BigInteger.prototype._dlShiftTo = bnpDLShiftTo;
BigInteger.prototype._drShiftTo = bnpDRShiftTo;
BigInteger.prototype._lShiftTo = bnpLShiftTo;
BigInteger.prototype._rShiftTo = bnpRShiftTo;
BigInteger.prototype._subTo = bnpSubTo;
BigInteger.prototype._multiplyTo = bnpMultiplyTo;
BigInteger.prototype._squareTo = bnpSquareTo;
BigInteger.prototype._divRemTo = bnpDivRemTo;
BigInteger.prototype._invDigit = bnpInvDigit;
BigInteger.prototype._isEven = bnpIsEven;
//BigInteger.prototype._exp = bnpExp;

// public
//BigInteger.prototype._toString = bnToString;
BigInteger.prototype._negate = bnNegate;
BigInteger.prototype._abs = bnAbs;
BigInteger.prototype._compareTo = bnCompareTo;
BigInteger.prototype._bitLength = bnBitLength;
BigInteger.prototype._mod = bnMod;
//BigInteger.prototype._modPowInt = bnModPowInt;

// "constants"
BigInteger._ZERO = nbv(0);
BigInteger._ONE = nbv(1);
BigInteger._THREE = nbv(3);
// Copyright (c) 2005-2009  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Extended JavaScript BN functions, required for RSA private ops.

// Version 1.1: new BigInteger("0", 10) returns "proper" zero
// Version 1.2: square() API, isProbablePrime fix

// (public)
function bnClone() { var r = nbi(); this._copyTo(r); return r; }

// (public) return value as integer
function bnIntValue() {
  if(this.s < 0) {
    if(this.t == 1) return this[0]-this._DV;
    else if(this.t == 0) return -1;
  }
  else if(this.t == 1) return this[0];
  else if(this.t == 0) return 0;
  // assumes 16 < DB < 32
  return ((this[1]&((1<<(32-this._DB))-1))<<this._DB)|this[0];
}

// (public) return value as byte
function bnByteValue() { return (this.t==0)?this.s:(this[0]<<24)>>24; }

// (public) return value as short (assumes DB>=16)
function bnShortValue() { return (this.t==0)?this.s:(this[0]<<16)>>16; }

// (protected) return x s.t. r^x < DV
function bnpChunkSize(r) { return Math.floor(Math.LN2*this._DB/Math.log(r)); }

// (public) 0 if this == 0, 1 if this > 0
function bnSigNum() {
  if(this.s < 0) return -1;
  else if(this.t <= 0 || (this.t == 1 && this[0] <= 0)) return 0;
  else return 1;
}

// (protected) convert to radix string
function bnpToRadix(b) {
  if(b == null) b = 10;
  if(this._signum() == 0 || b < 2 || b > 36) return "0";
  var cs = this._chunkSize(b);
  var a = Math.pow(b,cs);
  var d = nbv(a), y = nbi(), z = nbi(), r = "";
  this._divRemTo(d,y,z);
  while(y._signum() > 0) {
    r = (a+z._intValue())._toString(b).substr(1) + r;
    y._divRemTo(d,y,z);
  }
  return z._intValue()._toString(b) + r;
}

// (protected) convert from radix string
function bnpFromRadix(s,b) {
  this._fromInt(0);
  if(b == null) b = 10;
  var cs = this._chunkSize(b);
  var d = Math.pow(b,cs), mi = false, j = 0, w = 0;
  for(var i = 0; i < s.length; ++i) {
    var x = intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-" && this._signum() == 0) mi = true;
      continue;
    }
    w = b*w+x;
    if(++j >= cs) {
      this._dMultiply(d);
      this._dAddOffset(w,0);
      j = 0;
      w = 0;
    }
  }
  if(j > 0) {
    this._dMultiply(Math.pow(b,j));
    this._dAddOffset(w,0);
  }
  if(mi) BigInteger._ZERO._subTo(this,this);
}

// (protected) alternate constructor
function bnpFromNumber(a,b,c) {
  if("number" == typeof b) {
    // new BigInteger(int,int,RNG)
    if(a < 2) this._fromInt(1);
    else {
      this._fromNumber(a,c);
      if(!this._testBit(a-1))	// force MSB set
        this._bitwiseTo(BigInteger._ONE._shiftLeft(a-1),op_or,this);
      if(this._isEven()) this._dAddOffset(1,0); // force odd
      while(!this._isProbablePrime(b)) {
        this._dAddOffset(2,0);
        if(this._bitLength() > a) this._subTo(BigInteger._ONE._shiftLeft(a-1),this);
      }
    }
  }
  else {
    // new BigInteger(int,RNG)
    var x = new Array(), t = a&7;
    x.length = (a>>3)+1;
    b.nextBytes(x);
    if(t > 0) x[0] &= ((1<<t)-1); else x[0] = 0;
    this._fromBytes(x);
  }
}

// (public) convert to bigendian byte array
function bnToByteArray() {
  var i = this.t, r = new Array();
  r[0] = this.s;
  var p = this._DB-(i*this._DB)%8, d, k = 0;
  if(i-- > 0) {
    if(p < this._DB && (d = this[i]>>p) != (this.s&this._DM)>>p)
      r[k++] = d|(this.s<<(this._DB-p));
    while(i >= 0) {
      if(p < 8) {
        d = (this[i]&((1<<p)-1))<<(8-p);
        d |= this[--i]>>(p+=this._DB-8);
      }
      else {
        d = (this[i]>>(p-=8))&0xff;
        if(p <= 0) { p += this._DB; --i; }
      }
      if(k == 0 && (this.s&0x80) != (d&0x80)) ++k;
      if(k > 0 || d != this.s) r[k++] = d;
    }
  }
  return r;
}

function bnEquals(a) { return(this._compareTo(a)==0); }
function bnMin(a) { return(this._compareTo(a)<0)?this:a; }
function bnMax(a) { return(this._compareTo(a)>0)?this:a; }

// (protected) r = this op a (bitwise)
function bnpBitwiseTo(a,op,r) {
  var i, f, m = Math.min(a.t,this.t);
  for(i = 0; i < m; ++i) r[i] = op(this[i],a[i]);
  if(a.t < this.t) {
    f = a.s&this._DM;
    for(i = m; i < this.t; ++i) r[i] = op(this[i],f);
    r.t = this.t;
  }
  else {
    f = this.s&this._DM;
    for(i = m; i < a.t; ++i) r[i] = op(f,a[i]);
    r.t = a.t;
  }
  r.s = op(this.s,a.s);
  r._clamp();
}

// (public) this & a
function op_and(x,y) { return x&y; }
function bnAnd(a) { var r = nbi(); this._bitwiseTo(a,op_and,r); return r; }

// (public) this | a
function op_or(x,y) { return x|y; }
function bnOr(a) { var r = nbi(); this._bitwiseTo(a,op_or,r); return r; }

// (public) this ^ a
function op_xor(x,y) { return x^y; }
function bnXor(a) { var r = nbi(); this._bitwiseTo(a,op_xor,r); return r; }

// (public) this & ~a
function op_andnot(x,y) { return x&~y; }
function bnAndNot(a) { var r = nbi(); this._bitwiseTo(a,op_andnot,r); return r; }

// (public) ~this
function bnNot() {
  var r = nbi();
  for(var i = 0; i < this.t; ++i) r[i] = this._DM&~this[i];
  r.t = this.t;
  r.s = ~this.s;
  return r;
}

// (public) this << n
function bnShiftLeft(n) {
  var r = nbi();
  if(n < 0) this._rShiftTo(-n,r); else this._lShiftTo(n,r);
  return r;
}

// (public) this >> n
function bnShiftRight(n) {
  var r = nbi();
  if(n < 0) this._lShiftTo(-n,r); else this._rShiftTo(n,r);
  return r;
}

// return index of lowest 1-bit in x, x < 2^31
function lbit(x) {
  if(x == 0) return -1;
  var r = 0;
  if((x&0xffff) == 0) { x >>= 16; r += 16; }
  if((x&0xff) == 0) { x >>= 8; r += 8; }
  if((x&0xf) == 0) { x >>= 4; r += 4; }
  if((x&3) == 0) { x >>= 2; r += 2; }
  if((x&1) == 0) ++r;
  return r;
}

// (public) returns index of lowest 1-bit (or -1 if none)
function bnGetLowestSetBit() {
  for(var i = 0; i < this.t; ++i)
    if(this[i] != 0) return i*this._DB+lbit(this[i]);
  if(this.s < 0) return this.t*this._DB;
  return -1;
}

// return number of 1 bits in x
function cbit(x) {
  var r = 0;
  while(x != 0) { x &= x-1; ++r; }
  return r;
}

// (public) return number of set bits
function bnBitCount() {
  var r = 0, x = this.s&this._DM;
  for(var i = 0; i < this.t; ++i) r += cbit(this[i]^x);
  return r;
}

// (public) true iff nth bit is set
function bnTestBit(n) {
  var j = Math.floor(n/this._DB);
  if(j >= this.t) return(this.s!=0);
  return((this[j]&(1<<(n%this._DB)))!=0);
}

// (protected) this op (1<<n)
function bnpChangeBit(n,op) {
  var r = BigInteger._ONE._shiftLeft(n);
  this._bitwiseTo(r,op,r);
  return r;
}

// (public) this | (1<<n)
function bnSetBit(n) { return this._changeBit(n,op_or); }

// (public) this & ~(1<<n)
function bnClearBit(n) { return this._changeBit(n,op_andnot); }

// (public) this ^ (1<<n)
function bnFlipBit(n) { return this._changeBit(n,op_xor); }

// (protected) r = this + a
function bnpAddTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]+a[i];
    r[i++] = c&this._DM;
    c >>= this._DB;
  }
  if(a.t < this.t) {
    c += a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this._DM;
      c >>= this._DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c += a[i];
      r[i++] = c&this._DM;
      c >>= this._DB;
    }
    c += a.s;
  }
  r.s = (c<0)?-1:0;
  if(c > 0) r[i++] = c;
  else if(c < -1) r[i++] = this._DV+c;
  r.t = i;
  r._clamp();
}

// (public) this + a
function bnAdd(a) { var r = nbi(); this._addTo(a,r); return r; }

// (public) this - a
function bnSubtract(a) { var r = nbi(); this._subTo(a,r); return r; }

// (public) this * a
function bnMultiply(a) { var r = nbi(); this._multiplyTo(a,r); return r; }

// (public) this^2
function bnSquare() { var r = nbi(); this._squareTo(r); return r; }

// (public) this / a
function bnDivide(a) { var r = nbi(); this._divRemTo(a,r,null); return r; }

// (public) this % a
function bnRemainder(a) { var r = nbi(); this._divRemTo(a,null,r); return r; }

// (public) [this/a,this%a]
function bnDivideAndRemainder(a) {
  var q = nbi(), r = nbi();
  this._divRemTo(a,q,r);
  return new Array(q,r);
}

// (protected) this *= n, this >= 0, 1 < n < DV
function bnpDMultiply(n) {
  this[this.t] = this._am(0,n-1,this,0,0,this.t);
  ++this.t;
  this._clamp();
}

// (protected) this += n << w words, this >= 0
function bnpDAddOffset(n,w) {
  if(n == 0) return;
  while(this.t <= w) this[this.t++] = 0;
  this[w] += n;
  while(this[w] >= this._DV) {
    this[w] -= this._DV;
    if(++w >= this.t) this[this.t++] = 0;
    ++this[w];
  }
}

// A "null" reducer
function NullExp() {}
function nNop(x) { return x; }
function nMulTo(x,y,r) { x._multiplyTo(y,r); }
function nSqrTo(x,r) { x._squareTo(r); }

//NullExp.prototype._convert = nNop;
//NullExp.prototype._revert = nNop;
//NullExp.prototype._mulTo = nMulTo;
//NullExp.prototype._sqrTo = nSqrTo;

// (public) this^e
function bnPow(e) { return this._exp(e,new NullExp()); }

// (protected) r = lower n words of "this * a", a.t <= n
// "this" should be the larger one if appropriate.
function bnpMultiplyLowerTo(a,n,r) {
  var i = Math.min(this.t+a.t,n);
  r.s = 0; // assumes a,this >= 0
  r.t = i;
  while(i > 0) r[--i] = 0;
  var j;
  for(j = r.t-this.t; i < j; ++i) r[i+this.t] = this._am(0,a[i],r,i,0,this.t);
  for(j = Math.min(a.t,n); i < j; ++i) this._am(0,a[i],r,i,0,n-i);
  r._clamp();
}

// (protected) r = "this * a" without lower n words, n > 0
// "this" should be the larger one if appropriate.
function bnpMultiplyUpperTo(a,n,r) {
  --n;
  var i = r.t = this.t+a.t-n;
  r.s = 0; // assumes a,this >= 0
  while(--i >= 0) r[i] = 0;
  for(i = Math.max(n-this.t,0); i < a.t; ++i)
    r[this.t+i-n] = this._am(n-i,a[i],r,0,0,this.t+i-n);
  r._clamp();
  r._drShiftTo(1,r);
}

// Barrett modular reduction
function Barrett(m) {
  // setup Barrett
  this.r2 = nbi();
  this.q3 = nbi();
  BigInteger._ONE._dlShiftTo(2*m.t,this.r2);
  this.mu = this.r2._divide(m);
  this.m = m;
}

function barrettConvert(x) {
  if(x.s < 0 || x.t > 2*this.m.t) return x._mod(this.m);
  else if(x._compareTo(this.m) < 0) return x;
  else { var r = nbi(); x._copyTo(r); this._reduce(r); return r; }
}

function barrettRevert(x) { return x; }

// x = x mod m (HAC 14.42)
function barrettReduce(x) {
  x._drShiftTo(this.m.t-1,this.r2);
  if(x.t > this.m.t+1) { x.t = this.m.t+1; x._clamp(); }
  this.mu._multiplyUpperTo(this.r2,this.m.t+1,this.q3);
  this.m._multiplyLowerTo(this.q3,this.m.t+1,this.r2);
  while(x._compareTo(this.r2) < 0) x._dAddOffset(1,this.m.t+1);
  x._subTo(this.r2,x);
  while(x._compareTo(this.m) >= 0) x._subTo(this.m,x);
}

// r = x^2 mod m; x != r
function barrettSqrTo(x,r) { x._squareTo(r); this._reduce(r); }

// r = x*y mod m; x,y != r
function barrettMulTo(x,y,r) { x._multiplyTo(y,r); this._reduce(r); }

//Barrett.prototype._convert = barrettConvert;
//Barrett.prototype._revert = barrettRevert;
Barrett.prototype._reduce = barrettReduce;
//Barrett.prototype._mulTo = barrettMulTo;
//Barrett.prototype._sqrTo = barrettSqrTo;

// (public) this^e % m (HAC 14.85)
function bnModPow(e,m) {
  var i = e._bitLength(), k, r = nbv(1), z;
  if(i <= 0) return r;
  else if(i < 18) k = 1;
  else if(i < 48) k = 3;
  else if(i < 144) k = 4;
  else if(i < 768) k = 5;
  else k = 6;
  if(i < 8)
    z = new Classic(m);
  else if(m._isEven())
    z = new Barrett(m);
  else
    z = new Montgomery(m);

  // precomputation
  var g = new Array(), n = 3, k1 = k-1, km = (1<<k)-1;
  g[1] = z._convert(this);
  if(k > 1) {
    var g2 = nbi();
    z._sqrTo(g[1],g2);
    while(n <= km) {
      g[n] = nbi();
      z._mulTo(g2,g[n-2],g[n]);
      n += 2;
    }
  }

  var j = e.t-1, w, is1 = true, r2 = nbi(), t;
  i = nbits(e[j])-1;
  while(j >= 0) {
    if(i >= k1) w = (e[j]>>(i-k1))&km;
    else {
      w = (e[j]&((1<<(i+1))-1))<<(k1-i);
      if(j > 0) w |= e[j-1]>>(this._DB+i-k1);
    }

    n = k;
    while((w&1) == 0) { w >>= 1; --n; }
    if((i -= n) < 0) { i += this._DB; --j; }
    if(is1) {	// ret == 1, don't bother squaring or multiplying it
      g[w]._copyTo(r);
      is1 = false;
    }
    else {
      while(n > 1) { z._sqrTo(r,r2); z._sqrTo(r2,r); n -= 2; }
      if(n > 0) z._sqrTo(r,r2); else { t = r; r = r2; r2 = t; }
      z._mulTo(r2,g[w],r);
    }

    while(j >= 0 && (e[j]&(1<<i)) == 0) {
      z._sqrTo(r,r2); t = r; r = r2; r2 = t;
      if(--i < 0) { i = this._DB-1; --j; }
    }
  }
  return z._revert(r);
}

// (public) gcd(this,a) (HAC 14.54)
function bnGCD(a) {
  var x = (this.s<0)?this._negate():this._clone();
  var y = (a.s<0)?a._negate():a._clone();
  if(x._compareTo(y) < 0) { var t = x; x = y; y = t; }
  var i = x._getLowestSetBit(), g = y._getLowestSetBit();
  if(g < 0) return x;
  if(i < g) g = i;
  if(g > 0) {
    x._rShiftTo(g,x);
    y._rShiftTo(g,y);
  }
  while(x._signum() > 0) {
    if((i = x._getLowestSetBit()) > 0) x._rShiftTo(i,x);
    if((i = y._getLowestSetBit()) > 0) y._rShiftTo(i,y);
    if(x._compareTo(y) >= 0) {
      x._subTo(y,x);
      x._rShiftTo(1,x);
    }
    else {
      y._subTo(x,y);
      y._rShiftTo(1,y);
    }
  }
  if(g > 0) y._lShiftTo(g,y);
  return y;
}

// (protected) this % n, n < 2^26
function bnpModInt(n) {
  if(n <= 0) return 0;
  var d = this._DV%n, r = (this.s<0)?n-1:0;
  if(this.t > 0)
    if(d == 0) r = this[0]%n;
    else for(var i = this.t-1; i >= 0; --i) r = (d*r+this[i])%n;
  return r;
}

// (public) 1/this % m (HAC 14.61)
function bnModInverse(m) {
  var ac = m._isEven();
  if((this._isEven() && ac) || m._signum() == 0) return BigInteger._ZERO;
  var u = m._clone(), v = this._clone();
  var a = nbv(1), b = nbv(0), c = nbv(0), d = nbv(1);
  while(u._signum() != 0) {
    while(u._isEven()) {
      u._rShiftTo(1,u);
      if(ac) {
        if(!a._isEven() || !b._isEven()) { a._addTo(this,a); b._subTo(m,b); }
        a._rShiftTo(1,a);
      }
      else if(!b._isEven()) b._subTo(m,b);
      b._rShiftTo(1,b);
    }
    while(v._isEven()) {
      v._rShiftTo(1,v);
      if(ac) {
        if(!c._isEven() || !d._isEven()) { c._addTo(this,c); d._subTo(m,d); }
        c._rShiftTo(1,c);
      }
      else if(!d._isEven()) d._subTo(m,d);
      d._rShiftTo(1,d);
    }
    if(u._compareTo(v) >= 0) {
      u._subTo(v,u);
      if(ac) a._subTo(c,a);
      b._subTo(d,b);
    }
    else {
      v._subTo(u,v);
      if(ac) c._subTo(a,c);
      d._subTo(b,d);
    }
  }
  if(v._compareTo(BigInteger._ONE) != 0) return BigInteger._ZERO;
  if(d._compareTo(m) >= 0) return d._subtract(m);
  if(d._signum() < 0) d._addTo(m,d); else return d;
  if(d._signum() < 0) return d._add(m); else return d;
}

var lowprimes = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997];
var lplim = (1<<26)/lowprimes[lowprimes.length-1];

// (public) test primality with certainty >= 1-.5^t
function bnIsProbablePrime(t) {
  var i, x = this._abs();
  if(x.t == 1 && x[0] <= lowprimes[lowprimes.length-1]) {
    for(i = 0; i < lowprimes.length; ++i)
      if(x[0] == lowprimes[i]) return true;
    return false;
  }
  if(x._isEven()) return false;
  i = 1;
  while(i < lowprimes.length) {
    var m = lowprimes[i], j = i+1;
    while(j < lowprimes.length && m < lplim) m *= lowprimes[j++];
    m = x._modInt(m);
    while(i < j) if(m%lowprimes[i++] == 0) return false;
  }
  return x._millerRabin(t);
}

// (protected) true if probably prime (HAC 4.24, Miller-Rabin)
function bnpMillerRabin(t) {
  var n1 = this._subtract(BigInteger._ONE);
  var k = n1._getLowestSetBit();
  if(k <= 0) return false;
  var r = n1._shiftRight(k);
  t = (t+1)>>1;
  if(t > lowprimes.length) t = lowprimes.length;
  var a = nbi();
  for(var i = 0; i < t; ++i) {
    //Pick bases at random, instead of starting at 2
    a._fromInt(lowprimes[Math.floor(Math.random()*lowprimes.length)]);
    var y = a._modPow(r,this);
    if(y._compareTo(BigInteger._ONE) != 0 && y._compareTo(n1) != 0) {
      var j = 1;
      while(j++ < k && y._compareTo(n1) != 0) {
        y = y._modPowInt(2,this);
        if(y._compareTo(BigInteger._ONE) == 0) return false;
      }
      if(y._compareTo(n1) != 0) return false;
    }
  }
  return true;
}

// protected
//BigInteger.prototype._chunkSize = bnpChunkSize;
//BigInteger.prototype._toRadix = bnpToRadix;
//BigInteger.prototype._fromRadix = bnpFromRadix;
//BigInteger.prototype._fromNumber = bnpFromNumber;
//BigInteger.prototype._bitwiseTo = bnpBitwiseTo;
//BigInteger.prototype._changeBit = bnpChangeBit;
BigInteger.prototype._addTo = bnpAddTo;
//BigInteger.prototype._dMultiply = bnpDMultiply;
//BigInteger.prototype._dAddOffset = bnpDAddOffset;
BigInteger.prototype._multiplyLowerTo = bnpMultiplyLowerTo;
BigInteger.prototype._multiplyUpperTo = bnpMultiplyUpperTo;
//BigInteger.prototype._modInt = bnpModInt;
//BigInteger.prototype._millerRabin = bnpMillerRabin;

// public
BigInteger.prototype._clone = bnClone;
//BigInteger.prototype._intValue = bnIntValue;
//BigInteger.prototype._byteValue = bnByteValue;
//BigInteger.prototype._shortValue = bnShortValue;
BigInteger.prototype._signum = bnSigNum;
BigInteger.prototype._toByteArray = bnToByteArray;
BigInteger.prototype._equals = bnEquals;
//BigInteger.prototype._min = bnMin;
//BigInteger.prototype._max = bnMax;
//BigInteger.prototype._and = bnAnd;
//BigInteger.prototype._or = bnOr;
//BigInteger.prototype._xor = bnXor;
//BigInteger.prototype._andNot = bnAndNot;
//BigInteger.prototype._not = bnNot;
BigInteger.prototype._shiftLeft = bnShiftLeft;
//BigInteger.prototype._shiftRight = bnShiftRight;
//BigInteger.prototype._getLowestSetBit = bnGetLowestSetBit;
//BigInteger.prototype._bitCount = bnBitCount;
BigInteger.prototype._testBit = bnTestBit;
//BigInteger.prototype._setBit = bnSetBit;
//BigInteger.prototype._clearBit = bnClearBit;
//BigInteger.prototype._flipBit = bnFlipBit;
BigInteger.prototype._add = bnAdd;
BigInteger.prototype._subtract = bnSubtract;
BigInteger.prototype._multiply = bnMultiply;
BigInteger.prototype._divide = bnDivide;
//BigInteger.prototype._remainder = bnRemainder;
//BigInteger.prototype._divideAndRemainder = bnDivideAndRemainder;
BigInteger.prototype._modPow = bnModPow;
BigInteger.prototype._modInverse = bnModInverse;
//BigInteger.prototype._pow = bnPow;
//BigInteger.prototype._gcd = bnGCD;
//BigInteger.prototype._isProbablePrime = bnIsProbablePrime;

// JSBN-specific extension
BigInteger.prototype._square = bnSquare;

// BigInteger interfaces not implemented in jsbn:

// BigInteger(int signum, byte[] magnitude)
// double doubleValue()
// float floatValue()
// int hashCode()
// long longValue()
// static BigInteger valueOf(long val)
