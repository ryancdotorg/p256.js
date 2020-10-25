var B49 = (function(){
  var L = new Int8Array(123), i, c, P = [1];
  var POW2_40 = 1099511627776;
  var log2 = Math.log2 || function(x) { return Math.log(x)/Math.log(2); };
  for (i = 122; i >= 0; --i) {
    if (i > 48) {
      L[i] = -1;
    } else {
      c = '23456789BCDFGHJKLMNPQRSTWXYZbcdfghjklmnpqrstwxyz_'.charCodeAt(i);
      L[i] = c;
      L[c] = i;
    }
  }
  for (i = 1; i < 10; ++i) { P[i] = P[i-1] * 49; }
  function d2c(d) { return String.fromCharCode(L[d|0]); }
  function c2d(c) { return (c > 49 && c < 123) ? L[c] : -1; }
  function b49dw(ary, accum_h, accum_l, r) {
    switch (r) {
      default: throw new Error('Invalid Base49!');
      case 10: ary.push(accum_h >> 8);
      case  9: ary.push(accum_h & 255);
      case  8: ary.push((accum_l / 4294967296) | 0);
      case  6: ary.push((accum_l >> 24) & 255);
      case  5: ary.push((accum_l >> 16) & 255);
      case  3: ary.push((accum_l >> 8) & 255);
      case  2: ary.push(accum_l & 255);
      case  0: break;
    }
    return ary;
  }
  return {
    encode: function(u8) {
      var p = 0, accum = 0, i, r, st = '';
      while (p < u8.length) {
        accum *= 256;
        if (p % 7 == 6) {
          // accum can represent integers 0 to 2^53 exactly, but we now could
          // have a value as high as 2^56 - 256 there. Fortunately, the value
          // will still be accurate since the low 8 bits are zero. As soon as
          // a base49 digit is extracted, the new 8 bits can be safely added.
          i = 10;
          st += d2c(accum / P[--i]); accum = (accum % P[i]) + u8[p++];
          while (i) { st += d2c(accum / P[--i]); accum %= P[i]; }
          accum = 0;
        } else {
          accum += u8[p++];
        }
      }
      if (r = p % 7) {
        i = Math.ceil(8*(r)/log2(49));
        while (i) { st += d2c(accum / P[--i]); accum %= P[i]; }
      }
      return st;
    },

    decode: function(st) {
      var p = 0, accum_l = 0, accum_h = 0, i, r, ary = [];

      var load = function(c) {
        // crappy fixed precision bignum impl
        accum_l = accum_l * 49 + c2d(c);
        accum_h = accum_h * 49 + Math.floor(accum_l / POW2_40);
        accum_l %= POW2_40;
      };

      while (p < st.length) {
        load(st.charCodeAt(p++));
        if (p % 10 == 0) {
          b49dw(ary, accum_h, accum_l, 10);
          accum_h = accum_l = 0;
        }
      }
      if (r = p % 10) {
        b49dw(ary, accum_h, accum_l, p % 10);
      }

      return ary;
    }
  };
})();
