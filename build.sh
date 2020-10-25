#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

rm p256.*js* 2>/dev/null || true

# full build
terser lib/*.js util.js \
	--ecma 5 \
	-b \
	--define WITH_SEED=true \
	--define WITH_JWK=true --define WITH_ASN1=true \
	--define WITH_IMPORT=true --define WITH_EXPORT=true \
	--define WITH_PUBLIC=true --define WITH_PRIVATE=true \
	-e 'exports:typeof exports==="undefined"?this["P256"]={}:exports' \
	-o p256.js

function run_terser {
	OUTPUT="$1"

	# minified build
	terser lib/*.js util.js \
		--ecma 5 \
		-c passes=2 \
		-m --mangle-props regex=/^_./ \
		--source-map "includeSources" \
		--define WITH_SEED=$WITH_SEED \
		--define WITH_JWK=$WITH_JWK --define WITH_ASN1=$WITH_ASN1 \
		--define WITH_IMPORT=$WITH_IMPORT --define WITH_EXPORT=$WITH_EXPORT \
		--define WITH_PUBLIC=$WITH_PUBLIC --define WITH_PRIVATE=$WITH_PRIVATE \
		-e 'exports:typeof exports==="undefined"?this["P256"]={}:exports' \
		-o "$OUTPUT"

	brotli -f -q 11 "$OUTPUT"
	zopfli -f "$OUTPUT"
}

# defaults
WITH_SEED=true
WITH_JWK=true WITH_ASN1=true
WITH_PUBLIC=true WITH_PRIVATE=true
WITH_IMPORT=true WITH_EXPORT=true

run_terser p256.all.min.js

WITH_ASN1=false run_terser p256.jwk.min.js

WITH_JWK=false run_terser p256.asn1.min.js

WITH_JWK=false WITH_PRIVATE=false WITH_EXPORT=false run_terser p256.import_pub_asn1.min.js


ls -Sl p256.*js.br
ls -Sl p256.*js.gz

time node test.js
