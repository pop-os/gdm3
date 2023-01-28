#!/usr/bin/env bash
# Copyright 2023 - Marco Trevisan
# Released under the GPLv3 terms
#
# A simple tool to generate CA certificates signed by both a root cert authority
# and by an intermediate one, to verify smartcard usage using softhism2.
# Used to verify p11_child usage in SSSD.
set -xe

required_tools=(
    p11tool        # debian package: gnutls-bin
    openssl        # debian package: openssl
    softhsm2-util  # debian package: softhsm2
)

for cmd in "${required_tools[@]}"; do
  if ! command -v "$cmd" > /dev/null; then
    echo "Tool $cmd missing"
    exit 1
  fi
done

PIN=${PIN:-053350}
SOFTHSM2_MODULE=${SOFTHSM2_MODULE:-$(realpath "$(find /usr/lib/*softhsm/libsofthsm2.so | head -n 1)")}
SSSD_P11_CHILD=${SSSD_P11_CHILD:-/usr/libexec/sssd/p11_child}
TOKEN_ID=${TOKEN_ID:-00112233445566778899FFAABBCCDDEEFF012345}

if [ ! -v NO_SSSD_TESTS ]; then
  if [ ! -x "$SSSD_P11_CHILD" ]; then
    if [ ! -e "$$SSSD_P11_CHILD" ]; then
      echo "Cannot find $SSSD_P11_CHILD"
    else
      echo "Cannot execute $SSSD_P11_CHILD, try using sudo..."
    fi
    exit 1
  else
    ca_db_arg="ca_db"
    p11_child_help=$("$SSSD_P11_CHILD" --help &>/dev/stdout)
    if echo "$p11_child_help" | grep nssdb -qs; then
      ca_db_arg=nssdb
    fi

    echo "$p11_child_help" | grep -qs -- "--${ca_db_arg}"
  fi
fi

if [ ! -e "$SOFTHSM2_MODULE" ]; then
  echo "Cannot find softhsm2-module at $SOFTHSM2_MODULE"
  exit 1
fi

tmpdir=${TEST_TMPDIR:-$(mktemp -d -t "sssd-softhsm2-XXXXXX")}
keys_size=1024

if [[ ! -v KEEP_TEMPORARY_FILES ]]; then
  trap 'rm -rf "$tmpdir"' EXIT
fi
trap 'set +x; echo -e "\nUnexpected failure!!!"' ERR

echo -n 01 > "$tmpdir/serial"
touch "$tmpdir/index.txt"
mkdir -p "$tmpdir/new_certs"

function expect_fail() {
  local cmd="$1"
  shift

  if "$cmd" "$@"; then
    echo "Unexpected failure!"
    exit 1
  fi
}


## Root CA certificate generation

cat <<EOF > "$tmpdir/test-root-CA.config"
[ ca ]
default_ca = CA_default

[ CA_default ]
dir              = $tmpdir
database         = \$dir/index.txt
new_certs_dir    = \$dir/new_certs

certificate      = \$dir/test-root-CA.pem
serial           = \$dir/serial
private_key      = \$dir/test-root-CA-key.pem
RANDFILE         = \$dir/rand

default_days     = 365
default_crl_days = 30
default_md       = sha256

policy           = policy_any
email_in_dn      = no

name_opt         = ca_default
cert_opt         = ca_default
copy_extensions  = copy

[ usr_cert ]
authorityKeyIdentifier = keyid, issuer

[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints       = CA:true
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints       = CA:true
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign

[ policy_any ]
organizationName       = supplied
organizationalUnitName = supplied
commonName             = supplied
emailAddress           = optional

[ req ]
distinguished_name = req_distinguished_name
prompt             = no

[ req_distinguished_name ]
O  = Test Organization
OU = Test Organization Unit
CN = Test Organization Root CA
EOF

root_ca_key_pass="pass:random-root-CA-password-${RANDOM}"

openssl genrsa -aes256 \
  -out "$tmpdir/test-root-CA-key.pem" \
  -passout "$root_ca_key_pass" \
  "$keys_size"

openssl req -passin "$root_ca_key_pass" \
  -batch -config "$tmpdir/test-root-CA.config" -x509 -new -nodes \
  -key "$tmpdir/test-root-CA-key.pem" -sha256 -days 1024 -set_serial 0 \
  -extensions v3_ca -out "$tmpdir/test-root-CA.pem"

openssl x509 -noout -in "$tmpdir/test-root-CA.pem"


## Intermediate CA certificate generation

cat <<EOF > "$tmpdir/test-intermediate-CA.config"
[ ca ]
default_ca = CA_default

[ CA_default ]
dir              = $tmpdir
database         = \$dir/index.txt
new_certs_dir    = \$dir/new_certs

certificate      = \$dir/test-intermediate-CA.pem
serial           = \$dir/serial
private_key      = \$dir/test-intermediate-CA-key.pem
RANDFILE         = \$dir/rand

default_days     = 365
default_crl_days = 30
default_md       = sha256

policy           = policy_any
email_in_dn      = no

name_opt         = ca_default
cert_opt         = ca_default
copy_extensions  = copy

[ usr_cert ]
authorityKeyIdentifier = keyid, issuer

[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints       = CA:true
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints       = CA:true
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign

[ policy_any ]
organizationName       = supplied
organizationalUnitName = supplied
commonName             = supplied
emailAddress           = optional

[ req ]
distinguished_name = req_distinguished_name
prompt             = no

[ req_distinguished_name ]
O  = Test Organization
OU = Test Organization Unit
CN = Test Organization Intermediate CA
EOF

intermediate_ca_key_pass="pass:random-intermediate-CA-password-${RANDOM}"

openssl genrsa -aes256 \
  -out "$tmpdir/test-intermediate-CA-key.pem" \
  -passout "$intermediate_ca_key_pass" \
  "$keys_size"

openssl req \
  -batch -new -nodes \
  -passin "$intermediate_ca_key_pass" \
  -config "$tmpdir/test-intermediate-CA.config" \
  -key "$tmpdir/test-intermediate-CA-key.pem" \
  -passout "$root_ca_key_pass" \
  -sha256 \
  -extensions v3_ca \
  -out "$tmpdir/test-intermediate-CA-certificate-request.pem"

openssl req -text -noout -in "$tmpdir/test-intermediate-CA-certificate-request.pem"

openssl ca \
  -batch -notext \
  -config "$tmpdir/test-root-CA.config" \
  -passin "$root_ca_key_pass"\
  -keyfile "$tmpdir/test-root-CA-key.pem" \
  -in "$tmpdir/test-intermediate-CA-certificate-request.pem" \
  -days 365 -extensions v3_intermediate_ca -out "$tmpdir/test-intermediate-CA.pem"

openssl x509 -noout -in "$tmpdir/test-intermediate-CA.pem"
openssl verify -CAfile "$tmpdir/test-root-CA.pem" "$tmpdir/test-intermediate-CA.pem"


## Sub-Intermediate CA certificate generation

cat <<EOF > "$tmpdir/test-sub-intermediate-CA.config"
[ ca ]
default_ca = CA_default

[ CA_default ]
dir              = $tmpdir
database         = \$dir/index.txt
new_certs_dir    = \$dir/new_certs

certificate      = \$dir/test-sub-intermediate-CA.pem
serial           = \$dir/serial
private_key      = \$dir/test-sub-intermediate-CA-key.pem
RANDFILE         = \$dir/rand

default_days     = 365
default_crl_days = 30
default_md       = sha256

policy           = policy_any
email_in_dn      = no

name_opt         = ca_default
cert_opt         = ca_default
copy_extensions  = copy

[ usr_cert ]
authorityKeyIdentifier = keyid, issuer

[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints       = CA:true
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints       = CA:true
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign

[ policy_any ]
organizationName       = supplied
organizationalUnitName = supplied
commonName             = supplied
emailAddress           = optional

[ req ]
distinguished_name = req_distinguished_name
prompt             = no

[ req_distinguished_name ]
O  = Test Organization
OU = Test Organization Unit
CN = Test Organization Sub Intermediate CA
EOF

sub_intermediate_ca_key_pass="pass:random-sub-intermediate-CA-password-${RANDOM}"

openssl genrsa -aes256 \
  -out "$tmpdir/test-sub-intermediate-CA-key.pem" \
  -passout "$sub_intermediate_ca_key_pass" \
  "$keys_size"

openssl req \
  -batch -new -nodes \
  -passin "$sub_intermediate_ca_key_pass" \
  -config "$tmpdir/test-sub-intermediate-CA.config" \
  -key "$tmpdir/test-sub-intermediate-CA-key.pem" \
  -passout "$intermediate_ca_key_pass" \
  -sha256 \
  -extensions v3_ca \
  -out "$tmpdir/test-sub-intermediate-CA-certificate-request.pem"

openssl req -text -noout -in "$tmpdir/test-sub-intermediate-CA-certificate-request.pem"

openssl ca \
  -batch -notext \
  -config "$tmpdir/test-intermediate-CA.config" \
  -passin "$intermediate_ca_key_pass"\
  -keyfile "$tmpdir/test-intermediate-CA-key.pem" \
  -in "$tmpdir/test-sub-intermediate-CA-certificate-request.pem" \
  -days 365 -extensions v3_intermediate_ca -out "$tmpdir/test-sub-intermediate-CA.pem"

openssl x509 -noout -in "$tmpdir/test-sub-intermediate-CA.pem"
openssl verify \
  -partial_chain \
  -CAfile "$tmpdir/test-intermediate-CA.pem" "$tmpdir/test-sub-intermediate-CA.pem"

expect_fail\
  openssl verify \
    -CAfile "$tmpdir/test-root-CA.pem" "$tmpdir/test-sub-intermediate-CA.pem"


## Root CA Trusted Certificate generation

cat <<"EOF" > "$tmpdir/test-root-CA-trusted-certificate-0001.config"
[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]
O = Test Organization
OU = Test Organization Unit
CN = Test Organization Root Trusted Certificate 0001

[ req_exts ]
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "Test Organization Root CA trusted Certificate"
subjectKeyIdentifier = hash
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection
subjectAltName = email:mail@3v1n0.net,URI:https://github.com/3v1n0/
EOF

root_ca_trusted_cert_0001_key_pass="pass:random-root-ca-trusted-cert-0001-${RANDOM}"
openssl genrsa -aes256 \
  -out "$tmpdir/test-root-CA-trusted-certificate-0001-key.pem" \
  -passout "$root_ca_trusted_cert_0001_key_pass" \
  "$keys_size"

openssl req \
  -new -nodes \
  -reqexts req_exts \
  -passin "$root_ca_trusted_cert_0001_key_pass" \
  -key "$tmpdir/test-root-CA-trusted-certificate-0001-key.pem" \
  -config "$tmpdir/test-root-CA-trusted-certificate-0001.config" \
  -out "$tmpdir/test-root-CA-trusted-certificate-0001-request.pem"

openssl req -text -noout \
  -in "$tmpdir/test-root-CA-trusted-certificate-0001-request.pem"

openssl ca \
  -batch -notext \
  -config "$tmpdir/test-root-CA.config" \
  -passin "$root_ca_key_pass" \
  -keyfile "$tmpdir/test-root-CA-key.pem" \
  -in "$tmpdir/test-root-CA-trusted-certificate-0001-request.pem" \
  -days 365 -extensions usr_cert \
  -out "$tmpdir/test-root-CA-trusted-certificate-0001.pem"

openssl x509 -noout \
  -in "$tmpdir/test-root-CA-trusted-certificate-0001.pem"

openssl verify -CAfile \
  "$tmpdir/test-root-CA.pem" \
  "$tmpdir/test-root-CA-trusted-certificate-0001.pem"

expect_fail \
  openssl verify -CAfile \
    "$tmpdir/test-intermediate-CA.pem" \
    "$tmpdir/test-root-CA-trusted-certificate-0001.pem"


## Intermediate CA Trusted Certificate generation

cat <<"EOF" > "$tmpdir/test-intermediate-CA-trusted-certificate-0001.config"
[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]
O = Test Organization
OU = Test Organization Unit
CN = Test Organization Intermediate Trusted Certificate 0001

[ req_exts ]
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "Test Organization Intermediate CA trusted Certificate"
subjectKeyIdentifier = hash
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection
subjectAltName = email:mail@3v1n0.net,URI:https://github.com/3v1n0/
EOF

intermediate_ca_trusted_cert_0001_key_pass="pass:random-intermediate-ca-trusted-cert-0001-${RANDOM}"

openssl genrsa -aes256 \
  -out "$tmpdir/test-intermediate-CA-trusted-certificate-0001-key.pem" \
  -passout "$intermediate_ca_trusted_cert_0001_key_pass" \
  "$keys_size"

openssl req \
  -new -nodes \
  -reqexts req_exts \
  -passin "$intermediate_ca_trusted_cert_0001_key_pass" \
  -key "$tmpdir/test-intermediate-CA-trusted-certificate-0001-key.pem" \
  -config "$tmpdir/test-intermediate-CA-trusted-certificate-0001.config" \
  -out "$tmpdir/test-intermediate-CA-trusted-certificate-0001-request.pem"

openssl req -text -noout \
  -in "$tmpdir/test-intermediate-CA-trusted-certificate-0001-request.pem"

openssl ca \
  -passin "$intermediate_ca_key_pass" \
  -config "$tmpdir/test-intermediate-CA.config" -batch -notext \
  -keyfile "$tmpdir/test-intermediate-CA-key.pem" \
  -in "$tmpdir/test-intermediate-CA-trusted-certificate-0001-request.pem" \
  -days 365 -extensions usr_cert \
  -out "$tmpdir/test-intermediate-CA-trusted-certificate-0001.pem"

openssl x509 -noout \
  -in "$tmpdir/test-intermediate-CA-trusted-certificate-0001.pem"

echo "This certificate should not be trusted fully"
expect_fail \
  openssl verify \
    -CAfile "$tmpdir/test-intermediate-CA.pem" \
    "$tmpdir/test-intermediate-CA-trusted-certificate-0001.pem"

openssl verify -partial_chain \
  -CAfile "$tmpdir/test-intermediate-CA.pem" \
  "$tmpdir/test-intermediate-CA-trusted-certificate-0001.pem"


## Sub Intermediate CA Trusted Certificate generation

cat <<"EOF" > "$tmpdir/test-sub-intermediate-CA-trusted-certificate-0001.config"
[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]
O = Test Organization
OU = Test Organization Unit
CN = Test Organization Sub Intermediate Trusted Certificate 0001

[ req_exts ]
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "Test Organization Sub Intermediate CA trusted Certificate"
subjectKeyIdentifier = hash
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection
subjectAltName = email:mail@3v1n0.net,URI:https://github.com/3v1n0/
EOF

sub_intermediate_ca_trusted_cert_0001_key_pass="pass:random-sub-intermediate-ca-trusted-cert-0001-${RANDOM}"

openssl genrsa -aes256 \
  -out "$tmpdir/test-sub-intermediate-CA-trusted-certificate-0001-key.pem" \
  -passout "$sub_intermediate_ca_trusted_cert_0001_key_pass" \
  "$keys_size"

openssl req \
  -new -nodes \
  -reqexts req_exts \
  -passin "$sub_intermediate_ca_trusted_cert_0001_key_pass" \
  -key "$tmpdir/test-sub-intermediate-CA-trusted-certificate-0001-key.pem" \
  -config "$tmpdir/test-sub-intermediate-CA-trusted-certificate-0001.config" \
  -out "$tmpdir/test-sub-intermediate-CA-trusted-certificate-0001-request.pem"

openssl req -text -noout \
  -in "$tmpdir/test-sub-intermediate-CA-trusted-certificate-0001-request.pem"

openssl ca \
  -passin "$sub_intermediate_ca_key_pass" \
  -config "$tmpdir/test-sub-intermediate-CA.config" -batch -notext \
  -keyfile "$tmpdir/test-sub-intermediate-CA-key.pem" \
  -in "$tmpdir/test-sub-intermediate-CA-trusted-certificate-0001-request.pem" \
  -days 365 -extensions usr_cert \
  -out "$tmpdir/test-sub-intermediate-CA-trusted-certificate-0001.pem"

openssl x509 -noout \
  -in "$tmpdir/test-sub-intermediate-CA-trusted-certificate-0001.pem"

echo "This certificate should not be trusted fully"
expect_fail \
  openssl verify \
    -CAfile "$tmpdir/test-sub-intermediate-CA.pem" \
    "$tmpdir/test-sub-intermediate-CA-trusted-certificate-0001.pem"

expect_fail \
  openssl verify \
    -CAfile "$tmpdir/test-intermediate-CA.pem" \
    "$tmpdir/test-sub-intermediate-CA-trusted-certificate-0001.pem"

openssl verify -partial_chain \
  -CAfile "$tmpdir/test-sub-intermediate-CA.pem" \
  "$tmpdir/test-sub-intermediate-CA-trusted-certificate-0001.pem"

expect_fail \
  openssl verify -partial_chain \
    -CAfile "$tmpdir/test-intermediate-CA.pem" \
    "$tmpdir/test-sub-intermediate-CA-trusted-certificate-0001.pem"


## Full chain verification tests

echo "Building a the full-chain CA file..."
cat \
  "$tmpdir/test-root-CA.pem" \
  "$tmpdir/test-intermediate-CA.pem" \
  "$tmpdir/test-sub-intermediate-CA.pem" \
  > "$tmpdir/test-full-chain-CA.pem"

cat \
  "$tmpdir/test-root-CA.pem" \
  "$tmpdir/test-intermediate-CA.pem" \
  > "$tmpdir/test-root-intermediate-chain-CA.pem"

cat \
  "$tmpdir/test-intermediate-CA.pem" \
  "$tmpdir/test-sub-intermediate-CA.pem" \
  > "$tmpdir/test-intermediate-sub-chain-CA.pem"

openssl crl2pkcs7 \
  -nocrl -certfile "$tmpdir/test-full-chain-CA.pem" \
  | openssl pkcs7 -print_certs -noout 

openssl verify \
  -CAfile "$tmpdir/test-full-chain-CA.pem" \
  "$tmpdir/test-intermediate-CA.pem"

openssl verify \
  -CAfile "$tmpdir/test-full-chain-CA.pem" \
  "$tmpdir/test-root-CA-trusted-certificate-0001.pem"

openssl verify \
  -CAfile "$tmpdir/test-full-chain-CA.pem" \
  "$tmpdir/test-intermediate-CA-trusted-certificate-0001.pem"

openssl verify \
  -CAfile "$tmpdir/test-full-chain-CA.pem" \
  "$tmpdir/test-root-intermediate-chain-CA.pem"

openssl verify \
  -CAfile "$tmpdir/test-full-chain-CA.pem" \
  "$tmpdir/test-sub-intermediate-CA-trusted-certificate-0001.pem"

echo "Certificates generation completed!"

function prepare_softhsm2_card() {
  local certificate="$1"
  local key_pass="$2"

  local key_cn
  local key_name
  local tokens_dir
  local output_cert_file

  token_name=
  key_name="$(basename "$certificate" .pem)"
  key_cn="$(openssl x509 -noout -subject -nameopt multiline -in "$certificate" \
      | sed -n 's/ *commonName *= //p')"

  if [ -v SOFTHSM2_ISOLATED_CONFIGS ]; then
    key_name+="-${RANDOM}"
  fi

  export SOFTHSM2_CONF="$tmpdir/softhsm2-${key_name}.conf"

  tokens_dir="$tmpdir/$(basename "$SOFTHSM2_CONF" .conf)"
  token_name="${key_cn:0:25} Token"

  if [ ! -e "$SOFTHSM2_CONF" ] || [ ! -d "$tokens_dir" ]; then
    local key_file
    local decrypted_key

    mkdir -p "$tokens_dir"

    key_file="$tmpdir/${key_name}-key.pem"
    decrypted_key="$tmpdir/${key_name}-key-decrypted.pem"

    cat <<EOF > "$SOFTHSM2_CONF"
directories.tokendir = $tokens_dir
objectstore.backend = file
slots.removable = true
EOF

    softhsm2-util --init-token \
      --label "$token_name" \
      --pin "$PIN" --so-pin "$PIN" --free || return 2

    softhsm2-util --show-slots || return 2

    p11tool \
      --provider="$SOFTHSM2_MODULE" \
      --write \
      --no-mark-private \
      --load-certificate="$certificate" \
      --login --set-pin="$PIN" \
      --label "$key_cn" \
      --id "$TOKEN_ID" || return 2

    openssl rsa \
      -passin "$key_pass" \
      -in "$key_file" \
      -out "$decrypted_key" || return 2

    p11tool \
      --provider="$SOFTHSM2_MODULE" \
      --write \
      --load-privkey="$decrypted_key" \
      --login --set-pin="$PIN" \
      --label "$key_cn Key" \
      --id "$TOKEN_ID" || return 2

    rm "$decrypted_key"

    p11tool \
      --provider="$SOFTHSM2_MODULE" \
      --list-all || return 2
  fi

  echo "$token_name"
}

function check_certificate() {
  local certificate="$1"
  local key_pass="$2"
  local key_ring="$3"
  local verify_option="$4"

  prepare_softhsm2_card "$certificate" "$key_pass" || return 2

  if [ -n "$verify_option" ]; then
    local verify_arg="--verify=$verify_option"
  fi

  local output_base_name="SSSD-child-${RANDOM}"
  local output_file="$tmpdir/$output_base_name.output"
  output_cert_file="$tmpdir/$output_base_name.pem"

  "$SSSD_P11_CHILD" \
    --pre -d 10 \
    --logger=stderr \
    --debug-fd=2 \
    "$verify_arg" \
    --${ca_db_arg}="$key_ring" > "$output_file" || return 2

  grep -qs "$TOKEN_ID" "$output_file" || return 2

  echo "-----BEGIN CERTIFICATE-----" > "$output_cert_file"
  tail -n1 "$output_file" >> "$output_cert_file"
  echo "-----END CERTIFICATE-----" >> "$output_cert_file"

  openssl x509 -text -noout -in "$output_cert_file" || return 2

  local found_md5 expected_md5
  expected_md5=$(openssl x509 -noout -modulus -in "$certificate")
  found_md5=$(openssl x509 -noout -modulus -in "$output_cert_file")

  if [ "$expected_md5" != "$found_md5" ]; then
    echo "Unexpected certificate found: $found_md5"
    return 3
  fi

  # Try to authorize now!

  output_file="$tmpdir/${output_base_name}-auth.output"
  output_cert_file="$tmpdir/$(basename "$output_file" .output).pem"

  echo -n "$PIN" | "$SSSD_P11_CHILD" \
    --auth -d 10 --debug-fd=2 \
    --${ca_db_arg}="$key_ring" \
    --pin \
    --key_id "$TOKEN_ID" \
    "$verify_arg" \
    --token_name "$token_name" \
    --module_name "$SOFTHSM2_MODULE" > "$output_file" || return 2

  grep -qs "$TOKEN_ID" "$output_file" || return 2

  echo "-----BEGIN CERTIFICATE-----" > "$output_cert_file"
  tail -n1 "$output_file" >> "$output_cert_file"
  echo "-----END CERTIFICATE-----" >> "$output_cert_file"

  openssl x509 -text -noout -in "$output_cert_file" || return 2

  found_md5=$(openssl x509 -noout -modulus -in "$output_cert_file")

  if [ "$expected_md5" != "$found_md5" ]; then
    echo "Unexpected certificate found: $found_md5"
    return 3
  fi
}

function valid_certificate() {
  if ! check_certificate "$@"; then
    echo "Unexpected failure!"
    exit 2
  fi
}


function invalid_certificate() {
  if check_certificate "$@"; then
    echo "Unexpected pass!"
    exit 2
  fi
}

if [[ -v NO_SSSD_TESTS ]]; then
  if [[ -v GENERATE_SMART_CARDS ]]; then
    prepare_softhsm2_card \
      "$tmpdir/test-root-CA-trusted-certificate-0001.pem" \
      "$root_ca_trusted_cert_0001_key_pass"

    prepare_softhsm2_card \
      "$tmpdir/test-intermediate-CA-trusted-certificate-0001.pem" \
      "$intermediate_ca_trusted_cert_0001_key_pass"

    prepare_softhsm2_card \
      "$tmpdir/test-sub-intermediate-CA-trusted-certificate-0001.pem" \
      "$sub_intermediate_ca_trusted_cert_0001_key_pass"
  fi

  echo "Certificates generation completed!"
  exit 0
fi

## Checking that Root CA Trusted certificate is accepted

invalid_certificate \
  "$tmpdir/test-root-CA-trusted-certificate-0001.pem" \
  "$root_ca_trusted_cert_0001_key_pass" \
  /dev/null

valid_certificate \
  "$tmpdir/test-root-CA-trusted-certificate-0001.pem" \
  "$root_ca_trusted_cert_0001_key_pass" \
  /dev/null \
  "no_verification"

valid_certificate \
  "$tmpdir/test-root-CA-trusted-certificate-0001.pem" \
  "$root_ca_trusted_cert_0001_key_pass" \
  "$tmpdir/test-root-CA.pem"

valid_certificate \
  "$tmpdir/test-root-CA-trusted-certificate-0001.pem" \
  "$root_ca_trusted_cert_0001_key_pass" \
  "$tmpdir/test-root-CA.pem" \
  "partial_chain"

valid_certificate \
  "$tmpdir/test-root-CA-trusted-certificate-0001.pem" \
  "$root_ca_trusted_cert_0001_key_pass" \
  "$tmpdir/test-full-chain-CA.pem"

valid_certificate \
  "$tmpdir/test-root-CA-trusted-certificate-0001.pem" \
  "$root_ca_trusted_cert_0001_key_pass" \
  "$tmpdir/test-full-chain-CA.pem" \
  "partial_chain"

invalid_certificate \
  "$tmpdir/test-root-CA-trusted-certificate-0001.pem" \
  "$root_ca_trusted_cert_0001_key_pass" \
  "$tmpdir/test-intermediate-CA.pem"

invalid_certificate \
  "$tmpdir/test-root-CA-trusted-certificate-0001.pem" \
  "$root_ca_trusted_cert_0001_key_pass" \
  "$tmpdir/test-intermediate-CA.pem" \
  "partial_chain"


## Checking that Intermediate CA Trusted certificate is accepted

invalid_certificate \
  "$tmpdir/test-intermediate-CA-trusted-certificate-0001.pem" \
  "$intermediate_ca_trusted_cert_0001_key_pass" \
  /dev/null

valid_certificate \
  "$tmpdir/test-intermediate-CA-trusted-certificate-0001.pem" \
  "$intermediate_ca_trusted_cert_0001_key_pass" \
  /dev/null \
  "no_verification"

invalid_certificate \
  "$tmpdir/test-intermediate-CA-trusted-certificate-0001.pem" \
  "$intermediate_ca_trusted_cert_0001_key_pass" \
  "$tmpdir/test-root-CA.pem"

invalid_certificate \
  "$tmpdir/test-intermediate-CA-trusted-certificate-0001.pem" \
  "$intermediate_ca_trusted_cert_0001_key_pass" \
  "$tmpdir/test-root-CA.pem" \
  "partial_chain"

valid_certificate \
  "$tmpdir/test-intermediate-CA-trusted-certificate-0001.pem" \
  "$intermediate_ca_trusted_cert_0001_key_pass" \
  "$tmpdir/test-full-chain-CA.pem"

valid_certificate \
  "$tmpdir/test-intermediate-CA-trusted-certificate-0001.pem" \
  "$intermediate_ca_trusted_cert_0001_key_pass" \
  "$tmpdir/test-full-chain-CA.pem" \
  "partial_chain"

invalid_certificate \
  "$tmpdir/test-intermediate-CA-trusted-certificate-0001.pem" \
  "$intermediate_ca_trusted_cert_0001_key_pass" \
  "$tmpdir/test-intermediate-CA.pem"

valid_certificate \
  "$tmpdir/test-intermediate-CA-trusted-certificate-0001.pem" \
  "$intermediate_ca_trusted_cert_0001_key_pass" \
  "$tmpdir/test-intermediate-CA.pem" \
  "partial_chain"


## Checking that Sub Intermediate CA Trusted certificate is accepted

invalid_certificate \
  "$tmpdir/test-sub-intermediate-CA-trusted-certificate-0001.pem" \
  "$sub_intermediate_ca_trusted_cert_0001_key_pass" \
  "$tmpdir/test-root-CA.pem"

invalid_certificate \
  "$tmpdir/test-sub-intermediate-CA-trusted-certificate-0001.pem" \
  "$sub_intermediate_ca_trusted_cert_0001_key_pass" \
  "$tmpdir/test-root-CA.pem" \
  "partial_chain"

valid_certificate \
  "$tmpdir/test-sub-intermediate-CA-trusted-certificate-0001.pem" \
  "$sub_intermediate_ca_trusted_cert_0001_key_pass" \
  "$tmpdir/test-full-chain-CA.pem"

valid_certificate \
  "$tmpdir/test-sub-intermediate-CA-trusted-certificate-0001.pem" \
  "$sub_intermediate_ca_trusted_cert_0001_key_pass" \
  "$tmpdir/test-full-chain-CA.pem" \
  "partial_chain"

invalid_certificate \
  "$tmpdir/test-sub-intermediate-CA-trusted-certificate-0001.pem" \
  "$sub_intermediate_ca_trusted_cert_0001_key_pass" \
  "$tmpdir/test-sub-intermediate-CA.pem"

invalid_certificate \
  "$tmpdir/test-sub-intermediate-CA-trusted-certificate-0001.pem" \
  "$sub_intermediate_ca_trusted_cert_0001_key_pass" \
  "$tmpdir/test-root-intermediate-chain-CA.pem" \
  "partial_chain"

valid_certificate \
  "$tmpdir/test-sub-intermediate-CA-trusted-certificate-0001.pem" \
  "$sub_intermediate_ca_trusted_cert_0001_key_pass" \
  "$tmpdir/test-sub-intermediate-CA.pem" \
  "partial_chain"

valid_certificate \
  "$tmpdir/test-sub-intermediate-CA-trusted-certificate-0001.pem" \
  "$sub_intermediate_ca_trusted_cert_0001_key_pass" \
  "$tmpdir/test-intermediate-sub-chain-CA.pem" \
  "partial_chain"

set +x

echo
echo "Test completed, Root CA and intermediate issued certificates verified!"
