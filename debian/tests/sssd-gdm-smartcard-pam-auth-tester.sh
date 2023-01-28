#!/usr/bin/env bash
# Copyright 2023 - Marco Trevisan
# Released under the GPLv3 terms
#
# A simple tool to simulate PAM authentication using GDM smartcard settings
#
# To be used with https://gist.github.com/3v1n0/287d02ca8e03936f1c7bba992173d47a
set -xe

required_tools=(
    gdm3           # debian package: gdm3
    pamtester      # debian package: pamtester
    softhsm2-util  # debian package: softhsm2
    sssd           # debian package: sssd
)

if [[ ! -v OFFLINE_MODE ]]; then
  required_tools+=(
    wget  # debian package: wget
  )
fi

if [ "$(id -u)" != 0 ] || [ -z "$SUDO_USER" ]; then
  echo "This tool requires sudo!"
  exit 2
fi

for cmd in "${required_tools[@]}"; do
  if ! command -v "$cmd" > /dev/null; then
    echo "Tool $cmd missing"
    exit 1
  fi
done

PIN=${PIN:-123456}
GDM_USER=${GDM_USER:-gdm}
tmpdir=${TEST_TMPDIR:-$(mktemp -d -t "sssd-softhsm2-gdm-certs-XXXXXX")}
backupsdir=

alternative_pam_configs=(
  /etc/pam.d/gdm-smartcard-sssd-exclusive
  /etc/pam.d/gdm-smartcard-sssd-or-password
)

declare -a restore_paths
declare -a delete_paths

function restore_changes() {
  for path in "${restore_paths[@]}"; do
    local original_path
    original_path="/$(realpath --strip --relative-base="$backupsdir" "$path")"
    rm "$original_path" && mv "$path" "$original_path" || true
  done

  for path in "${delete_paths[@]}"; do
    rm -f "$path"
    #find "$(dirname "$path")" -empty -delete || true
  done

  update-alternatives --auto gdm-smartcard

  if [ -e /etc/sssd/sssd.conf ]; then
    chmod 600 /etc/sssd/sssd.conf || return 1
    systemctl restart sssd || true
  else
    systemctl stop sssd || true
  fi

  if [ -e /etc/softhsm/softhsm2.conf ]; then
    chmod 600 /etc/softhsm/softhsm2.conf || return 1
  fi

  rm -rf "$tmpdir"
}

function backup_file() {
  if [ -z "$backupsdir" ]; then
    backupsdir=$(mktemp -d -t "sssd-softhsm2-gdm-backups-XXXXXX")
  fi

  if [ -e "$1" ]; then
    local back_dir="$backupsdir/$(dirname "$1")"
    local back_path="$back_dir/$(basename "$1")"
    [ ! -e "$back_path" ] || return 1

    mkdir -p "$back_dir" || return 1
    mv "$1" "$back_path" || return 1

    restore_paths+=("$back_path")
  else
    delete_paths+=("$1")
  fi
}

function handle_exit() {
  exit_code=$?

  restore_changes || return 1

  if [ $exit_code = 0 ]; then
    rm -rf "$backupsdir"
    set +x
    echo "Script completed successfully!"
  else
    set +x
    echo "Script failed, check the log!"
    echo "  Backup preserved at $backupsdir"
    echo "  PAM Log: /var/log/auth.log"
    echo "  SSSD PAM Log: /var/log/sssd/sssd_pam.log"
    echo "  SSSD p11_child Log: /var/log/sssd/p11_child.log"
  fi
}

trap 'handle_exit' EXIT

tester="$(dirname "$0")"/sssd-softhism2-certificates-tests.sh
if [ ! -e "$tester" ]; then
  echo "Required $tester missing, we're downloading it..."
  tester="$tmpdir/sssd-softhism2-certificates-tests.sh"
  wget -q -c https://gist.github.com/3v1n0/287d02ca8e03936f1c7bba992173d47a/raw/sssd-softhism2-certificates-tests.sh \
    -O "$tester"
  [ -e "$tester" ] || exit 1
fi

export PIN TEST_TMPDIR="$tmpdir" GENERATE_SMART_CARDS=1 KEEP_TEMPORARY_FILES=1 NO_SSSD_TESTS=1
bash "$tester"

find "$tmpdir" -type d -exec chmod 777 {} \;
find "$tmpdir" -type f -exec chmod 666 {} \;

backup_file /etc/sssd/sssd.conf

user_home="$(runuser -u "$SUDO_USER" -- sh -c 'echo ~')"
mkdir -p "$user_home"
chown "$SUDO_USER:$SUDO_USER" "$user_home"

gdm_home="$(runuser -u "$GDM_USER" -- sh -c 'echo ~')"
mkdir -p "$gdm_home"
chown "$GDM_USER:$GDM_USER" "$gdm_home"

user_config="$(runuser -u "$SUDO_USER" -- sh -c 'echo ${XDG_CONFIG_HOME:-~/.config}')"
gdm_config="$(runuser -u "$GDM_USER" -- sh -c 'echo ${XDG_CONFIG_HOME:-~/.config}')"
system_config="/etc"

softhsm2_conf_paths=(
  "$SUDO_USER:$user_config/softhsm2/softhsm2.conf"
  "$GDM_USER:$gdm_config/softhsm2/softhsm2.conf"
  "root:$system_config/softhsm/softhsm2.conf"
)

for path_pair in "${softhsm2_conf_paths[@]}"; do
  IFS=":" read -r -a path <<< "${path_pair}"
  path="${path[1]}"
  backup_file "$path"
done

function test_authentication() {
  certificate_config="$1"
  ca_db="$2"
  verification_options="$3"

  mkdir -p -m 700 /etc/sssd

  cat <<EOF > /etc/sssd/sssd.conf || return 2
[sssd]
enable_files_domain = True
services = pam
#certificate_verification = $verification_options

[certmap/implicit_files/$SUDO_USER]
matchrule = <SUBJECT>.*Test Organization.*

[pam]
pam_cert_db_path = $ca_db
pam_cert_verification = $verification_options
pam_cert_auth = True
pam_verbosity = 10
debug_level = 10
EOF

  chmod 600 /etc/sssd/sssd.conf || return 2

  for path_pair in "${softhsm2_conf_paths[@]}"; do
    IFS=":" read -r -a path <<< "${path_pair}"
    user="${path[0]}"
    path="${path[1]}"

    runuser -u "$user" -- mkdir -p "$(dirname "$path")" || return 2
    runuser -u "$user" -- ln -sf "$certificate_config" "$path" || return 2
    runuser -u "$user" -- softhsm2-util --show-slots | grep "Test Organization" \
      || return 2
  done

  systemctl restart sssd || return 2

  for alternative in "${alternative_pam_configs[@]}"; do
    sudo update-alternatives --set gdm-smartcard "$alternative"

    echo -n -e "$PIN" | runuser -u "$SUDO_USER" -- \
      pamtester -v gdm-smartcard "$SUDO_USER" authenticate  || return 2
    echo -n -e "$PIN" | runuser -u "$SUDO_USER" -- \
      pamtester -v gdm-smartcard "" authenticate  || return 2

    if echo -n -e "wrong${PIN}" | runuser -u "$SUDO_USER" -- \
        pamtester -v gdm-smartcard "$SUDO_USER" authenticate; then
      echo "Unexpected pass!"
      return 2
    fi

    if echo -n -e "wrong${PIN}" | runuser -u "$SUDO_USER" -- \
        pamtester -v gdm-smartcard "" authenticate; then
      echo "Unexpected pass!"
      return 2
    fi

    if echo -n -e "$PIN" | pamtester -v gdm-smartcard root authenticate; then
      echo "Unexpected pass!"
      return 2
    fi

    if [[ -v WAIT ]]; then
      echo "Press any key and enter to continue"
      systemctl restart gdm3
      read
    fi
  done
}

test_authentication \
  "$tmpdir/softhsm2-test-root-CA-trusted-certificate-0001.conf" \
  "$tmpdir/test-full-chain-CA.pem"

test_authentication \
  "$tmpdir/softhsm2-test-sub-intermediate-CA-trusted-certificate-0001.conf" \
  "$tmpdir/test-full-chain-CA.pem"

test_authentication \
  "$tmpdir/softhsm2-test-sub-intermediate-CA-trusted-certificate-0001.conf" \
  "$tmpdir/test-sub-intermediate-CA.pem" \
  "partial_chain"
