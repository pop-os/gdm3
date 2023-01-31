#!/usr/bin/env bash

if adduser --disabled-password --gecos "" tester; then
  usermod -a -G sudo tester
  echo "tester ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
fi

runuser -u tester -- sudo -E bash \
  debian/tests/sssd-gdm-smartcard-pam-auth-tester.sh
