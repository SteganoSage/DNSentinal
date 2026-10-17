#!/usr/bin/env bash
# Lab certificates for DoT and DoH (plan §6.2): a local CA, and a server
# certificate it signs for localhost plus any names and addresses given.
#
#   certs/make_certs.sh                      # localhost, 127.0.0.1, ::1
#   certs/make_certs.sh dns.lab 10.10.0.2    # ...and these
#
# Writes certs/ca.crt, certs/ca.key, certs/server.crt and certs/server.key
# (all git-ignored). The CA is made once and reused, so clients that trust
# it keep trusting new server certificates. Trust certs/ca.crt in clients:
#   kdig @127.0.0.1 +tls-ca=certs/ca.crt +tls-hostname=localhost example.com
#   curl --cacert certs/ca.crt ...           (and import it into a browser for DoH)
# A phone's Private DNS ignores user-installed CAs and needs a publicly
# trusted certificate instead (Let's Encrypt with a DNS-01 challenge).
set -euo pipefail

dir="$(cd "$(dirname "$0")" && pwd)"
san="DNS:localhost,IP:127.0.0.1,IP:::1"
for extra in "$@"; do
    if [[ $extra =~ ^[0-9.]+$ || $extra == *:* ]]; then san+=",IP:$extra"; else san+=",DNS:$extra"; fi
done

if [[ ! -f $dir/ca.key ]]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
        -keyout "$dir/ca.key" -out "$dir/ca.crt" -subj "/CN=DNSentinel lab CA" 2>/dev/null
    chmod 600 "$dir/ca.key"
    echo "made a lab CA: $dir/ca.crt"
fi

openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$dir/server.key" -out "$dir/server.csr" -subj "/CN=DNSentinel" 2>/dev/null
openssl x509 -req -in "$dir/server.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" \
    -set_serial "0x$(openssl rand -hex 16)" -days 825 -out "$dir/server.crt" \
    -extfile <(printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' "$san") 2>/dev/null
rm -f "$dir/server.csr"
chmod 600 "$dir/server.key"
echo "wrote $dir/server.crt for $san, signed by $dir/ca.crt"
