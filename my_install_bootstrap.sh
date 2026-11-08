#!/bin/bash

# License
clear
echo 'MIT License'
echo ''
echo 'Copyright (c) 2018 jacktooandroid'
echo ''
echo 'Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:'
echo ''
echo 'The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.'
echo ''
echo 'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.'
echo ''
echo 'Installation will continue in 3 seconds...'
sleep 3

clear

set -euo pipefail

# Configuration
TOTALSWAPREQUIREDGB=4
SWAPFILE="/swapfile"
UOS_URL="https://fw-download.ubnt.com/data/unifi-os-server/5172-linux-x64-5.1.42-12e9e3cf-8f8b-4e54-928c-76b80a10c8a4.42-x64"
UOS_INSTALLER="/tmp/unifi-os-server-installer"

# System memory logic(s) and variable(s)
TOTALSWAP=$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo)
TOTALSWAPREQUIRED=$((TOTALSWAPREQUIREDGB * 1024 * 1024))
if [[ $TOTALSWAP -lt $TOTALSWAPREQUIRED ]]; then
    TOTALSWAPTOADDMB=$(((TOTALSWAPREQUIRED - TOTALSWAP + 1023) / 1024))
else
    TOTALSWAPTOADDMB=0
fi

# Check memory requirement
if [[ $TOTALSWAPTOADDMB -gt 0 ]]; then
    if [[ -e "$SWAPFILE" ]]; then
        echo "$SWAPFILE already exists. Exiting to avoid overwriting existing swap."
        exit 1
    fi

    echo "Adding ${TOTALSWAPTOADDMB} MiB of swap..."
    sudo fallocate -l "${TOTALSWAPTOADDMB}M" "$SWAPFILE" || exit 1
    sudo chmod 600 "$SWAPFILE" || exit 1
    sudo mkswap "$SWAPFILE" || exit 1
    sudo swapon "$SWAPFILE" || exit 1

    if ! awk -v file="$SWAPFILE" '$1 == file && $3 == "swap" {found=1} END {exit !found}' /etc/fstab; then
        sudo cp /etc/fstab "/etc/fstab.bak.$(date +%Y%m%d%H%M%S)" || exit 1
        echo "$SWAPFILE none swap sw 0 0" | sudo tee -a /etc/fstab || exit 1
    fi

    echo "Additional swap successfully configured."
else
    echo "Existing swap meets the ${TOTALSWAPREQUIREDGB} GiB requirement. No additional swap needed."
fi

# Install prerequisites
sudo apt update && sudo apt -y install podman slirp4netns passt uidmap ca-certificates gnupg curl wget

# Download Cloudflare scripts
sudo wget https://raw.githubusercontent.com/jacktooandroid/cloudflare/master/cloudflare_ddns-una.sh -O /usr/local/bin/cloudflare_ddns-una.sh
sudo curl https://raw.githubusercontent.com/jacktooandroid/cloudflare/master/cloudflare_ddns-una.sh -o /usr/local/bin/cloudflare_ddns-una.sh
sudo wget https://raw.githubusercontent.com/jacktooandroid/cloudflare/master/cloudflare_cname-una.sh -O /tmp/cloudflare_cname-una.sh
sudo curl https://raw.githubusercontent.com/jacktooandroid/cloudflare/master/cloudflare_cname-una.sh -o /tmp/cloudflare_cname-una.sh
sudo wget https://raw.githubusercontent.com/jacktooandroid/cloudflare/master/cloudflare_ddns-restoredefault.sh -O /tmp/cloudflare_ddns-restoredefault.sh
sudo curl https://raw.githubusercontent.com/jacktooandroid/cloudflare/master/cloudflare_ddns-restoredefault.sh -o /tmp/cloudflare_ddns-restoredefault.sh

# Install miscellaneous software
# sudo apt install -y haveged
sudo apt install -y certbot fail2ban glances traceroute lynx dnsutils cron
sudo apt install -y lm-sensors miniupnpc natpmpc
curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | sudo bash
sudo apt install -y speedtest

# Install iptables-persistent
echo 'iptables-persistent iptables-persistent/autosave_v4 boolean true' | sudo debconf-set-selections
echo 'iptables-persistent iptables-persistent/autosave_v6 boolean true' | sudo debconf-set-selections
sudo apt -y install iptables-persistent

# Redirect UniFi Network Application ports
sudo iptables -t nat -I PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 11443
sudo ip6tables -t nat -I PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 11443
sudo netfilter-persistent save

# Install UniFi OS Server
sudo curl -fL --retry 3 "$UOS_URL" -o "$UOS_INSTALLER"
sudo chmod +x "$UOS_INSTALLER"
sudo "$UOS_INSTALLER"
sudo usermod -aG uosserver admin

# MiniUPNP settings
echo 'upnpc -r 443 tcp' | sudo tee -a /usr/local/bin/miniupnp.sh
echo 'upnpc -r 6789 tcp' | sudo tee -a /usr/local/bin/miniupnp.sh
echo 'upnpc -r 8080 tcp' | sudo tee -a /usr/local/bin/miniupnp.sh
echo 'upnpc -r 11443 tcp' | sudo tee -a /usr/local/bin/miniupnp.sh
echo 'upnpc -r 8444 tcp' | sudo tee -a /usr/local/bin/miniupnp.sh
echo 'upnpc -r 8880 tcp' | sudo tee -a /usr/local/bin/miniupnp.sh
echo 'upnpc -r 3478 udp' | sudo tee -a /usr/local/bin/miniupnp.sh
# bash /usr/local/bin/miniupnp.sh

# NATPMP settings
echo "natpmpc -a 443 443 tcp" | sudo tee -a /usr/local/bin/natpmp.sh
echo "natpmpc -a 6789 6789 tcp" | sudo tee -a /usr/local/bin/natpmp.sh
echo "natpmpc -a 8080 8080 tcp" | sudo tee -a /usr/local/bin/natpmp.sh
echo "natpmpc -a 11443 11443 tcp" | sudo tee -a /usr/local/bin/natpmp.sh
echo "natpmpc -a 8444 8444 tcp" | sudo tee -a /usr/local/bin/natpmp.sh
echo "natpmpc -a 8880 8880 tcp" | sudo tee -a /usr/local/bin/natpmp.sh
echo "natpmpc -a 3478 3478 udp" | sudo tee -a /usr/local/bin/natpmp.sh
# bash /usr/local/bin/natpmp.sh

exit