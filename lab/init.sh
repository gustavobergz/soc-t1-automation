#!/bin/sh
set -e
export PATH=/sbin:/usr/sbin:/bin:/usr/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
exec </dev/ttyS0 >/dev/ttyS0 2>&1
stty -echo -icanon min 1 time 0

for option in $(cat /proc/cmdline); do
    case "$option" in soc.role=*) role=${option#soc.role=} ;; esac
done
if [ -z "$role" ] && [ -f /soc-e1000.ko ]; then
    insmod /soc-e1000.ko
    case "$(cat /sys/class/net/eth0/address)" in
        08:00:27:76:00:10) role=manager ;;
        08:00:27:76:00:20) role=victim ;;
        08:00:27:76:00:30) role=attacker ;;
        08:00:27:76:00:40) role=soar ;;
    esac
fi
case "$role" in
    manager) ip=10.77.0.10 ;;
    victim) ip=10.77.0.20 ;;
    attacker) ip=10.77.0.30 ;;
    soar) ip=10.77.0.40 ;;
    *) echo 'Unknown SOC guest role'; exit 1 ;;
esac

hostname "soc-$role"
ip link set lo up
ip link set eth0 up
ip addr add "$ip/24" dev eth0
exec /soc-lab "$role" "$ip"
