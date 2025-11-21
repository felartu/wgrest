package handlers

import (
	"fmt"
	"github.com/suquant/wgrest/utils"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"math/big"
	"net"
	"time"
)

func resolvePrivateKey(key *string) (*wgtypes.Key, error) {
	if key != nil {
		parsed, err := wgtypes.ParseKey(*key)
		if err != nil {
			return nil, err
		}
		return &parsed, nil
	}

	generated, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	return &generated, nil
}

func resolvePresharedKey(key *string) (*wgtypes.Key, error) {
	if key != nil {
		psk, err := wgtypes.ParseKey(*key)
		if err != nil {
			return nil, err
		}
		return &psk, nil
	}
	psk, err := wgtypes.GenerateKey()
	if err != nil {
		return nil, err
	}
	return &psk, nil
}

func parseKeepalive(v string) (*time.Duration, error) {
	if v == "" {
		return nil, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func durationSeconds(d *time.Duration) int {
	if d == nil {
		return 0
	}
	return int(d.Seconds())
}

func parseAllowedIPs(values []string) ([]net.IPNet, error) {
	result := make([]net.IPNet, len(values))
	for i, v := range values {
		ip, ipNet, err := net.ParseCIDR(v)
		if err != nil {
			return nil, err
		}
		ipNet.IP = ip
		result[i] = *ipNet
	}
	return result, nil
}

func assignAddresses(requested *[]string, device *wgtypes.Device, used map[string]struct{}) ([]string, error) {
	pools, err := utils.GetInterfaceIPs(device.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to read interface addresses: %w", err)
	}

	var poolNets []net.IPNet
	for _, p := range pools {
		_, ipNet, err := net.ParseCIDR(p)
		if err != nil {
			continue
		}
		poolNets = append(poolNets, *ipNet)
	}
	if len(poolNets) == 0 {
		return nil, fmt.Errorf("no address pools available")
	}

	assign := func(ipNet *net.IPNet) string {
		ipNetStr := ipNet.String()
		used[ipNetStr] = struct{}{}
		return ipNetStr
	}

	if requested != nil && len(*requested) > 0 {
		var assigned []string
		for _, addr := range *requested {
			ip, ipNet, err := net.ParseCIDR(addr)
			if err != nil {
				return nil, err
			}
			ipNet.IP = ip
			if _, exists := used[ipNet.String()]; exists {
				alt, err := findNextFree(ipNet.IP.To4() != nil, poolNets, used)
				if err != nil {
					return nil, err
				}
				assigned = append(assigned, assign(alt))
			} else {
				assigned = append(assigned, assign(ipNet))
			}
		}
		return assigned, nil
	}

	if alt, err := findNextFree(true, poolNets, used); err == nil {
		return []string{assign(alt)}, nil
	}
	if alt, err := findNextFree(false, poolNets, used); err == nil {
		return []string{assign(alt)}, nil
	}

	return nil, fmt.Errorf("no free addresses available")
}

func findNextFree(ipv4 bool, pools []net.IPNet, used map[string]struct{}) (*net.IPNet, error) {
	for _, pool := range pools {
		if ipv4 && pool.IP.To4() == nil {
			continue
		}
		if !ipv4 && pool.IP.To4() != nil {
			continue
		}

		ones, bits := pool.Mask.Size()
		hostBits := bits - ones
		if hostBits <= 0 {
			continue
		}

		start := ipToBigInt(pool.IP.Mask(pool.Mask))
		limit := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
		for offset := int64(1); offset < limit.Int64(); offset++ {
			candidateInt := new(big.Int).Add(start, big.NewInt(offset))
			candidateIP := bigIntToIP(candidateInt, ipv4)
			cNet := net.IPNet{
				IP:   candidateIP,
				Mask: pool.Mask,
			}
			if _, exists := used[cNet.String()]; !exists {
				return &cNet, nil
			}
		}
	}
	return nil, fmt.Errorf("no free addresses in pools")
}

func ipToBigInt(ip net.IP) *big.Int {
	return new(big.Int).SetBytes(ip.To16())
}

func bigIntToIP(i *big.Int, ipv4 bool) net.IP {
	b := i.Bytes()
	if ipv4 {
		b = padBytes(b, net.IPv4len)
		return net.IP(b)
	}
	b = padBytes(b, net.IPv6len)
	return net.IP(b)
}

func padBytes(b []byte, size int) []byte {
	if len(b) >= size {
		return b[len(b)-size:]
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}

func pskString(psk *wgtypes.Key) string {
	if psk == nil {
		return ""
	}
	return psk.String()
}
