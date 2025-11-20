package handlers

import (
	"bytes"
	"fmt"
	"github.com/suquant/wgrest/utils"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const wgQuickDir = "/etc/wireguard"

func (c *WireGuardContainer) persistDeviceConfig(device wgtypes.Device) error {
	addresses, err := utils.GetInterfaceIPs(device.Name)
	if err != nil {
		return fmt.Errorf("failed to read interface addresses: %w", err)
	}

	data, err := renderWGQuickConfig(device, addresses)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(wgQuickDir, 0700); err != nil {
		return err
	}

	filePath := filepath.Join(wgQuickDir, device.Name+".conf")
	tmpFile, err := os.CreateTemp(wgQuickDir, device.Name+".conf.tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return err
	}

	if err := tmpFile.Chmod(0600); err != nil {
		tmpFile.Close()
		return err
	}

	if err := tmpFile.Close(); err != nil {
		return err
	}

	return os.Rename(tmpFile.Name(), filePath)
}

func (c *WireGuardContainer) removeDeviceConfig(name string) error {
	filePath := filepath.Join(wgQuickDir, name+".conf")
	if _, err := os.Stat(filePath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		return err
	}

	return os.Remove(filePath)
}

func enableWGQuickService(name string) error {
	unit := fmt.Sprintf("wg-quick@%s.service", name)
	cmd := exec.Command("systemctl", "enable", unit)
	return cmd.Run()
}

func disableWGQuickService(name string) error {
	unit := fmt.Sprintf("wg-quick@%s.service", name)
	cmd := exec.Command("systemctl", "disable", unit)
	return cmd.Run()
}

func ensureMasqueradeRule(name string) error {
	comment := fmt.Sprintf("wgrest_%s_nat", name)
	check := exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING", "-o", name, "-j", "MASQUERADE", "-m", "comment", "--comment", comment)
	if err := check.Run(); err == nil {
		return nil
	}

	add := exec.Command("iptables", "-t", "nat", "-I", "POSTROUTING", "-o", name, "-j", "MASQUERADE", "-m", "comment", "--comment", comment)
	return add.Run()
}

func removeMasqueradeRule(name string) error {
	comment := fmt.Sprintf("wgrest_%s_nat", name)
	del := exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-o", name, "-j", "MASQUERADE", "-m", "comment", "--comment", comment)
	if err := del.Run(); err != nil {
		return err
	}
	return nil
}

func renderWGQuickConfig(device wgtypes.Device, addresses []string) ([]byte, error) {
	buf := &bytes.Buffer{}
	fmt.Fprintln(buf, "[Interface]")
	fmt.Fprintf(buf, "PrivateKey = %s\n", device.PrivateKey.String())
	if device.ListenPort != 0 {
		fmt.Fprintf(buf, "ListenPort = %d\n", device.ListenPort)
	}
	if device.FirewallMark != 0 {
		fmt.Fprintf(buf, "FwMark = %d\n", device.FirewallMark)
	}
	if len(addresses) > 0 {
		fmt.Fprintf(buf, "Address = %s\n", strings.Join(addresses, ", "))
	}

	for _, peer := range device.Peers {
		fmt.Fprintln(buf, "")
		fmt.Fprintln(buf, "[Peer]")
		fmt.Fprintf(buf, "PublicKey = %s\n", peer.PublicKey.String())
		if peer.PresharedKey != (wgtypes.Key{}) {
			fmt.Fprintf(buf, "PresharedKey = %s\n", peer.PresharedKey.String())
		}
		if len(peer.AllowedIPs) > 0 {
			allowed := make([]string, len(peer.AllowedIPs))
			for i, v := range peer.AllowedIPs {
				allowed[i] = v.String()
			}
			fmt.Fprintf(buf, "AllowedIPs = %s\n", strings.Join(allowed, ", "))
		}
		if peer.Endpoint != nil {
			fmt.Fprintf(buf, "Endpoint = %s\n", peer.Endpoint.String())
		}
		if peer.PersistentKeepaliveInterval > 0 {
			keepalive := int(peer.PersistentKeepaliveInterval / time.Second)
			fmt.Fprintf(buf, "PersistentKeepalive = %d\n", keepalive)
		}
	}

	return buf.Bytes(), nil
}
