package handlers

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/skip2/go-qrcode"
	"github.com/suquant/wgrest/models"
	"github.com/suquant/wgrest/storage"
	"github.com/suquant/wgrest/utils"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
)

type peerConfigOptions struct {
	forceUpdateOnly         bool
	alwaysReplaceAllowedIPs bool
	overridePublicKey       *wgtypes.Key
}

type peerApplyResult struct {
	peer       wgtypes.Peer
	device     *wgtypes.Device
	privateKey *wgtypes.Key
}

type peerApplyError struct {
	status int
	code   string
	err    error
}

func (e *peerApplyError) Error() string {
	if e == nil || e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (c *WireGuardContainer) applyPeerConfig(ctx echo.Context, name string, request models.PeerCreateOrUpdateRequest, opts peerConfigOptions) (*peerApplyResult, *peerApplyError) {
	var privateKey *wgtypes.Key
	peerConf := wgtypes.PeerConfig{}

	switch {
	case opts.overridePublicKey != nil:
		peerConf.PublicKey = *opts.overridePublicKey
	case request.PublicKey != nil:
		pubKey, err := wgtypes.ParseKey(*request.PublicKey)
		if err != nil {
			ctx.Logger().Errorf("failed to parse public key: %s", err)
			return nil, &peerApplyError{status: http.StatusBadRequest, code: "wireguard_config_error", err: err}
		}
		peerConf.PublicKey = pubKey
	case request.PrivateKey != nil:
		privKey, err := wgtypes.ParseKey(*request.PrivateKey)
		if err != nil {
			ctx.Logger().Errorf("failed to parse private key: %s", err)
			return nil, &peerApplyError{status: http.StatusBadRequest, code: "wireguard_config_error", err: err}
		}
		peerConf.PublicKey = privKey.PublicKey()
		privateKey = &privKey
	default:
		privKey, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			ctx.Logger().Errorf("failed to generate private key: %s", err)
			return nil, &peerApplyError{status: http.StatusInternalServerError, code: "wireguard_config_error", err: err}
		}
		peerConf.PublicKey = privKey.PublicKey()
		privateKey = &privKey
	}

	if privateKey != nil {
		if err := c.storage.WritePeerOptions(peerConf.PublicKey, storage.StorePeerOptions{
			PrivateKey: privateKey.String(),
		}); err != nil {
			ctx.Logger().Errorf("failed to save peer options: %s", err)
			return nil, &peerApplyError{status: http.StatusInternalServerError, code: "wireguard_config_error", err: err}
		}
	}

	client, err := wgctrl.New()
	if err != nil {
		ctx.Logger().Errorf("failed to init wireguard ipc: %s", err)
		return nil, &peerApplyError{status: http.StatusInternalServerError, code: "wireguard_client_error", err: err}
	}
	defer client.Close()

	device, err := client.Device(name)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &peerApplyError{status: http.StatusNotFound, code: "wireguard_device_error", err: err}
		}

		ctx.Logger().Errorf("failed to get wireguard device: %s", err)
		return nil, &peerApplyError{status: http.StatusInternalServerError, code: "wireguard_device_error", err: err}
	}

	peerExists := false
	if !opts.forceUpdateOnly {
		for _, p := range device.Peers {
			if p.PublicKey == peerConf.PublicKey {
				peerExists = true
				break
			}
		}
	}

	if opts.alwaysReplaceAllowedIPs || request.AllowedIps != nil {
		peerConf.ReplaceAllowedIPs = true
	}

	if err := request.Apply(&peerConf); err != nil {
		ctx.Logger().Errorf("failed to apply peer config: %s", err)
		return nil, &peerApplyError{status: http.StatusBadRequest, code: "wireguard_config_error", err: err}
	}

	if opts.forceUpdateOnly || peerExists {
		peerConf.UpdateOnly = true
	}

	deviceConf := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			peerConf,
		},
	}

	if err := client.ConfigureDevice(name, deviceConf); err != nil {
		ctx.Logger().Errorf("failed to configure wireguard device(%s): %s", name, err)
		return nil, &peerApplyError{status: http.StatusBadRequest, code: "wireguard_error", err: err}
	}

	device, err = client.Device(name)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &peerApplyError{status: http.StatusNotFound, code: "wireguard_device_error", err: err}
		}

		ctx.Logger().Errorf("failed to get wireguard device: %s", err)
		return nil, &peerApplyError{status: http.StatusInternalServerError, code: "wireguard_device_error", err: err}
	}

	var peer *wgtypes.Peer
	for _, v := range device.Peers {
		if v.PublicKey == peerConf.PublicKey {
			peer = &v
			break
		}
	}

	if peer == nil {
		return nil, &peerApplyError{status: http.StatusNotFound, code: "peer_not_found", err: fmt.Errorf("peer not found")}
	}

	storeOptions := storage.StorePeerOptions{}
	if privateKey != nil {
		storeOptions.PrivateKey = privateKey.String()
	}
	if request.PresharedKey != nil {
		storeOptions.PresharedKey = *request.PresharedKey
	}

	if storeOptions.PrivateKey != "" || storeOptions.PresharedKey != "" {
		if err := c.storage.WritePeerOptions(peer.PublicKey, storeOptions); err != nil {
			ctx.Logger().Errorf("failed to save peer options: %s", err)
			return nil, &peerApplyError{status: http.StatusInternalServerError, code: "wireguard_config_error", err: err}
		}
	}

	if err := c.persistDeviceConfig(*device); err != nil {
		ctx.Logger().Errorf("failed to persist device(%s) config: %s", name, err)
		return nil, &peerApplyError{status: http.StatusInternalServerError, code: "wireguard_device_error", err: err}
	}

	return &peerApplyResult{
		peer:       *peer,
		device:     device,
		privateKey: privateKey,
	}, nil
}

// CreateDevice - Create new device
func (c *WireGuardContainer) CreateDevice(ctx echo.Context) error {
	var request models.DeviceCreateOrUpdateRequest
	if err := ctx.Bind(&request); err != nil {
		return err
	}

	if request.Name == nil || *request.Name == "" {
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "request_params_error",
			Message: "device name is required",
		})
	}

	name := *request.Name

	_, err := netlink.LinkByName(name)
	if err == nil {
		return ctx.JSON(http.StatusConflict, models.Error{
			Code:    "wireguard_device_exists",
			Message: "device already exists",
		})
	}

	var notFoundErr netlink.LinkNotFoundError
	if err != nil && !errors.As(err, &notFoundErr) {
		ctx.Logger().Errorf("failed to check device existence(%s): %s", name, err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	wgLink := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
		LinkType: "wireguard",
	}

	if err := netlink.LinkAdd(wgLink); err != nil {
		ctx.Logger().Errorf("failed to create wireguard device(%s): %s", name, err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		ctx.Logger().Errorf("failed to load newly created device(%s): %s", name, err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	cleanup := func() {
		if err := netlink.LinkDel(link); err != nil {
			ctx.Logger().Errorf("failed to cleanup device(%s): %s", name, err)
		}
	}

	if request.Networks != nil {
		for _, cidr := range *request.Networks {
			ip, ipNet, parseErr := net.ParseCIDR(cidr)
			if parseErr != nil {
				ctx.Logger().Errorf("failed to parse network(%s) for %s: %s", cidr, name, parseErr)
				cleanup()
				return ctx.JSON(http.StatusBadRequest, models.Error{
					Code:    "request_params_error",
					Message: parseErr.Error(),
				})
			}

			// Keep the host IP provided by the user instead of the masked network address.
			ipNet.IP = ip

			if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ipNet}); err != nil {
				ctx.Logger().Errorf("failed to add addr(%s) to %s: %s", cidr, name, err)
				cleanup()
				return ctx.JSON(http.StatusInternalServerError, models.Error{
					Code:    "wireguard_device_error",
					Message: err.Error(),
				})
			}
		}
	}

	if err := netlink.LinkSetUp(link); err != nil {
		ctx.Logger().Errorf("failed to set device(%s) up: %s", name, err)
		cleanup()
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	conf := wgtypes.Config{}
	if err := request.Apply(&conf); err != nil {
		ctx.Logger().Errorf("failed to apply device(%s) config: %s", name, err)
		cleanup()
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "wireguard_config_error",
			Message: err.Error(),
		})
	}

	var device *wgtypes.Device
	client, err := wgctrl.New()
	if err != nil {
		ctx.Logger().Errorf("failed to init wireguard ipc: %s", err)
		cleanup()
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_client_error",
			Message: err.Error(),
		})
	}
	defer client.Close()

	if err := client.ConfigureDevice(name, conf); err != nil {
		ctx.Logger().Errorf("failed to configure wireguard device(%s): %s", name, err)
		cleanup()
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "wireguard_error",
			Message: err.Error(),
		})
	}

	device, err = client.Device(name)
	if err != nil {
		if os.IsNotExist(err) {
			return ctx.NoContent(http.StatusNotFound)
		}

		ctx.Logger().Errorf("failed to get wireguard device: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	result := models.NewDevice(device)
	if err := applyNetworks(&result); err != nil {
		ctx.Logger().Errorf("failed to get networks for interface %s: %s", result.Name, err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	if err := c.persistDeviceConfig(*device); err != nil {
		ctx.Logger().Errorf("failed to persist device(%s) config: %s", name, err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	if err := enableWGQuickService(name); err != nil {
		ctx.Logger().Errorf("failed to enable wg-quick service for device(%s): %s", name, err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	if err := ensureMasqueradeRule(name); err != nil {
		ctx.Logger().Errorf("failed to ensure nat rule for device(%s): %s", name, err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	return ctx.JSON(http.StatusCreated, result)
}

// CreateDevicePeer - Create new device peer
func (c *WireGuardContainer) CreateDevicePeer(ctx echo.Context) error {
	var request models.PeerCreateOrUpdateRequest
	if err := ctx.Bind(&request); err != nil {
		return err
	}

	if request.AllowedIps == nil || len(*request.AllowedIps) == 0 {
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "request_params_error",
			Message: "allowed_ips is required",
		})
	}

	name := ctx.Param("name")

	result, herr := c.applyPeerConfig(ctx, name, request, peerConfigOptions{})
	if herr != nil {
		return ctx.JSON(herr.status, models.Error{
			Code:    herr.code,
			Message: herr.err.Error(),
		})
	}

	return ctx.JSON(http.StatusCreated, models.NewPeer(result.peer))
}

// ConnectDevicePeer - One-shot peer create/update and return config parameters
func (c *WireGuardContainer) ConnectDevicePeer(ctx echo.Context) error {
	name := ctx.Param("name")

	var request models.ConnectRequest
	if err := ctx.Bind(&request); err != nil {
		return err
	}

	client, err := wgctrl.New()
	if err != nil {
		ctx.Logger().Errorf("failed to init wireguard ipc: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_client_error",
			Message: err.Error(),
		})
	}
	defer client.Close()

	device, err := client.Device(name)
	if err != nil {
		if os.IsNotExist(err) {
			return ctx.NoContent(http.StatusNotFound)
		}

		ctx.Logger().Errorf("failed to get wireguard device: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	deviceOptions, err := c.storage.ReadDeviceOptions(name)
	if err != nil && !os.IsNotExist(err) {
		ctx.Logger().Errorf("failed to get device options: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}
	if deviceOptions == nil {
		deviceOptions = &c.defaultDeviceOptions
	}

	clientPrivKey, err := resolvePrivateKey(request.PrivateKey)
	if err != nil {
		ctx.Logger().Errorf("failed to resolve private key: %s", err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "wireguard_config_error",
			Message: err.Error(),
		})
	}

	psk, err := resolvePresharedKey(request.PresharedKey)
	if err != nil {
		ctx.Logger().Errorf("failed to resolve preshared key: %s", err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "wireguard_config_error",
			Message: err.Error(),
		})
	}

	// reuse stored preshared key if none provided
	if request.PresharedKey == nil {
		if opts, err := c.storage.ReadPeerOptions(clientPrivKey.PublicKey()); err == nil && opts != nil && opts.PresharedKey != "" {
			existing, parseErr := wgtypes.ParseKey(opts.PresharedKey)
			if parseErr == nil {
				psk = &existing
			}
		}
	}

	host := deviceOptions.Host
	if host == "" {
		if h, err := utils.GetExternalIP(); err == nil {
			host = h
		}
	}

	used := map[string]struct{}{}
	for _, p := range device.Peers {
		for _, ipnet := range p.AllowedIPs {
			used[ipKey(ipnet.IP)] = struct{}{}
		}
	}
	if ips, err := utils.GetInterfaceIPs(device.Name); err == nil {
		for _, addr := range ips {
			ip, _, err := net.ParseCIDR(addr)
			if err != nil {
				continue
			}
			used[ipKey(ip)] = struct{}{}
		}
	}

	assignedAddrs, err := assignAddresses(request.Addresses, device, used)
	if err != nil {
		ctx.Logger().Errorf("failed to assign addresses: %s", err)
		return ctx.JSON(http.StatusConflict, models.Error{
			Code:    "address_allocation_error",
			Message: err.Error(),
		})
	}

	allowedIPs := deviceOptions.AllowedIPs
	if len(allowedIPs) == 0 {
		allowedIPs = assignedAddrs
	}
	if request.AllowedIps != nil {
		allowedIPs = *request.AllowedIps
	}

	duration, err := parseKeepalive(request.PersistentKeepaliveInterval)
	if err != nil {
		ctx.Logger().Errorf("failed to parse keepalive: %s", err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "wireguard_config_error",
			Message: err.Error(),
		})
	}

	reqAllowed := allowedIPs
	pkStr := clientPrivKey.String()
	peerReq := models.PeerCreateOrUpdateRequest{
		PrivateKey:                  &pkStr,
		AllowedIps:                  &reqAllowed,
		PersistentKeepaliveInterval: request.PersistentKeepaliveInterval,
	}
	pskStr := ""
	if psk != nil {
		pskStr = psk.String()
		peerReq.PresharedKey = &pskStr
	}

	result, herr := c.applyPeerConfig(ctx, name, peerReq, peerConfigOptions{
		alwaysReplaceAllowedIPs: true,
	})
	if herr != nil {
		return ctx.JSON(herr.status, models.Error{
			Code:    herr.code,
			Message: herr.err.Error(),
		})
	}

	device = result.device

	resp := models.ConnectResponse{
		Interface: models.ConnectResponseInterface{
			PrivateKey: pkStr,
			Addresses:  assignedAddrs,
			DNS:        deviceOptions.DNSServers,
		},
		Peer: models.ConnectResponsePeer{
			PublicKey:           device.PublicKey.String(),
			PresharedKey:        pskStr,
			Endpoint:            fmt.Sprintf("%s:%d", host, device.ListenPort),
			AllowedIps:          allowedIPs,
			PersistentKeepalive: durationSeconds(duration),
		},
	}

	return ctx.JSON(http.StatusCreated, resp)
}

// DeleteDevice - Delete Device
func (c *WireGuardContainer) DeleteDevice(ctx echo.Context) error {
	name := ctx.Param("name")

	client, err := wgctrl.New()
	if err != nil {
		ctx.Logger().Errorf("failed to init wireguard ipc: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_client_error",
			Message: err.Error(),
		})
	}
	defer client.Close()

	device, err := client.Device(name)
	if err != nil && !os.IsNotExist(err) {
		ctx.Logger().Errorf("failed to get wireguard device: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}
	var peers []wgtypes.Peer
	if device != nil {
		peers = device.Peers
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		var notFoundErr netlink.LinkNotFoundError
		if errors.As(err, &notFoundErr) || os.IsNotExist(err) {
			return ctx.NoContent(http.StatusNotFound)
		}

		ctx.Logger().Errorf("failed to find device(%s): %s", name, err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	if err := netlink.LinkDel(link); err != nil {
		ctx.Logger().Errorf("failed to delete device(%s): %s", name, err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	if err := c.removeDeviceConfig(name); err != nil {
		ctx.Logger().Errorf("failed to remove device(%s) config: %s", name, err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	if err := disableWGQuickService(name); err != nil {
		ctx.Logger().Errorf("failed to disable wg-quick service for device(%s): %s", name, err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	for _, p := range peers {
		if err := c.storage.DeletePeerOptions(p.PublicKey); err != nil && !os.IsNotExist(err) {
			ctx.Logger().Errorf("failed to delete peer options(%s): %s", p.PublicKey.String(), err)
		}
	}

	if err := c.storage.DeleteDeviceOptions(name); err != nil && !os.IsNotExist(err) {
		ctx.Logger().Errorf("failed to delete device options(%s): %s", name, err)
	}

	if err := removeMasqueradeRule(name); err != nil {
		ctx.Logger().Errorf("failed to remove nat rule for device(%s): %s", name, err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	return ctx.NoContent(http.StatusNoContent)
}

// DeleteDevicePeer - Delete device's peer
func (c *WireGuardContainer) DeleteDevicePeer(ctx echo.Context) error {
	name := ctx.Param("name")
	urlSafePubKey, err := url.QueryUnescape(ctx.Param("urlSafePubKey"))
	if err != nil {
		ctx.Logger().Errorf("failed to parse pub key: %s", err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "request_params_error",
			Message: err.Error(),
		})
	}

	pubKey, err := parseUrlSafeKey(urlSafePubKey)
	if err != nil {
		ctx.Logger().Errorf("failed to parse pub key: %s", err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "request_params_error",
			Message: err.Error(),
		})
	}

	client, err := wgctrl.New()
	if err != nil {
		ctx.Logger().Errorf("failed to init wireguard ipc: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_client_error",
			Message: err.Error(),
		})
	}
	defer client.Close()

	_, err = client.Device(name)
	if err != nil {
		if os.IsNotExist(err) {
			return ctx.NoContent(http.StatusNotFound)
		}

		ctx.Logger().Errorf("failed to get wireguard device: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	device, err := client.Device(name)
	if err != nil {
		if os.IsNotExist(err) {
			return ctx.NoContent(http.StatusNotFound)
		}

		ctx.Logger().Errorf("failed to get wireguard device: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	var peer *wgtypes.Peer
	for _, v := range device.Peers {
		if v.PublicKey == pubKey {
			peer = &v
			break
		}
	}

	if peer == nil {
		return ctx.JSON(http.StatusNotFound, models.Error{
			Code:    "peer_not_found",
			Message: "peer not found",
		})
	}

	deviceConf := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			wgtypes.PeerConfig{
				PublicKey: pubKey,
				Remove:    true,
			},
		},
	}

	if err := client.ConfigureDevice(name, deviceConf); err != nil {
		ctx.Logger().Errorf("failed to configure wireguard device(%s): %s", name, err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "wireguard_error",
			Message: err.Error(),
		})
	}

	device, err = client.Device(name)
	if err != nil {
		if os.IsNotExist(err) {
			return ctx.NoContent(http.StatusNotFound)
		}

		ctx.Logger().Errorf("failed to get wireguard device: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	if err := c.persistDeviceConfig(*device); err != nil {
		ctx.Logger().Errorf("failed to persist device(%s) config: %s", name, err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	if err := c.storage.DeletePeerOptions(pubKey); err != nil && !os.IsNotExist(err) {
		ctx.Logger().Errorf("failed to delete peer options(%s): %s", pubKey.String(), err)
	}

	return ctx.JSON(http.StatusOK, models.NewPeer(*peer))
}

// GetDevice - Get device info
func (c *WireGuardContainer) GetDevice(ctx echo.Context) error {
	name := ctx.Param("name")

	client, err := wgctrl.New()
	if err != nil {
		ctx.Logger().Errorf("failed to init wireguard ipc: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_client_error",
			Message: err.Error(),
		})
	}
	defer client.Close()

	device, err := client.Device(name)
	if err != nil {
		if os.IsNotExist(err) {
			return ctx.NoContent(http.StatusNotFound)
		}

		ctx.Logger().Errorf("failed to get wireguard device: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	result := models.NewDevice(device)
	if err := applyNetworks(&result); err != nil {
		ctx.Logger().Errorf("failed to get networks for interface %s: %s", result.Name, err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	if err := c.persistDeviceConfig(*device); err != nil {
		ctx.Logger().Errorf("failed to persist device(%s) config: %s", name, err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	return ctx.JSON(http.StatusOK, result)
}

// GetDevicePeer - Get device peer info
func (c *WireGuardContainer) GetDevicePeer(ctx echo.Context) error {
	name := ctx.Param("name")
	urlSafePubKey, err := url.QueryUnescape(ctx.Param("urlSafePubKey"))
	if err != nil {
		ctx.Logger().Errorf("failed to parse pub key: %s", err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "request_params_error",
			Message: err.Error(),
		})
	}
	pubKey, err := parseUrlSafeKey(urlSafePubKey)
	if err != nil {
		ctx.Logger().Errorf("failed to parse pub key: %s", err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "request_params_error",
			Message: err.Error(),
		})
	}

	client, err := wgctrl.New()
	if err != nil {
		ctx.Logger().Errorf("failed to init wireguard ipc: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_client_error",
			Message: err.Error(),
		})
	}
	defer client.Close()

	device, err := client.Device(name)
	if err != nil {
		if os.IsNotExist(err) {
			return ctx.NoContent(http.StatusNotFound)
		}

		ctx.Logger().Errorf("failed to get wireguard device: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	var peer *wgtypes.Peer
	for _, v := range device.Peers {
		if v.PublicKey == pubKey {
			peer = &v
			break
		}
	}

	if peer == nil {
		return ctx.JSON(http.StatusNotFound, models.Error{
			Code:    "peer_not_found",
			Message: "peer not found",
		})
	}

	return ctx.JSON(http.StatusOK, models.NewPeer(*peer))
}

// ListDevicePeers - Peers list
func (c *WireGuardContainer) ListDevicePeers(ctx echo.Context) error {
	name := ctx.Param("name")

	client, err := wgctrl.New()
	if err != nil {
		ctx.Logger().Errorf("failed to init wireguard ipc: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_client_error",
			Message: err.Error(),
		})
	}
	defer client.Close()

	device, err := client.Device(name)
	if err != nil {
		if os.IsNotExist(err) {
			return ctx.NoContent(http.StatusNotFound)
		}

		ctx.Logger().Errorf("failed to get wireguard device: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	filteredPeers := device.Peers
	q := ctx.QueryParam("q")
	if q != "" {
		filteredPeers = utils.FilterPeersByQuery(q, filteredPeers)
	}

	sortField := ctx.QueryParam("sort")
	if sortField != "" {
		if err := utils.SortPeersByField(sortField, filteredPeers); err != nil {
			ctx.Logger().Errorf("failed sort paginatedPeers: %s", err)
			return ctx.JSON(http.StatusBadRequest, models.Error{
				Code:    "request_params_error",
				Message: err.Error(),
			})
		}
	}

	paginator, err := getPaginator(ctx, len(filteredPeers))
	if err != nil {
		ctx.Logger().Errorf("failed to init paginator: %s", err)
		return err
	}

	beginIndex := paginator.Offset()
	endIndex := beginIndex + paginator.PerPageNums
	if int64(beginIndex) > paginator.Nums() {
		beginIndex = int(paginator.Nums())
	}
	if int64(endIndex) > paginator.Nums() {
		endIndex = int(paginator.Nums())
	}

	paginatedPeers := filteredPeers[beginIndex:endIndex]
	result := make([]models.Peer, len(paginatedPeers))
	for i, v := range paginatedPeers {
		result[i] = models.NewPeer(v)
	}

	paginator.Write(ctx.Response())
	return ctx.JSON(http.StatusOK, result)
}

// ListDevices - Devices list
func (c *WireGuardContainer) ListDevices(ctx echo.Context) error {
	client, err := wgctrl.New()
	if err != nil {
		ctx.Logger().Errorf("failed to init wireguard ipc: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_client_error",
			Message: err.Error(),
		})
	}
	defer client.Close()

	devices, err := client.Devices()
	if err != nil {
		ctx.Logger().Errorf("failed to get wireguard devices: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_client_error",
			Message: err.Error(),
		})
	}

	paginator, err := getPaginator(ctx, len(devices))
	if err != nil {
		ctx.Logger().Errorf("failed to init paginator: %s", err)
		return err
	}

	beginIndex := paginator.Offset()
	endIndex := beginIndex + paginator.PerPageNums
	if int64(beginIndex) > paginator.Nums() {
		beginIndex = int(paginator.Nums())
	}
	if int64(endIndex) > paginator.Nums() {
		endIndex = int(paginator.Nums())
	}

	filteredDevices := devices[beginIndex:endIndex]
	result := make([]models.Device, len(filteredDevices))
	for i, v := range filteredDevices {
		device := models.NewDevice(v)
		if err := applyNetworks(&device); err != nil {
			ctx.Logger().Errorf("failed to get networks for interface %s: %s", device.Name, err)
			return ctx.JSON(http.StatusInternalServerError, models.Error{
				Code:    "wireguard_device_error",
				Message: err.Error(),
			})
		}

		result[i] = device
	}

	paginator.Write(ctx.Response())
	return ctx.JSON(http.StatusOK, result)
}

// UpdateDevice - Update device
func (c *WireGuardContainer) UpdateDevice(ctx echo.Context) error {
	name := ctx.Param("name")

	var request models.DeviceCreateOrUpdateRequest
	if err := ctx.Bind(&request); err != nil {
		return err
	}

	client, err := wgctrl.New()
	if err != nil {
		ctx.Logger().Errorf("failed to init wireguard ipc: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_client_error",
			Message: err.Error(),
		})
	}
	defer client.Close()

	_, err = client.Device(name)
	if err != nil {
		if os.IsNotExist(err) {
			return ctx.NoContent(http.StatusNotFound)
		}

		ctx.Logger().Errorf("failed to get wireguard device: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}
	conf := wgtypes.Config{}
	err = request.Apply(&conf)
	if err != nil {
		ctx.Logger().Errorf("failed to get wireguard device conf: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_config_error",
			Message: err.Error(),
		})
	}

	if err := client.ConfigureDevice(name, conf); err != nil {
		ctx.Logger().Errorf("failed to configure wireguard device: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_error",
			Message: err.Error(),
		})
	}

	device, err := client.Device(name)
	if err != nil {
		if os.IsNotExist(err) {
			return ctx.NoContent(http.StatusNotFound)
		}

		ctx.Logger().Errorf("failed to get wireguard device: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	result := models.NewDevice(device)
	if err := applyNetworks(&result); err != nil {
		ctx.Logger().Errorf("failed to get networks for interface %s: %s", result.Name, err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	if err := c.persistDeviceConfig(*device); err != nil {
		ctx.Logger().Errorf("failed to persist device(%s) config: %s", name, err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	return ctx.JSON(http.StatusOK, result)
}

// UpdateDevicePeer - Update device's peer
func (c *WireGuardContainer) UpdateDevicePeer(ctx echo.Context) error {
	name := ctx.Param("name")
	urlSafePubKey, err := url.QueryUnescape(ctx.Param("urlSafePubKey"))
	if err != nil {
		ctx.Logger().Errorf("failed to parse pub key: %s", err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "request_params_error",
			Message: err.Error(),
		})
	}
	pubKey, err := parseUrlSafeKey(urlSafePubKey)
	if err != nil {
		ctx.Logger().Errorf("failed to parse pub key: %s", err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "request_params_error",
			Message: err.Error(),
		})
	}

	var request models.PeerCreateOrUpdateRequest
	if err := ctx.Bind(&request); err != nil {
		return err
	}

	pubStr := pubKey.String()
	request.PublicKey = &pubStr

	result, herr := c.applyPeerConfig(ctx, name, request, peerConfigOptions{
		forceUpdateOnly:         true,
		alwaysReplaceAllowedIPs: true,
		overridePublicKey:       &pubKey,
	})
	if herr != nil {
		return ctx.JSON(herr.status, models.Error{
			Code:    herr.code,
			Message: herr.err.Error(),
		})
	}

	return ctx.JSON(http.StatusOK, models.NewPeer(result.peer))
}

func (c *WireGuardContainer) getDevicePeerQuickConfig(ctx echo.Context) (io.Reader, error) {
	name := ctx.Param("name")
	urlSafePubKey, err := url.QueryUnescape(ctx.Param("urlSafePubKey"))
	if err != nil {
		return nil, err
	}

	pubKey, err := parseUrlSafeKey(urlSafePubKey)
	if err != nil {
		return nil, err
	}

	peerOptions, err := c.storage.ReadPeerOptions(pubKey)
	if err != nil {
		return nil, err
	}

	deviceOptions, err := c.storage.ReadDeviceOptions(name)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	if deviceOptions == nil {
		deviceOptions = &c.defaultDeviceOptions
	}

	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer client.Close()

	device, err := client.Device(name)
	if err != nil {
		return nil, err
	}

	var peer *wgtypes.Peer
	for _, v := range device.Peers {
		if v.PublicKey == pubKey {
			peer = &v
			break
		}
	}

	if peer == nil {
		return nil, os.ErrNotExist
	}

	quickConf, err := utils.GetPeerQuickConfig(*device, *peer, utils.PeerQuickConfigOptions{
		PrivateKey: &peerOptions.PrivateKey,
		DNSServers: &deviceOptions.DNSServers,
		AllowedIPs: &deviceOptions.AllowedIPs,
		Host:       &deviceOptions.Host,
	})

	if err != nil {
		return nil, err
	}

	return quickConf, nil
}

// GetDevicePeerQuickConfig - Get device peer quick config
func (c *WireGuardContainer) GetDevicePeerQuickConfig(ctx echo.Context) error {
	quickConf, err := c.getDevicePeerQuickConfig(ctx)
	if err != nil {
		ctx.Logger().Errorf("failed to get quick config: %s", err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "request_params_error",
			Message: err.Error(),
		})
	}

	return ctx.Stream(http.StatusOK, "text/plain", quickConf)
}

// GetDevicePeerQuickConfigQRCodePNG - Get device peer quick config QR code
func (c *WireGuardContainer) GetDevicePeerQuickConfigQRCodePNG(ctx echo.Context) error {
	quickConf, err := c.getDevicePeerQuickConfig(ctx)
	if err != nil {
		ctx.Logger().Errorf("failed to get quick config: %s", err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "request_params_error",
			Message: err.Error(),
		})
	}

	widthParam := ctx.QueryParam("width")
	if widthParam == "" {
		widthParam = "256"
	}
	width, err := strconv.Atoi(widthParam)
	if err != nil {
		ctx.Logger().Errorf("failed to parse width: %s", err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "request_params_error",
			Message: err.Error(),
		})
	}

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(quickConf); err != nil {
		ctx.Logger().Errorf("failed to reade quick config: %s", err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "request_params_error",
			Message: err.Error(),
		})
	}

	qrBytes, err := qrcode.Encode(buf.String(), qrcode.Medium, width)
	if err != nil {
		ctx.Logger().Errorf("failed to generate qr code: %s", err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "request_params_error",
			Message: err.Error(),
		})
	}

	qrBuff := bytes.NewBuffer(qrBytes)
	return ctx.Stream(http.StatusOK, "image/png", qrBuff)
}

// GetDeviceOptions - Get device options
func (c *WireGuardContainer) GetDeviceOptions(ctx echo.Context) error {
	name := ctx.Param("name")

	client, err := wgctrl.New()
	if err != nil {
		ctx.Logger().Errorf("failed to init wireguard ipc: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_client_error",
			Message: err.Error(),
		})
	}
	defer client.Close()

	if _, err := client.Device(name); err != nil {
		if os.IsNotExist(err) {
			return ctx.NoContent(http.StatusNotFound)
		}

		ctx.Logger().Errorf("failed to get wireguard device: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	options, err := c.storage.ReadDeviceOptions(name)
	if err != nil && !os.IsNotExist(err) {
		ctx.Logger().Errorf("failed to get device options: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	if options == nil {
		options = &c.defaultDeviceOptions
	}

	return ctx.JSON(http.StatusOK, models.NewDeviceOptions(*options))
}

// UpdateDeviceOptions - Update device's options
func (c *WireGuardContainer) UpdateDeviceOptions(ctx echo.Context) error {
	name := ctx.Param("name")

	client, err := wgctrl.New()
	if err != nil {
		ctx.Logger().Errorf("failed to init wireguard ipc: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_client_error",
			Message: err.Error(),
		})
	}
	defer client.Close()

	if _, err := client.Device(name); err != nil {
		if os.IsNotExist(err) {
			return ctx.NoContent(http.StatusNotFound)
		}

		ctx.Logger().Errorf("failed to get wireguard device: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	var request models.DeviceOptionsUpdateRequest
	if err := ctx.Bind(&request); err != nil {
		return err
	}

	options, err := c.storage.ReadDeviceOptions(name)
	if err != nil && !os.IsNotExist(err) {
		ctx.Logger().Errorf("failed to get device options: %s", err)
	}

	if options == nil {
		options = &storage.StoreDeviceOptions{}
	}

	ctx.Logger().Printf("request: %+v\n", request)
	ctx.Logger().Printf("options: %+v\n", *options)

	if err := request.Apply(options); err != nil {
		ctx.Logger().Errorf("failed to update device options: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	err = c.storage.WriteDeviceOptions(name, *options)
	if err != nil {
		ctx.Logger().Errorf("failed to save device options: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	return ctx.JSON(http.StatusOK, models.NewDeviceOptions(*options))
}
