package models

type ConnectResponseInterface struct {
	PrivateKey string   `json:"private_key"`
	Addresses  []string `json:"addresses"`
	DNS        []string `json:"dns"`
}

type ConnectResponsePeer struct {
	PublicKey           string   `json:"public_key"`
	PresharedKey        string   `json:"preshared_key"`
	Endpoint            string   `json:"endpoint"`
	AllowedIps          []string `json:"allowed_ips"`
	PersistentKeepalive int      `json:"persistent_keepalive"`
}

type ConnectResponse struct {
	Interface ConnectResponseInterface `json:"interface"`
	Peer      ConnectResponsePeer      `json:"peer"`
}
