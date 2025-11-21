package models

// ConnectRequest - Create/update peer and return connection parameters.
type ConnectRequest struct {
	// Optional client private key; if empty server generates one.
	PrivateKey *string `json:"private_key,omitempty"`

	// Optional preshared key; if empty server generates one.
	PresharedKey *string `json:"preshared_key,omitempty"`

	// Requested interface addresses for the client.
	Addresses *[]string `json:"addresses,omitempty"`

	// Peer allowed IPs; if omitted server may derive from addresses or defaults.
	AllowedIps *[]string `json:"allowed_ips,omitempty"`

	// Peer's keepalive interval.
	PersistentKeepaliveInterval string `json:"persistent_keepalive_interval,omitempty"`
}
