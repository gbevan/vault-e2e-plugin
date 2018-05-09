package e2e

// E2eEnrolementEntry structure repesenting an E2E public key enrolement
type E2eEnrolementEntry struct { // nolint
	// ID string `json:"id" structs:"id" mapstructure:"id"`

	Name string `json:"name" structs:"name" mapstructure:"name"`

	PubKey string `json:"pubkey" structs:"pubkey" mapstructure:"pubkey"`

	Fingerprint string `json:"fingerprint" structs:"fingerprint" mapstructure:"fingerprint"`

	Authorised bool `json:"authorised" structs:"authorised" mapstructure:"authorised"`

	Created string `json:"created" structs:"created" mapstructure:"created"`
}
