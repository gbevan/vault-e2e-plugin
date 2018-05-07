package e2e

type E2eEnrolementEntry struct {
	ID string `json:"id" structs:"id" mapstructure:"id"`

	Name string `json:"name" structs:"name" mapstructure:"name"`

	PubKey string `json:"pubkey" structs:"pubkey" mapstructure:"pubkey"`

	Fingerprint string `json:"fingerprint" structs:"fingerprint" mapstructure:"fingerprint"`

	Authorised bool `json:"authorised" structs:"authorised" mapstructure:"authorised"`

	Created string `json:"created" structs:"created" mapstructure:"created"`
}
