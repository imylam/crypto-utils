package argon2id

type Argon2Configs struct {
	TimeCost   uint32
	MemoryCost uint32
	Threads    uint8
	KeyLength  uint32
}

func DefaultConfigs() *Argon2Configs {
	return &Argon2Configs{
		TimeCost:   2,
		MemoryCost: 64 * 1024,
		Threads:    4,
		KeyLength:  32,
	}
}
