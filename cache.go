package webpush

type Cacher interface {
	GetString(key interface{}) (string, bool, error)
	SetString(key interface{}, value string) error
}

type noCache struct {
}

func (c noCache) GetString(key interface{}) (string, bool, error) {
	return "", false, nil
}

func (c noCache) SetString(key interface{}, value string) error {
	return nil
}
