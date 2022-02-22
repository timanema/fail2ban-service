package storage

import (
	"github.com/pkg/errors"
	"net"
	"time"
)

var NotFoundErr = errors.New("entry not found")

type AuthenticationEntry struct {
	Source    string
	Service   string
	Timestamp time.Time
}

func (e AuthenticationEntry) Valid() bool {
	return net.ParseIP(e.Source) != nil && len(e.Service) > 0 && !e.Timestamp.IsZero()
}

type BlockEntry struct {
	Source string
	Timestamp time.Time
	Duration time.Duration
}

type Storage interface {
	AddAuthenticationEntry(entry AuthenticationEntry) error
	FindAuthenticationEntries(ip string) (map[AuthenticationEntry]struct{}, error)
	AddBlockEntry(entry BlockEntry) error
	RemoveBlockEntry(ip string) error
	FindBlockEntry(ip string) (BlockEntry, error)
	AllBlockEntries() ([]BlockEntry, error)
	CleanBlockEntries() error
}
