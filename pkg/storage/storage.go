package storage

import (
	"github.com/pkg/errors"
	"github.com/timanema/fail2ban-service/pkg/unix_time"
	"net"
	"time"
)

var NotFoundErr = errors.New("entry not found")

type AuthenticationEntry struct {
	Source    string         `json:"source"`
	Service   string         `json:"service"`
	Timestamp unix_time.Time `json:"timestamp"`
}

func (e AuthenticationEntry) Valid() bool {
	return net.ParseIP(e.Source) != nil && len(e.Service) > 0 && !e.Timestamp.Time().IsZero()
}

type BlockEntry struct {
	Source    string
	Timestamp unix_time.Time
	Duration  time.Duration
}

type Storage interface {
	AddAuthenticationEntry(entry AuthenticationEntry) error
	FindAuthenticationEntries(ip string) (map[AuthenticationEntry]struct{}, error)
	FindSources() (map[string]int, error)
	AddBlockEntry(entry BlockEntry) error
	RemoveBlockEntry(ip string) error
	FindBlockEntry(ip string) (BlockEntry, error)
	AllBlockEntries() ([]BlockEntry, error)
	CleanBlockEntries() error
}
