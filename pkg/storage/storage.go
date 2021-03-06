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
	Source    string         `json:"source"`
	Timestamp unix_time.Time `json:"timestamp"`
	Duration  time.Duration  `json:"duration"`
}

func (e BlockEntry) IsActive() bool {
	return e.Timestamp.Time().Add(e.Duration).After(time.Now())
}

type ExternalModule struct {
	Id      uint32 `json:"id"`
	Address string `json:"address"`
	Method  string `json:"method"`
}

type Storage interface {
	AddAuthenticationEntry(entry AuthenticationEntry) error
	FindAuthenticationEntries(ip string) (map[AuthenticationEntry]struct{}, error)
	FindSources() (map[string]int, error)
	AddBlockEntry(entry BlockEntry) error
	RemoveBlockEntry(ip string) error
	FindBlockEntry(ip string) (BlockEntry, error)
	AllBlockEntries(onlyActive bool) ([]BlockEntry, error)
	CleanBlockEntries() error
	AddExternalModule(module ExternalModule) error
	RemoveExternalModule(id uint32) error
	GetExternalModules() ([]ExternalModule, error)
	GetExternalModuleByAddress(address string) (ExternalModule, error)
	Close() error
}
