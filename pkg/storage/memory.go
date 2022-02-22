package storage

import (
	"sync"
	"time"
)

type MemoryStorage struct {
	lock sync.RWMutex

	authEntries  map[string]map[AuthenticationEntry]struct{}
	blockEntries map[string]BlockEntry
}

func NewMemoryStore() Storage {
	return &MemoryStorage{
		lock:         sync.RWMutex{},
		authEntries:  make(map[string]map[AuthenticationEntry]struct{}),
		blockEntries: make(map[string]BlockEntry),
	}
}

func (m *MemoryStorage) AddAuthenticationEntry(entry AuthenticationEntry) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if _, ok := m.authEntries[entry.Source]; !ok {
		m.authEntries[entry.Source] = make(map[AuthenticationEntry]struct{})
	}

	m.authEntries[entry.Source][entry] = struct{}{}
	return nil
}

func (m *MemoryStorage) FindAuthenticationEntries(ip string) (map[AuthenticationEntry]struct{}, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	if entries, ok := m.authEntries[ip]; ok {
		return entries, nil
	}

	return nil, NotFoundErr
}

func (m *MemoryStorage) FindSources() (map[string]int, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	res := make(map[string]int, len(m.authEntries))
	for source, entries := range m.authEntries {
		res[source] = len(entries)
	}

	return res, nil
}

func (m *MemoryStorage) AddBlockEntry(entry BlockEntry) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.blockEntries[entry.Source] = entry
	return nil
}

func (m *MemoryStorage) RemoveBlockEntry(ip string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	delete(m.blockEntries, ip)
	return nil
}

func (m *MemoryStorage) FindBlockEntry(ip string) (BlockEntry, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	if entry, ok := m.blockEntries[ip]; ok {
		return entry, nil
	}

	return BlockEntry{}, NotFoundErr
}

func (m *MemoryStorage) AllBlockEntries() ([]BlockEntry, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	entries := make([]BlockEntry, 0, len(m.blockEntries))
	for _, e := range m.blockEntries {
		entries = append(entries, e)
	}

	return entries, nil
}

func (m *MemoryStorage) CleanBlockEntries() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	for ip, e := range m.blockEntries {
		if e.Timestamp.Time().Add(e.Duration).Before(time.Now()) {
			delete(m.blockEntries, ip)
		}
	}

	return nil
}
