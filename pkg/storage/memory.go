package storage

import (
	"log"
	"sync"
	"time"
)

type MemoryStorage struct {
	lock sync.RWMutex

	authEntries     map[string]map[AuthenticationEntry]struct{}
	blockEntries    map[string]BlockEntry
	externalModules map[uint32]ExternalModule
}

func NewMemoryStore() Storage {
	return &MemoryStorage{
		lock:            sync.RWMutex{},
		authEntries:     make(map[string]map[AuthenticationEntry]struct{}),
		blockEntries:    make(map[string]BlockEntry),
		externalModules: make(map[uint32]ExternalModule),
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

func (m *MemoryStorage) AddExternalModule(module ExternalModule) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.externalModules[module.Id] = module
	log.Printf("added external module: %+v\n", module)
	return nil
}

func (m *MemoryStorage) RemoveExternalModule(id uint32) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	module, ok := m.externalModules[id]
	if ok {
		log.Printf("removed external module: %+v\n", module)
	}
	delete(m.externalModules, id)
	return nil
}

func (m *MemoryStorage) GetExternalModules() ([]ExternalModule, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	res := make([]ExternalModule, 0, len(m.externalModules))
	for _, module := range m.externalModules {
		res = append(res, module)
	}

	return res, nil
}

func (m *MemoryStorage) GetExternalModuleByAddress(address string) (ExternalModule, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	for _, module := range m.externalModules {
		if module.Address == address {
			return module, nil
		}
	}

	return ExternalModule{}, NotFoundErr
}
