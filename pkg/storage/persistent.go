package storage

import (
	"encoding/gob"
	"github.com/pkg/errors"
	"log"
	"os"
)

type persistentData struct {
	AuthEntries     map[string]map[AuthenticationEntry]struct{}
	BlockEntries    map[string]BlockEntry
	ExternalModules map[uint32]ExternalModule
}

type PersistentStorage struct {
	memory *MemoryStorage
}

func NewPersistentStore() Storage {
	p := &PersistentStorage{}

	if err := p.Read(); err != nil {
		log.Fatalf("failed to read from persistent storage: %v\n", err)
	}

	return p
}

func (p *PersistentStorage) Read() error {
	m := NewMemoryStore().(*MemoryStorage)
	p.memory = m

	if _, err := os.Stat("data.gob"); errors.Is(err, os.ErrNotExist) {
		return nil
	}

	m.lock.Lock()
	defer m.lock.Unlock()
	d := &persistentData{}

	f, err := os.Open("data.gob")
	if err != nil {
		return errors.Wrap(err, "failed to open data file")
	}

	dec := gob.NewDecoder(f)
	if err := dec.Decode(d); err != nil {
		return errors.Wrap(err, "failed to decode data")
	}

	m.authEntries = d.AuthEntries
	m.blockEntries = d.BlockEntries
	m.externalModules = d.ExternalModules
	return nil
}

func (p *PersistentStorage) Save() error {
	f, err := os.Create("data.gob")
	if err != nil {
		return errors.Wrap(err, "failed to create data file")
	}

	p.memory.lock.RLock()
	defer p.memory.lock.RUnlock()

	d := persistentData{
		AuthEntries:     p.memory.authEntries,
		BlockEntries:    p.memory.blockEntries,
		ExternalModules: p.memory.externalModules,
	}

	enc := gob.NewEncoder(f)
	if err := enc.Encode(d); err != nil {
		return errors.Wrap(err, "failed to encode data")
	}

	return nil
}

func (p *PersistentStorage) AsyncSave() {
	go func() {
		if err := p.Save(); err != nil {
			log.Printf("error occurred while saving data: %v\n", err)
		}
	}()
}

func (p *PersistentStorage) AddAuthenticationEntry(entry AuthenticationEntry) error {
	defer p.AsyncSave()
	return p.memory.AddAuthenticationEntry(entry)
}

func (p *PersistentStorage) FindAuthenticationEntries(ip string) (map[AuthenticationEntry]struct{}, error) {
	return p.memory.FindAuthenticationEntries(ip)
}

func (p *PersistentStorage) FindSources() (map[string]int, error) {
	return p.memory.FindSources()
}

func (p *PersistentStorage) AddBlockEntry(entry BlockEntry) error {
	defer p.AsyncSave()
	return p.memory.AddBlockEntry(entry)
}

func (p *PersistentStorage) RemoveBlockEntry(ip string) error {
	defer p.AsyncSave()
	return p.memory.RemoveBlockEntry(ip)
}

func (p *PersistentStorage) FindBlockEntry(ip string) (BlockEntry, error) {
	return p.memory.FindBlockEntry(ip)
}

func (p *PersistentStorage) AllBlockEntries() ([]BlockEntry, error) {
	return p.memory.AllBlockEntries()
}

func (p *PersistentStorage) CleanBlockEntries() error {
	defer p.AsyncSave()
	return p.memory.CleanBlockEntries()
}

func (p *PersistentStorage) AddExternalModule(module ExternalModule) error {
	defer p.AsyncSave()
	return p.memory.AddExternalModule(module)
}

func (p *PersistentStorage) RemoveExternalModule(id uint32) error {
	defer p.AsyncSave()
	return p.memory.RemoveExternalModule(id)
}

func (p *PersistentStorage) GetExternalModules() ([]ExternalModule, error) {
	return p.memory.GetExternalModules()
}

func (p *PersistentStorage) GetExternalModuleByAddress(address string) (ExternalModule, error) {
	return p.memory.GetExternalModuleByAddress(address)
}

func (p *PersistentStorage) Close() error {
	return p.Save()
}
