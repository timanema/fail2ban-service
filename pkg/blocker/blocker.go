package blocker

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/timanema/fail2ban-service/pkg/storage"
	"github.com/timanema/fail2ban-service/pkg/unix_time"
	"sync"
	"time"
)

type Policy struct {
	Attempts  int           `json:"attempts"`
	Period    time.Duration `json:"period"`
	BlockTime time.Duration `json:"blocktime"`
}

type Blocker struct {
	lock   sync.Mutex
	store  storage.Storage
	policy Policy
}

func New(store storage.Storage, policy Policy) *Blocker {
	return &Blocker{
		lock:   sync.Mutex{},
		store:  store,
		policy: policy,
	}
}

func (b *Blocker) AddEntry(entry storage.AuthenticationEntry) error {
	if blocked, _, _ := b.IsBlocked(entry.Source); blocked {
		return nil
	}

	if err := b.store.AddAuthenticationEntry(entry); err != nil {
		return errors.Wrap(err, "failed to add entry to store")
	}

	entries, err := b.store.FindAuthenticationEntries(entry.Source)
	if err != nil {
		return errors.Wrap(err, "failed to retrieve auth entries from store")
	}

	count := 0
	for entry := range entries {
		if time.Now().Add(-1 * b.policy.Period).Before(entry.Timestamp.Time()) {
			count += 1

			if count >= b.policy.Attempts {
				if _, err := b.BlockIP(entry.Source); err != nil {
					return errors.Wrapf(err, "failed to block %v", entry.Source)
				}
				break
			}
		}
	}

	return nil
}

func (b *Blocker) BlockIP(ip string) (storage.BlockEntry, error) {
	entry := storage.BlockEntry{
		Source:    ip,
		Timestamp: unix_time.Time(time.Now()),
		Duration:  b.policy.BlockTime,
	}

	if err := b.store.AddBlockEntry(entry); err != nil {
		return storage.BlockEntry{}, errors.Wrap(err, "failed to store block in store")
	}

	return entry, errors.Wrap(b.notifyExternal(entry), "failed to notify external modules of block")
}

func (b *Blocker) UnblockIP(ip string) error {
	// Expired entry
	entry := storage.BlockEntry{
		Source:    ip,
		Timestamp: unix_time.Time(time.Now()),
		Duration:  -1 * b.policy.BlockTime,
	}

	if err := b.store.RemoveBlockEntry(ip); err != nil {
		return errors.Wrap(err, "failed to remove block entry from store")
	}

	return errors.Wrap(b.notifyExternal(entry), "failed to notify external modules of unblock")
}

func (b *Blocker) IsBlocked(ip string) (bool, storage.BlockEntry, error) {
	entry, err := b.store.FindBlockEntry(ip)
	if err == storage.NotFoundErr {
		return false, storage.BlockEntry{}, nil
	}

	if err != nil {
		return false, storage.BlockEntry{}, errors.Wrap(err, "unable to load block entry")
	}

	return entry.Timestamp.Time().Add(entry.Duration).After(time.Now()), entry, nil
}

func (b *Blocker) UpdatePolicy(policy Policy) {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.policy = policy
}

func (b *Blocker) Policy() Policy {
	b.lock.Lock()
	defer b.lock.Unlock()

	return b.policy
}

func (b *Blocker) NotifyAll() error {
	entries, err := b.store.AllBlockEntries()
	if err != nil {
		return errors.Wrap(err, "failed to retrieve all block entries")
	}

	for _, e := range entries {
		if err := b.notifyExternal(e); err != nil {
			return errors.Wrapf(err, "failed to notify modules of %v", e)
		}
	}

	if err := b.store.CleanBlockEntries(); err != nil {
		return errors.Wrap(err, "failed to clean block store")
	}
	return nil
}

func (b *Blocker) notifyExternal(entry storage.BlockEntry) error {
	// TODO
	block := entry.Timestamp.Time().Add(entry.Duration).After(time.Now())
	fmt.Printf("notifying external modules of %v (block=%v)\n", entry, block)
	return nil
}
