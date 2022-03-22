package blocker

import (
	"bytes"
	"encoding/json"
	"github.com/pkg/errors"
	"github.com/timanema/fail2ban-service/pkg/storage"
	"log"
	"math/rand"
	"net/http"
)

type externalRequest struct {
	storage.BlockEntry
	Blocked bool `json:"blocked"`
}

func (b *Blocker) notifyExternal(entry storage.BlockEntry) error {
	block := entry.IsActive()
	req := externalRequest{
		BlockEntry: entry,
		Blocked:    block,
	}

	// Check if notification is not needed
	b.lock.Lock()
	lastUpdate, ok := b.lastExternalUpdate[entry.Source]
	b.lock.Unlock()

	if ok && lastUpdate == block {
		return nil
	}

	marshalledReq, err := json.Marshal(req)
	if err != nil {
		return errors.Wrap(err, "unable to marshal request")
	}

	external, err := b.store.GetExternalModules()
	if err != nil {
		return errors.Wrap(err, "unable to get external modules")
	}

	id := rand.Uint32()
	log.Printf("notifying external modules (%v) of %+v (event=%v)\n", len(external), req, id)
	for _, module := range external {
		module := module

		go func() {
			r, err := http.NewRequest(module.Method, module.Address, bytes.NewBuffer(marshalledReq))
			if err != nil {
				log.Printf("failed to create request for module %v for event %v: %v\n", module, id, err)
				return
			}

			resp, err := http.DefaultClient.Do(r)
			if err != nil {
				log.Printf("failed to update external module %v for event %v (method=%v): %v\n", module, id, err)
				return
			}

			if resp.StatusCode != http.StatusOK {
				log.Printf("updated external module %v for event %v, but reacted with http status: %v (%v)\n", module, id, resp.StatusCode, http.StatusText(resp.StatusCode))
			}
		}()
	}

	b.lock.Lock()
	b.lastExternalUpdate[entry.Source] = block
	b.lock.Unlock()

	return nil
}
