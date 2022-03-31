package blocker

import (
	"github.com/coreos/go-iptables/iptables"
	"log"
)

func (b *Blocker) addIptablesBan(source string) {
	ipt, err := iptables.New()
	if err != nil {
		log.Printf("failed to get iptables link for blocking: %v\n", err)
		return
	}

	if err := ipt.AppendUnique("filter", "INPUT", "-s", source, "-j", "DROP"); err != nil {
		log.Printf("failed to insert iptables rule for blocking: %v\n", err)
	}
}

func (b *Blocker) removeIptablesBan(source string) {
	ipt, err := iptables.New()
	if err != nil {
		log.Printf("failed to get iptables link for unblocking: %v\n", err)
		return
	}

	if err := ipt.DeleteIfExists("filter", "INPUT", "-s", source, "-j", "DROP"); err != nil {
		log.Printf("failed to insert iptables rule for unblocking: %v\n", err)
	}
}
