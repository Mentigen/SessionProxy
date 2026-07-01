// Package pubsub is a minimal in-process fan-out broadcaster. It exists so
// the data plane (internal/service's EnforcementService) can publish
// events - blacklist violations, auto-terminations - without knowing who,
// if anyone, is listening; the gRPC AdminService and the web dashboard's
// SSE endpoint both subscribe to the same Hub. There is no persistence and
// no cross-process delivery: a subscriber that connects after an event was
// published simply never sees it, same as any live tail.
package pubsub

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// EventType distinguishes the two things worth streaming to a live
// consumer today; more can be added without changing Hub itself.
type EventType string

const (
	EventBlacklistViolation EventType = "blacklist_violation"
	EventLinkTerminated     EventType = "link_terminated"
)

type Event struct {
	Type       EventType
	LinkID     uuid.UUID
	Message    string
	OccurredAt time.Time
}

// Hub fans out published events to every currently subscribed channel. A
// slow or gone subscriber never blocks a publisher: sends are non-blocking
// and simply drop for that one subscriber if its buffer is full, matching
// the same trade-off internal/proxy.AsyncAccessLogger makes for the same
// reason - a live feed favors freshness over completeness.
type Hub struct {
	mu   sync.Mutex
	subs map[chan Event]struct{}
}

func NewHub() *Hub {
	return &Hub{subs: make(map[chan Event]struct{})}
}

// Subscribe registers a new listener. Call the returned cancel func when
// done to stop receiving and release the channel.
func (h *Hub) Subscribe() (events <-chan Event, cancel func()) {
	ch := make(chan Event, 32)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()

	cancel = func() {
		h.mu.Lock()
		if _, ok := h.subs[ch]; ok {
			delete(h.subs, ch)
			close(ch)
		}
		h.mu.Unlock()
	}
	return ch, cancel
}

func (h *Hub) Publish(e Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- e:
		default:
		}
	}
}
