package sync

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/sgrumley/oauth/pkg/logger"
)

type Data struct {
	State    string
	ClientID string
	AuthCode string
	Service  string // this should be an enum
}

type Sync struct {
	requests map[string]chan Data
	rwmu     *sync.RWMutex
}

func New() *Sync {
	return &Sync{
		requests: make(map[string]chan Data),
		rwmu:     &sync.RWMutex{},
	}
}

func (s *Sync) Register(id string) chan Data {
	ch := make(chan Data, 1)
	s.rwmu.Lock()
	defer s.rwmu.Unlock()
	s.requests[id] = ch

	return ch
}

func (s *Sync) Wait(ctx context.Context, id string) (Data, error) {
	s.rwmu.RLock()
	ch, ok := s.requests[id]
	s.rwmu.RUnlock()

	if !ok {
		return Data{}, fmt.Errorf("no channel registered for id: %s", id)
	}

	select {
	case <-ctx.Done():
		return Data{}, fmt.Errorf("deadline exceeded for callback: %w", ctx.Err())
	case data := <-ch:
		return data, nil
	}
}

func (s *Sync) Push(id string, data Data) error {
	s.rwmu.RLock()
	ch, ok := s.requests[id]
	s.rwmu.RUnlock()

	if !ok {
		return fmt.Errorf("no channel registered for id: %s", id)
	}

	ch <- data
	return nil
}

func Callback(logger *logger.Logger, syncer *Sync) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.Info("[Callback] Received from: " + r.RequestURI)

		clientID := r.URL.Query().Get("client_id")
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		// Check for errors in the callback
		if errMsg := r.URL.Query().Get("error"); errMsg != "" {
			errDesc := r.URL.Query().Get("error_description")
			http.Error(w, fmt.Sprintf("%s: %s", errMsg, errDesc), http.StatusBadRequest)
			return
		}

		if err := syncer.Push(state, Data{
			State:    state,
			ClientID: clientID,
			AuthCode: code,
			Service:  "server",
		}); err != nil {
			logger.Error("[Callback] channel send failed", err)
			http.Error(w, "callback push failed", http.StatusInternalServerError)
		}

		logger.Info("[Callback]  channel sent")
		w.WriteHeader(http.StatusOK)
	}
}
