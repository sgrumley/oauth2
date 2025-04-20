package store

import (
	"fmt"
	"sync"

	"github.com/sgrumley/oauth/internal/models"
)

type Store struct {
	clients   map[string]models.Client
	tokens    map[string]models.Token
	authCodes map[string]models.AuthCode
	mu        sync.RWMutex
}

func New() *Store {
	store := &Store{
		clients:   make(map[string]models.Client),
		tokens:    make(map[string]models.Token),
		authCodes: make(map[string]models.AuthCode),
	}

	// mock clients
	store.clients["test_client"] = models.Client{
		ID:          "test_client",
		Secret:      "test_secret",
		RedirectURI: "http://localhost:8081/callback", // TODO: should enable comma seperated options and request must be one of them
	}

	return store
}

func (s *Store) GetClient(clientID string) (models.Client, error) {
	client, ok := s.clients[clientID]
	if !ok {
		return models.Client{}, fmt.Errorf("client not found")
	}
	return client, nil
}

func (s *Store) SetToken(tok models.Token) {
	s.mu.Lock()
	s.tokens[tok.AccessToken] = tok
	s.mu.Unlock()
}

func (s *Store) GetAuthCode(clientID string) (models.AuthCode, error) {
	for key, code := range s.authCodes {
		fmt.Println("available codes ", key, " ", code)
	}
	acode, ok := s.authCodes[clientID]
	if !ok {
		return models.AuthCode{}, fmt.Errorf("auth code not found")
	}
	return acode, nil
}

func (s *Store) SetAuthCode(code string, ac models.AuthCode) {
	s.mu.Lock()
	s.authCodes[code] = ac
	s.mu.Unlock()
}

func (s *Store) DeleteAuthCode(code string) {
	delete(s.authCodes, code)
}
