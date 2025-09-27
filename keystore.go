package wampshell

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
)

type KeyStore struct {
	keys     map[string][]string
	onUpdate func(map[string][]string)
	sync.RWMutex
}

func NewKeyStore() *KeyStore {
	return &KeyStore{
		keys: make(map[string][]string),
	}
}

func (k *KeyStore) HasKey(realm, key string) bool {
	k.RLock()
	defer k.RUnlock()

	keys, ok := k.keys[realm]
	if !ok {
		return false
	}

	return slices.Contains(keys, key)
}

func (k *KeyStore) OnUpdate(cb func(map[string][]string)) {
	k.Lock()
	defer k.Unlock()
	k.onUpdate = cb
}

func (k *KeyStore) Update(keys map[string][]string) {
	k.Lock()
	defer k.Unlock()

	for realm, newList := range keys {
		existing := k.keys[realm]
		k.keys[realm] = append(existing[:0:0], newList...)
	}

	if k.onUpdate != nil {
		go k.onUpdate(k.keys)
	}
}

func readKeys(filePath string) (map[string][]string, error) {
	keys := make(map[string][]string)

	if err := os.MkdirAll(filepath.Dir(filePath), 0700); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		if err := os.WriteFile(filePath, []byte(""), 0600); err != nil {
			return nil, fmt.Errorf("failed to create file %s: %w", filePath, err)
		}
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", filePath, err)
	}

	for _, keyWithRealm := range strings.Split(string(data), "\n") {
		keyWithRealm = strings.TrimSpace(keyWithRealm)
		if keyWithRealm == "" {
			continue
		}

		parts := strings.Fields(keyWithRealm)
		keyHex := strings.TrimSpace(parts[0])

		keyBytes, err := hex.DecodeString(keyHex)
		if err != nil || len(keyBytes) != 32 {
			continue
		}

		realm := "wampshell"
		if len(parts) > 1 {
			realm = strings.TrimSpace(parts[1])
		}

		if keys[realm] == nil {
			keys[realm] = make([]string, 0)
		}

		keys[realm] = append(keys[realm], parts[0])
	}

	return keys, nil
}

func (k *KeyStore) Watch(filePath string) (*fsnotify.Watcher, error) {
	keys, err := readKeys(filePath)
	if err != nil {
		return nil, err
	}
	k.Update(keys)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create fsnotify watcher: %w", err)
	}

	dir := filepath.Dir(filePath)
	if err = watcher.Add(dir); err != nil {
		_ = watcher.Close()
		return nil, fmt.Errorf("failed to watch %s: %w", dir, err)
	}

	go k.watch(filePath, watcher)

	return watcher, nil
}

func (k *KeyStore) watch(filePath string, watcher *fsnotify.Watcher) {
	fileName := filepath.Base(filePath)

	for event := range watcher.Events {
		if filepath.Base(event.Name) != fileName {
			continue
		}

		switch {
		case event.Has(fsnotify.Write), event.Has(fsnotify.Create):
			keys, err := readKeys(filePath)
			if err != nil {
				continue
			}
			k.Update(keys)

		case event.Has(fsnotify.Remove), event.Has(fsnotify.Rename):
			k.Update(make(map[string][]string))
		}
	}
}

func (k *KeyStore) AuthorizedKeys() ([]string, error) {
	k.RLock()
	defer k.RUnlock()

	if len(k.keys) == 0 {
		return nil, fmt.Errorf("no keys in KeyStore")
	}

	var keys []string
	for realm, ks := range k.keys {
		for _, key := range ks {
			if realm == "wampshell" {
				keys = append(keys, key)
			} else {
				keys = append(keys, fmt.Sprintf("%s %s", key, realm))
			}
		}
	}
	return keys, nil
}
