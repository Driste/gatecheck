package cache

import (
	"fmt"
	"os"

	"github.com/gatecheckdev/gatecheck/internal/log"
)

type Cache interface {
	Open() (err error)
	Close() (err error)
	Put(key []byte, value []byte) (err error)
	Get(key []byte) (value []byte, err error)
	Has(key []byte) (err error)
}

type EPSSCache struct {
	filePath   string
	fileHandle *os.File
}

// type CacheMetadata struct {
// 	lastUpdated string
// 	dbEndpoint  string
// }

func NewCache() (cache Cache, err error) {
	dirname, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("unable to get home directory: %v", err)
	}
	log.Debugf("Got home dir: %s", dirname)
	filePath := fmt.Sprintf("%s/.cache/gatecheck", dirname)
	os.MkdirAll(filePath, 0766)
	filePath = fmt.Sprintf("%s/epssCache.db", filePath)
	return &EPSSCache{filePath: filePath}, nil
}

func (c *EPSSCache) Open() (err error) {
	if c.fileHandle != nil {
		return
	}

	_, err = os.Stat(c.filePath)
	if err != nil {
		log.Debugf("No Cache, creating new cache at %s", c.filePath)
		c.fileHandle, err = os.Create(c.filePath)
	} else {
		log.Debugf("Found cache at %s", c.filePath)
		c.fileHandle, err = os.Open(c.filePath)
	}

	return
}

func (c *EPSSCache) Close() (err error) {
	if c.fileHandle == nil {
		return
	}
	err = c.fileHandle.Close()
	if err != nil {
		return
	}
	c.fileHandle = nil
	return
}

func (c *EPSSCache) Put(key []byte, value []byte) (err error) {
	if c.fileHandle == nil {
		return
	}

	bb := append(pad(key, 18), pad(value, 100)...)
	bb = append(bb, []byte("\n")...)
	_, err = c.fileHandle.Write(bb)
	return
}

func (c *EPSSCache) Get(key []byte) (value []byte, err error) {
	if c.fileHandle == nil {
		return
	}
	return nil, nil
}

func (c *EPSSCache) Has(key []byte) (err error) {
	if c.fileHandle == nil {
		return
	}
	return nil
}

func pad(bb []byte, size int) []byte {
	tmp := make([]byte, size)
	l := len(bb)
	if l > size {
		log.Debugf("Key is bigger than the key size!! %d", size)
	}
	copy(tmp[size-l:], bb)
	return tmp
}
