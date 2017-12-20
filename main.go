package main

import (
	"fmt"
	"log"

	"github.com/dgraph-io/badger"
	uuid "github.com/satori/go.uuid"
)

func putString(tx *badger.Txn, key string, value string) error {
	return tx.Set([]byte(key), []byte(value))
}

func main() {
	opts := badger.DefaultOptions
	opts.Dir = "/tmp/badger"
	opts.ValueDir = "/tmp/badger"
	db, err := badger.Open(opts)
	if err != nil {
		log.Fatalf("Error loading database: %v", err)
	}
	defer db.Close()
	err = db.Update(func(tx *badger.Txn) error {
		for i := 0; i < 10; i++ {
			perr := putString(tx, fmt.Sprintf("/nanodegree/nd001%d", i), uuid.NewV4().String())
			if perr != nil {
				log.Printf("Error putting String: %v\n", perr)
				return perr
			}
		}
		return nil
	})
	if err != nil {
		log.Fatalf("Error updating database: %v", err)
	}

	err = db.View(func(tx *badger.Txn) error {
		it := tx.NewIterator(badger.DefaultIteratorOptions)
		prefix := []byte("/nanodegree/nd001")
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			k := item.Key()
			v, verr := item.Value()
			if verr != nil {
				log.Fatalf("Error retrieving value from item: %v", verr)
			}
			fmt.Printf("key: %s, value: %s\n", k, v)
		}
		return nil
	})
	if err != nil {
		log.Fatalf("Error viewing database: %v", err)
	}
}
