package db_test

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/dgraph-io/badger"
)

const TestPath = "/tmp/badger"

type Blob []byte

type Commit struct {
	Timestamp time.Time `json:"timestamp"`
	Author    string    `json:"author"` // could be a user ref
	Message   string    `json:"message"`
	Parent    string    `json:"parent"` // sha of the parent
	SHA       string    `json:"sha"`    // sha of the new version
}

func (b Blob) Sha() string {
	return fmt.Sprintf("%x", sha1.Sum(b))
}

func cleanupDBFiles() error {
	return os.RemoveAll(TestPath)
}

func dbOptions() badger.Options {
	opts := badger.DefaultOptions
	opts.Dir = TestPath
	opts.ValueDir = TestPath
	return opts
}

func dbOpen() (*badger.DB, error) {
	return badger.Open(dbOptions())
}

func putStr(tx *badger.Txn, k, v string) error {
	return tx.Set([]byte(k), []byte(v))
}

func putBlob(tx *badger.Txn, blob Blob) (string, error) {
	sha := blob.Sha()
	err := tx.Set([]byte("/blob/"+sha), blob)
	return sha, err
}

func getBlob(tx *badger.Txn, sha string) (Blob, error) {
	item, err := tx.Get([]byte("/blob/" + sha))
	if err != nil {
		return nil, err
	}
	v, err := item.Value()
	if err != nil {
		return nil, err
	}
	return v, nil
}

func putPath(txn *badger.Txn, path string, sha string) error {
	return txn.Set([]byte("/path"+path), []byte(sha))
}

func getPath(txn *badger.Txn, path string) (string, error) {
	item, err := txn.Get([]byte("/path" + path))
	if err != nil {
		return "", err
	}
	v, err := item.ValueCopy(nil)
	if err != nil {
		return "", err
	}
	return string(v), err
}

// TODO(art): I think these have to be updated to handle a fully-qualified key
// (e.g., /blob/<sha> or /tree/<sha> or even /foo/bar/<sha>) instead of assuming
// all shas belong in /blob/

// putBlobAtPath first stores the blob at /blob/<sha>, then creates a reference at
// /path/<path> with the blob's sha
func putBlobAtPath(txn *badger.Txn, blob Blob, path string) (string, error) {
	sha, err := putBlob(txn, blob)
	if err != nil {
		return "", err
	}
	err = putPath(txn, path, sha)
	if err != nil {
		return "", err
	}
	return sha, nil
}

// getBlobAtPath first finds the sha at /path/<path>, then finds the blob at
// /blob/<sha>
func getBlobAtPath(txn *badger.Txn, path string) (Blob, error) {
	sha, err := getPath(txn, path)
	if err != nil {
		return nil, err
	}
	blob, err := getBlob(txn, sha)
	if err != nil {
		return nil, err
	}
	return blob, nil
}

func makeJSONBlob(obj interface{}) (Blob, error) {
	return json.Marshal(obj)
}

func TestSha(t *testing.T) {
	type test struct {
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Email     string `json:"email"`
	}
	testUser := test{"Art", "Gillespie", "art@udacity.com"}
	var bUser Blob
	bUser, err := makeJSONBlob(testUser)
	if err != nil {
		t.Fatalf("Couldn't serialize user to json: %v", err)
	}

	testUser2 := test{"ART", "Gillespie", "art@udacity.com"}
	var bUser2 Blob
	bUser2, err = makeJSONBlob(testUser2)
	if bUser.Sha() == bUser2.Sha() {
		t.Fatalf("Expected %s != %s", bUser.Sha(), bUser2.Sha())
	}
	bUser3, err := makeJSONBlob(test{"Art", "Gillespie", "art@udacity.com"})
	if bUser.Sha() != bUser3.Sha() {
		t.Fatalf("Expected %s == %s", bUser.Sha(), bUser3.Sha())
	}
}

func TestOne(t *testing.T) {
	db, err := dbOpen()
	if err != nil {
		t.Fatalf("Error loading database: %v", err)
	}
	defer db.Close()
	defer cleanupDBFiles()

	type user struct {
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Email     string `json:"email"`
	}
	blob, err := makeJSONBlob(&user{"Art", "Gillespie", "art@udacity.com"})
	if err != nil {
		t.Fatalf("Couldn't make json blob: %v", err)
	}
	db.Update(func(tx *badger.Txn) error {
		sha, err := putBlob(tx, blob)
		if err != nil {
			t.Fatalf("putBlob failed with error: %v", err)
		}
		t.Logf("putBlob returned sha: %s", sha)
		rblob, err := getBlob(tx, sha)
		if err != nil {
			t.Fatalf("getBlob failed with error: %v", err)
		}
		var u user
		err = json.Unmarshal(rblob, &u)
		if err != nil {
			t.Fatalf("couldn't unmarshal blob: %v", err)
		}
		if rblob.Sha() != sha {
			t.Fatalf("Expected fetched blob's sha to match stored blob's sha %s != %s", rblob.Sha(), sha)
		}
		if u.Email != "art@udacity.com" {
			t.Fatalf("Expected fetched blob's email to match: %s != %s", u.Email, "art@udacity.com")
		}
		return nil
	})
}

// Do transactions work the way you think they do? Yup!
func TestTx(t *testing.T) {
	db, err := dbOpen()
	if err != nil {
		t.Fatalf("Error loading database: %v", err)
	}
	defer db.Close()
	defer cleanupDBFiles()
	err = db.Update(func(tx *badger.Txn) error {
		err := putStr(tx, "message", "foobar")
		if err != nil {
			t.Fatalf("putStr failed with error: %v", err)
		}
		return fmt.Errorf("transaction failed!")
	})
	if err == nil || err.Error() != "transaction failed!" {
		t.Fatalf("not the error we were expecting: %v", err)
	}
	err = db.View(func(tx *badger.Txn) error {
		_, err := tx.Get([]byte("message"))
		return err
	})
	if err != badger.ErrKeyNotFound {
		t.Fatalf("Expected ErrKeyNotFound, got: %v", err)
	}
}
func TestRefs(t *testing.T) {
	db, err := dbOpen()
	if err != nil {
		t.Fatalf("Error loading database: %v", err)
	}
	defer db.Close()
	defer cleanupDBFiles()

	type user struct {
		ID        string `json:"id"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Email     string `json:"email"`
	}

	// putUser puts the user in /blob, then adds them to path /path/user/<id>/__latest -> sha
	putUser := func(txn *badger.Txn, u user) error {
		blobUser, err := makeJSONBlob(u)
		if err != nil {
			return err
		}
		// paths have the format /<type>/<stable_id>/<refname> and _always_ return a key, e.g. `/blob/<sha>`
		_, err = putBlobAtPath(txn, blobUser, "/user/"+u.ID+"/__latest")
		if err != nil {
			return err
		}
		return nil
	}

	u := user{"123456", "Art", "Gillespie", "art@udacity.com"}
	err = db.Update(func(txn *badger.Txn) error {
		err := putUser(txn, u)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatalf("db.Update(putUser) failed with error: %v", err)
	}
	err = db.View(func(txn *badger.Txn) error {
		sha, err := getPath(txn, "/user/"+u.ID+"/__latest")
		if err != nil {
			return err
		}
		t.Logf("getPath returned sha: %s", sha)
		blobUser, err := getBlob(txn, sha)
		if err != nil {
			return err
		}
		var u2 user
		err = json.Unmarshal(blobUser, &u2)
		if err != nil {
			t.Fatalf("de-serializing userBlob failed with error: %v", err)
		}
		t.Logf("Got user: %+v", u2)
		return nil
	})
	if err != nil {
		t.Fatalf("db.View(getUser) failed with error: %v", err)
	}
}

/*
 * TODO(art): How are commits stored in git? Are they hashed and stored in the object database?
 * What's the algorithm for displaying them? Need to re-read git internals.
 */
func TestTimeSorting(t *testing.T) {
	db, err := dbOpen()
	if err != nil {
		t.Fatalf("Error loading database: %v", err)
	}
	defer db.Close()
	defer cleanupDBFiles()

	putCommit := func(txn *badger.Txn, commit *Commit) error {
		commitBytes, err := json.Marshal(commit)
		if err != nil {
			return err
		}
		t.Logf("put commit at %s", fmt.Sprintf("/commit/%d", commit.Timestamp.Unix()))
		return txn.Set([]byte(fmt.Sprintf("/commit/%d", commit.Timestamp.Unix())), commitBytes)
	}

	// store commits at `/commit/timestamp` and seek on them

	ts, err := time.Parse("Mon Jan 2 15:04:05 -0700 MST 2006", "Mon Jan 2 15:04:05 -0700 MST 2006")
	if err != nil {
		t.Fatalf("time.Parse failed with error: %v", err)
	}
	err = db.Update(func(txn *badger.Txn) error {
		for i := 0; i < 100; i++ {
			ts = ts.Add(time.Minute)
			c := Commit{ts, "art@udacity.com", "commit message " + string(i), "abcdef", "ghijklm"}
			err = putCommit(txn, &c)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("db.Update failed with error: %v", err)
	}
	// Neat: example of retrieving five most recent commits in descending order starting at
	// unix timestamp 1136245084
	err = db.View(func(txn *badger.Txn) error {
		// you'd need to truncate to use valid for prefix
		prefix := []byte(fmt.Sprintf("/commit/%d", 1136245084))
		opts := badger.DefaultIteratorOptions
		// reverse-sort keys (descending timestamps)
		opts.Reverse = true
		it := txn.NewIterator(opts)
		defer it.Close()
		var count int
		for it.Seek(prefix); it.Valid(); it.Next() {
			if count > 4 {
				break
			}
			item := it.Item()
			k := item.Key()
			t.Logf("got key: %s", k)
			v, err := item.Value()
			if err != nil {
				t.Fatalf("Retrieving item.value failed with error: %v", err)
			}
			var commit Commit
			err = json.Unmarshal(v, &commit)
			if err != nil {
				t.Fatalf("json.Unmarshal(commit) failed with error: %v", err)
			}
			t.Logf("got commit for date: %v", commit.Timestamp)
			count++
		}
		return nil
	})
}
