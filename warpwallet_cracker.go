package main

import (
    "golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	"bytes"
	"crypto/sha256"
	"fmt"
	"time"
	"os"
	"math/rand"
	"github.com/vsergeev/btckeygenie/btckey"
)
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
const (
    letterIdxBits = 6                    // 6 bits to represent a letter index
    letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
    letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var src = rand.NewSource(time.Now().UnixNano())

func RandStringBytesMaskImprSrc(n int) string {
    b := make([]byte, n)
    // A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
    for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
        if remain == 0 {
            cache, remain = src.Int63(), letterIdxMax
        }
        if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
            b[i] = letterBytes[idx]
            i--
        }
        cache >>= letterIdxBits
        remain--
    }

    return string(b)
}

func main () {
	var address string
	saltValue := ""
	
	if len(os.Args) >= 2 {
		address = os.Args[1]
		if len(os.Args) == 3 {
			saltValue = os.Args[2]
		} else {
			saltValue = "";
		}
	} else {
		fmt.Printf("Usage: %s [Address] [Salt - optional]\n\n", os.Args[0])
		os.Exit(0)
	}
	
	fmt.Printf("Using address \"%s\" and salt \"%s\"\n", address, saltValue)
	
	tries := 0
	start := time.Now()
	for {
		passphraseValue := RandStringBytesMaskImprSrc(8)
		bruteforce(passphraseValue, saltValue, address);
		tries += 1
		fmt.Printf("\rTried %d passphrases in %s [last passphrase: %s]", tries, time.Since(start), passphraseValue)
	}
}

func bruteforce(passphraseValue string, saltValue string, address string) {
	var priv btckey.PrivateKey
	var err error
	
    pass := fmt.Sprint(passphraseValue, "\x01")
    salt := fmt.Sprint(saltValue, "\x01")
    key, _ := scrypt.Key([]byte(pass), []byte(salt), 262144, 8, 1, 32)
    pass = fmt.Sprint(passphraseValue, "\x02")
    salt = fmt.Sprint(saltValue, "\x02")
    key2 := pbkdf2.Key([]byte(pass), []byte(salt), 65536, 32, sha256.New)

    var result bytes.Buffer
    for i := 0; i < len(key); i++ {
        result.WriteByte(key[i] ^ key2[i])
    }

	err = priv.FromBytes(result.Bytes())
	if err != nil {
		fmt.Printf("Error importing private key: %s [%s]\n", err, passphraseValue)
		os.Exit(0)
	}
	
	address_uncompressed := priv.ToAddressUncompressed()
	wif := priv.ToWIF()
	
	if (address_uncompressed == address) {
		fmt.Printf("Found! Passphrase      %s\n", passphraseValue)
		fmt.Printf("Bitcoin Address (Uncompressed)      %s\n", address_uncompressed)
		fmt.Printf("Private Key WIF (Uncompressed)      %s\n", wif)
		os.Exit(0)
	}
}
