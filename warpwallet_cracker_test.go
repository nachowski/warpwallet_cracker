package main

import "testing"

var bruteforceTests = []struct {
  passphrase	string // passphrase input
  salt			string // salt input
  address		string // address input
}{
	// first warpwallet challenge
	{"PuACRv0R", "", "1AdU3EcimMFN7JLJtceSyrmFYE3gF5ZnGj"},
	 // first 4 test vectors
	{"ER8FT+HFjk0", "7DpniYifN6c", "1J32CmwScqhwnNQ77cKv9q41JGwoZe2JYQ"},
	{"YqIDBApDYME", "G34HqIgjrIc", "19aKBeXe2mi4NbQRpYUrCLZtRDHDUs9J7J"},
	{"FPdAxCygMJg", "X+qaSwhUYXw", "14Pqeo9XNRxjtKFFYd6TvRrJuZxVpciS81"},
	{"gdoyAj5Y+jA", "E+6ZzCnRqVM", "1KiiYhv9xkTZfcLYwqPhYHrSbvwJFFUgKv"},
}

func TestBruteforce(t *testing.T) {
	for _, tt := range bruteforceTests {
		actual := bruteforce(tt.passphrase, tt.salt, tt.address)
		if actual != tt.passphrase {
			t.Error("Test failed, expected: '%s', got: '%s'", tt.passphrase, actual)
		}
	  }
}

func BenchmarkBruteforce(b *testing.B) {
	for n := 0; n < b.N; n++ {
		// use the first test vector
        bruteforce("ER8FT+HFjk0", "7DpniYifN6c", "1J32CmwScqhwnNQ77cKv9q41JGwoZe2JYQ")
     }
}
