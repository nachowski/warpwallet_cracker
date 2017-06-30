# warpwallet_cracker
A brute-force cracker in Go for the WarpWallet Challenge 2: https://keybase.io/warp/

# Usage

```
$ ./run.sh 
Using address "1MkupVKiCik9iyfnLrJoZLx9RH4rkF3hnA" and salt "a@b.c"
Tried 4 passphrases in 2.269448485s [last passphrase: 2zZM3L1C]
```

# How-to
Build:

`go build warpwallet_cracker.go`

Params:

`./warpwallet_cracker [Address] [Salt - optional]`

Run (Windows):

`run.bat`

Run (*nix):

`./run.sh`

Run unit tests and benchmark:

`go test -bench=.`
