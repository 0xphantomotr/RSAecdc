package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Create two distinct large prime numbers p, q
func generatePrimeNumber(bits int) (*big.Int, error) {
	return rand.Prime(rand.Reader, bits)
}

// n = p * q
func calculateN(p, q *big.Int) *big.Int {
	return new(big.Int).Mul(p, q)
}

// φ(n) = (p-1) * (q-1)
func calculateTotient(p, q *big.Int) *big.Int {
	one := big.NewInt(1)
	pMinus1 := new(big.Int).Sub(p, one)
	qMinus1 := new(big.Int).Sub(q, one)
	return new(big.Int).Mul(pMinus1, qMinus1)
}

// e such that 1 < e < φ(n), and e is co-prime to φ(n)
func findE(totient *big.Int) *big.Int {
	e := big.NewInt(3)
	for {
		if gcd := new(big.Int).GCD(nil, nil, e, totient); gcd.Cmp(big.NewInt(1)) == 0 {
			break
		}
		e.Add(e, big.NewInt(2))
	}
	return e
}

// d ≡ e^(-1) mod φ(n)
func modInverse(e, totient *big.Int) *big.Int {
	d := new(big.Int).ModInverse(e, totient)
	return d
}

// generate RSA Keys
func generateRsaKeys(bits int) (*big.Int, *big.Int, *big.Int, *big.Int, *big.Int) {
	p, _ := generatePrimeNumber(bits)
	q, _ := generatePrimeNumber(bits)
	n := calculateN(p, q)
	totient := calculateTotient(p, q)
	e := findE(totient)
	d := modInverse(e, totient)
	return p, q, n, e, d
}

// ciphertext = message^e mod n
func encrypt(message, e, n *big.Int) *big.Int {
	return new(big.Int).Exp(message, e, n)
}

// message = ciphertext^d mod n
func decrypt(ciphertext, d, n *big.Int) *big.Int {
	return new(big.Int).Exp(ciphertext, d, n)
}

func messageToBigInt(message string) *big.Int {
	messageInt := big.NewInt(0)
	messageInt.SetBytes([]byte(message))
	return messageInt
}

func bigIntToMessage(messageInt *big.Int) string {
	return string(messageInt.Bytes())
}

func main() {
	p, q, n, e, d := generateRsaKeys(1024)
	fmt.Println("Prime p:", p)
	fmt.Println("Prime q:", q)
	message := "O VALTER O BYTHQIM"
	messageInt := messageToBigInt(message)
	ciphertext := encrypt(messageInt, e, n)
	fmt.Println("Encrypted Message:", ciphertext)

	decryptedMessageInt := decrypt(ciphertext, d, n)
	decryptedMessage := bigIntToMessage(decryptedMessageInt)
	fmt.Println("Decrypted Message:", decryptedMessage)
}
