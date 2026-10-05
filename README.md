# CYBRY460-EXAM-1


## Student

Joseph Herron

## Description

This project contains my solutions for Exam 1 in CYBR 460 Applied Cryptography. The programs were written in **Python 3** using the `cryptography` package.

The exam focuses on common cryptography problems involving CBC, CFB, PKCS#7 padding, authenticated encryption, and replay protection.

## Problems Completed

### Problem 1 – CBC Decryption with Missing IV

Implemented CBC decryption when the IV is unavailable. The first plaintext block cannot be recovered without the IV, but later plaintext blocks can be recovered using the previous ciphertext block.

### Problem 2 – CFB Error Propagation

Implemented a function that encrypts plaintext using CFB mode, corrupts selected ciphertext bytes, and compares the original and corrupted plaintext. The program reports which bytes and blocks changed.

### Problem 3 – CBC Bit Flipping

Implemented a CBC bit-flipping attack using XOR. The program modifies the previous ciphertext block so that a selected byte in the next plaintext block changes to a chosen target value.

### Problem 4 – PKCS#7 Unpadding

Implemented a strict PKCS#7 unpadding function. The function checks the block size, message length, padding value, and all padding bytes before returning the unpadded message.

### Problem 5 – Encrypt-then-MAC

Implemented authenticated encryption using encryption and HMAC-SHA-256. The nonce, ciphertext, and additional authenticated data are authenticated before the message is decrypted. Modified ciphertext, nonce, AAD, or authentication tags are rejected.

### Problem 6 – Replay Protection

Implemented a replay-protected receiver using HMAC authentication and sequence numbers. The receiver keeps track of the highest sequence number received from each sender and rejects replayed or older messages.

## Testing

Each problem includes tests demonstrating that the functions work as required.

The tests include:

* Valid encryption and decryption
* Invalid keys and ciphertext lengths
* Corrupted ciphertext
* CBC bit flipping
* Valid and invalid PKCS#7 padding
* Modified authentication data
* Invalid authentication tags
* Replay attacks
* Multiple senders and sequence numbers

## Python Package

The project uses the `cryptography` package.

It can be installed with:

```bash
python3 -m pip install cryptography
```

## AI Assistance

Generative AI was permitted for this exam. I used ChatGPT to help explain cryptography concepts, troubleshoot Python errors, and develop and review parts of the code.

The prompts used included:

1. "Help me solve Problem 1 in Python 3 using the cryptography package."

2. "Explain CBC decryption when the IV is missing in simple terms."

3. "Help me implement CFB error propagation in Python."

4. "Help me implement CBC bit flipping using XOR."

5. "Help me implement strict PKCS#7 unpadding in Python."

6. "Help me implement authenticated encryption using Encrypt-then-MAC."

7. "Help me implement replay protection using HMAC and sequence numbers."

8. "Help me fix the indentation error in my Python code."

I reviewed and tested the generated code and made changes as needed to complete the exam requirements.
