from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def decrypt_cbc_missing_iv(key: bytes, ciphertext: bytes) -> dict:
    # Check the key
    if len(key) not in (16, 24, 32):
        raise ValueError("Invalid AES key length")

    # Check the ciphertext
    if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
        raise ValueError("Invalid ciphertext length")

    # Split ciphertext into 16-byte blocks
    blocks = [
        ciphertext[i:i + 16]
        for i in range(0, len(ciphertext), 16)
    ]

    recoverable = []
    unrecoverable = [0]

    # Block 0 cannot be recovered because the IV is missing
    for i in range(1, len(blocks)):

        cipher = Cipher(
            algorithms.AES(key),
            modes.ECB()
        )

        decryptor = cipher.decryptor()

        decrypted = decryptor.update(blocks[i])
        decrypted += decryptor.finalize()

        # CBC:
        # plaintext = decrypted block XOR previous ciphertext block
        plaintext = bytes(
            a ^ b
            for a, b in zip(decrypted, blocks[i - 1])
        )

        recoverable.append(plaintext)

    return {
        "recoverable_blocks": recoverable,
        "unrecoverable_blocks": unrecoverable,
        "explanation":
            "Block 0 cannot be recovered because the IV is missing. "
            "Later blocks can be recovered using the previous ciphertext block."
    }


# -------------------------
# TEST
# -------------------------

key = b"0123456789abcdef"
iv = b"abcdef0123456789"

plaintext = (
    b"Block 0 is here!"
    b"Block 1 is here!"
    b"Block 2 is here!"
)

# Create valid CBC ciphertext
cipher = Cipher(
    algorithms.AES(key),
    modes.CBC(iv)
)

encryptor = cipher.encryptor()

ciphertext = encryptor.update(plaintext)
ciphertext += encryptor.finalize()

# Pretend we lost the IV
result = decrypt_cbc_missing_iv(key, ciphertext)

print("Unrecoverable blocks:")
print(result["unrecoverable_blocks"])

print("\nRecoverable blocks:")

for block in result["recoverable_blocks"]:
    print(block)

print("\nExplanation:")
print(result["explanation"])
 
 #TASK 2 CFB ERROR PROPAGATION EXPERIMENT

def cfb_corruption_report(
    key: bytes,
    iv: bytes,
    plaintext: bytes,
    corrupt_block: int,
    corrupt_byte_count: int = 2
) -> dict:

    # Encrypt the plaintext
    cipher = Cipher(
        algorithms.AES(key),
        modes.CFB(iv)
    )

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Make a copy so we can change it
    corrupted = bytearray(ciphertext)

    # Change the requested bytes
    start = corrupt_block * 16

    for i in range(corrupt_byte_count):
        corrupted[start + i] ^= 0xFF

    corrupted = bytes(corrupted)

    # Decrypt original ciphertext
    cipher = Cipher(
        algorithms.AES(key),
        modes.CFB(iv)
    )

    decryptor = cipher.decryptor()
    original_plaintext = decryptor.update(ciphertext)
    original_plaintext += decryptor.finalize()

    # Decrypt corrupted ciphertext
    cipher = Cipher(
        algorithms.AES(key),
        modes.CFB(iv)
    )

    decryptor = cipher.decryptor()
    corrupted_plaintext = decryptor.update(corrupted)
    corrupted_plaintext += decryptor.finalize()

    # Find changed bytes
    changed_bytes = []

    for i in range(len(plaintext)):
        if original_plaintext[i] != corrupted_plaintext[i]:
            changed_bytes.append(i)

    # Find changed blocks
    changed_blocks = sorted(
        set(i // 16 for i in changed_bytes)
    )

    return {
        "original_ciphertext": ciphertext,
        "corrupted_ciphertext": corrupted,
        "original_plaintext": original_plaintext,
        "corrupted_plaintext": corrupted_plaintext,
        "changed_byte_indexes": changed_bytes,
        "changed_block_indexes": changed_blocks
    }
 #----TASK 2 TEST 1 
 
key = b"0123456789abcdef"
iv = b"abcdef0123456789"

plaintext = (
    b"Block 0 is here!"
    b"Block 1 is here!"
    b"Block 2 is here!"
)

result = cfb_corruption_report(
    key,
    iv,
    plaintext,
    corrupt_block=0,
    corrupt_byte_count=2
)
print("TASK 2 TEST 1:")
print("Original ciphertext:")
print(result["original_ciphertext"])

print("\nCorrupted ciphertext:")
print(result["corrupted_ciphertext"])

print("\nOriginal plaintext:")
print(result["original_plaintext"])

print("\nCorrupted plaintext:")
print(result["corrupted_plaintext"])

print("\nChanged byte indexes:")
print(result["changed_byte_indexes"])

print("\nChanged block indexes:")
print(result["changed_block_indexes"])
    #TASK 2 TEST 2 CHECKING CORRUPTION OF 2 DIFFERENT CIPHERTEXT BLOCKS
result2 = cfb_corruption_report(
    key,
    iv,
    plaintext,
    corrupt_block=1,
    corrupt_byte_count=2
)

print("\n--- Second Test ---")

print("Changed byte indexes:")
print(result2["changed_byte_indexes"])

print("Changed block indexes:")
print(result2["changed_block_indexes"])

#TASK 3 CBC Bit-Flipping 

def cbc_bitflip(
    previous_ciphertext_block: bytes,
    current_ciphertext_block: bytes,
    known_plaintext_block: bytes,
    byte_index: int,
    target_byte: int
) -> bytes:

    # Check inputs
    if len(previous_ciphertext_block) != 16:
        raise ValueError("Previous block must be 16 bytes")

    if len(current_ciphertext_block) != 16:
        raise ValueError("Current block must be 16 bytes")

    if len(known_plaintext_block) != 16:
        raise ValueError("Plaintext block must be 16 bytes")

    if byte_index < 0 or byte_index >= 16:
        raise ValueError("Invalid byte index")

    if target_byte < 0 or target_byte > 255:
        raise ValueError("Target must be between 0 and 255")

    # Make a copy of the previous ciphertext block
    modified = bytearray(previous_ciphertext_block)

    # CBC bit-flipping formula
    modified[byte_index] ^= known_plaintext_block[byte_index]
    modified[byte_index] ^= target_byte

    return bytes(modified)


#-------------TASK 3 TEST  ENCRYPTING A PLAINTEXT
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


key = b"0123456789abcdef"
iv = b"abcdef0123456789"

plaintext = b"Attack at dawn!!"

# Encrypt
cipher = Cipher(
    algorithms.AES(key),
    modes.CBC(iv)
)

encryptor = cipher.encryptor()

ciphertext = encryptor.update(plaintext)
ciphertext += encryptor.finalize()

# Get the two blocks
previous_block = iv
current_block = ciphertext[:16]

# We know the original plaintext
known_plaintext = plaintext

# Change the first byte from 'A' to 'X'
modified_previous = cbc_bitflip(
    previous_block,
    current_block,
    known_plaintext,
    0,
    ord('X')
)

# Decrypt using the modified previous block
cipher = Cipher(
    algorithms.AES(key),
    modes.CBC(modified_previous)
)

decryptor = cipher.decryptor()

modified_plaintext = decryptor.update(current_block)
modified_plaintext += decryptor.finalize()
print("TASK 3 TEST:")
print("Original plaintext:")
print(plaintext)

print("\nModified plaintext:")
print(modified_plaintext)

#Formula modified[i] = original [i] ^ known_plaintext[i] ^ target



#-----TASK 4 PKCS #7 PADDING VALIDATOR 
def pkcs7_unpad(data: bytes, block_size: int) -> bytes:

    # Check block size
    if block_size < 1 or block_size > 255:
        raise ValueError("Invalid block size")

    # Data cannot be empty
    if len(data) == 0:
        raise ValueError("Invalid padding")

    # Data must be a multiple of the block size
    if len(data) % block_size != 0:
        raise ValueError("Invalid padding")

    # Last byte tells us how much padding there is
    padding = data[-1]

    # Padding must be between 1 and block_size
    if padding < 1 or padding > block_size:
        raise ValueError("Invalid padding")

    # Check every padding byte
    for i in range(1, padding + 1):
        if data[-i] != padding:
            raise ValueError("Invalid padding")

    # Remove the padding
    return data[:-padding]

#---TASK 4 TEST (5 SEPERATE TESTS)
# Test 1: Valid padding with one byte
data1 = b"123456789012\x04\x04\x04\x04"

print("Test 1:", pkcs7_unpad(data1, 16))


# Test 2: Valid padding with two bytes
data2 = b"HELLO WORLD!!\x03\x03\x03"

print("Test 2:", pkcs7_unpad(data2, 16))


# Test 3: Valid padding with 1 byte
data3 = b"123456789012345\x01"

print("Test 3:", pkcs7_unpad(data3, 16))


# Test 4: Invalid padding
try:
    pkcs7_unpad(b"HELLO WORLD!\x04\x04\x04\x03", 16)
    print("Test 4 failed")
except ValueError:
    print("Test 4 passed")


# Test 5: Invalid block size
try:
    pkcs7_unpad(b"HELLO", 0)
    print("Test 5 failed")
except ValueError:
    print("Test 5 passed")


# Test 6: Data is not block-aligned
try:
    pkcs7_unpad(b"HELLO", 16)
    print("Test 6 failed")
except ValueError:
    print("Test 6 passed")

#for this test I'm checking if my function rejects empty data, Invalid block sizes, padding value - 0, data that isn't block alligned, padding larger than the blok size and padding where the bytes don't match 
#The last byte tells me how many padding bytes are present. The function checks that the value is between 1 and the block size and then checks every padding byte to make sure they all have the same value. If the padding is valid, it removes the padding and returns the original data. Otherwise, it raises a generic ValueError.

#---TASK 5 AUTHENTICATION ENCRYPTION 
# GOAL = PLAINTEXT -> ENCRYPT -> CIPHERTEXT -> HMAC -> TAG
#WHEN I OPEN THE MESSAGE THE TAG SHOULD BE CHECKED FIRST ALWAYS 

import os
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def seal(
    key_enc: bytes,
    key_mac: bytes,
    plaintext: bytes,
    aad: bytes = b""
) -> tuple:

    # Create a random 12-byte nonce
    nonce = os.urandom(12)

    # Encrypt the plaintext
    aes = AESGCM(key_enc)

    ciphertext = aes.encrypt(
        nonce,
        plaintext,
        aad
    )

    # Create HMAC over nonce + ciphertext + AAD
    data = nonce + ciphertext + aad

    tag = hmac.new(
        key_mac,
        data,
        hashlib.sha256
    ).digest()

    return nonce, ciphertext, tag


# DECRYPTION FUNCTION
def open_sealed(
    key_enc: bytes,
    key_mac: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    aad: bytes = b""
) -> bytes:

    # Recreate the data that was authenticated
    data = nonce + ciphertext + aad

    # Calculate the expected tag
    expected_tag = hmac.new(
        key_mac,
        data,
        hashlib.sha256
    ).digest()

    # Check the tag BEFORE decrypting
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("Authentication failed")

    # Only decrypt after authentication succeeds
    aes = AESGCM(key_enc)

    return aes.decrypt(
        nonce,
        ciphertext,
        aad
    )


#TASK 5 TEST 
key_enc = AESGCM.generate_key(bit_length=128)
key_mac = os.urandom(32)

plaintext = b"This is a secret message."
aad = b"header information"

# Encrypt
nonce, ciphertext, tag = seal(
    key_enc,
    key_mac,
    plaintext,
    aad
)

# Correct message
result = open_sealed(
    key_enc,
    key_mac,
    nonce,
    ciphertext,
    tag,
    aad
)

print("Original:", plaintext)
print("Decrypted:", result)





bad_ciphertext = bytearray(ciphertext)

bad_ciphertext[0] ^= 1


try:
    open_sealed(
        key_enc,
        key_mac,
        nonce,
        bytes(bad_ciphertext),
        tag,
        aad
    )
    print("Test failed")
except ValueError:
    print("Modified ciphertext rejected")








bad_nonce = bytearray(nonce)

bad_nonce[0] ^= 1

try:
    open_sealed(
        key_enc,
        key_mac,
        bytes(bad_nonce),
        ciphertext,
        tag,
        aad
    )
    print("Test failed")
except ValueError:
    print("Modified nonce rejected")











try:
    open_sealed(
        key_enc,
        key_mac,
        nonce,
        ciphertext,
        tag,
        b"wrong header"
    )
    print("Test failed")
except ValueError:
    print("Modified AAD rejected")







#---TASK 6: MACs AND REPLAY PROTECTION 

import hmac
import hashlib


class ReplayProtectedReceiver:

    def __init__(self, mac_key: bytes):
        self.mac_key = mac_key
        self.highest = {}

    def accept(
        self,
        sender_id: str,
        sequence: int,
        message: bytes,
        tag: bytes
    ) -> bool:

        data = (
            sender_id.encode()
            + sequence.to_bytes(8, "big")
            + message
        )

        expected_tag = hmac.new(
            self.mac_key,
            data,
            hashlib.sha256
        ).digest()

        if not hmac.compare_digest(tag, expected_tag):
            return False

        if sender_id in self.highest:
            if sequence <= self.highest[sender_id]:
                return False

        self.highest[sender_id] = sequence

        return True


def make_tag(
    mac_key: bytes,
    sender_id: str,
    sequence: int,
    message: bytes
) -> bytes:

    data = (
        sender_id.encode()
        + sequence.to_bytes(8, "big")
        + message
    )

    return hmac.new(
        mac_key,
        data,
        hashlib.sha256
    ).digest()


# -------------------------
# TESTS
# -------------------------

key = b"12345678901234567890123456789012"

receiver = ReplayProtectedReceiver(key)


# Test 1: Valid message
message = b"Hello"

tag = make_tag(
    key,
    "Alice",
    1,
    message
)

print("Valid message:",
      receiver.accept(
          "Alice",
          1,
          message,
          tag
      ))


# Test 2: Tampered message
tampered_message = b"HELLO"

print("Tampered message:",
      receiver.accept(
          "Alice",
          2,
          tampered_message,
          tag
      ))


# Test 3: Replay
print("Replay:",
      receiver.accept(
          "Alice",
          1,
          message,
          tag
      ))


# Test 4: New sequence number
message2 = b"New message"

tag2 = make_tag(
    key,
    "Alice",
    2,
    message2
)

print("New sequence:",
      receiver.accept(
          "Alice",
          2,
          message2,
          tag2
      ))


# Test 5: Different sender
message3 = b"Hello from Bob"

tag3 = make_tag(
    key,
    "Bob",
    1,
    message3
)

print("Bob:",
      receiver.accept(
          "Bob",
          1,
          message3,
          tag3
      ))








