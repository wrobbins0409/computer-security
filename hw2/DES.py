# DES Decryption Implementation in Python

# Define permutation tables
# Initial permutation
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# Inverse initial permutation
IP_INVERSE = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

# Permuted choice 1 for key generation
PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

# Permuted choice 2 for key generation
PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

# Expansion permutation
E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

# S-boxes
S_BOXES = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

# P-box permutation
P = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]

# Key shift schedule
SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


def permute(input_block, table):
    """Apply a permutation table to a block"""
    return [input_block[i-1] for i in table]


def left_shift(bits, n):
    """Perform a circular left shift on a list of bits"""
    return bits[n:] + bits[:n]


def xor(a, b):
    """XOR two bit arrays"""
    return [a_bit ^ b_bit for a_bit, b_bit in zip(a, b)]


def split_in_half(bits):
    """Split a list in half"""
    half = len(bits) // 2
    return bits[:half], bits[half:]


def s_box_substitution(expanded_block):
    """Apply S-box substitution"""
    output = []

    # Process 6 bits at a time through the S-boxes
    for i in range(8):
        block = expanded_block[i*6:(i+1)*6]

        # Determine row and column for S-box lookup
        # Row is determined by the first and last bit
        row = (block[0] << 1) | block[5]

        # Column is determined by the middle 4 bits
        col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]

        # Get the value from the S-box
        value = S_BOXES[i][row][col]

        # Convert to binary (4 bits)
        for j in range(3, -1, -1):
            output.append((value >> j) & 1)

    return output


def f_function(r_block, subkey):
    """The Feistel function used in DES"""
    # Expand the 32-bit block to 48 bits
    expanded = permute(r_block, E)

    # XOR with the subkey
    xored = xor(expanded, subkey)

    # S-box substitution (48 bits -> 32 bits)
    substituted = s_box_substitution(xored)

    # Apply P-box permutation
    permuted = permute(substituted, P)

    return permuted


def generate_subkeys(key_bits):
    """Generate the 16 subkeys for DES"""
    # Apply PC-1 permutation to reduce key from 64 to 56 bits
    key_permuted = permute(key_bits, PC1)

    # Split into left and right halves
    c, d = split_in_half(key_permuted)

    # Generate 16 subkeys
    subkeys = []
    for i in range(16):
        # Apply the appropriate shift
        c = left_shift(c, SHIFTS[i])
        d = left_shift(d, SHIFTS[i])

        # Combine the halves and apply PC-2 permutation
        combined = c + d
        subkey = permute(combined, PC2)

        subkeys.append(subkey)

    return subkeys


def des_decrypt(ciphertext_bits, key_bits):
    """Decrypt a message using DES"""
    # Generate subkeys
    subkeys = generate_subkeys(key_bits)

    # Print the subkeys
    print("Generated 16 round keys:")
    for i, key in enumerate(subkeys):
        print(f"K{i+1}: {''.join(map(str, key))}")

    # Apply initial permutation
    permuted_ciphertext = permute(ciphertext_bits, IP)

    # Split into left and right halves
    left, right = split_in_half(permuted_ciphertext)

    print(f"Initial L0: {''.join(map(str, left))}")
    print(f"Initial R0: {''.join(map(str, right))}")

    # Process 16 rounds
    for i in range(16):
        # For decryption, use subkeys in reverse order
        subkey = subkeys[15 - i]

        # Calculate f function output
        f_output = f_function(right, subkey)
        print(f"Round {i+1} f function output: {''.join(map(str, f_output))}")

        # Save the current right half
        next_left = right

        # Calculate the new right half
        next_right = xor(left, f_output)

        # Update for next round
        left = next_left
        right = next_right

        print(f"L{i+1}: {''.join(map(str, left))}")
        print(f"R{i+1}: {''.join(map(str, right))}")

    # Swap the left and right halves
    combined = right + left

    # Apply final permutation
    plaintext = permute(combined, IP_INVERSE)

    return plaintext


def binary_to_ascii(binary):
    """Convert a binary array to ASCII text"""
    ascii_text = ""
    for i in range(0, len(binary), 8):
        byte = binary[i:i+8]
        char_code = int(''.join(map(str, byte)), 2)
        ascii_text += chr(char_code)
    return ascii_text


def main():
    # Given information
    ciphertext = "1100101011101101101000100110010101011111101101110011100001110011"
    key_binary = "0100110001001111010101100100010101000011010100110100111001000100"

    # Convert to lists of bits
    ciphertext_bits = [int(bit) for bit in ciphertext]
    key_bits = [int(bit) for bit in key_binary]

    # Perform DES decryption
    plaintext_bits = des_decrypt(ciphertext_bits, key_bits)

    # Convert to ASCII
    plaintext = binary_to_ascii(plaintext_bits)

    print("\nDeciphered message in binary:", ''.join(map(str, plaintext_bits)))
    print("Deciphered message in ASCII:", plaintext)


if __name__ == "__main__":
    main()
