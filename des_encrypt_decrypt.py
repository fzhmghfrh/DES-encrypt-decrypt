import os

def bin_to_dec(binary):
	decimal_value, i = 0, 0
	while(binary != 0):
		decimal_digit = binary % 10
		decimal_value = decimal_value + decimal_digit * pow(2, i)
		binary = binary//10
		i += 1
	return decimal_value

def dec_to_bin(decimal_number):
	binary_string = bin(decimal_number).replace("0b", "")
	if len(binary_string) % 4 != 0:
		padding_length = 4 - (len(binary_string) % 4)
		binary_string = '0' * padding_length + binary_string
	return binary_string

def hex_to_bin(hex_string):
	hex_to_bin_map = {'0': "0000", '1': "0001", '2': "0010", '3': "0011",
        '4': "0100", '5': "0101", '6': "0110", '7': "0111",
        '8': "1000", '9': "1001", 'A': "1010", 'B': "1011",
        'C': "1100", 'D': "1101", 'E': "1110", 'F': "1111"
    }
	binary_string = ""
	for i in range(len(hex_string)):
		binary_string += hex_to_bin_map[hex_string[i]]
	return binary_string

def bin_to_hex(bin_string):
	hex_to_bin_map = {
        "0000": '0', "0001": '1', "0010": '2', "0011": '3',
        "0100": '4', "0101": '5', "0110": '6', "0111": '7',
        "1000": '8', "1001": '9', "1010": 'A', "1011": 'B',
        "1100": 'C', "1101": 'D', "1110": 'E', "1111": 'F'
    }
	hex_string = ""
	for i in range(0, len(bin_string), 4):
		bin_chunk = ""
		bin_chunk = bin_chunk + bin_string[i]
		bin_chunk = bin_chunk + bin_string[i + 1]
		bin_chunk = bin_chunk + bin_string[i + 2]
		bin_chunk = bin_chunk + bin_string[i + 3]
		hex_string = hex_string + hex_to_bin_map[bin_chunk]

	return hex_string

def permute_bits(input_bits, perm_table, length):
	permuted_bits = ""
	for i in range(0, length):
		permuted_bits +=  input_bits[perm_table[i] - 1]
	return permuted_bits

def left_shift(bits, nth_shifts):
    for _ in range(nth_shifts):
        bits = bits[1:] + bits[0]
    return bits

def calculate_xor(a, b):
    return ''.join('1' if a[i] != b[i] else '0' for i in range(len(a)))

initial_permutation = [58, 50, 42, 34, 26, 18, 10, 2,
				60, 52, 44, 36, 28, 20, 12, 4,
				62, 54, 46, 38, 30, 22, 14, 6,
				64, 56, 48, 40, 32, 24, 16, 8,
				57, 49, 41, 33, 25, 17, 9, 1,
				59, 51, 43, 35, 27, 19, 11, 3,
				61, 53, 45, 37, 29, 21, 13, 5,
				63, 55, 47, 39, 31, 23, 15, 7]

expansion_d_box = [32, 1, 2, 3, 4, 5, 4, 5,
					6, 7, 8, 9, 8, 9, 10, 11,
					12, 13, 12, 13, 14, 15, 16, 17,
					16, 17, 18, 19, 20, 21, 20, 21,
					22, 23, 24, 25, 24, 25, 26, 27,
					28, 29, 28, 29, 30, 31, 32, 1]

straight_permutation = [16, 7, 20, 21,
						29, 12, 28, 17,
						1, 15, 23, 26,
						5, 18, 31, 10,
						2, 8, 24, 14,
						32, 27, 3, 9,
						19, 13, 30, 6,
						22, 11, 4, 25]

s_box = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
		[0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
		[4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
		[15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

		[[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
		[3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
		[0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
		[13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

		[[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
		[13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
		[13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
		[1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

		[[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
		[13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
		[10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
		[3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

		[[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
		[14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
		[4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
		[11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

		[[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
		[10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
		[9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
		[4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

		[[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
		[13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
		[1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
		[6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

		[[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
		[1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
		[7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
		[2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

final_permutation = [40, 8, 48, 16, 56, 24, 64, 32,
			39, 7, 47, 15, 55, 23, 63, 31,
			38, 6, 46, 14, 54, 22, 62, 30,
			37, 5, 45, 13, 53, 21, 61, 29,
			36, 4, 44, 12, 52, 20, 60, 28,
			35, 3, 43, 11, 51, 19, 59, 27,
			34, 2, 42, 10, 50, 18, 58, 26,
			33, 1, 41, 9, 49, 17, 57, 25]


def des_encrypt(plaintext, binary_roundkeys, hexadecimal_roundkeys):
	plaintext = hex_to_bin(plaintext)

	plaintext = permute_bits(plaintext, initial_permutation, 64)
	# print("IP", bin_to_hex(plaintext))

	left = plaintext[0:32]
	right = plaintext[32:64]
	for i in range(0, 16):
		right_expanded = permute_bits(right, expansion_d_box, 48)

		xor_x = calculate_xor(right_expanded, binary_roundkeys[i])

		sbox_str = ""
		for j in range(0, 8):
			row = bin_to_dec(int(xor_x[j * 6] + xor_x[j * 6 + 5]))
			col = bin_to_dec(
				int(xor_x[j * 6 + 1] + xor_x[j * 6 + 2] + xor_x[j * 6 + 3] + xor_x[j * 6 + 4]))
			val = s_box[j][row][col]
			sbox_str = sbox_str + dec_to_bin(val)

		sbox_str = permute_bits(sbox_str, straight_permutation, 32)

		result = calculate_xor(left, sbox_str)
		left = result

		if i != 15:
			left, right = right, left
		# print(f"Round {i + 1:<2} {bin_to_hex(left):<16} {bin_to_hex(right):<16} {hexadecimal_roundkeys[i]}")
		combine = left + right

	cipher_text = permute_bits(combine, final_permutation, 64)
	return cipher_text

# Key generation
generate_key = os.urandom(8)
key = generate_key.hex().upper()
key = hex_to_bin(key)

key = permute_bits(key, [57, 49, 41, 33, 25, 17, 9, 1,
                            58, 50, 42, 34, 26, 18, 10, 2,
                            59, 51, 43, 35, 62, 54, 46, 38,
                            30, 22, 14, 6, 61, 53, 45, 37,
                            29, 21, 13, 5, 28, 20, 12, 4,
                            27, 19, 11, 3, 60, 52, 44, 36,
                            63, 55, 47, 39, 31, 23, 15, 7], 56)

shift_table = [1, 1, 2, 2,
			2, 2, 2, 2,
			1, 2, 2, 2,
			2, 2, 2, 1]

# PC 2
key_compression = [14, 17, 11, 24, 1, 5,
			3, 28, 15, 6, 21, 10,
			23, 19, 12, 4, 26, 8,
			16, 7, 27, 20, 13, 2,
			41, 52, 31, 37, 47, 55,
			30, 40, 51, 45, 33, 48,
			44, 49, 39, 56, 34, 53,
			46, 42, 50, 36, 29, 32]

left = key[0:28]
right = key[28:56]

binary_roundkeys = []
hexadecimal_roundkeys = []
for i in range(0, 16):
	left = left_shift(left, shift_table[i])
	right = left_shift(right, shift_table[i])

	combine_str = left + right

	round_key = permute_bits(combine_str, key_compression, 48)

	binary_roundkeys.append(round_key)
	hexadecimal_roundkeys.append(bin_to_hex(round_key))


plaintext = "ABCD12ABCD123456"

print("Encryption")
cipher_text = bin_to_hex(des_encrypt(plaintext, binary_roundkeys, hexadecimal_roundkeys))
print("Cipher Text : ", cipher_text)

print("Decryption")
rkb_rev = binary_roundkeys[::-1]
rk_rev = hexadecimal_roundkeys[::-1]
text = bin_to_hex(des_encrypt(cipher_text, rkb_rev, rk_rev))
print("Plain Text : ", text)

