import math
import textwrap
import random
from functools import reduce

"""
s-boxy generuję w sposób pseudolosowy, korzystając z biblioteki random
dostępnej w Pythonie.

Powodem, dla którego wykorzystywane są s-boxy, jest wprowadzenie nieliniowości
do algorytmu szyfrowania. s-boxy powinny zostać poddane testom, które sprawdzają,
czy uzyskane z ich pomocą przekształcenia pozwalają otrzymać szyfrogram, dla
którego trudno będzie znaleźć zaszyfrowany tekst jawny.

W tej implementacji ograniczam się do uproszczonego generowania wartości
s-boxów, korzystając z liczb pseudolosowych wygenerowanych z rozkładu jednostajnego.
Każdy wiersz s-boxa zawiera liczby z zakresu od 0 do 15 włącznie, wymieszane,
przy pomocy funkcji shuffle z biblioteki random.
"""
def generate_sboxes(count, seed=0):
    random.seed(seed)
    result = []

    for _ in range(count):
        sbox = []
        for _ in range(4):
            row = list(range(16))
            random.shuffle(row)
            sbox.append(row)
        result.append(sbox)
        
    return result

def generate_permutation_table(size, seed=0):
    random.seed(seed)
    result = list(range(size))
    random.shuffle(result)
    return result

def generate_expansion_table(from_size=32, to_size=48, seed=0):
    random.seed(seed)
    result = []
    r = list(range(1, from_size + 1))
    
    for _ in range(int(to_size / from_size)):
        random.shuffle(r)
        result.extend(r)
    
    random.shuffle(r)
    result.extend(r[:to_size-from_size])

    return result

SEED = 42

PC1 = generate_permutation_table(56, SEED)
PC2 = generate_permutation_table(56, SEED)
ROUND_SHIFTS = [2, 1, 1, 3, 1, 3, 2, 1, 2, 2, 1, 1, 1, 3, 1, 3]
EXPANSION_TABLE = generate_expansion_table(32, 48, SEED)
SBOX = generate_sboxes(8, SEED)
PERMUTATION_TABLE = generate_permutation_table(32, SEED)
INITIAL_PERMUTATION_TABLE = generate_permutation_table(64, SEED)
INVERSE_PERMUTATION_TABLE = generate_permutation_table(64, SEED)

def apply_PC1(pc1_table, keys_64bits):
    keys_56bits = ""
    for index in pc1_table:
        keys_56bits += keys_64bits[index - 1] 
    return keys_56bits

def split56bits_in_half(keys_56bits):
    left_keys, right_keys = keys_56bits[:28], keys_56bits[28:]
    return left_keys, right_keys

def circular_left_shift(bits, number_of_bits):
    shifted_bits = bits[number_of_bits:] + bits[:number_of_bits]
    return shifted_bits

def circular_right_shift(bits, number_of_bits):
    shifted_bits = bits[-number_of_bits:] + bits[:-number_of_bits]
    return shifted_bits

def apply_PC2(pc2_table, keys_56bits):
    keys_48bits = ""
    for index in pc2_table:
        keys_48bits += keys_56bits[index - 1]
    return keys_48bits

def generate_keys(key_64bits):
    round_keys = list()
    
    key_56bits = apply_PC1(PC1, key_64bits)
    left56, right56 = split56bits_in_half(key_56bits)

    for shift in ROUND_SHIFTS:
        left56 = circular_left_shift(left56, shift)
        right56 = circular_right_shift(right56, shift)
        round_keys.append(apply_PC2(PC2, left56 + right56))
    
    return round_keys

def apply_expansion(expansion_table, bits32):
    bits48 = ""
    for index in expansion_table:
        bits48 += bits32[index - 1]
    return bits48

def XOR(bits1,bits2):
    xor_result = ""
    for index in range(len(bits1)):
        if bits1[index] == bits2[index]: 
            xor_result += '0'
        else:
            xor_result += '1'
    return xor_result

def split48bits_in_6bits(XOR_48bits):
    list_of_6bits = textwrap.wrap(XOR_48bits, 6)
    return list_of_6bits

def get_first_and_last_bit(bits6):
    two_bits = bits6[0] + bits6[-1] 
    return two_bits

def get_middle_four_bits(bits6):
    four_bits = bits6[1:5] 
    return four_bits

def apply_permutation(permutation_table, text):
    permuted32bits = ""
    for index in permutation_table:
        permuted32bits += text[index-1]
    return permuted32bits

def binary_to_decimal(binary_bits):
    decimal = int(binary_bits, 2)
    return decimal

def decimal_to_binary(decimal):
    binary4bits = bin(decimal)[2:].zfill(4)
    return binary4bits

def sbox_lookup(sbox_count, first_last, middle4):
    d_first_last = binary_to_decimal(first_last)
    d_middle = binary_to_decimal(middle4)
    sbox_value = SBOX[sbox_count][d_first_last][d_middle]
    return decimal_to_binary(sbox_value)

def functionF(pre32bits, key48bits):
    pre_bits_expanded = apply_expansion(EXPANSION_TABLE, pre32bits)
    xor_bits = XOR(pre_bits_expanded, key48bits)
    blocks6bits = split48bits_in_6bits(xor_bits)
    sbox_blocks = [
        sbox_lookup(i, get_first_and_last_bit(bits6), get_middle_four_bits(bits6))
        for i, bits6 in enumerate(blocks6bits)
    ]
    sboxes_output = ''.join(sbox_blocks)
    return apply_permutation(PERMUTATION_TABLE, sboxes_output)

def split64bits_in_half(binary_bits):
    return binary_bits[:32], binary_bits[32:]

def apply_feistel(bits, key_48bits):
    left32, right32 = bits[:32], bits[32:]
    return XOR(right32, functionF(left32, key_48bits)) + left32

def swapRL(bits64):
    return bits64[32:] + bits64[:32]

def create_blocks(message):
    message_bits = int_list_to_bin_str(into_int_array(message))
    blocks = [message_bits[i:i+64] for i in range(0, len(message_bits), 64)]
    blocks[-1] = blocks[-1].rjust(64, '0')
    return blocks

def bin_string_to_text(bin_string):
    return ''.join(chr(int(bin_string[i:i+8], 2)) for i in range(0, len(bin_string), 8))

def DES(message, keys):
    message_blocks = create_blocks(message)
    cipher_blocks = [
        swapRL(reduce(lambda result, round_key: apply_feistel(result, round_key), keys, block)) 
        for block in message_blocks
    ]
    cipher_blocks[-1] = cipher_blocks[-1][:len(message_blocks[-1])]
    return bin_string_to_text(''.join(cipher_blocks))

def int_list_to_bin_str(message_list):
    binary = []
    for x in message_list: 
        binary.append(get_bin(x, 8))
    binary_str = ""
    for x in binary:
        binary_str += x 
    return binary_str

get_bin = lambda x, n: format(x, 'b').zfill(n)

def into_int_array(message: str):
    int_array = []
    msg_array = list(message) 
    for i in msg_array:
        int_array.append(ord(i))
    return int_array

def create_64_bits_key(key):
    # Skracamy klucz do 8 bajtów (64 bitów), jeżeli jest dłuższy
    key_8bytes = (key * math.ceil(8 / len(key)))[:8]
    return int_list_to_bin_str(into_int_array(key_8bytes))[:64]

def DES_encrypt(message, key):
    return DES(message, generate_keys(create_64_bits_key(key)))
    

def DES_decrypt(message, key):
    return DES(message, generate_keys(create_64_bits_key(key))[::-1])

if __name__ == '__main__':
    message = "Message!" # Blok ma rozmiar 64 bitów
    key = "mojklucz" # Klucz ma rozmiar 64 bitów

    encrypted_text = DES_encrypt(message, key)
    decrypted_text = DES_decrypt(encrypted_text, key)

    print("Encrypted text: ", encrypted_text)
    print("Decrypted text: ", decrypted_text)
