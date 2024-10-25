import os
import re

def print_green(text):
    print(f'\033[92m{text}\033[0m')

def find_latest_file(pattern, directory):
    max_num = -1
    latest_file = None
    for filename in os.listdir(directory):
        match = re.match(pattern, filename)
        if match:
            num = int(match.group(1))
            if num > max_num:
                max_num = num
                latest_file = os.path.join(directory, filename)
    return latest_file

def extract_key(file_path, key_type):
    with open(file_path, 'r') as file:
        content = file.read()
    if key_type == 'ECC':
        return re.findall(r"(\w{64})", content)
    elif key_type == 'AES':
        return re.search(r"(\w{64})", content).group(1)

def write_key_to_file(key, filename):
    os.makedirs('Temp Keys', exist_ok=True)
    path = os.path.join('Temp Keys', filename)
    with open(path, 'w') as file:
        file.write(key)
    print_green(f'Success writing {filename}')

def main():
    ecc_pattern = r"ECC_key_pair_(\d+).txt"
    aes_pattern = r"AES_key_(\d+).txt"
    ecc_dir = 'ECC Keys'
    aes_dir = 'AES Keys'

    latest_ecc_file = find_latest_file(ecc_pattern, ecc_dir)
    latest_aes_file = find_latest_file(aes_pattern, aes_dir)
    
    if not latest_ecc_file or not latest_aes_file:
        print("Files not found in the directories.")
        return
    
    print(f'Extracting {os.path.basename(latest_ecc_file)}')
    print(f'Extracting {os.path.basename(latest_aes_file)}')
    
    ecc_keys = extract_key(latest_ecc_file, 'ECC')
    write_key_to_file(ecc_keys[0], 'ECC-key-1.txt')
    write_key_to_file(ecc_keys[1], 'ECC-key-2.txt')
    
    aes_key = extract_key(latest_aes_file, 'AES')
    write_key_to_file(aes_key, 'AES-key.txt')

if __name__ == "__main__":
    main()
