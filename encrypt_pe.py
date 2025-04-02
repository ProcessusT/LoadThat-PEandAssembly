import sys
import os

def generate_encrypted_pe(input_file, output_file=None, xor_key=0xBA):
    try:
        with open(input_file, 'rb') as f:
            pe_data = f.read()

        encrypted_pe = bytearray()
        for byte in pe_data:
            encrypted_pe.append(byte ^ xor_key)

        encrypted_pe_str = "unsigned char encryptedPE[] = {\n"
        line_length = 16
        for i in range(0, len(encrypted_pe), line_length):
            line = ', '.join(f"0x{byte:02X}" for byte in encrypted_pe[i:i+line_length])
            encrypted_pe_str += "    " + line + ",\n"
        encrypted_pe_str += "};\n"
        encrypted_pe_str += f"size_t encryptedPESize = {len(encrypted_pe)};\n"
        encrypted_pe_str += f"const unsigned char xorKey = 0x{xor_key:02X};\n"

        if output_file:
            with open(output_file, 'w') as out_file:
                out_file.write(encrypted_pe_str)
            print(f"[+] Encrypted PE généré et sauvegardé dans : {output_file}")
        else:
            print(encrypted_pe_str)
    except FileNotFoundError:
        print(f"[-] Fichier introuvable : {input_file}")
    except Exception as e:
        print(f"[-] Une erreur est survenue : {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage : python encrypt_pe.py <fichier_PE> [output_file]")
        sys.exit(1)
    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None
    if not os.path.exists(input_path):
        print(f"[-] Le fichier spécifié n'existe pas : {input_path}")
        sys.exit(1)
    generate_encrypted_pe(input_path, output_path)