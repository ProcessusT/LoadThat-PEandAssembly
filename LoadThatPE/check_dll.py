import pefile
import os
import sys

# =============================================================================
# check_dll.py
#
# Objectif : trouver dans System32 une DLL dont la section .text est assez
# grande pour y ecrire ("stomper") notre PE chiffre directement en memoire.
#
# Principe du section stomping :
#   - On charge une DLL legitime avec LoadLibraryA()
#   - On localise sa section .text (deja mappee en memoire par Windows)
#   - On y ecrit notre blob chiffre (VirtualProtect RW -> ecriture -> RX)
#   - La region memoire apparait "backed" par la DLL sur disque -> moins suspect
#     qu'une region anonyme allouee avec VirtualAlloc
#
# Ce script calcule la taille du PE cible et compare avec toutes les DLL
# de System32 pour identifier celles dont la section .text est suffisamment
# grande pour accueillir notre payload.
# =============================================================================

print("=" * 75)
print("  check_dll.py - Recherche de DLL candidate pour section stomping")
print("=" * 75)
print()

if len(sys.argv) < 2:
    print("Usage: check_dll.py <payload.exe>")
    print()
    print("  <payload.exe> : le PE a charger via section stomping")
    print("  Le script calculera sa taille et cherchera une DLL adequare")
    print("  dans C:\\Windows\\System32")
    sys.exit(1)

payload_path = sys.argv[1]
print(f"[*] Analyse du payload : {payload_path}")

if not os.path.exists(payload_path):
    print(f"[-] Fichier introuvable : {payload_path}")
    sys.exit(1)

pe_payload = pefile.PE(payload_path)
payload_size = max(
    s.VirtualAddress + s.Misc_VirtualSize
    for s in pe_payload.sections
)
pe_payload.close()

print(f"[+] Taille necessaire (image virtuelle) : {payload_size} bytes ({payload_size // 1024} Ko)")
print(f"[*] On cherche des DLL dont la section .text >= {payload_size} bytes")
print()

system32 = r"C:\Windows\System32"
print(f"[*] Scan de : {system32}")

all_dlls   = [f for f in os.listdir(system32) if f.lower().endswith(".dll")]
print(f"[*] {len(all_dlls)} DLL trouvees, analyse en cours...\n")

results  = []
errors   = 0
no_text  = 0
too_small = 0
adequate = 0

for i, fname in enumerate(all_dlls, 1):
    fpath = os.path.join(system32, fname)
    try:
        pe = pefile.PE(fpath, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']
        ])
        found_text = False
        for section in pe.sections:
            name = section.Name.rstrip(b'\x00').decode(errors='replace')
            if name == ".text":
                found_text = True
                size = section.Misc_VirtualSize
                ok   = size >= payload_size
                results.append((fname, size, ok))
                if ok:
                    adequate += 1
                else:
                    too_small += 1
                break
        if not found_text:
            no_text += 1
        pe.close()
    except Exception:
        errors += 1
        continue

    # Progress tous les 50
    if i % 50 == 0:
        print(f"    ... {i}/{len(all_dlls)} DLL analysees ({adequate} candidates jusqu ici)")

print()
print(f"[+] Analyse terminee.")
print(f"    DLL analysees       : {len(all_dlls)}")
print(f"    Avec section .text  : {len(results)}")
print(f"    Sans section .text  : {no_text}")
print(f"    Erreurs de parsing  : {errors}")
print(f"    Trop petites        : {too_small}")
print(f"    ADEQUATES (<---)    : {adequate}")
print()

# Trier par taille decroissante
results.sort(key=lambda x: x[1], reverse=True)

print(f"{'DLL':<40} {'Taille .text':>15}    {'Adequate':>10}")
print("-" * 75)
for fname, size, ok in results:
    flag = "OUI <---" if ok else "non"
    print(f"{fname:<40} {size:>15} bytes    {flag:>10}")

print()
print(f"[*] {adequate} DLL adequates pour un payload de {payload_size} bytes ({payload_size // 1024} Ko)")
if adequate > 0:
    best = [r for r in results if r[2]]
    print(f"[+] Meilleure candidate : {best[0][0]} ({best[0][1]} bytes dans .text)")
    print(f"    -> Mettre cette valeur dans le loader : target_dll = \"{best[0][0]}\"")
else:
    print("[-] Aucune DLL adequate trouvee. Le payload est peut-etre trop grand.")
