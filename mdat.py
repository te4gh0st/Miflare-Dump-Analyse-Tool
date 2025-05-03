#!/usr/bin/env python3
"""
Miflare Dump Analyse Tool (1K/4K)

A command-line utility for analyzing and manipulating MIFARE Classic dumps.

Main Features:
- Load and display .bin dumps of 1K (16 sectors) or 4K (64 sectors) MIFARE Classic cards
- Optional bit-level view with --bits (-b)
- Visual highlight of UID, BCC, ATQA, and SAK in sector 0, block 0
- Visual parsing of trailer blocks: Key A, Access Bits, User Data, and Key B
- Detect MIFARE tag type and manufacturer
- Calculate and verify BCC for custom UIDs (--calc-bcc)
- Decode access bits (--calc-access) or generate them interactively (--gen-access)
- Compare two dumps with optional diff-only mode (--compare, --diff-only)
- Multilingual support: English (default) and Russian (--lang ru)

Example Usage:
  ./mdat.py dump.bin --bits
  ./mdat.py --calc-bcc B7 52 3D 22
  ./mdat.py --calc-access FF 07 08
  ./mdat.py --gen-access
  ./mdat.py --compare dump1.bin dump2.bin --diff-only

--
Copyright (c) 2025 te4gh0st
"""
import argparse
import sys

# ANSI escape codes for colors
RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"
GRAY = "\033[90m"

LANG_TEXT = {
    'en': {
        'sector': 'Sector', 'block': 'Block', 'uid': 'UID', 'bcc': 'BCC',
        'atqa': 'ATQA', 'sak': 'SAK', 'type': 'Tag type', 'mf': 'Manufacturer',
        'access': 'Access', 'calc_bcc': 'Calculated BCC',
        'access_calc': 'Access bits calculation',
        'access_block': 'Access Block',
        'read_write': 'Key A/B read & write (insecure)',
        'read_only': 'Key A read only',
        'read_allow_write_never': 'Read with Key A, writing not allowed',
        'read_write_key_b': 'Read/Write with Key B',
        'read_key_b_write_never': 'Read with Key B, writing not allowed',
        'no_access': 'No access',
        'custom': 'Custom', 'trailer': 'Trailer',
        'compare': 'Comparing dumps',
        'diff_only': 'Differences only',
        'trailer_details': {
            (0, 0, 0): 'Key A/B can be read/written, access bits are changeable (insecure)',
            (0, 1, 0): 'Key B can be read/written with Key A, access bits are changeable',
            (1, 0, 0): 'Key B can be read with Key A, access bits are changeable',
            (1, 1, 0): 'Key B can be read with Key A, access bits are changeable (requires Key B)',
            (1, 0, 1): 'Access bits readable with Key A/B, write only with Key B. Keys cannot be read.',
            (0, 0, 1): 'Transport configuration: access only via Key A, keys are not readable. (insecure)',
            (0, 1, 1): 'Read/write via Key B, partially via Key A.',
            (1, 1, 1): 'Access blocked. Authentication only.',
        },
        'gen_access': '=== Access Bytes Generator ===\nSelect access bits for each block:',
        'input_prompt': 'Choose option [1-8] for block {i}: ',
        'user_data_prompt': 'UserData byte (hex, e.g. 69) [00]: ',
        'invalid_choice': 'Invalid choice. Please enter a number from 1 to 8.',
        'invalid_hex': 'Invalid hex input. Defaulting to 00.',
        'result': 'Result:',
        'no_description': 'No description available.',
        'access_bytes': 'Access Bytes',
        "valid_access_bytes": 'Access bytes are valid',
        'invalid_access_bytes': 'Access bytes are INVALID!',
        'byte': 'Byte',
        'differences': 'Total differences'
    },
    'ru': {
        'sector': 'Сектор', 'block': 'Блок', 'uid': 'UID', 'bcc': 'BCC',
        'atqa': 'ATQA', 'sak': 'SAK', 'type': 'Тип метки', 'mf': 'Производитель',
        'access': 'Права', 'calc_bcc': 'Вычисленный BCC',
        'access_calc': 'Калькулятор бит доступа',
        'access_block': 'Блок доступа',
        'custom': 'Пользовательские', 'trailer': 'Трейлер',
        'read_write': 'Чтение/запись с ключом A/B (небезопасно)',
        'read_only': 'Только чтение с ключом A',
        'read_allow_write_never': 'Чтение с ключом A, запись невозможна',
        'read_write_key_b': 'Чтение/запись с ключом B',
        'read_key_b_write_never': 'Чтение с ключом B, запись невозможна',
        'no_access': 'Нет доступа',
        'compare': 'Сравнение дампов',
        'diff_only': 'Только различия',
         'trailer_details': {
             (0, 0, 0): 'Ключи A/B доступны для чтения/записи, биты доступа изменяемы (небезопасно)',
             (0, 1, 0): 'Ключ B доступен для чтения/записи с Key A, биты доступа изменяемы',
             (1, 0, 0): 'Ключ B доступен для чтения с Key A, биты доступа изменяемы',
             (1, 1, 0): 'Ключ B доступен для чтения с Key A, биты доступа изменяемы (требуется Key B)',
             (1, 0, 1): 'Для чтения битов доступа нужен Key A/B, запись только с Key B. Ключи недоступны для чтения.',
             (0, 0, 1): 'Транспортная конфигурация: доступ только через Key A, ключи не читаются. (небезопасно)',
             (0, 1, 1): 'Чтение и запись через Key B, частично через Key A.',
             (1, 1, 1): 'Доступ заблокирован. Только аутентификация.',
        },
        'gen_access': '=== Генератор байтов доступа ===\nВыберите биты доступа для каждого блока:',
        'input_prompt': 'Выберите вариант [1-8] для блока {i}: ',
        'user_data_prompt': 'Байт UserData (в hex, напр. 69) [00]: ',
        'invalid_choice': 'Неверный выбор. Введите число от 1 до 8.',
        'invalid_hex': 'Неверный формат hex. Используется значение по умолчанию: 00.',
        'result': 'Результат:',
        'no_description': 'Описание недоступно.',
        'access_bytes': 'Байты доступа',
        "valid_access_bytes": 'Байты доступа корректны!',
        'invalid_access_bytes': 'Байты доступа некорректны!',
        'byte': 'Байт',
        'differences': 'Всего отличий'

    }
}

access_map = {
    (0, 0, 0): ('read_write', None),
    (1, 0, 0): ('read_only', None),
    (0, 1, 0): ('read_allow_write_never', None),
    (0, 0, 1): ('read_write_key_b', None),
    (0, 1, 1): ('read_write_key_b', None),
    (1, 0, 1): ('read_key_b_write_never', None),
    (1, 1, 0): ('read_write_key_b', None),
    (1, 1, 1): ('no_access', None),
}

TAG_TYPES = {
    (0x0004, 0x08): ('MIFARE Classic 1K', 'NXP'),
    (0x0002, 0x18): ('MIFARE Classic 4K', 'NXP'),
    (0x0344, 0x38): ('MIFARE Ultralight', 'NXP'),
    (0x0044, 0x20): ('MIFARE DESFire EV1/EV2', 'NXP'),
    (0x0400, 0x88): ('Cascade Tag (7-byte UID)', 'NXP'),
    (0x4400, 0x98): ('MIFARE Classic 4K with 7-byte UID', 'NXP'),
}

def color_bits(val, mask=None, color=YELLOW):
    bits = ''.join(str((val >> i) & 1) for i in reversed(range(8)))
    if mask is None:
        return bits
    mask_bits = ''.join(str((mask >> i) & 1) for i in reversed(range(8)))
    out = []
    for b, m in zip(bits, mask_bits):
        out.append((color + b + RESET) if m == '1' else b)
    return ''.join(out)


def calc_bcc(uid_bytes):
    b = 0
    for x in uid_bytes:
        b ^= x
    return b


def parse_access(byte6, byte7, byte8):
    """
    Парсит access bits из трёх байт (byte6, byte7, byte8),
    проверяет корректность по контрольным битам,
    и возвращает матрицу [блок][C1, C2, C3] и флаг валидности.
    """

    def get_bit(value, bit):
        return (value >> bit) & 1

    # C1: из byte7, биты 4–7
    c1 = [get_bit(byte7, 4 + i) for i in range(4)]

    # C1': из byte6, биты 0–3
    c1_inv = [get_bit(byte6, i) for i in range(4)]

    # C2: из byte8, биты 0–3
    c2 = [get_bit(byte8, i) for i in range(4)]

    # C2': из byte6, биты 4–7
    c2_inv = [get_bit(byte6, 4 + i) for i in range(4)]

    # C3: из byte8, биты 4–7
    c3 = [get_bit(byte8, 4 + i) for i in range(4)]

    # C3': из byte7, биты 0–3
    c3_inv = [get_bit(byte7, i) for i in range(4)]

    # Проверка валидности контрольных битов
    valid = all(
        (c1[i] ^ c1_inv[i]) == 1 and
        (c2[i] ^ c2_inv[i]) == 1 and
        (c3[i] ^ c3_inv[i]) == 1
        for i in range(4)
    )

    # Формируем матрицу [блок][C1, C2, C3]
    matrix = [
        [c1[0], c2[0], c3[0]],
        [c1[1], c2[1], c3[1]],
        [c1[2], c2[2], c3[2]],
        [c1[3], c2[3], c3[3]],
    ]

    return matrix, valid


def describe_access(bits_matrix, valid, lang):
    t = LANG_TEXT[lang]
    desc = {}

    for i, (c1, c2, c3) in enumerate(bits_matrix):
        if i < 3:
            entry = access_map.get((c1, c2, c3))
            d = t[entry[0]] if entry else f"{t['custom']} ({c1},{c2},{c3})"
        else:
            d = t['trailer_details'].get((c1, c2, c3), t['trailer'])
        desc[i] = d

    return {
        "valid": valid,
        "description": desc
    }



def hexdump(b): return ' '.join(f"{x:02X}" for x in b)


def show_sector(sec, idx, args, txt):
    print(CYAN + f"{txt['sector']} {idx}" + RESET)
    for i, blk in enumerate(sec):
        header = f" {txt['block']} {i}: {hexdump(blk)}"
        print(header)
        if args.bits:
            bits_str = ' '.join(color_bits(x, mask=0xFF) for x in blk)
            print(f"  Bits : {bits_str}")
        # UID block
        if idx == 0 and i == 0:
            uid = blk[:4]
            bcc_byte = blk[4]
            sak = blk[5]
            atqa = (blk[7] << 8) | blk[6]
            calc = calc_bcc(uid)
            ok = calc == bcc_byte
            print(f"  {txt['uid']}: " + ' '.join(MAGENTA + f"{x:02X}" + RESET for x in uid))
            print(f"  {txt['bcc']}: {YELLOW}{bcc_byte:02X}{RESET} ({txt['calc_bcc']}: {calc:02X}) → " +
                  (GREEN + "OK" + RESET if ok else RED + "FAIL" + RESET))
            print(f"  {txt['atqa']}: {atqa:04X}, {txt['sak']}: {sak:02X}")
        # Trailer block with Key A, Access Bits, User Data, Key B
        if i == 3:
            key_a = blk[0:6]
            ab6, ab7, ab8 = blk[6], blk[7], blk[8]
            user_data = blk[9]
            key_b = blk[10:16]
            # Colored segments
            ka_str = ' '.join(MAGENTA + f"{x:02X}" + RESET for x in key_a)
            ab_str = ' '.join(YELLOW + f"{x:02X}" + RESET for x in (ab6, ab7, ab8))
            ud_str = CYAN + f"{user_data:02X}" + RESET
            kb_str = ' '.join(GREEN + f"{x:02X}" + RESET for x in key_b)
            print(f"  Key A       : {ka_str}")
            print(f"  Access bits : {ab_str}  UserData: {ud_str}")
            print(f"  Key B       : {kb_str}")
            # decode access
            bits, valid = parse_access(ab6, ab7, ab8)
            result = describe_access(bits, valid, args.lang)
            desc = result["description"]
            t = LANG_TEXT[args.lang]

            for block in sorted(desc):
                print(f"   {t['access_block']} {block}: {MAGENTA}{desc[block]}{RESET}")

            # Добавим вывод информации о корректности access bits
            if valid:
                print(
                    f"    {GREEN}{txt['valid_access_bytes'] if 'valid_access_bytes' in txt else 'Access bytes are valid.'}{RESET}")
            else:
                print(
                    f"    {RED}{txt['invalid_access_bytes'] if 'invalid_access_bytes' in txt else 'Access bytes are INVALID!'}{RESET}")


def load(path):
    d = open(path, 'rb').read()
    if len(d) not in (1024, 4096):
        sys.exit("Bad dump size")
    bl = [d[i:i+16] for i in range(0, len(d), 16)]
    return [bl[i*4:(i+1)*4] for i in range(len(bl)//4)]

def generate_access_bytes(specs):
    """
    Генерирует три байта доступа (byte6, byte7, byte8) по заданным C1,C2,C3 для 4 блоков.
    specs — dict: ключ = номер блока 0–3, значение = кортеж (C1, C2, C3).
    Возвращает кортеж (byte6, byte7, byte8).
    """
    byte6 = 0
    byte7 = 0
    byte8 = 0

    for i in range(4):
        c1, c2, c3 = specs[i]

        # Инвертированные контрольные биты
        c1_inv = 1 - c1
        c2_inv = 1 - c2
        c3_inv = 1 - c3

        # byte6:
        #   биты 0–3 = C1' (c1_inv)
        #   биты 4–7 = C2' (c2_inv)
        byte6 |= (c1_inv << i)
        byte6 |= (c2_inv << (4 + i))

        # byte7:
        #   биты 0–3 = C3' (c3_inv)
        #   биты 4–7 = C1  (c1)
        byte7 |= (c3_inv << i)
        byte7 |= (c1     << (4 + i))

        # byte8:
        #   биты 0–3 = C2  (c2)
        #   биты 4–7 = C3  (c3)
        byte8 |= (c2 << i)
        byte8 |= (c3 << (4 + i))

    return byte6, byte7, byte8

def generate_access_interactive(lang):
    t = LANG_TEXT[lang]
    print(f"{CYAN}{t['gen_access']}{RESET}")
    specs = {}

    options = list(access_map.items())
    print(options)
    print()
    trailer_options = list(t['trailer_details'].items())
    print(trailer_options)

    # Сбор желаемых C1,C2,C3 для каждого блока
    for i in range(4):
        print(f"\n{YELLOW}Block {i}:{RESET}")
        if i != 3:
            for idx, (bits, (key, _)) in enumerate(options, 1):
                print(f"  {idx}. C1,C2,C3 = {bits} — {t.get(key, key)}")

            while True:
                choice = input(t['input_prompt'].format(i=i, max=len(options)))
                if choice.isdigit() and 1 <= int(choice) <= len(options):
                    bits = options[int(choice)-1][0]
                    specs[i] = bits
                    if lang == 'ru':
                        print(f"{MAGENTA}Выбрано: C1={bits[0]}, C2={bits[1]}, C3={bits[2]}{RESET}")
                    else:
                        print(f"{MAGENTA}Choice: C1={bits[0]}, C2={bits[1]}, C3={bits[2]}{RESET}")
                    break
                else:
                    print(f"{RED}{t['invalid_choice']}{RESET}")
        else:
            for idx, (bits, key) in enumerate(trailer_options, 1):
                print(f"  {idx}. C1,C2,C3 = {bits} — {t.get(key, key)}")

            while True:
                choice = input(t['input_prompt'].format(i=i, max=len(options)))
                if choice.isdigit() and 1 <= int(choice) <= len(options):
                    bits = options[int(choice) - 1][0]
                    specs[i] = bits
                    if lang == 'ru':
                        print(f"{MAGENTA}Выбрано: C1={bits[0]}, C2={bits[1]}, C3={bits[2]}{RESET}")
                    else:
                        print(f"{MAGENTA}Choice: C1={bits[0]}, C2={bits[1]}, C3={bits[2]}{RESET}")
                    break
                else:
                    print(f"{RED}{t['invalid_choice']}{RESET}")

    # UserData input
    ud_in = input(f"{CYAN}{t['user_data_prompt']}{RESET}") or "00"
    try:
        ud = int(ud_in, 16)
    except ValueError:
        print(f"{RED}{t['invalid_hex']}{RESET}")
        ud = 0x00

    # Генерация байт
    byte6, byte7, byte8 = generate_access_bytes(specs)
    if lang == 'ru':
        print(f"\n{GREEN}Сгенерированные байты доступа:{RESET}")
    else:
        print(f"\n{GREEN}Generated access bytes:{RESET}")

    # Дополнительно можно проверить через парсер
    matrix, valid = parse_access(byte6, byte7, byte8)
    for i, (c1, c2, c3) in enumerate(matrix):
        print(f" Block {i}: C1={c1}, C2={c2}, C3={c3}")

    print(f"\n{GREEN}{t['result']}{RESET}")
    print(f"Access bytes: {YELLOW}{byte6:02X} {byte7:02X} {byte8:02X}{RESET}  UserData: {CYAN}{ud:02X}{RESET}")
    sys.exit(0)


def highlight_diff_bytes(b1: bytes, b2: bytes) -> tuple[str, str]:
    """Подсвечивает отличающиеся байты красным, совпадающие серым"""
    h1 = []
    h2 = []
    for byte1, byte2 in zip(b1, b2):
        hex1 = f"{byte1:02X}"
        hex2 = f"{byte2:02X}"
        if byte1 != byte2:
            h1.append(f"{RED}{hex1}{RESET}")
            h2.append(f"{RED}{hex2}{RESET}")
        else:
            h1.append(f"{GRAY}{hex1}{RESET}")
            h2.append(f"{GRAY}{hex2}{RESET}")
    return ' '.join(h1), ' '.join(h2)



def compare_dumps(path1, path2, args, txt):
    d1 = load(path1)
    d2 = load(path2)
    print(f"{CYAN}{txt['compare']}{RESET}")
    diffs = 0
    for si, (s1, s2) in enumerate(zip(d1, d2)):
        for bi, (b1, b2) in enumerate(zip(s1, s2)):
            if args.diff_only:
                if b1 != b2:
                    diffs += 1
                    print(f"{YELLOW}{txt['sector']} {si} {txt['block']} {bi}:{RESET}")
                    h1, h2 = highlight_diff_bytes(b1, b2)
                    print(f"  A: {h1}")
                    print(f"  B: {h2}")
            else:
                marker = GREEN + '==' + RESET if b1 == b2 else RED + '!=' + RESET
                h1, h2 = highlight_diff_bytes(b1, b2)
                print(f"{txt['sector']} {si:<2} {txt['block']} {bi}: {h1} {marker} {h2}")
                if b1 != b2:
                    diffs += 1
    print(f"\n{MAGENTA}{txt['differences']}: {diffs}{RESET}")
    sys.exit(0)


def main():
    p = argparse.ArgumentParser(
        description='Miflare Dump Analyse Tool\nCopyright (c) 2025 te4gh0st',
        formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument('dump', nargs='?', help='.bin dump file')
    p.add_argument('--bits', '-b', action='store_true', help='Show bits view (Показать биты)')
    p.add_argument('--lang', choices=['en', 'ru'], default='en', help='Language / Язык')
    p.add_argument('--calc-bcc', nargs='+', metavar='BYTE',
                   help='Calculate BCC for UID bytes (Вычислить BCC для байт UID)')
    p.add_argument('--calc-access', nargs=3, metavar='HEX',
                   help='Decode access bytes FF 07 08 (Декодировать байты доступа FF 07 08)')
    p.add_argument('--gen-access', action='store_true', help='Generate access bytes interactively (Интерактивная генерация бит доступа)')
    p.add_argument('--compare', nargs=2, metavar=('DUMP1','DUMP2'),
                   help='Compare two dumps (Сравнить два дампа)')
    p.add_argument('--diff-only', action='store_true', help='Show only differences when comparing (Только различия)')
    args = p.parse_args()
    txt = LANG_TEXT[args.lang]

    if args.calc_bcc:
        uid = [int(x, 16) for x in args.calc_bcc]
        print(f"{txt['uid']}: {' '.join(f"{x:02X}" for x in uid)} → {txt['bcc']}: {calc_bcc(uid):02X}")
        sys.exit(0)

    if args.calc_access:
        ab6, ab7, ab8 = [int(x, 16) for x in args.calc_access]
        bits, valid = parse_access(ab6, ab7, ab8)
        result = describe_access(bits, valid, args.lang)
        desc = result["description"]
        t = LANG_TEXT[args.lang]

        print(f"{CYAN}{t['access_calc']}{RESET}")
        print(f"{YELLOW}{'Access Matrix:':<20}{RESET}")
        for block, (c1, c2, c3) in enumerate(bits):
            print(f"  Block {block:<2}:  C1={c1}  C2={c2}  C3={c3}")

        print(f"\n{YELLOW}{'Descriptions:' if args.lang == 'en' else 'Пояснения:'}{RESET}")
        for block in sorted(desc):
            print(f"  {t['access_block']} {block}: {MAGENTA}{desc[block]}{RESET}")

        print(f"\n{GREEN}{t['access_bytes']}:{RESET}  [{t['byte']} 6] = {RED}{ab6:02X}{RESET} "
              f"[{t['byte']} 7] = {RED}{ab7:02X}{RESET}   [{t['byte']} 8] = {RED}{ab8:02X}{RESET}")

        # Вывод флага корректности
        if valid:
            print(f"\n{GREEN}{t['valid_access_bytes']}{RESET}")
        else:
            print(f"\n{RED}{t['invalid_access_bytes']}{RESET}")

        sys.exit(0)

    if args.gen_access:
        generate_access_interactive(args.lang)

    if args.compare:
        compare_dumps(args.compare[0], args.compare[1], args, txt)

    if not args.dump:
        p.print_help()
        sys.exit(1)

    secs = load(args.dump)

    # Display tag type and manufacturer
    if secs and secs[0] and secs[0][0]:
        block0 = secs[0][0]
        sak = block0[5]
        atqa = (block0[7] << 8) | block0[6]
        tag_type, manufacturer = TAG_TYPES.get((atqa, sak), ('Unknown', 'Unknown'))
        print(f"{txt['type']}: {MAGENTA}{tag_type}{RESET}\n{txt['mf']}: {MAGENTA}{manufacturer}{RESET}\n")

    for i, sec in enumerate(secs):
        show_sector(sec, i, args, txt)

if __name__ == '__main__':
    main()
