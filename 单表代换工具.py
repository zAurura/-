import sys
import random
import re
from collections import Counter

class MonoalphabeticCipher:
    def __init__(self):
        self.alphabet = 'abcdefghijklmnopqrstuvwxyz'
        self.suggested_freq_order = [
            'e', 't', 'a', 'o', 'i', 'n', 's', 'h', 'r', 'd', 'l', 'c',
            'u', 'm', 'w', 'f', 'g', 'y', 'p', 'b', 'v', 'k', 'j', 'x',
            'q', 'z'
        ]
        self.suggested_first_letter_order = [
            's', 'c', 'p', 'a', 'd', 'r', 'b', 't', 'm', 'f',
            'i', 'e', 'h', 'l', 'g', 'w', 'o', 'u', 'n', 'v',
            'j', 'k', 'q', 'y', 'z', 'x'
        ]
        self.common_words = {
            1: {'a', 'i'},
            2: {"am", "an", "as", "at", "be", "by", "do", "go", "he", "hi",
                "if", "in", "is", "it", "me", "my", "no", "of", "on", "or",
                "so", "to", "up", "us", "we"},
            3: {"the", "and", "for", "you", "are", "but", "not", "all", "any",
                "can", "her", "was", "one", "our", "out", "get", "has", "him",
                "his", "how", "man", "new", "now", "old", "see", "two", "way",
                "who", "did", "its", "let", "put", "say", "she", "too", "use"},
            4: {"that", "with", "this", "have", "from", "they", "were", "will",
                "your", "what", "when", "them", "like", "time", "more", "some",
                "over", "such", "here", "than", "then", "also", "into", "only"}
        }
        self.word_length_hints = {
            1: "可能为: a, i",
            2: "可能为: be, of, to, in, it, on, as, at, by, he, me, my, no, up, us",
            3: "可能为: THE, AND, FOR, YOU, ARE, BUT, NOT, ALL, ANY, CAN, HER, WAS, ONE, OUR, OUT, GET, HAS, HIS, HOW, NEW, NOW, SEE, TWO, WHO, SAY, SHE, TOO, USE",
            4: "可能为: THAT, WITH, THIS, HAVE, FROM, THEY, WERE, WILL, YOUR, WHAT, WHEN, THEM, LIKE, TIME, MORE, SOME, OVER, SUCH, HERE, THAN, THEN, ALSO, INTO, ONLY"
        }

    def encrypt(self, plaintext, key=None):
        if not key:
            key = self.generate_random_key()
        return self._substitute_text(plaintext, self.alphabet, key)

    def decrypt(self, ciphertext, key):
        return self._substitute_text(ciphertext, key, self.alphabet)

    def generate_random_key(self):
        chars = list(self.alphabet)
        random.shuffle(chars)
        self.cipher_alphabet = ''.join(chars)
        return self.cipher_alphabet

    def set_key_by_mapping(self, mapping_str):
        try:
            key = [''] * 26
            mappings = mapping_str.split(',')
            for m in mappings:
                k, v = m.split('->')
                orig_index = self.alphabet.index(k.strip().lower())
                key[orig_index] = v.strip().lower()
            if '' in key:
                raise ValueError("映射不完整")
            if len(set(key)) != 26:
                raise ValueError("存在重复映射")
            self.cipher_alphabet = ''.join(key)
            return True
        except Exception as e:
            print(f"无效映射: {e}")
            return False

    def frequency_suggest_key(self, ciphertext):
        filtered = [c.lower() for c in ciphertext if c.lower() in self.alphabet]
        freq = Counter(filtered)
        cipher_chars = sorted(freq.keys(), key=lambda x: (-freq[x], x))
        for c in self.alphabet:
            if c not in cipher_chars:
                cipher_chars.append(c)
        key = [''] * 26
        for plain_order, plain_char in enumerate(self.suggested_freq_order):
            if plain_order < len(cipher_chars):
                cipher_char = cipher_chars[plain_order]
                key[self.alphabet.index(plain_char)] = cipher_char
        remaining_plain = [c for c in self.alphabet if c not in key]
        remaining_cipher = [c for c in self.alphabet if c not in cipher_chars[:len(self.suggested_freq_order)]]
        for i, cipher_char in enumerate(remaining_cipher):
            if i < len(remaining_plain):
                key[self.alphabet.index(cipher_char)] = remaining_plain[i]
        return ''.join(key)

    def _substitute_text(self, text, source, target):
        result = []
        for c in text:
            if c.lower() in source:
                index = source.index(c.lower())
                new_char = target[index] if c.islower() else target[index].upper()
                result.append(new_char)
            else:
                result.append(c)
        return ''.join(result)

    def analyze_text(self, ciphertext):
        analysis = {}
        filtered = [c.lower() for c in ciphertext if c.lower() in self.alphabet]
        analysis['letter_freq'] = Counter(filtered)
        words = re.findall(r'\b[a-zA-Z]+\b', ciphertext)
        first_letters = [word[0].lower() for word in words if len(word) > 0]
        analysis['first_letter_freq'] = Counter(first_letters)
        analysis['short_words'] = {}
        for length in [1, 2, 3, 4]:
            words_of_length = [word.lower() for word in words if len(word) == length]
            analysis['short_words'][length] = Counter(words_of_length)
        analysis['total_letters'] = len(filtered)
        return analysis

class MonoalphabeticCipherSystem:
    def __init__(self):
        self.cipher = MonoalphabeticCipher()
        self.current_key = None

    def show_menu(self):
        print("\n" + "="*40)
        print("单表代换密码系统".center(35))
        print("="*40)
        print("1. 加密明文")
        print("2. 解密密文")
        print("3. 唯密文攻击分析")
        print("4. 退出系统")
        print("="*40)

    def run(self):
        while True:
            self.show_menu()
            choice = input("请选择操作：").strip()
            if choice == '1':
                self.encrypt_menu()
            elif choice == '2':
                self.decrypt_menu()
            elif choice == '3':
                self.ciphertext_only_attack_menu()
            elif choice == '4':
                sys.exit("退出系统")
            else:
                print("无效选项，请重新输入")

    def encrypt_menu(self):
        text = input("输入要加密的明文：")
        key = None
        if input("使用随机密钥？(y/n): ").lower() == 'n':
            key = input("输入26字母替换密钥（留空随机生成）：").lower()
            if len(key) != 26 or not key.isalpha():
                print("无效密钥，使用随机生成")
                key = self.cipher.generate_random_key()
        else:
            key = self.cipher.generate_random_key()
        encrypted = self.cipher.encrypt(text, key)
        print("\n加密结果：")
        print(encrypted)
        print(f"使用密钥: {key}")

    def decrypt_menu(self):
        text = input("输入要解密的密文：")
        key = input("输入26字母解密密钥：").lower()
        if len(key) != 26 or not key.isalpha():
            print("无效密钥！")
            return
        decrypted = self.cipher.decrypt(text, key)
        print("\n解密结果：")
        print(decrypted)

    def ciphertext_only_attack_menu(self):
        ciphertext = input("输入要分析的密文：")
        analysis = self.cipher.analyze_text(ciphertext)
        total_letters = analysis['total_letters']

        # 显示字母频率
        print("\n字母频率分析（降序排列）：")
        sorted_letters = sorted(analysis['letter_freq'].items(),
                               key=lambda x: (-x[1], x[0]))
        ENGLISH_FREQ = {
            'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97, 'n': 6.75,
            's': 6.33, 'h': 6.09, 'r': 5.99, 'd': 4.25, 'l': 4.03, 'c': 2.78,
            'u': 2.76, 'm': 2.41, 'w': 2.36, 'f': 2.23, 'g': 2.02, 'y': 1.97,
            'p': 1.93, 'b': 1.29, 'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15,
            'q': 0.10, 'z': 0.07
        }
        for i, (char, count) in enumerate(sorted_letters):
            percent = (count / total_letters) * 100 if total_letters else 0
            standard_prob = ENGLISH_FREQ.get(char, 0)
            print(f"{char.upper()}: {count}次, {percent:.2f}% (标准: {standard_prob:.2f}%)")

        # 显示首字母频率
        print("\n\n首字母频率分析（降序排列）：")
        if analysis['first_letter_freq']:
            total_first = sum(analysis['first_letter_freq'].values())
            sorted_first = sorted(analysis['first_letter_freq'].items(),
                                 key=lambda x: (-x[1], x[0]))
            for i, (char, count) in enumerate(sorted_first):
                percent = (count / total_first) * 100 if total_first else 0
                standard_char = self.cipher.suggested_first_letter_order[i] if i < len(self.cipher.suggested_first_letter_order) else '?'
                print(f"{char.upper()}: {count}次, {percent:.2f}% (标准首字母: {standard_char.upper()})")

        # 显示短单词提示
        print("\n常见短单词分析：")
        for length in [1, 2, 3, 4]:
            counter = analysis['short_words'].get(length, Counter())
            if not counter:
                continue
            print(f"\n{length}字母单词出现频率：{self.cipher.word_length_hints.get(length, '')}")
            for word, count in counter.most_common(5):
                common = ""
                if length in self.cipher.common_words:
                    common = "(可能是常见单词)" if word in self.cipher.common_words[length] else ""
                print(f"'{word}': {count}次 {common}")

        # 生成初始密钥建议
        proposed_key = self.cipher.frequency_suggest_key(ciphertext)
        print("\n\n基于频率分析的初始密钥建议：")
        print(f"密钥: {proposed_key}")

        # 高频双字母分析
        print("\n高频双字母组合（可能对应th/he/in等）：")
        if len(ciphertext) >= 2:
            digraphs = Counter()
            filtered = [c.lower() for c in ciphertext if c.lower() in self.cipher.alphabet]
            for i in range(len(filtered)-1):
                pair = filtered[i] + filtered[i+1]
                digraphs[pair] += 1
            for pair, count in digraphs.most_common(5):
                print(f"{pair}: {count}次")

        # 交互选项
        print("\n建议操作：")
        print("1. 使用建议密钥解密")
        print("2. 进入交互式调整")
        print("3. 返回主菜单")
        choice = input("请选择操作：").strip()

        if choice == '1':
            decrypted = self.cipher.decrypt(ciphertext, proposed_key)
            print("\n解密结果：")
            print(decrypted)
        elif choice == '2':
            self.key_adjustment_menu(ciphertext, proposed_key)

    def key_adjustment_menu(self, ciphertext, initial_key):
        current_key = list(initial_key)
        while True:
            decrypted = self.cipher.decrypt(ciphertext, ''.join(current_key))
            print("\n当前解密结果（前500字符）：")
            print(decrypted[:500])

            print("\n当前密钥映射：(明文->密文)")
            for i, c in enumerate(self.cipher.alphabet):
                print(f"{c.upper()}→{current_key[i].upper()}", end=' ')
                if (i+1) % 8 == 0:
                    print()

            print("\n操作选项：")
            print("1. 修改单个映射")
            print("2. 交换映射")
            print("3. 保存并退出")
            print("4. 放弃修改")
            choice = input("请选择操作：").strip()

            if choice == '1':
                plain_char = input("输入要修改的明文字母：").lower()
                if plain_char not in self.cipher.alphabet:
                    print("无效字母！")
                    continue
                cipher_char = input("输入对应的密文字母：").lower()
                if cipher_char not in self.cipher.alphabet:
                    print("无效字母！")
                    continue
                if cipher_char in current_key:
                    old_index = current_key.index(cipher_char)
                    current_key[old_index] = ''
                index = self.cipher.alphabet.index(plain_char)
                current_key[index] = cipher_char
                unused = [c for c in self.cipher.alphabet if c not in current_key]
                for i in range(26):
                    if current_key[i] == '' and unused:
                        current_key[i] = unused.pop(0)
            elif choice == '2':
                c1 = input("输入第一个明文字母：").lower()
                c2 = input("输入第二个明文字母：").lower()
                if c1 not in self.cipher.alphabet or c2 not in self.cipher.alphabet:
                    print("无效输入！")
                    continue
                i1 = self.cipher.alphabet.index(c1)
                i2 = self.cipher.alphabet.index(c2)
                current_key[i1], current_key[i2] = current_key[i2], current_key[i1]
            elif choice == '3':
                self.cipher.cipher_alphabet = ''.join(current_key)
                print("密钥已保存！")
                return
            elif choice == '4':
                return
            else:
                print("无效选择！")

if __name__ == "__main__":
    system = MonoalphabeticCipherSystem()
    system.run()
