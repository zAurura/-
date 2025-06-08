import sys
import random
import re
from collections import Counter

class MonoalphabeticCipher:
    def __init__(self):
        self.original_alphabet = 'abcdefghijklmnopqrstuvwxyz'
        self.cipher_alphabet = None
        self.freq_standard = [
            'e', 't', 'a', 'o', 'i', 'n', 's', 'h', 'r', 'd', 'l', 'c',
            'u', 'm', 'w', 'f', 'g', 'y', 'p', 'b', 'v', 'k', 'j', 'x',
            'q', 'z'
        ]
        self.first_letter_standard = [
            's', 'c', 'p', 'a', 'd', 'r', 'b', 't', 'm', 'f',
            'i', 'e', 'h', 'l', 'g', 'w', 'o', 'u', 'n', 'v',
            'j', 'k', 'q', 'v', 'z', 'x'
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
        return self._substitute(plaintext, self.original_alphabet, key)

    def decrypt(self, ciphertext, key):
        return self._substitute(ciphertext, key, self.original_alphabet)

    def set_custom_key(self, mapping_str):
        try:
            key = [''] * 26
            mappings = mapping_str.split(',')
            for m in mappings:
                k, v = m.split('->')
                orig_index = self.original_alphabet.index(k.strip().lower())
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

    def frequency_attack(self, ciphertext):
        filtered = [c.lower() for c in ciphertext if c.lower() in self.original_alphabet]
        freq = Counter(filtered)

        # 按频率降序排序，相同频率按字母顺序
        cipher_chars = sorted(freq.keys(), key=lambda x: (-freq[x], x))
        # 补全未出现的字母（按字母表顺序）
        for c in self.original_alphabet:
            if c not in cipher_chars:
                cipher_chars.append(c)

        # 生成密钥：原字母表位置 -> 对应的明文字母
        key = [''] * 26
        for plain_order, plain_char in enumerate(self.freq_standard):
            if plain_order < len(cipher_chars):
                cipher_char = cipher_chars[plain_order]
                # 在密钥中的对应位置放置明文字母
                key[self.original_alphabet.index(plain_char)] = cipher_char

        # 处理剩余未映射的字母
        remaining_plain = [c for c in self.original_alphabet if c not in key]
        remaining_cipher = [c for c in self.original_alphabet if c not in cipher_chars[:len(self.freq_standard)]]
        
        for i, cipher_char in enumerate(remaining_cipher):
            if i < len(remaining_plain):
                key[self.original_alphabet.index(cipher_char)] = remaining_plain[i]
        
        return ''.join(key)
    def generate_random_key(self):
        chars = list(self.original_alphabet)
        random.shuffle(chars)
        self.cipher_alphabet = ''.join(chars)
        return self.cipher_alphabet

    def _substitute(self, text, source, target):
        result = []
        for c in text:
            if c.lower() in source:
                index = source.index(c.lower())
                new_char = target[index] if c.islower() else target[index].upper()
                result.append(new_char)
            else:
                result.append(c)
        return ''.join(result)

    def _analyze_text(self, ciphertext):
        """综合文本分析"""
        analysis = {}
        
        # 全字母频率
        filtered = [c.lower() for c in ciphertext if c.lower() in self.original_alphabet]
        analysis['letter_freq'] = Counter(filtered)
        
        # 首字母频率
        words = re.findall(r'\b[a-zA-Z]+\b', ciphertext)
        first_letters = [word[0].lower() for word in words if len(word) > 0]
        analysis['first_letter_freq'] = Counter(first_letters)
        
        # 短单词分析
        analysis['short_words'] = {}
        for length in [1, 2, 3, 4]:
            words_of_length = [word.lower() for word in words if len(word) == length]
            analysis['short_words'][length] = Counter(words_of_length)
        
        return analysis

class CipherSystem:
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
                self.handle_encrypt()
            elif choice == '2':
                self.handle_decrypt()
            elif choice == '3':
                self.handle_frequency_attack()
            elif choice == '4':
                sys.exit("退出系统")
            else:
                print("无效选项，请重新输入")

    def handle_encrypt(self):
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

    def handle_decrypt(self):
        text = input("输入要解密的密文：")
        key = input("输入26字母解密密钥：").lower()
        if len(key) != 26 or not key.isalpha():
            print("无效密钥！")
            return
        
        decrypted = self.cipher.decrypt(text, key)
        print("\n解密结果：")
        print(decrypted)

    def handle_frequency_attack(self):
        ciphertext = input("输入要分析的密文：")
        analysis = self.cipher._analyze_text(ciphertext)
        
        # 显示字母频率
        print("\n字母频率分析（降序排列）：")
        sorted_letters = sorted(analysis['letter_freq'].items(), 
                               key=lambda x: (-x[1], x[0]))
        for i, (char, count) in enumerate(sorted_letters):
            # 添加标准字母提示
            standard_char = self.cipher.freq_standard[i] if i < len(self.cipher.freq_standard) else '?'
            print(f"{char.upper()}: {count}次({standard_char})\n")

        # 显示首字母频率
        print("\n\n首字母频率分析（降序排列）：")
        if analysis['first_letter_freq']:
            sorted_first = sorted(analysis['first_letter_freq'].items(),
                                 key=lambda x: (-x[1], x[0]))
            for i, (char, count) in enumerate(sorted_first):
                # 获取标准首字母提示
                if i < len(self.cipher.first_letter_standard):
                    standard_char = self.cipher.first_letter_standard[i]
                else:
                    standard_char = '?'
                print(f"{char.upper()}: {count}次({standard_char.upper()})\n")
        
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
        proposed_key = self.cipher.frequency_attack(ciphertext)
        print("\n\n基于频率分析的初始密钥建议：")
        print(f"密钥: {proposed_key}")
        
        # 高频双字母分析
        print("\n高频双字母组合（可能对应th/he/in等）：")
        if len(ciphertext) >= 2:
            digraphs = Counter()
            filtered = [c.lower() for c in ciphertext if c.lower() in self.cipher.original_alphabet]
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
            self.manual_key_adjustment(ciphertext, proposed_key)

    def manual_key_adjustment(self, ciphertext, initial_key):
        current_key = list(initial_key)
        while True:
            decrypted = self.cipher.decrypt(ciphertext, ''.join(current_key))
            print("\n当前解密结果（前500字符）：")
            print(decrypted[:500])
            
            print("\n当前密钥映射：(明文->密文)")
            for i, c in enumerate(self.cipher.original_alphabet):
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
                cipher_char = input("输入要修改的明文字母：").lower()
                if cipher_char not in self.cipher.original_alphabet:
                    print("无效字母！")
                    continue
                new_plain = input("输入对应的密文字母：").lower()
                if new_plain not in self.cipher.original_alphabet:
                    print("无效字母！")
                    continue
                
                # 检查重复映射
                if new_plain in current_key:
                    old_index = current_key.index(new_plain)
                    current_key[old_index] = ''
                
                # 更新映射
                index = self.cipher.original_alphabet.index(cipher_char)
                current_key[index] = new_plain
                
                # 自动填充空白
                unused = [c for c in self.cipher.original_alphabet if c not in current_key]
                for i in range(26):
                    if current_key[i] == '' and unused:
                        current_key[i] = unused.pop(0)
            
            elif choice == '2':
                c1 = input("输入第一个明文字母：").lower()
                c2 = input("输入第二个明文字母：").lower()
                if c1 not in self.cipher.original_alphabet or c2 not in self.cipher.original_alphabet:
                    print("无效输入！")
                    continue
                
                i1 = self.cipher.original_alphabet.index(c1)
                i2 = self.cipher.original_alphabet.index(c2)
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
    system = CipherSystem()
    system.run()