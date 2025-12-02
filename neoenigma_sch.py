import tkinter as tk
import time
from tkinter import messagebox

import secrets
import zlib
import hmac
import hashlib
from argon2.low_level import hash_secret_raw, Type

HEX_CHARS : str = "0123456789abcdef"

class CryptionMain:
    def __init__(self, text : str, key : str) -> None:
        self.key : str = StringProcessor(key).clean_space()
        self.text : str = text
        self.add_info_length : int = 16 # 随机盐、mac的字节大小
    
    def encryption(self) -> str:
        compressed_text : str = StringProcessor(self.text).compress()
        salt : str = get_random_hex(self.add_info_length)
        mac : str = self.generate_mac(compressed_text, salt)

        enigma = EnigmaMachine(compressed_text,self.key,salt)
        encrypted_text : str = enigma.encrypte()

        return salt + encrypted_text + mac

    def decryption(self) -> tuple[bool,str]:
        try:
            self.text = StringProcessor(self.text).hex_only()
            mac = self.text[-self.add_info_length*2:]
            salt = self.text[:self.add_info_length*2]
            encrypted_text : str = self.text[self.add_info_length*2:-self.add_info_length*2]

            enigma = EnigmaMachine(encrypted_text,self.key,salt)
            decrypted_text : str = enigma.encrypte()

            check_mac : str = self.generate_mac(decrypted_text, salt)
            if hmac.compare_digest(check_mac,mac):
                return True, StringProcessor(decrypted_text).decompress()
            else:
                return False,''
        except:
            return False, ''

    def generate_mac(self, text : str, salt : str) -> str: # 生成mac认证
        hmac_result : bytes = hmac.new(
            key=(self.key + salt).encode('utf-8'),
            msg=text.encode('utf-8'),
            digestmod=hashlib.sha3_512
        ).digest()
        return hashlib.shake_256(hmac_result).hexdigest(self.add_info_length) # 使用shake256生成指定长度

class StringProcessor:
    def __init__(self, string : str) -> None:
        self.string = string
    
    def clean_space(self) -> str: # 清除字符串的空白字符
        return ''.join(self.string.split())

    def hex_only(self) -> str: # 清除文本中所有非十六进制的字符
        result : str = ''
        for c in self.string:
            if c in HEX_CHARS:
                result += c
            else: 
                continue
        return result

    def compress(self) -> str: # 压缩字符串，并输出十六进制文本
        data : bytes = self.string.encode('utf-8')
        data_compressed : bytes = zlib.compress(data)
        return data_compressed.hex()

    def decompress(self) -> str: # 解压十六进制的压缩结果，并输出明文
        data = bytes.fromhex(self.string)
        decompressed_data : bytes = zlib.decompress(data)
        return decompressed_data.decode("utf-8")

    def cut_to_list(self,cut_num : int) -> list[str]: # 按数量切分一个字符串至数组
        return [self.string[i:i + cut_num] for i in range(0, len(self.string), cut_num)]

    def change_line(self,line : int) -> str:
        result : str = ''
        for i, char in enumerate(self.string):
            result += char
            if (i + 1) % line == 0:
                result += '\n'
        return result
    
    def shuffle(self, seed : str) -> str: # seed应为16进制值
        chars : list[str] = list(self.string)
        random_hex_numbers : list[str] = self.derive_seed(bytes.fromhex(seed))
        for f in range(len(chars) - 1, 0, -1): # 使用伪随机数进行打乱，使用Fisher-Yates算法
            y = int(random_hex_numbers[f],16) % (f + 1)
            chars[f], chars[y] = chars[y], chars[f]
        return ''.join(chars)

    def derive_seed(self, seed : bytes) -> list[str]:
        string_len : int = len(self.string)
        derived_seed : str = hashlib.shake_256(seed).hexdigest(2 * string_len) # 生成所需的派生长度
        random_hex_numbers : list[str] = StringProcessor(derived_seed).cut_to_list(4)
        return random_hex_numbers

class EnigmaMachine:
    def __init__(self, text : str, key : str, salt : str) -> None:
        self.text : str = text
        unrest_alphabet_seed : str = hashlib.sha3_512((key + salt).encode('utf-8')).hexdigest()
        self.alphabet : str = StringProcessor(HEX_CHARS).shuffle(unrest_alphabet_seed) # 十六进制的所有排序组合为16!
        self.alphabet_len = len(self.alphabet)

        parameter_generator = EnigmaParametersGenerator(key,salt,self.alphabet)
        self.rotors : list[str] = parameter_generator.generate_rotors()
        self.deflects : list[int] = parameter_generator.generate_deflects()
        self.turn_extent : int = parameter_generator.generate_turn_extent()
        self.chars_conversion : list[str] = parameter_generator.generate_chars_convertion()

    def encrypte(self) -> str:
        text : str = self.text
        result : str = ""
        for letter in text:
            for i, rotor in enumerate(self.rotors):
                index_alphabet = self.alphabet.index(letter)
                index_deflected = (index_alphabet + self.deflects[i]) % self.alphabet_len
                letter_index = rotor.index(self.alphabet[index_deflected])
                letter = self.alphabet[letter_index]
            letter = self.character_conversion(letter, self.chars_conversion)
            for l in reversed(range(len(self.rotors))):
                index_alphabet = self.alphabet.index(letter)
                rotor_letter = self.rotors[l][index_alphabet]
                rotor_letter_index = self.alphabet.index(rotor_letter)
                index_deflected = (rotor_letter_index - self.deflects[l]) % self.alphabet_len
                letter = self.alphabet[index_deflected]
            self.deflects = self.turn_deflect()
            result += letter
        return result

    def turn_deflect(self) -> list[int]:
        length_alphabet : int = self.alphabet_len
        length_deflect : int = len(self.deflects)

        turned_deflect : list[int] = self.deflects.copy()
        turned_deflect[0] += self.turn_extent
        for i in range(length_deflect - 1):
            carry : int = turned_deflect[i] // length_alphabet
            turned_deflect[i + 1] += carry
            turned_deflect[i] %= length_alphabet
        turned_deflect[length_deflect - 1] %= length_alphabet
        return turned_deflect
    
    @staticmethod
    def character_conversion(letter : str, parameter : list[str]) -> str:
        for c in parameter:
            if letter in c:
                letter_index = c.index(letter)
                letter = c[(letter_index + 1) % 2]
                break
        return letter

class EnigmaParametersGenerator:
    def __init__(self, key : str, salt : str, alphabet : str) -> None:
        self.init_parameter : str = hash_secret_raw( # 通过随机盐与密钥生成参数
            secret=key.encode('utf-8'),
            salt=bytes.fromhex(salt),
            time_cost=4,
            memory_cost=256*1024, # KB
            parallelism=4,
            hash_len=64, # bytes
            type=Type.ID
        ).hex()
        self.alphabet : str = alphabet
        self.shuffle_value_places : int = 12 # 可以覆盖16!的十六进制长度
        self.rotors_num : int = 9
        # 加上字符转换，整个算法参数将会有(16!)^10种组合，不包含旋转强度的情况下

    def generate_turn_extent(self) -> int: # 生成旋转轮子的强度
        parameter : str = self.init_parameter[self.shuffle_value_places*self.rotors_num:-self.shuffle_value_places] # 应取八个十六进制字符
        return int(parameter, 16) + 1 # 数值范围：1~FFFFFFFF+1
    
    def generate_deflects(self) -> list[int]: # 设定每个轮子的初始状态
        # 使用shake派生（或者压缩）整个初始值，并通过这个派生设定每个轮子的初始位置
        derived_parameter : str = hashlib.shake_256(bytes.fromhex(self.init_parameter)).hexdigest(self.rotors_num*2)
        random_hex_numbers : list[str] = StringProcessor(derived_parameter).cut_to_list(4)
        random_numbers : list[int] = []
        for n in random_hex_numbers:
            random_numbers.append(int(n,16)%len(self.alphabet))
        return random_numbers
    
    def generate_rotors(self) -> list[str]:
        # 将初始参数切分，并将各个投入打乱算法打乱字符表
        rotors_parameter : str = self.init_parameter[:self.rotors_num*self.shuffle_value_places]
        list_parameters : list[str] = StringProcessor(rotors_parameter).cut_to_list(self.shuffle_value_places)
        rotors : list[str] = []
        for p in list_parameters:
            rotors.append(StringProcessor(self.alphabet).shuffle(p))
        return rotors
    
    def generate_chars_convertion(self) -> list[str]:
        parameter : str = self.init_parameter[-self.shuffle_value_places:]
        unrested_alphabet : str = StringProcessor(self.alphabet).shuffle(parameter)
        return StringProcessor(unrested_alphabet).cut_to_list(2)

class UIManager:
    def __init__(self, root : tk.Tk) -> None:
        self.root = root
        self.ui_setup()

    def ui_setup(self) -> None:
        self.root.title("NeoEnigma")
        self.root.geometry("800x640")
        self.root.resizable(False,False)
        self.root.option_add("*Font", ("Noto Sans Mono",14))

        self.key_entry = tk.Entry(self.root)
        self.text_box = tk.Text(self.root)
        self.scrollbar = tk.Scrollbar(self.root,command=self.text_box.yview)

        self.generate_key_button = tk.Button(
            self.root,
            text="生成",
            command=self.generate_key
        )
        self.encryption_button = tk.Button(
            self.root,
            text="加密",
            command=self.access_encryption
        )
        self.decryption_button = tk.Button(
            self.root,
            text="解密",
            command=self.access_decryption
        )

        self.key_entry.place(x=20,y=15,width=695,height=35)
        self.text_box.place(x=20, y=55, width=745, height=510)
        self.scrollbar.place(x=765, y=55, width=15, height=510)
        self.text_box.config(yscrollcommand=self.scrollbar.set)

        self.key_entry.bind("<Control-Key-a>", self.select_all_entry)
        self.key_entry.bind("<Control-Key-A>", self.select_all_entry)
        self.text_box.bind("<Control-Key-a>", self.select_all_text)
        self.text_box.bind("<Control-Key-A>", self.select_all_text)

        self.generate_key_button.place(x=720,y=15,width=60,height=35)
        self.encryption_button.place(x=20, y=575,width=370, height=50)
        self.decryption_button.place(x=410, y=575,width=370, height=50)

        self.processing_ui(False)

    def processing_ui(self, is_processing : bool) -> None:
        if is_processing == True:
            self.root.config(cursor="watch")
            self.text_box.config(cursor="watch",state = "disabled")
            self.key_entry.config(cursor="watch",state = "disabled")
            self.encryption_button.config(state = "disabled")
            self.decryption_button.config(state = "disabled")
            self.generate_key_button.config(state = "disabled")
        else:
            self.root.config(cursor="arrow")
            self.text_box.config(cursor="xterm",state = "normal")
            self.key_entry.config(cursor="xterm",state = "normal")
            self.encryption_button.config(state = "normal")
            self.decryption_button.config(state = "normal")
            self.generate_key_button.config(state = "normal")
        self.root.update()

    def access_encryption(self) -> None:
        start_time : float = time.time()
        self.processing_ui(True)
        user_key : str = self.key_entry.get()
        user_text : str = self.text_box.get("1.0", "end-1c")

        cryption_program = CryptionMain(user_text, user_key)
        cryption_result : str = cryption_program.encryption()
        processed_result : str = StringProcessor(cryption_result).change_line(64)
        self.processing_ui(False)

        self.set_text_box(processed_result)
        end_time : float = time.time()
        messagebox.showinfo("加密完成",f"总共花费{str(end_time - start_time)[:5]}秒")

    def access_decryption(self) -> None:
        start_time : float = time.time()
        self.processing_ui(True)
        user_key : str = self.key_entry.get()
        crypted_text : str = self.text_box.get("1.0", "end-1c")
        cryption_program = CryptionMain(crypted_text, user_key)
        cryption_result : tuple[bool,str] = cryption_program.decryption()
        self.processing_ui(False)

        if cryption_result[0] == True:
            self.set_text_box(cryption_result[1])
            end_time : float = time.time()
            messagebox.showinfo("解密完成",f"总共花费{str(end_time - start_time)[:5]}秒")
        else:
            messagebox.showerror("解密失败","密钥、密文不正确。")

    def generate_key(self) -> None:
        new_key : str = get_random_hex(16)
        self.key_entry.delete(0,tk.END)
        self.key_entry.insert(0,new_key)

    def set_text_box(self, new_text : str) -> None:
        self.text_box.delete("1.0", "end-1c")
        self.text_box.insert("1.0", new_text)

    def select_all_text(self,_) -> str:
        self.text_box.tag_add(tk.SEL, "1.0", tk.END)
        self.text_box.mark_set(tk.INSERT, "1.0")
        self.text_box.see(tk.INSERT)
        return "break"
    
    def select_all_entry(self,_) -> str:
        self.key_entry.select_range(0, tk.END)
        return "break"

# 用于外部调用
def get_random_hex(bytes_length : int) -> str:
    return secrets.token_hex(bytes_length)

def main() -> None:
    root = tk.Tk()
    app = UIManager(root)
    _ = app
    root.mainloop()

if __name__ == "__main__":
    main()
