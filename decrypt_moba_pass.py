import argparse
import base64
import configparser
import itertools
import os.path
import winreg

from typing import Dict, List
from enum import Enum

from Crypto.Hash import SHA512
from Crypto.Cipher import AES


class MobaXtermCipher:
    def __init__(self, master_password: bytes):
        self._key = SHA512.new(master_password).digest()[0:32]
        self._cipher = None

    def _generate_cipher(self) -> None:
        init_vector = AES.new(key=self._key, mode=AES.MODE_ECB).encrypt(b"\x00" * AES.block_size)
        self._cipher = AES.new(key=self._key, iv=init_vector, mode=AES.MODE_CFB, segment_size=8)

    def encrypt_password(self, plain_text: bytes) -> str:
        self._generate_cipher()
        return base64.b64encode(self._cipher.encrypt(plain_text))

    def decrypt_password(self, cipher_text: str) -> bytes:
        self._generate_cipher()
        return self._cipher.decrypt(base64.b64decode(cipher_text))


class MobaItem():
    def __init__(self, name: str = "", username: str = "", password: str = ""):
        self.name: str = name
        self.user: str = username
        self.password: str = password


class MobaXtermDecrypter():
    INI_SECTION_PASS = "Passwords"
    INI_SECTION_CRED = "Credentials"
    REG_HIVE = winreg.HKEY_CURRENT_USER
    REGKEY_PASS = "Software\\Mobatek\\MobaXterm\\P"
    REGKEY_CRED = "Software\\Mobatek\\MobaXterm\\C"
    ENCODING = "utf-8"

    def __init__(self):
        pass

    def display_clear_credentials(self, master_password: str, ini_file: str = None) -> None:
        raw_data = self._extract_raw_data(self.INI_SECTION_CRED, self.REG_HIVE, self.REGKEY_CRED, ini_file)
        # parse username / password
        parsed_data: List[MobaItem] = []
        for k, v in raw_data.items():
            item = MobaItem(name=k)
            if ":" in v:
                item.user = v.split(":")[0]
                item.password = v.split(":")[1]
            else:
                item.user = v
            parsed_data.append(item)

        decrypted_data = self._decrypt_data(parsed_data, master_password)
        self._display_data(self.INI_SECTION_CRED, decrypted_data)

    def display_clear_passwords(self, master_password: str, ini_file: str = None) -> None:
        raw_data = self._extract_raw_data(self.INI_SECTION_PASS, self.REG_HIVE, self.REGKEY_PASS, ini_file)
        # parse username / password
        parsed_data: List[MobaItem] = []
        for k, v in raw_data.items():
            item = MobaItem(password=v)
            if ":" in k:
                item.name = k.split(":")[0]
                item.user = k.split(":")[1]
            else:
                item.user = k
            parsed_data.append(item)

        decrypted_data = self._decrypt_data(parsed_data, master_password)
        self._display_data(self.INI_SECTION_PASS, decrypted_data)

    def _extract_raw_data(self, ini_section: str, winreg_key_name: str, winreg_subkey_name: str, ini_file: str = None) -> Dict[str, str]:
        raw_data: Dict[str, str]
        if ini_file:
            raw_data = self._fetch_inifile_section(ini_file, ini_section)
        else:
            raw_data = self._fetch_winreg_values(winreg_key_name, winreg_subkey_name)
        return raw_data

    def _fetch_winreg_values(self, key: str, sub_key: str) -> Dict[str, str]:
        credentials: Dict[str, str] = {}
        try:
            reg_data = winreg.OpenKey(key, sub_key)
        except FileNotFoundError:
            print(f"Registry key not found: {key} - {sub_key}")
            return {}

        for i in itertools.count(0):
            try:
                value_name, value_data, _ = winreg.EnumValue(reg_data, i)
            except OSError:
                break
            credentials[value_name] = value_data

        return credentials

    def _fetch_inifile_section(self, filename: str, section: str) -> Dict[str, str]:
        if not os.path.exists(filename):
            raise FileNotFoundError
        cfg = configparser.ConfigParser(delimiters=("="), strict=False)
        cfg.read(filename)
        credentials: Dict[str, str] = {}
        if section in cfg.sections():
            for cred in cfg[section]:
                credentials[cred] = cfg.get(section, cred)

        return credentials

    def _decrypt_data(self, items: List[MobaItem], master_password: str = None) -> List[MobaItem]:
        cipher = MobaXtermCipher(master_password.encode(self.ENCODING))

        decrypted_items = []
        for item in items:
            decrypted_pass = cipher.decrypt_password(item.password).decode(self.ENCODING)
            decrypted_items.append(MobaItem(item.name, item.user, decrypted_pass))
        return decrypted_items

    def _display_data(self, title: str, data: List[MobaItem]) -> None:
        if len(data) > 0:
            # get max cell length
            max_name = max([len(x.name) for x in data])
            max_user = max([len(x.user) for x in data])
            max_pass = max([len(x.password) for x in data])
            max_length = max_name + max_user + max_pass + 10
            row_format = f"| {{:<{max_name}}} | {{:<{max_user}}} | {{:<{max_pass}}} |"

            print(f"\n{title.center(max_length, '=')}")
            for item in data:
                print(row_format.format(item.name, item.user, item.password))
            print("".center(max_length, '='))


class ExtractionMode(Enum):
    CRED = 'cred'
    PASS = 'pass'
    ALL = 'all'

    def __str__(self):
        return self.value


def main():
    parser = argparse.ArgumentParser(description="Decrypt MobaXterm stored credentials & passwords.")
    parser.add_argument("-p", "--password", help="MobaXterm master password.", required=True)
    parser.add_argument("-f", "--file", help="MobaXterm ini file. Uses Windows registry data if not set.")
    parser.add_argument("-m", "--mode", choices=list(ExtractionMode), default="all", help="Extraction mode: credentials, password or all (default value).")
    args = parser.parse_args()

    ini_file = args.file
    master_password = args.password
    mode = args.mode

    moba_decrypt = MobaXtermDecrypter()
    if mode in [ExtractionMode.ALL.value, ExtractionMode.CRED.value]:
        moba_decrypt.display_clear_credentials(master_password, ini_file)
    if mode in [ExtractionMode.ALL.value, ExtractionMode.PASS.value]:
        moba_decrypt.display_clear_passwords(master_password, ini_file)


if __name__ == "__main__":
    main()
