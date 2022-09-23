# mobaxterm-decrypt-pass

Decrypt MobaXterm stored credentials & passwords.

## Requirements

- Python 3
- [cryptodome](https://pypi.org/project/pycryptodome/) library

## Usage

```text
python decrypt_moba_pass.py [-h] -p PASSWORD [-f FILE] [-m {cred,pass,all}]
```

### Options
```text
options:
  -h, --help            
                        show this help message and exit
  
  -p PASSWORD, --password PASSWORD
                        MobaXterm master password.
  
  -f FILE, --file FILE  
                        MobaXterm ini file. Uses Windows registry data if not set.
  
  -m {cred,pass,all}, --mode {cred,pass,all}
                        Extraction mode: credentials, password or all (default value).
```
