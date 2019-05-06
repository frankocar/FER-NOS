from PyInquirer import Token, ValidationError, Validator, prompt, style_from_dict
from Cryptodome import Random
from Cryptodome.Hash import SHA, SHA224, SHA256, SHA384, SHA512, SHA3_224, SHA3_256, SHA3_384, SHA3_512
from Cryptodome.Cipher import AES, DES3
from Crypto.PublicKey import RSA
import math
from collections import defaultdict
import binascii
import base64
import os

try:
    import colorama
    colorama.init()
except ImportError:
    colorama = None

try:
    from termcolor import colored
except ImportError:
    colored = None


style = style_from_dict({
    Token.QuestionMark: '#fac731 bold',
    Token.Answer: '#4688f1 bold',
    Token.Instruction: '',
    Token.Separator: '#cc5454',
    Token.Selected: '#0abf5b',
    Token.Pointer: '#673ab7 bold',
    Token.Question: '',
})

modes = {"CFB": AES.MODE_CFB, "OFB": AES.MODE_OFB, "CBC": AES.MODE_CBC}
hashAlgos = {"SHA-1": SHA,
             "SHA-224": SHA224, "SHA-256": SHA256, "SHA-384": SHA384, "SHA-512": SHA512,
             "SHA3-224": SHA3_224, "SHA3-256": SHA3_256, "SHA3-384": SHA3_384, "SHA3-512": SHA3_512}

BEGIN_DATA = "---BEGIN OS2 CRYPTO DATA---"
END_DATA = "---END OS2 CRYPTO DATA---"
INDENT = "    "
ROW_LEN = 60


class FileReader:
    def __init__(self, filePath):
        self.data = defaultdict(list)

        with open(filePath) as f:
            self.reading = False
            section = ""
            for l in f:
                if l.strip() == BEGIN_DATA:
                    self.reading = True
                    continue
                if not self.reading:
                    continue
                if l.strip() == END_DATA:
                    self.reading = False
                    break

                if l.strip() == "":
                    continue

                if not l.startswith(INDENT):
                    section = l.strip()[:-1]
                else:
                    self.data[section].append(l.strip())

    def longString(self, name):
        return ''.join(self.data[name])

    def bigHexNumber(self, name):
        return int(''.join(self.data[name]), 16)

    def base64Data(self, name):
        return base64.b64decode(''.join(self.data[name]))

    def getDescription(self):
        return self.longString("Description")

    def getFileName(self):
        return self.longString("File name")

    def getMethod(self):
        return self.data['Method']

    def getKeyLen(self):
        return [int(x, 16) for x in self.data["Key length"]]

    def getSecretKey(self):
        return self.bigHexNumber("Secret key")

    def getIV(self):
        return binascii.unhexlify(''.join(self.data["Initialization vector"]))

    def getModulus(self):
        return self.bigHexNumber("Modulus")

    def getPublicExponent(self):
        return self.bigHexNumber("Public exponent")

    def getPrivateExponent(self):
        return self.bigHexNumber("Private exponent")

    def getSignature(self):
        return self.bigHexNumber("Signature")

    def getData(self):
        return self.base64Data("Data")

    def getEnvelopeData(self):
        return self.base64Data("Envelope data")

    def getEnvelopeCryptKey(self):
        return self.bigHexNumber("Envelope crypt key")


class FileWriter:
    def __init__(self, filePath):
        if not os.path.exists(os.path.dirname(filePath)):
            os.makedirs(os.path.dirname(filePath))

        self.file = open(filePath, 'w')
        self.file.write(BEGIN_DATA + "\n")

    def stringWriter(self, name, string):
        self.file.write(name + ":\n")

        if len(string) <= 60:
            self.file.write(INDENT + string + "\n")
            self.file.write("\n")
            return

        data = ""
        rows = math.ceil(len(string) / ROW_LEN)
        for i in range(rows):
            data += INDENT
            data += string[i * ROW_LEN:min((i+1)*ROW_LEN, len(string))]
            data += "\n"

        self.file.write(data)
        self.file.write("\n")

    def listWriter(self, name, vals):
        self.file.write(name + ":\n")
        for v in vals:
            self.file.write(INDENT + v + "\n")
        self.file.write("\n")


    def writeDescription(self, desc):
        self.stringWriter("Description", desc)

    def writeFileName(self, name):
        self.stringWriter("File name", name)

    def writeMethod(self, methods):
        self.listWriter("Method", methods)

    def writeKeyLen(self, lens):
        self.listWriter("Key length", (f'0{l:x}' for l in lens))

    def writeSecretKey(self, key):
        self.stringWriter("Secret key", f'{key:x}')

    def writeIV(self, iv):
        self.stringWriter("Initialization vector", iv.hex())

    def writeModulus(self, mod):
        self.stringWriter("Modulus", f'{mod:x}')

    def writePublicExponent(self, exp):
        self.stringWriter("Public exponent", f'{exp:x}')

    def writePrivateExponent(self, exp):
        self.stringWriter("Private exponent", f'{exp:x}')

    def writeSignature(self, sig):
        self.stringWriter("Signature", f'{sig:x}')

    def writeData(self, data):
        self.stringWriter("Data", base64.b64encode(data).decode())

    def writeEnvelopeData(self, data):
        self.stringWriter("Envelope data", base64.b64encode(data).decode())

    def writeEnvelopeCryptKey(self, key):
        self.stringWriter("Envelope crypt key", key.hex())

    def close(self):
        self.file.write(END_DATA + "\n")
        self.file.close()


class FilePathValidator(Validator):
    def validate(self, value):
        if len(value.text):
            if os.path.isfile(value.text):
                return True
            else:
                raise ValidationError(
                    message="File not found",
                    cursor_position=len(value.text))
        else:
            raise ValidationError(
                message="You can't leave this blank",
                cursor_position=len(value.text))


def padText(text, bytes):
    return text + (bytes - len(text) % bytes) * chr(bytes - len(text) % bytes)


def unpad(text):
    return text[:-ord(text[len(text)-1:])]


def createEnvelope():
    data = prompt([
        {
            'type': 'input',
            'name': 'in_path',
            'message': 'Enter input file path:',
            'default': './testIn.txt',
            'validate': FilePathValidator,
            'filter': lambda val: val.strip()
        },
        {
            'type': 'input',
            'name': 'key_path',
            'message': 'Enter destination public key file path:',
            'default': './testPublicKey.key',
            'validate': FilePathValidator,
            'filter': lambda val: val.strip()
        },
        {
            'type': 'input',
            'name': 'out_path',
            'message': 'Enter digital envelope output file path:',
            'default': './testEnvelopeOut.txt',
            'filter': lambda val: val.strip()
        },
        {
            'type': 'list',
            'name': 'method',
            'message': 'Pick an algorithm:',
            'choices': ["AES", "3DES"],
            'filter': lambda val: val.strip()
        },
        {
            'type': 'list',
            'name': 'aes_key_size',
            'message': 'AES key size (in bytes):',
            'choices': (str(x) for x in AES.key_size),
            'when': lambda x: x.get('method') == "AES",
            'filter': lambda val: int(val.strip())
        },
        {
            'type': 'list',
            'name': '3des_key_size',
            'message': 'DES key size (in bytes):',
            'choices': (str(x) for x in DES3.key_size),
            'when': lambda x: x.get('method') == "3DES",
            'filter': lambda val: int(val.strip())
        },
        {
            'type': 'list',
            'name': 'crypto_mode',
            'message': 'Encryption mode:',
            'choices': modes.keys(),
            'filter': lambda val: modes[val.strip()]
        },
    ], style=style)

    inputFile = open(data['in_path']).read()
    publicKey = FileReader(data['key_path'])

    env = FileWriter(data['out_path'])
    env.writeDescription('Envelope')
    env.writeFileName(os.path.basename(data['in_path']))
    env.writeMethod([data['method'], "RSA"])

    keyLen = data['3des_key_size'] if data['method'] == '3DES' else data['aes_key_size']
    key = Random.new().read(keyLen)

    if data['method'] == "AES":
        if data['crypto_mode'] != 3 and len(inputFile) % 16 != 0:
            # inputFile += ''.join(' ' for _ in range(16 - (len(inputFile) % 16)))
            inputFile = padText(inputFile, 16)
        iv = Random.new().read(AES.block_size)
        aes = AES.new(key, data['crypto_mode'], iv)
        msgEnc = aes.encrypt(inputFile.encode())
    else:
        if data['crypto_mode'] != 3 and len(inputFile) % 8 != 0:
            # inputFile += ''.join(' ' for _ in range(8 - (len(inputFile) % 8)))
            inputFile = padText(inputFile, 8)
        iv = Random.new().read(DES3.block_size)
        des3 = DES3.new(key, data['crypto_mode'], iv)
        msgEnc = des3.encrypt(inputFile.encode())


    rsa = RSA.construct((publicKey.getModulus(), publicKey.getPublicExponent()))
    keyEnc = rsa.encrypt(key, None)

    env.writeKeyLen((keyLen * 8, publicKey.getKeyLen()[0]))
    env.writeIV(iv)
    env.writeEnvelopeData(msgEnc)
    env.writeEnvelopeCryptKey(keyEnc[0])
    env.close()


def createSignature():
    data = prompt([
        {
            'type': 'input',
            'name': 'in_path',
            'message': 'Enter input file path:',
            'default': './testIn.txt',
            'validate': FilePathValidator,
            'filter': lambda val: val.strip()
        },
        {
            'type': 'input',
            'name': 'key_path',
            'message': 'Enter destination private key file path:',
            'default': './testPrivateKey.key',
            'validate': FilePathValidator,
            'filter': lambda val: val.strip()
        },
        {
            'type': 'input',
            'name': 'out_path',
            'message': 'Enter digital signature output file path:',
            'default': './testSignatureOut.txt',
            'filter': lambda val: val.strip()
        },
        {
            'type': 'list',
            'name': 'algorithm',
            'message': 'Encryption mode:',
            'choices': hashAlgos.keys(),
            'filter': lambda val: val.strip()
        }
    ], style=style)

    inputFile = open(data['in_path']).read()
    privateKey = FileReader(data['key_path'])

    algo = hashAlgos[data['algorithm']]

    sig = FileWriter(data['out_path'])
    sig.writeDescription("Signature")
    sig.writeFileName(os.path.basename(data['in_path']))
    sig.writeMethod([data['algorithm'], "RSA"])
    sig.writeKeyLen([algo.digest_size * 8, privateKey.getKeyLen()[0]])

    digest = algo.new(bytes(inputFile, 'UTF-8')).hexdigest()
    rsa = RSA.construct((privateKey.getModulus(), privateKey.getPrivateExponent()))

    enc = rsa.encrypt(int(digest, 16), None)

    sig.writeSignature(enc[0])
    sig.close()


def openEnvelope():
    data = prompt([
        {
            'type': 'input',
            'name': 'in_path',
            'message': 'Enter digital envelope file path:',
            'default': './testEnvelopeOut.txt',
            'validate': FilePathValidator,
            'filter': lambda val: val.strip()
        },
        {
            'type': 'input',
            'name': 'key_path',
            'message': 'Enter private key file path:',
            'default': './testPrivateKey.key',
            'validate': FilePathValidator,
            'filter': lambda val: val.strip()
        },
        {
            'type': 'input',
            'name': 'out_path',
            'message': 'Enter output file path:',
            'default': './testEnvelopeDecode.txt',
            'filter': lambda val: val.strip()
        },
        {
            'type': 'list',
            'name': 'crypto_mode',
            'message': 'Encryption mode:',
            'choices': modes.keys(),
            'filter': lambda val: modes[val.strip()]
        }
    ], style=style)

    env = FileReader(data['in_path'])
    privateKey = FileReader(data['key_path'])

    rsa = RSA.construct((privateKey.getModulus(), privateKey.getPrivateExponent()))
    key = rsa.encrypt(env.getEnvelopeCryptKey(), None)
    iv = env.getIV()

    if "AES" in env.getMethod():
        aes = AES.new(bytes.fromhex(f'{key[0]:x}'), data['crypto_mode'], iv)
        msg = aes.decrypt(env.getEnvelopeData())
    elif "3DES" in env.getMethod():
        des3 = DES3.new(bytes.fromhex(f'{key[0]:x}'), data['crypto_mode'], iv)
        msg = des3.decrypt(env.getEnvelopeData())

    msg = msg.decode()

    if data['crypto_mode'] != modes["CFB"]:
        msg = unpad(msg)

    print(msg)

    if not os.path.exists(os.path.dirname(data['out_path'])):
        os.makedirs(os.path.dirname(data['out_path']))

    with open(data['out_path'], 'w') as f:
        f.write(msg)


def openSignature():
    data = prompt([
        {
            'type': 'input',
            'name': 'in_path',
            'message': 'Enter digital signature file path:',
            'default': './testSignatureOut.txt',
            'validate': FilePathValidator,
            'filter': lambda val: val.strip()
        },
        {
            'type': 'confirm',
            'name': 'specify_file',
            'message': 'Do you want to specify a file to check?'
        },
        {
            'type': 'input',
            'name': 'check_path',
            'message': 'Enter the path of a file to check:',
            'default': './testIn.txt',
            'validate': FilePathValidator,
            'when': lambda d: d.get("specify_file", True),
            'filter': lambda val: val.strip()
        },
        {
            'type': 'input',
            'name': 'key_path',
            'message': 'Enter public key file path:',
            'default': './testPublicKey.key',
            'validate': FilePathValidator,
            'filter': lambda val: val.strip()
        }
    ], style=style)

    publicKey = FileReader(data['key_path'])
    sig = FileReader(data['in_path'])

    checkFile = None
    if data['specify_file']:
        checkFile = data['check_path']
    else:
        checkFile = "./" + sig.getFileName()

    inputFile = open(checkFile).read()

    algo = hashAlgos[sig.getMethod()[0]]

    digest = algo.new(bytes(inputFile, 'UTF-8')).hexdigest()
    rsa = RSA.construct((publicKey.getModulus(), publicKey.getPublicExponent()))

    enc = rsa.encrypt(sig.getSignature(), None)

    if digest.lower() == f'{enc[0]:x}'.lower():
        print("File is valid")
    else:
        print("INVALID file")


def openStamp():
    data = prompt([
        {
            'type': 'input',
            'name': 'in_path',
            'message': 'Enter digital envelope file path:',
            'default': './testEnvelopeOut.txt',
            'validate': FilePathValidator,
            'filter': lambda val: val.strip()
        },
        {
            'type': 'input',
            'name': 'key_path',
            'message': 'Enter private key file path:',
            'default': './testPrivateKey.key',
            'validate': FilePathValidator,
            'filter': lambda val: val.strip()
        },
        {
            'type': 'input',
            'name': 'public_key_path',
            'message': 'Enter public key file path:',
            'default': './testPublicKey.key',
            'validate': FilePathValidator,
            'filter': lambda val: val.strip()
        },
        {
            'type': 'list',
            'name': 'crypto_mode',
            'message': 'Encryption mode:',
            'choices': modes.keys(),
            'filter': lambda val: modes[val.strip()]
        },
        {
            'type': 'input',
            'name': 'sig_in_path',
            'message': 'Enter digital signature file path:',
            'default': './testSignatureOut.txt',
            'validate': FilePathValidator,
            'filter': lambda val: val.strip()
        }
    ], style=style)

    env = FileReader(data['in_path'])
    privateKey = FileReader(data['key_path'])
    publicKey = FileReader(data['public_key_path'])

    rsa = RSA.construct((privateKey.getModulus(), privateKey.getPrivateExponent()))
    key = rsa.encrypt(env.getEnvelopeCryptKey(), None)
    iv = env.getIV()

    if "AES" in env.getMethod():
        aes = AES.new(bytes.fromhex(f'{key[0]:x}'), data['crypto_mode'], iv)
        msg = aes.decrypt(env.getEnvelopeData())
    elif "3DES" in env.getMethod():
        des3 = DES3.new(bytes.fromhex(f'{key[0]:x}'), data['crypto_mode'], iv)
        msg = des3.decrypt(env.getEnvelopeData())

    msg = msg.decode()

    if data['crypto_mode'] != modes["CFB"]:
        msg = unpad(msg)

    print(msg)

    sig = FileReader(data['sig_in_path'])

    algo = hashAlgos[sig.getMethod()[0]]

    digest = algo.new(bytes(msg, 'UTF-8')).hexdigest()
    rsa = RSA.construct((publicKey.getModulus(), publicKey.getPublicExponent()))

    enc = rsa.encrypt(sig.getSignature(), None)

    if digest.lower() == f'{enc[0]:x}'.lower():
        print("File is valid")
    else:
        print("INVALID file")




def generateKeys():
    data = prompt([
        {
            'type': 'input',
            'name': 'key_size',
            'message': 'Enter RSA key pair size:',
            'default': '1024',
            'filter': lambda val: int(val.strip())
        },
        {
            'type': 'input',
            'name': 'private_file_path',
            'message': 'Enter private key file path:',
            'default': './generatedPrivate.key',
            'filter': lambda val: val.strip()
        },
        {
            'type': 'input',
            'name': 'public_file_path',
            'message': 'Enter public key file path:',
            'default': './generatedPublic.key',
            'filter': lambda val: val.strip()
        }
    ])

    keys = RSA.generate(data['key_size'])

    private = FileWriter(data['private_file_path'])
    public = FileWriter(data['public_file_path'])

    public.writeDescription("Public key")
    private.writeDescription("Private key")

    for x in [public, private]:
        x.writeMethod(["RSA"])
        x.writeKeyLen([data['key_size']])
        x.writeModulus(keys.n)

    public.writePublicExponent(keys.d)
    private.writePrivateExponent(keys.e)

    public.close()
    private.close()


actions = {'Create digital envelope': createEnvelope,
           'Create digital signature': createSignature,
           'Open digital envelope': openEnvelope,
           'Check digital signature': openSignature,
           'Check digital stamp': openStamp,
           'Generate RSA key pair': generateKeys}


def main():
    action = prompt([{
        'type': 'list',
        'name': 'action_type',
        'message': 'Content Type:',
        'choices': actions.keys(),
        'filter': lambda val: actions[val]
    }], style=style)

    action["action_type"]()


if __name__ == "__main__":
    main()

