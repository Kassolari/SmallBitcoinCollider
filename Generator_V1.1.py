import os, binascii, hashlib, base58, ecdsa, requests


def ripemd160(x):
    d = hashlib.new('ripemd160')
    d.update(x)
    return d

balance = 0
n = 0

while balance == 0:  # number of key pairs to generate`

    # generate private key , uncompressed WIF starts with "5"
    priv_key = os.urandom(32)
    fullkey = '80' + binascii.hexlify(priv_key).decode()
    sha256a = hashlib.sha256(binascii.unhexlify(fullkey)).hexdigest()
    sha256b = hashlib.sha256(binascii.unhexlify(sha256a)).hexdigest()
    WIF = base58.b58encode(binascii.unhexlify(fullkey + sha256b[:8]))

    # get public key , uncompressed address starts with "1"
    sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    publ_key = '04' + binascii.hexlify(vk.to_string()).decode()
    hash160 = ripemd160(hashlib.sha256(binascii.unhexlify(publ_key)).digest()).digest()
    publ_addr_a = b"\x00" + hash160
    checksum = hashlib.sha256(hashlib.sha256(publ_addr_a).digest()).digest()[:4]
    publ_addr_b = base58.b58encode(publ_addr_a + checksum)

    balance_url = "https://blockchain.info/q/addressbalance/" + publ_addr_b.decode()
    #balance_url = "https://blockexplorer.com/api/addr/" + publ_addr_b.decode() + "/balance"
    req = requests.get(balance_url)
    print(n)
    n+=1
    print("Private Key : " + WIF.decode())
    print("Bitcoin Address: " + publ_addr_b.decode())
    if req.text != "0":
       print(req.text)
       print("Private Key : " + WIF.decode())
       print("Bitcoin Address: " + publ_addr_b.decode())
       balance = 1
       print(n)
       break