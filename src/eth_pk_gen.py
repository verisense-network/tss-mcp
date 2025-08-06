from ecpy.curves import Curve
from ecpy.keys import ECPublicKey, ECPrivateKey
from eth_hash.auto import keccak
from eth_keys import keys
from eth_utils import decode_hex, encode_hex
from eth_utils.crypto import keccak
from eth_keys.exceptions import BadSignature

from eth_keys import keys
from eth_utils import decode_hex, encode_hex
from eth_utils.crypto import keccak


def recover_address_and_pubkey(msg_hash_hex: str, r_hex: str, s_hex: str, v: int):
    msg_hash = decode_hex(msg_hash_hex)
    r = int(r_hex, 16)
    s = int(s_hex, 16)

    if v >= 27:
        recovery_id = v - 27
    else:
        recovery_id = v

    signature = keys.Signature(vrs=(recovery_id, r, s))
    public_key = signature.recover_public_key_from_msg_hash(msg_hash)

    return {
        "public_key": public_key.to_hex(),
        "address": public_key.to_checksum_address(),
    }


# 你签名的原始消息
original_message = b"your message here"  # 👈 请替换成你实际签名的消息
msg = "0x0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000c30dd7e09af6e418ab27954cac4f4b564236e0af000000000000000000000000000000000000000000000000000000000000002a"
original_message = decode_hex(msg)

# 如果签名的内容是 EIP-191 格式（默认 MetaMask、ethers.js 等使用）
prefix = f"\x19Ethereum Signed Message:\n{len(original_message)}".encode()
eth_message = prefix + original_message
msg_hash = keccak(eth_message)
msg_hash_hex = encode_hex(msg_hash)
print("111", msg_hash_hex)

# 签名参数
r_hex = "0x6b49884c2e998716901acd93ec94486cc619d8bd1f029e2c5928111348471674"
s_hex = "0x0bbcabcb195bf4be5956b9ad1c163d1e840a814e4f1cbf1175be07820a75359e"
v = 1

result = recover_address_and_pubkey(msg_hash_hex, r_hex, s_hex, v)
print(result)

# private_key = 0x4646464646464646464646464646464646464646464646464646464646464646
private_key = 0x4C255BC10B88A7E131F85308761BE4C52714A99BB01135E8A66DBAC59ED4286F

cv = Curve.get_curve("secp256k1")
pv_key = ECPrivateKey(private_key, cv)
pu_key = pv_key.get_public_key()

# equivalent alternative for illustration:
concat_x_y = bytes.fromhex(hex(pu_key.W.x)[2:] + hex(pu_key.W.y)[2:])
# print the x and y in hex
print(hex(pu_key.W.x))
print(hex(pu_key.W.y))
print(concat_x_y.hex())
concat_x_y = pu_key.W.x.to_bytes(32, byteorder="big") + pu_key.W.y.to_bytes(
    32, byteorder="big"
)
eth_addr = "0x" + keccak(concat_x_y)[-20:].hex()

print("private key: ", hex(private_key))
print("eth_address: ", eth_addr)
