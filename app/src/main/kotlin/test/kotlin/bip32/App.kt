package test.kotlin.bip32

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.Key
import java.security.MessageDigest
import java.security.spec.KeySpec
import java.text.Normalizer
import java.util.Locale
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECParameterSpec
import sp.kx.bytes.writeBytes

private fun Int.hex(locale: Locale = Locale.US): String {
    return String.format(locale, "%02x", and(0xff))
}

private fun ByteArray.hex(locale: Locale = Locale.US): String {
    if (isEmpty()) return ""
    val builder = StringBuilder()
    builder.append(get(0).toInt().hex(locale))
    for (i in 1 until size) {
        builder.append(get(i).toInt().hex(locale))
    }
    return builder.toString()
}

private fun getSeed(mnemonic: String, passphrase: String): ByteArray {
    // To create a binary seed from the mnemonic, we use the PBKDF2 function
    val skf = SecretKeyFactory.getInstance("pbkdf2withhmacsha512")
    // with a mnemonic sentence (in UTF-8 NFKD) used as the password
    val password = Normalizer.normalize(mnemonic, Normalizer.Form.NFKD).toCharArray()
    // and the string "mnemonic" + passphrase (again in UTF-8 NFKD) used as the salt.
    val salt = "mnemonic${Normalizer.normalize(passphrase, Normalizer.Form.NFKD)}".toByteArray(charset = Charsets.UTF_8)
    // The iteration count is set to 2048 and HMAC-SHA512 is used as the pseudo-random function.
    val iterations = 2048
    // The length of the derived key is 512 bits (= 64 bytes).
    val keyLength = 512
    val keySpec: KeySpec = PBEKeySpec(password, salt, iterations, keyLength)
    val seed = skf.generateSecret(keySpec).encoded
    check(seed.size == keyLength / 8)
    val message = """
        mnemonic(${mnemonic.length}): "$mnemonic"
        passphrase(${passphrase.length}): "$passphrase"
        salt(${salt.size}): ${salt.hex()}
        seed(${seed.size}): ${seed.hex()}
    """.trimIndent()
    println(message)
    return seed
}

private fun getMasterKey(seed: ByteArray): ByteArray {
    // Calculate I = HMAC-SHA512(Key = "Bitcoin seed", Data = S)
    val mac = Mac.getInstance("hmacsha512")
    val encoded = "Bitcoin seed".toByteArray(charset = Charsets.UTF_8)
    val key: Key = SecretKeySpec(encoded, mac.algorithm)
    mac.init(key)
    val I = mac.doFinal(seed)
    check(I.size == 64)
    return I
}

private fun getExtendedKey(
    version: Int,
    depth: Int,
    fingerprint: Int,
    childNumber: Int,
    chainCode: ByteArray,
    encoded: ByteArray,
): ByteArray {
    return ByteArrayOutputStream().use { stream ->
        // 4 bytes: version bytes (mainnet: 0x0488b21e public, 0x0488ADE4 private; testnet: 0x043587cf public, 0x04358394 private)
        stream.writeBytes(version)

        // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
        stream.write(depth)

        // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
        stream.writeBytes(fingerprint)

        // 4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
        stream.writeBytes(childNumber)

        // 32 bytes: the chain code
        stream.writeBytes(chainCode)

        // 33 bytes: the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
        when (val size = encoded.size) {
            32 -> stream.write(0)
            33 -> {/*noop*/}
            else -> error("Key size $size is not supported!")
        }
        stream.writeBytes(encoded)
        stream.toByteArray()
    }
}

private fun getKeyHash(encoded: ByteArray): ByteArray {
    val sha256 = MessageDigest.getInstance("sha256")
    sha256.update(encoded)
    sha256.update(sha256.digest())
    return sha256.digest()
}

fun main() {
    val mnemonic = "foo"
    val passphrase = "bar"
    val seed = getSeed(mnemonic = mnemonic, passphrase = passphrase)
    val masterKey = getMasterKey(seed = seed)
    // Split I into two 32-byte sequences, IL and IR.
    // Use parse256(IL) as master secret key, and IR as master chain code.
    val secretKey = masterKey.copyOfRange(fromIndex = 0, toIndex = 32)
    val chainCode = masterKey.copyOfRange(fromIndex = 32, toIndex = 64)
    // todo
    val spec: ECParameterSpec = ECNamedCurveTable.getParameterSpec("secp256k1")
    val point = spec.g.multiply(BigInteger(1, secretKey))
    val publicKey = point.getEncoded(true)
    // Extended public and private keys are serialized as follows:
    val extendedPrivateKey = getExtendedKey(
        version = 0x0488ade4,
        depth = 0,
        fingerprint = 0,
        childNumber = 0,
        chainCode = chainCode,
        encoded = secretKey,
    )
    val extendedPublicKey = getExtendedKey(
        version = 0x0488b21e,
        depth = 0,
        fingerprint = 0,
        childNumber = 0,
        chainCode = chainCode,
        encoded = publicKey,
    )
    val message = """
        secret:key: ${secretKey.hex()}
        chain:code: ${chainCode.hex()}
        public:key(${publicKey.size}): ${publicKey.hex()}
        extended:private:key(${extendedPrivateKey.size}): ${extendedPrivateKey.hex()}
        extended:private:key:checksum: ${getKeyHash(extendedPrivateKey).copyOf(4).hex()}
        extended:public:key(${extendedPublicKey.size}): ${extendedPublicKey.hex()}
        extended:public:key:checksum: ${getKeyHash(extendedPublicKey).copyOf(4).hex()}
    """.trimIndent()
    println(message)
}
