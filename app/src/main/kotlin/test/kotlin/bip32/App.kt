package test.kotlin.bip32

import java.io.ByteArrayOutputStream
import java.io.OutputStream
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
import org.bouncycastle.crypto.digests.RIPEMD160Digest
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

private fun ByteArray.takeLastBytes(n: Int): ByteArray {
    val size = size
//    if (size == n) return this
    val bytes = ByteArray(n)
    val started = size - n
    for (index in 0 until n) {
        bytes[index] = this[index + started]
    }
    return bytes
}

private fun derive(secretKey: ByteArray, publicKey: ByteArray, chainCode: ByteArray, childIndex: Int): Pair<ByteArray, ByteArray> {
    // If not (normal child): let I = HMAC-SHA512(Key = cpar, Data = serP(point(kpar)) || ser32(i)).
    val data = ByteArrayOutputStream().use { stream ->
        stream.write(publicKey)
        stream.writeBytes(childIndex)
        stream.toByteArray()
    }
    val mac = Mac.getInstance("hmacsha512")
    val key: Key = SecretKeySpec(chainCode, mac.algorithm)
    mac.init(key)
    val I = mac.doFinal(data)
    check(I.size == 64)
    val IL = I.copyOfRange(fromIndex = 0, toIndex = 32)
    val IR = I.copyOfRange(fromIndex = 32, toIndex = 64)
    val spec: ECParameterSpec = ECNamedCurveTable.getParameterSpec("secp256k1")
    val ki = BigInteger(1, IL)
        .add(BigInteger(1, secretKey))
        .mod(spec.n)
        .toByteArray()
        .takeLastBytes(32)
    check(ki.size == 32) { "ki:size: ${ki.size}" }
    return ki to IR
}


private fun OutputStream.write32bit(value: Long) {
    write(value.shr(24).toInt())
    write(value.shr(16).toInt())
    write(value.shr(8).toInt())
    write(value.toInt())
}

private fun derive02(secretKey: ByteArray, chainCode: ByteArray, childIndex: Int): Pair<ByteArray, ByteArray> {
    // If so (hardened child): let I = HMAC-SHA512(Key = cpar, Data = 0x00 || ser256(kpar) || ser32(i)).
    // (Note: The 0x00 pads the private key to make it 33 bytes long.)
    val data = ByteArrayOutputStream().use { stream ->
        stream.write(0)
        stream.write(secretKey)
        stream.write32bit(childIndex + 0x80000000)
        stream.toByteArray()
    }
    check(data.size == 37) { "data:size: ${data.size}" }
    val mac = Mac.getInstance("hmacsha512")
    val key: Key = SecretKeySpec(chainCode, mac.algorithm)
    mac.init(key)
    val I = mac.doFinal(data)
    check(I.size == 64)
    val IL = I.copyOfRange(fromIndex = 0, toIndex = 32)
    val IR = I.copyOfRange(fromIndex = 32, toIndex = 64)
    // The returned child key ki is parse256(IL) + kpar (mod n).
    val spec: ECParameterSpec = ECNamedCurveTable.getParameterSpec("secp256k1")
    val ki = BigInteger(1, IL)
        .add(BigInteger(1, secretKey))
        .mod(spec.n)
        .toByteArray()
        .takeLastBytes(32)
    check(ki.size == 32) { "ki:size: ${ki.size}" }
    val sha256 = MessageDigest.getInstance("sha256")
    val hash = sha256.digest(secretKey)
    val h160 = RIPEMD160Digest()
    h160.update(hash, 0, hash.size)
    val fingerprint = ByteArray(20)
    h160.doFinal(fingerprint, 0)
    val message = """
        fingerprint(${fingerprint.size}): ${fingerprint.hex()}
    """.trimIndent()
    println(message)
    return ki to IR
}

private fun derive01(secretKey: ByteArray, chainCode: ByteArray, childNumber: Int) {
    val mac = Mac.getInstance("hmacsha512")
    val key: Key = SecretKeySpec(chainCode, mac.algorithm)
    mac.init(key)
    val seed = ByteArrayOutputStream().use { stream ->
        stream.writeBytes(secretKey)
        stream.writeBytes(childNumber)
        stream.toByteArray()
    }
    val I = mac.doFinal(seed)
    check(I.size == 64)
    val IL = I.copyOfRange(fromIndex = 0, toIndex = 32)
    val IR = I.copyOfRange(fromIndex = 32, toIndex = 64)
    val message = """
        childNumber: $childNumber
        IL(${IL.size}): ${IL.hex()}
        IR(${IR.size}): ${IR.hex()}
    """.trimIndent()
    println(message)
}

private fun getPublicKey(secretKey: ByteArray): ByteArray {
    val spec: ECParameterSpec = ECNamedCurveTable.getParameterSpec("secp256k1")
    val point = spec.g.multiply(BigInteger(1, secretKey))
    return point.getEncoded(true)
}

fun main() {
    val mnemonic = "fan habit farm amount quarter race already real symbol nothing range adjust"
    val passphrase = "bar"
    val seed = getSeed(mnemonic = mnemonic, passphrase = passphrase)
    val masterKey = getMasterKey(seed = seed)
    // Split I into two 32-byte sequences, IL and IR.
    // Use parse256(IL) as master secret key, and IR as master chain code.
    val secretKey = masterKey.copyOfRange(fromIndex = 0, toIndex = 32)
    val chainCode = masterKey.copyOfRange(fromIndex = 32, toIndex = 64)
    val publicKey = getPublicKey(secretKey = secretKey)
    // Extended public and private keys are serialized as follows:
//    val extendedPrivateKey = getExtendedKey(
//        version = 0x0488ade4,
//        depth = 0,
//        fingerprint = 0,
//        childNumber = 0,
//        chainCode = chainCode,
//        encoded = secretKey,
//    )
//    val extendedPublicKey = getExtendedKey(
//        version = 0x0488b21e,
//        depth = 0,
//        fingerprint = 0,
//        childNumber = 0,
//        chainCode = chainCode,
//        encoded = publicKey,
//    )
    val m0n = derive(
        secretKey = secretKey,
        publicKey = getPublicKey(secretKey = secretKey),
        chainCode = chainCode,
        childIndex = 0,
    )
    val m0h = derive02(
        secretKey = secretKey,
        chainCode = chainCode,
        childIndex = 0,
    )
    val m00n = derive(
        secretKey = m0h.first,
        publicKey = getPublicKey(secretKey = m0h.first),
        chainCode = m0h.second,
        childIndex = 0,
    )
    val m00h = derive02(
        secretKey = m0h.first,
        chainCode = m0h.second,
        childIndex = 0,
    )
    val message = """
        secret:key(${secretKey.size}): ${secretKey.hex()}
        chain:code(${chainCode.size}): ${chainCode.hex()}
        public:key(${publicKey.size}): ${publicKey.hex()}
        m/0           :key: ${m0n.first.hex()}
        m/0    :chain:code: ${m0n.second.hex()}
        m/0'          :key: ${m0h.first.hex()}
        m/0'   :chain:code: ${m0h.second.hex()}
        m/0'/0        :key: ${m00n.first.hex()}
        m/0'/0 :chain:code: ${m00n.second.hex()}
        m/0'/0'       :key: ${m00h.first.hex()}
        m/0'/0':chain:code: ${m00h.second.hex()}
    """.trimIndent()
    println(message)
}
