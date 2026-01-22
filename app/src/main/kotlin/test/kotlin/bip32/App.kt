package test.kotlin.bip32

import java.io.ByteArrayOutputStream
import java.security.Key
import java.security.MessageDigest
import java.security.spec.KeySpec
import java.text.Normalizer
import java.util.Locale
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
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

fun main() {
    val mnemonic = "foo"
    val passphrase = "bar"
    val seed = getSeed(mnemonic = mnemonic, passphrase = passphrase)
    val mk = MasterKey.from(seed = seed)
    val pubver = 0x0488b21e
    val prtver = 0x0488ade4
    val depth = 0
    val fingerprint = 0
    val childNumber = 0
    val sha256 = MessageDigest.getInstance("sha256")
    // Extended public and private keys are serialized as follows:
    val epk = ByteArrayOutputStream().use { stream ->
        // 4 bytes: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
        stream.writeBytes(prtver)

        // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
        stream.write(depth)

        // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
        stream.writeBytes(fingerprint)

        // 4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
        stream.writeBytes(childNumber)

        // 32 bytes: the chain code
        stream.writeBytes(mk.chainCode)

        // 33 bytes: the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
        stream.write(0)
        stream.writeBytes(mk.secretKey)
        stream.toByteArray()
    }
    // This 78 byte structure can be encoded like other Bitcoin data in Base58,
    // by first adding 32 checksum bits (derived from the double SHA-256 checksum),
    // and then converting to the Base58 representation.
    sha256.update(epk)
    sha256.update(sha256.digest())
    val hash = sha256.digest()
    val message = """
        mk:sk: ${mk.secretKey.hex()}
        mk:cc: ${mk.chainCode.hex()}
        epk(${epk.size}): ${epk.hex()}
        epk:sha256:sha256: ${hash.hex()}
        epk:checksum: ${hash.copyOf(4).hex()}
    """.trimIndent()
    println(message)
}
