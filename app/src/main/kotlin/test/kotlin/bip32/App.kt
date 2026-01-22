package test.kotlin.bip32

import java.security.Key
import java.security.spec.KeySpec
import java.text.Normalizer
import java.util.Locale
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

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
    // Calculate I = HMAC-SHA512(Key = "Bitcoin seed", Data = S)
    val mac = Mac.getInstance("hmacsha512")
    val encoded = "Bitcoin seed".toByteArray(charset = Charsets.UTF_8)
    val key: Key = SecretKeySpec(encoded, mac.algorithm)
    mac.init(key)
    val I = mac.doFinal(seed)
    // Split I into two 32-byte sequences, IL and IR.
    val IL = I.copyOfRange(fromIndex = 0, toIndex = 32)
    val IR = I.copyOfRange(fromIndex = 32, toIndex = 64)
    // Use parse256(IL) as master secret key, and IR as master chain code.
    val message = """
        key(${key.encoded.size}): ${key.encoded.hex()}
        I(${I.size}): ${I.hex()}
        IL(${IL.size}): ${IL.hex()}
        IR(${IR.size}): ${IR.hex()}
    """.trimIndent()
    println(message)
}
