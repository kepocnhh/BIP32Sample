package test.kotlin.bip32

import java.security.spec.KeySpec
import java.text.Normalizer
import java.util.Locale
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

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

fun main() {
    val mnemonic = "foo"
    val passphrase = "bar"
    // To create a binary seed from the mnemonic, we use the PBKDF2 function
    val skf = SecretKeyFactory.getInstance("pbkdf2withhmacsha512")
    // with a mnemonic sentence (in UTF-8 NFKD) used as the password
    val password = Normalizer.normalize(mnemonic, Normalizer.Form.NFKD).toCharArray()
    // and the string "mnemonic" + passphrase (again in UTF-8 NFKD) used as the salt.
    val salt = "mnemonic${Normalizer.normalize(passphrase, Normalizer.Form.NFKD)}".toByteArray()
    // The iteration count is set to 2048 and HMAC-SHA512 is used as the pseudo-random function.
    val iterations = 2048
    // The length of the derived key is 512 bits (= 64 bytes).
    val keyLength = 512
    val keySpec: KeySpec = PBEKeySpec(password, salt, iterations, keyLength)
    val key = skf.generateSecret(keySpec)
    val seed = key.encoded
    val message = """
        mnemonic(${mnemonic.length}): "$mnemonic"
        passphrase(${passphrase.length}): "$passphrase"
        salt(${salt.size}): ${salt.hex()}
        seed(${seed.size}): ${seed.hex()}
    """.trimIndent()
    println(message)
}
