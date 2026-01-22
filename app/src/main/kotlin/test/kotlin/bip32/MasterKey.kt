package test.kotlin.bip32

import java.security.Key
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

internal class MasterKey private constructor(
    val secretKey: ByteArray,
    val chainCode: ByteArray,
) {
   companion object {
       fun from(seed: ByteArray): MasterKey {
           // Calculate I = HMAC-SHA512(Key = "Bitcoin seed", Data = S)
           val mac = Mac.getInstance("hmacsha512")
           val encoded = "Bitcoin seed".toByteArray(charset = Charsets.UTF_8)
           val key: Key = SecretKeySpec(encoded, mac.algorithm)
           mac.init(key)
           val I = mac.doFinal(seed)
           check(I.size == 64)
           // Split I into two 32-byte sequences, IL and IR.
           val IL = I.copyOfRange(fromIndex = 0, toIndex = 32)
           val IR = I.copyOfRange(fromIndex = 32, toIndex = 64)
           // Use parse256(IL) as master secret key, and IR as master chain code.
           return MasterKey(
               secretKey = IL,
               chainCode = IR,
           )
       }
   }
}
