package example

import org.bouncycastle.crypto.generators.SCrypt;
import java.io.IOException;
import java.security.KeyPair;
import javax.xml.bind.DatatypeConverter;

class Encode(
  var encryption: Encryption
) {

  constructor(): this(
    Encryption()
  )

  @Throws ( Exception::class  )
  fun encrypt(plainText: String): String { return encryption.encryptPasswordBased(plainText);}

  fun hashpw(pass: String): String {


    val SALT = "@amG89>";

    // DifficultyFactor
    // These should be powers of 2
    val cpu = 8;
    val memory = 8;
    val parallelism = 8;
    val outputLength = 32;

      val hash: ByteArray = SCrypt.generate(pass.toByteArray(), SALT.toByteArray(), cpu, memory, parallelism, outputLength);

      val stored: String = DatatypeConverter.printHexBinary(hash);

    try {

      return encrypt(stored);

    } catch (e: Exception) {

      return "";
    }
  }

  fun verify(pass :String, hash: String): Boolean {

      val newPass: String = hashpw(pass)

      return newPass.equals(hash)
  }
}
