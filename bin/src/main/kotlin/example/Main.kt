package example;

fun printVerify(pass1: String, pass2: String, test: Boolean)
{
  val baseStr: String = String.format("%s, %s", pass1, pass2)

  if(test) {
    println(String.format("%s Match: True", baseStr))
  } else {
    println(String.format("%s Match: False", baseStr))
  }
}

// Driver code
@Throws(Exception::class)
fun main(args: Array<String>)
{
    val encode = Encode()

    val hash: String = encode.hashpw("pass123");

    val test1: Boolean = encode.verify("pass123", hash);

    val test2: Boolean = encode.verify("123pass", hash);

    printVerify("pass123", "pass123", test1)

    printVerify("pass123", "123pass", test2)
}
