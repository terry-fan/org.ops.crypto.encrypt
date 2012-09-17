package org.ops.crypto.encrypt

object Encrypt {
  import javax.crypto._
  import java.security._
  import javax.crypto.spec._
  import org.apache.commons.codec.binary.Base64
  import java.nio.{ByteBuffer,CharBuffer}
  import java.nio.charset.{Charset,CharsetDecoder,CharsetEncoder,CoderResult}

  val base64 = new Base64()
  
  def getCipher(key: Array[Byte], iv: Array[Byte]) = { 
    val c = Cipher.getInstance("AES/CBC/PKCS5Padding")
    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv))
    c
  }

  def getDecipher(key: Array[Byte], iv: Array[Byte]) = {
    val c = Cipher.getInstance("AES/CBC/PKCS5Padding")
    c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv))
    c
  }

  final val DEFAULT_CHARSET = Charset.forName("UTF-16LE")

  def encrypt(cipher: Cipher, s : String) = {
    val ba = cipher.doFinal(s.getBytes(DEFAULT_CHARSET))
    new String(Base64.encodeBase64String(ba))
  }

  def decrypt(cipher: Cipher, c : String) = {
    val decrypted = cipher.doFinal(Base64.decodeBase64(c))
    DEFAULT_CHARSET.newDecoder().decode(ByteBuffer.wrap(decrypted)).toString
  }
 
  def process_enc (keyInBase64: String, ivInBase64: String, data: String) : String =
  {
    val cipher = getCipher(Base64.decodeBase64(keyInBase64), Base64.decodeBase64(ivInBase64))
    encrypt(cipher, data)
  }

  def process_dec (keyInBase64: String, ivInBase64: String, data: String) : String =
  {
    val decipher = getDecipher(Base64.decodeBase64(keyInBase64), Base64.decodeBase64(ivInBase64))
    decrypt(decipher, data)
  }

  def showUsage () {
    println("Encryption:\r\nenc --key <encKeyInBase64> --iv <initialVectorInBase64> <data>")
    println("Encryption:\r\ndec --key <encKeyInBase64> --iv <initialVectorInBase64> <data>")
  }

  def showUnknownArgument (argument : String) {
    println("Unknow argument: " + argument)
  }

  def main (args : Array[String])
  {
     if (0 == args.length) {
       showUsage()
       return
     }

     val action = args(0)
     var key=""
     var iv=""
     var data=""

     var i = 1
     while (i < args.length) {
       args(i) match {
         case "--key" => {
           i+=1
           key = args(i)
         }
         case "--iv" => {
           i+=1
           iv = args(i)
         }
         case arg : String if arg startsWith "--" => {
           showUnknownArgument(arg)
           return
         }
         case _ => {
           data = args(i)
         }
       }
       i=i+1
     }

     val result = action match {
       case "enc" =>
         process_enc(key, iv, data)
       case "dec"=>
         process_dec(key, iv, data)
       case _ =>
         showUsage()
         ""
     }

     println(result)
  }
}


