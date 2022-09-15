package program.scanners.scan_operations.crypto

import program.scanners.scan_operations.ScanOperation
import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.br.instructions.LoadString
import org.opalj.br.ObjectType
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL
import program.scanners.scan_operations.SecurityWarning

object CbcPaddingOracle extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val operands = interpretation.operandsArray(pc)
    val cipherObjectType = ObjectType("javax/crypto/Cipher")

    if (methodCall.declaringClass == cipherObjectType &&
    methodCall.name == "getInstance") {
      val argumentOrigin = interpretation.domain.origins(operands(0))

      interpretation.code.instructions(argumentOrigin.head) match {
        case stringLoad: LoadString => return Array(
                "AES/CBC/PKCS5Padding",
                "Blowfish/CBC/PKCS5Padding",
                "DES/CBC/PKCS5Padding",
                "AES/CBC/PKCS7Padding",
                "Blowfish/CBC/PKCS7Padding",
                "DES/CBC/PKCS7Padding") contains
                stringLoad.value
        case _ =>
      }
    }
    return false
  }
  
  override def json = SecurityWarning(
    """The App uses the encryption mode CBC with PKCS5/PKCS7 padding. This
      configuration is vulnerable to padding oracle attacks.""",
    "ERROR",
    "cwe-649",
    "m5",
    "crypto-3",
    this.results,
    "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x04g-Testing-Cryptography.md#padding-oracle-attacks-due-to-weaker-padding-or-block-operation-implementations"
  )

  override def name = "CBC Padding Oracle"
}

/*patterns:
      - pattern-either:
          - pattern: |
              Cipher.getInstance("AES/CBC/PKCS5Padding")
          - pattern: |
              Cipher.getInstance("Blowfish/CBC/PKCS5Padding")
          - pattern: |
              Cipher.getInstance("DES/CBC/PKCS5Padding")
          - pattern: |
              Cipher.getInstance("AES/CBC/PKCS7Padding")
          - pattern: |
              Cipher.getInstance("Blowfish/CBC/PKCS7Padding")
          - pattern: |
              Cipher.getInstance("DES/CBC/PKCS7Padding")
*/