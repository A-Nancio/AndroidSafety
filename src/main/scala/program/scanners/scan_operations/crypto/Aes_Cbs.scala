package program.scanners.scan_operations.crypto

import program.scanners.scan_operations.ScanOperation
import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL
import program.scanners.scan_operations.SecurityWarning
import org.opalj.br.ObjectType
import org.opalj.br.instructions.LoadString

object Aes_CbsMode extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val operands = interpretation.operandsArray(pc)
    val cipherObjectType = ObjectType("javax/crypto/Cipher")
    
    if (methodCall.declaringClass == cipherObjectType && methodCall.name == "getInstance") {  
      val argumentOrigin = interpretation.domain.origins(operands(0))
      interpretation.code.instructions(argumentOrigin.head) match {
        case stringLoad: LoadString => return Array(
          "AES/ECB/NoPadding",
          "AES/ECB/PKCS5Padding") contains
          stringLoad.value
        case _ =>
      } 
    }
    return false
  }
  
  override def json = SecurityWarning(
    """The App uses ECB mode in Cryptographic encryption algorithm. ECB mode is
      known to be weak as it results in the same ciphertext for identical blocks
      of plaintext.""",
    "ERROR",
    "cwe-327",
    "m5",
    "crypto-2",
    this.results,
    "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x04g-Testing-Cryptography.md#weak-block-cipher-mode"
  )

  override def name = "AES in ECB mode"
}

/*
patterns:
      - pattern-either:
          - pattern: |
              Cipher.getInstance("=~/AES\/ECB.*-/i")
*/

object Aes_CbsModeDefault extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val operands = interpretation.operandsArray(pc)
    val cipherObjectType = ObjectType("javax.crypto.Cipher")
    
    if (methodCall.declaringClass == cipherObjectType && methodCall.name == "getInstance") {  
      val argumentOrigin = interpretation.domain.origins(operands(0))
      interpretation.code.instructions(argumentOrigin.head) match {
        case stringLoad: LoadString => return stringLoad.value == "AES"
        case _ =>
      } 
    }
    return false
  }
  
  override def json = SecurityWarning(
    """Calling Cipher.getInstance("AES") will return AES ECB mode by default. ECB
      mode is known to be weak as it results in the same ciphertext for
      identical blocks of plaintext.""",
    "ERROR",
    "cwe-327",
    "m5",
    "crypto-2",
    this.results,
    "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x04g-Testing-Cryptography.md#weak-block-cipher-mode"
  )

  override def name = "AES in default ECB mode"
}

/*
patterns:
      - pattern-either:
          - pattern: |
              Cipher.getInstance("AES")
*/