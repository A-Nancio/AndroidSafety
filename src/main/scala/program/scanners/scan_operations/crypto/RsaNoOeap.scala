package program.scanners.scan_operations.crypto

import program.scanners.scan_operations.ScanOperation
import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL
import program.scanners.scan_operations.SecurityWarning
import org.opalj.br.ObjectType
import org.opalj.br.instructions.LoadString
import cats.instances.string

object RsaNoOeap extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val cipherObjectType = ObjectType("javax/crypto/Cipher")

    if (methodCall.declaringClass == cipherObjectType && methodCall.name == "getInstance") {
      // Can not use auxiliary function for this operations
      val operands = interpretation.operandsArray(pc)
      val argumentOrigin = interpretation.domain.origins(operands(0))

      interpretation.code.instructions(argumentOrigin.head) match {
        case stringLoad: LoadString => return stringLoad.value.contains("RSA") &&
        stringLoad.value.contains("NoPadding")
        case _ => return false
      }
    }
    return false
  }
  
  
  override def json = SecurityWarning(
    """This App uses RSA Crypto without OAEP padding. The purpose of the padding
      scheme is to prevent a number of attacks on RSA that only work when the
      encryption is performed without padding.""",
    "ERROR",
    "cwe-780",
    "m5",
    "crypto-3",
    this.results,
    "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x04g-Testing-Cryptography.md#mobile-app-cryptography"
  )

  override def name = "RSA no OEAP padding"
}

/*patterns:
      - pattern-either:
          - pattern: |
              Cipher.getInstance($X, ...)
          - pattern: |
              javax.crypto.Cipher.getInstance($X, ...)
      - metavariable-regex:
          metavariable: $X
          regex: '(?i:.*rsa/.+/nopadding.*)'
*/
