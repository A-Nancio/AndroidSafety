package program.scanners.scan_operations

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL
import org.opalj.br.ObjectType
import org.opalj.br.instructions.LoadString

object WeakChipers extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val nullCipherType = ObjectType("javax/crypto/NullCipher")
    if (methodCall.declaringClass == nullCipherType && methodCall.name == "init")
      return true

    if (methodCall.name == "getInstance") {
      //can not use auxiliary operations since it requires particular intervention
      val operands = interpretation.operandsArray(pc)
      if (!operands.isEmpty) {
        val argumentOrigin = interpretation.domain.origins(operands(0))
  
        interpretation.code.instructions(argumentOrigin.head) match {
          case stringLoad: LoadString => 
            return Array("DES", "DESEDE", "RC2", "RC4", "BLOWFISH") contains 
            stringLoad.value.toUpperCase
          case _ => return false
        }
      }
    }
    return false
  }
  
  
  override def json = SecurityWarning(
    """Weak encryption algorithm identified. This algorithm is vulnerable to
      cryptographic attacks.""",
    "ERROR",
    "cwe-327",
    "m5",
    "crypto-4",
    this.results,
    "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x04g-Testing-Cryptography.md#identifying-insecure-andor-deprecated-cryptographic-algorithms-mstg-crypto-4"
  )

  override def name = "Weak Chipers"
}

/*patterns:
      - pattern-either:
          - pattern: |
              $C.getInstance("=~/des|desede|rc2|rc4|blowfish/i", ...);
          - pattern: |
              $C = new NullCipher();
*/
