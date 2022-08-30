package program.scanners.scan_operations.crypto

import program.scanners.scan_operations.ScanOperation
import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL
import program.scanners.scan_operations.SecurityWarning
import program.HelperFunctions
import org.opalj.br.instructions.LoadString

object InsecureSslV3 extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    if (methodCall.name == "getInstance") {
      val operands = interpretation.operandsArray(pc)
      val argumentOrigin = interpretation.domain.origins(operands(0))

      HelperFunctions.findInstruction(argumentOrigin.head, interpretation.code) match {
        case stringLoad: LoadString => return stringLoad.value == "SSLv3"
        case _ =>
      }
    }
    return false
  }
  
  override def json = SecurityWarning(
    "The App uses an insecure Random Number Generator.",
    "WARNING",
    Array("cwe: cwe-330",
      "owasp-mobile: m5",
      "masvs: crypto-6"),
    this.results,
    "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x04g-Testing-Cryptography.md#weak-random-number-generators"
  )

  override def name = "Insecure Random Number Generator"
}

/*patterns:
      - pattern-either:
          - pattern: |
              $S.getInstance("SSLv3");
*/