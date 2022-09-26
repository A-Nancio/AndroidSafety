package program.scanners.scan_operations

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL

object InsecureSslV3 extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    if (methodCall.name == "getInstance") {
      CodeTracker.processStringLoadOrigin(0, pc, Array("SSLv3"), interpretation)
    }
    return false
  }
  
  override def json = SecurityWarning(
    "SSLv3 is insecure and has multiple known vulnerabilities.",
    "WARNING",
    "cwe-330",
    "m5",
    "crypto-6",
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