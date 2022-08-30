package program.scanners.scan_operations.crypto

import program.scanners.scan_operations.ScanOperation
import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL
import program.scanners.scan_operations.SecurityWarning

object InsecureRandom extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    return methodCall.declaringClass.toJava == "java.util.Random" ||
           methodCall.declaringClass.toJava == "java.util.concurrent.ThreadLocalRandom"
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
