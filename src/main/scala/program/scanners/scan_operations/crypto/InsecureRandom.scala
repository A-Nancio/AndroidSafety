package program.scanners.scan_operations

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL
import org.opalj.br.ObjectType

object InsecureRandom extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val randomType = ObjectType("java/util/Random")
    val threadLocalRandomType = ObjectType("java/util/concurrent/ThreadLocalRandom")
    
    return methodCall.declaringClass == randomType ||
           methodCall.declaringClass == threadLocalRandomType
  }
  
  override def json = SecurityWarning(
    "The App uses an insecure Random Number Generator.",
    "WARNING",
    "cwe-330",
    "m5",
    "crypto-6",
    this.results,
    "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x04g-Testing-Cryptography.md#weak-random-number-generators"
  )

  override def name = "Insecure Random Number Generator"
}

/*
patterns:
      - pattern-either:
          - pattern: |
              import java.util.Random;
          - pattern: |
              import java.util.concurrent.ThreadLocalRandom;
*/