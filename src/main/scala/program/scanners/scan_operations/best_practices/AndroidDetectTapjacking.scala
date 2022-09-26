package program.scanners.scan_operations

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import org.opalj.value.IsIntegerValue
import java.net.URL

object AndroidDetectTapjacking extends BestPracticeScan {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    if (methodCall.name == "setFilterTouchesWhenObscured") {
      val reference = interpretation.operandsArray(pc)(0)

      if (reference.isPrimitiveValue) {
        reference.asPrimitiveValue match {
          case value: IsIntegerValue => return value.asConstantInteger == 1
          case _ => return false
        }
      }
    }
    
    return false
  }
  
  override def json = SecurityWarning(
    """This app does not have capabilities to prevent tapjacking attacks. An attacker can hijack the user's taps and tricks him into performing some critical operations that he did not intend to.""",
    "INFO",
    "cwe-200",
    "m1",
    "platform-9",
    this.results,
    "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md#testing-for-overlay-attacks-mstg-platform-9"

  )

  override def name = "Android Detect Tapjacking"
}

/*
patterns:
      - pattern-either:
          - pattern: |
              $F.setFilterTouchesWhenObscured(true);
*/