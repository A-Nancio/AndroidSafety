package program.scanners.scan_operations

import org.opalj.ai.AIResult
import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL

object JacksonDeserialization extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val operands = interpretation.operandsArray(pc)
    return methodCall.declaringClass == "com.fasterxml.jackson.databind.ObjectMapper" &&
    methodCall.name == "enableDefaultTyping" && operands.size == 1
  }

  override def json = SecurityWarning(
    """The app uses jackson deserialization library. Deserialization of untrusted
      input can result in arbitrary code execution. Consider using HMACs to sign
      the data stream to make sure it is not tampered with, or consider only 
      transmitting object fields and populating a new object.""",
      "ERROR",
      "cwe-502",
      "m1",
      "platform-8",
      this.results,
      "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md#testing-object-persistence-mstg-platform-8"
  )

  override def name = "Jackson Deserialization" 
}

/*patterns:
      - pattern-either:
          - pattern: |
              import com.fasterxml.jackson.databind.ObjectMapper;
              ...
              $Z.enableDefaultTyping();
*/