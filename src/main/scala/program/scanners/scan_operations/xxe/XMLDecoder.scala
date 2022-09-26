package program.scanners.scan_operations

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL
import org.opalj.br.ObjectType

object XMLDecoder extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val XMLDecoderType = ObjectType("java/beans/XMLDecoder")
    if (methodCall.declaringClass == XMLDecoderType && methodCall.name == "init") {
      !CodeTracker.processLoadConstantOrigin(0, pc, interpretation)
    }
    return false
  }
  
  override def json = SecurityWarning(
    """XMLDecoder should not be used to parse untrusted data.
      Deserializing user input can lead to arbitrary code execution.
      Use an alternative and explicitly disable external entities.""",
    "WARNING",
    "cwe-611",
    "m8",
    "platform-2",
    this.results,
    "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x04h-Testing-Code-Quality.md#injection-flaws-mstg-arch-2-and-mstg-platform-2"
  )

  override def name = "XML Decoder"
}

/*
patterns:
      - pattern: |
          $X $METHOD(...) {
            ...
            new XMLDecoder(...);
            ...
          }
      - pattern-not: |
          $X $METHOD(...) {
            ...
            new XMLDecoder("...");
            ...
          }
      - pattern-not: |-
          $X $METHOD(...) {
            ...
            String $STR = "...";
            ...
            new XMLDecoder($STR);
            ...
          }
*/