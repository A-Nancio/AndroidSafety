package program.scanners.scan_operations

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL
import org.opalj.br.ObjectType
import org.opalj.br.instructions.LoadString

object AesHardcodedKey extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val operands = interpretation.operandsArray
    if (methodCall.name == "init") {
      val reference = interpretation.operandsArray(pc)(operands.size -1)
      val origin = interpretation.domain.origins(reference)

      if (!origin.isEmpty) {
        val instructionOrigin = 
        interpretation.code.instructions(origin.head) match {
          case method: MethodInvocationInstruction => {
            val objType = ObjectType("javax/crypto/spec/SecretKeySpec")
            if (method.declaringClass == objType && method.name == "init") {
              
            }
          }
          case _ => return false
        }
      }
    }
    return false 
  }
  
  override def json = SecurityWarning(
    """XMLDecoder should not be used to parse untrusted data. Deserializing user input can lead to arbitrary code execution. Use an alternative and explicitly disable external entities.""",
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
      - pattern-either:
          - pattern: |
              $S = new SecretKeySpec("...".getBytes(), "AES");
              ...
              $C.init(..., $S); 
          - pattern: |
              $P = "...";
              ...
              $S = new SecretKeySpec($P.getBytes(), "AES");
              ...
              $C.init(..., $S);

*/