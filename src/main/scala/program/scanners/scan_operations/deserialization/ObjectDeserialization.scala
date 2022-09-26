package program.scanners.scan_operations

import org.opalj.ai.AIResult
import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL
import org.opalj.br.ObjectType

object ObjectDeserialization extends ScanOperation {  
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val objectInputStreamType = ObjectType("java/io/ObjectInputStream")

    return methodCall.declaringClass == objectInputStreamType && methodCall.name == "init"
  }

  override def json = SecurityWarning(
    """Found object deserialization using ObjectInputStream. Deserializing entire Java objects is dangerous because malicious actors can create Java object streams with unintended consequences. Ensure that the objects being deserialized are not user-controlled. Consider using HMACs to sign the data stream to make sure it is not tampered with, or consider only transmitting object fields and populating a new object.""",
      "WARNING",
      "cwe-502",
      "m1",
      "platform-8",
      this.results,
      "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md#testing-object-persistence-mstg-platform-8"
  )

  override def name = "Object Deserialization"
}

/*patterns:
      - pattern: new ObjectInputStream(...);
*/
