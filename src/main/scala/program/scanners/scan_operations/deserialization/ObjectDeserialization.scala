package program.scanners.scan_operations.deserialization

import program.scanners.scan_operations.ScanOperation
import program.scanners.scan_operations.SecurityWarning
import org.opalj.ai.AIResult
import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL

object ObjectDeserialization extends ScanOperation {  
  // NOTE LOOK INTO THE NAME OF CONSTRUCTER METHODS
  override def json = SecurityWarning(
    """Found object deserialization using ObjectInputStream. Deserializing entire
      Java objects is dangerous because malicious actors can create Java object
      streams with unintended consequences. Ensure that the objects being
      deserialized are not user-controlled. Consider using HMACs to sign the
      data stream to make sure it is not tampered with, or consider only 
      transmitting object fields and populating a new object.""",
      "WARNING",
      Array("CWE: cwe-502",
      "OWASP-MOBILE: m1",
      "MASVS: platform-8"),
      this.results,
      "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md#testing-object-persistence-mstg-platform-8"
  )

  override def name = "Object Deserialization"
}

/*patterns:
      - pattern: new ObjectInputStream(...);
*/
