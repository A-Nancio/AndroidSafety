package program.scanners.scan_operations

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.br.instructions.FieldAccess
import org.opalj.issues.Operands
import org.opalj.ai.AIResult
import org.opalj.br.PCAndInstruction
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import scala.annotation.meta.field

 
object WorldReadable extends ScanOperation {
  override def execute(pc_instruction: PCAndInstruction, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[java.net.URL]}): Boolean = {
    pc_instruction.instruction match {
      case fieldAccess: FieldAccess => {
        return fieldAccess.declaringClass.toJava == "android.content.Context" &&
        fieldAccess.name == "MODE_WORLD_READABLE"
      }
      case _ => return false
    }
  }

  override def json = SecurityWarning(
    "App can read/write to External Storage. Any App can read data written to External Storage.",
    "WARNING",
    Array(
    "CWE: cwe-276",
    "OWASP-MOBILE: m2",
    "MASVS: storage-2"),
    this.results,
    "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#testing-local-storage-for-sensitive-data-mstg-storage-1-and-mstg-storage-2"
  ) 

  override def name = "WorldReadable"
}

/* patterns:
      - pattern-either:
          - pattern: |
              Context.MODE_WORLD_READABLE
*/

object WorldWritablee extends ScanOperation {
  override def execute(pc_instruction: PCAndInstruction, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[java.net.URL]}): Boolean = {
    pc_instruction.instruction match {
      case fieldAccess: FieldAccess => {
        return fieldAccess.declaringClass.toJava == "android.content.Context" &&
        fieldAccess.name == "MODE_WORLD_WRITEABLE"
      }
      case _ => return false
    }
  }

  override def json = SecurityWarning(
    "App can read/write to External Storage. Any App can read data written to External Storage.",
    "WARNING",
    Array(
    "CWE: cwe-276: Incorrect Default Permissions",
    "OWASP-MOBILE: m2",
    "MASVS: storage-2"),
    this.results,
    "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#testing-local-storage-for-sensitive-data-mstg-storage-1-and-mstg-storage-2"
  ) 

  override def name = "WorldWritable"
}

/* patterns:
      - pattern-either:
          - pattern: |
              Context.MODE_WORLD_WRITEABLE
*/
