package program.scanners.scan_operations

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.br.instructions.FieldAccess
import org.opalj.issues.Operands
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import scala.annotation.meta.field
import org.opalj.br.ObjectType

 
object WorldReadable extends ScanOperation {
  override def execute(fieldAccess: FieldAccess, pc: Int): Boolean = {
    return fieldAccess.declaringClass == ObjectType("android/content/Context") &&
        fieldAccess.name == "MODE_WORLD_READABLE"
  }

  override def json = SecurityWarning(
    "App can read/write to External Storage. Any App can read data written to External Storage.",
    "WARNING",
    "cwe-276",
    "m2",
    "storage-2",
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

object WorldWritable extends ScanOperation {
  override def execute(fieldAccess: FieldAccess, pc: Int): Boolean = {
    return fieldAccess.declaringClass.toJava == "android.content.Context" &&
        fieldAccess.name == "MODE_WORLD_WRITEABLE"
  }

  override def json = SecurityWarning(
    "App can read/write to External Storage. Any App can read data written to External Storage.",
    "WARNING",
    "cwe-276",
    "m2",
    "storage-2",
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
