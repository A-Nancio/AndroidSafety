package program.scanners.scan_operations

import org.opalj.br.instructions.FieldAccess
import org.opalj.br.instructions.MethodInvocationInstruction

object Log extends ScanOperation{
  override def execute(instruction: MethodInvocationInstruction, callerClass: String): Boolean = {
    var declaringClass = instruction.declaringClass.toJava
    return Array("android.util.Log", "System.out").contains(declaringClass)
  } 
  
  def json: SecurityWarning = {
    return SecurityWarning(
      "The App logs information. Sensitive information should never be logged.",
      "info",
      Array("CWE-532: Insertion of Sensitive Information into Log File",
            "OWASP MASVS: MSTG-STORAGE-3"),
      results
    )
  }

  def name: String = "Logging usage"
}