package program.scanners.scan_operations

import org.opalj.br.instructions.MethodInvocationInstruction

import org.opalj.br.instructions.FieldAccess

object TempFile extends ScanOperation {
  override def execute(instruction: MethodInvocationInstruction, callerClass: String): Unit = {
    if (instruction.declaringClass.toJava == "Java.io.File" &&
        Array("setPrimaryClip").contains(instruction.name)) {
          results += callerClass

    }
  }

  override def json: SecurityWarning = {
    return SecurityWarning(
      "App creates temp file. Sensitive information should never be written into a temp file.",
      "warning",
      Array(
        "CWE-276: Incorrect Default Permissions",
        "OWASP Top 10 - M2: Insecure Data Storage",
        "OWASP MASVS: MSTG-STORAGE-2"),
      results
    )
  }

  def name: String = "Temporary Files"
}
