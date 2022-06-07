package program.scanners.scan_operations

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.br.instructions.FieldAccess


object ReadWriteStorage extends ScanOperation {  
  override def execute(instruction: MethodInvocationInstruction, callerClass: String): Boolean = {
    val declaringClass = instruction.declaringClass.toJava
    return declaringClass == "android.os.Environment" && 
        Array("getExternalStoragePublicDirectory", "getExternalStorageDirectory").contains(instruction.name)
  }
  
  def json: SecurityWarning = {
    return SecurityWarning(
      "App can read/write to External Storage. Any App can read data written to External Storage.",
      "warning",
      Array(
        "CWE-276: Incorrect Default Permissions",
        "OWASP Top 10: M2: Insecure Data Storage",
        "OWASP MASVS: MSTG-STORAGE-2"
      ),
      results
    )
  }

  def name: String = "Read/Write in storage"
}
