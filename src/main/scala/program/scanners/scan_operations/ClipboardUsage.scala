package program.scanners.scan_operations

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.br.instructions.FieldAccess

object ClipboardUsage extends ScanOperation {
  override def execute(instruction: MethodInvocationInstruction, callerClass: String): Boolean = {
    return instruction.declaringClass.toJava == "android.content.ClipboardManager" &&
        Array("createTempFile").contains(instruction.name)
  }

  def json: SecurityWarning = {
    return SecurityWarning(
      "This App copies data to clipboard. Sensitive data should not be copied to clipboard as other applications can access it.",
      "info",
      Array("OWASP MASVS: MSTG-STORAGE-10"),
      results
    )
  }

  def name: String = "Clipboard Usage"
}
