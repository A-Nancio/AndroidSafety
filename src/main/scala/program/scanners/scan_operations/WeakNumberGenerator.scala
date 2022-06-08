package program.scanners.scan_operations

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.br.instructions.FieldAccess

object WeakNumberGenerator extends ScanOperation {

  override def execute(instruction: MethodInvocationInstruction): Boolean = {
    return "java.util.Random" == instruction.declaringClass.toJava 
  }
  
  def json: SecurityWarning = {
    return SecurityWarning(
      "The App uses an insecure Random Number Generator.",
      "warning",
      Array("CWE-330: Use of Insufficiently Random Values",
            "OWASP Top 10: M5: Insufficient Cryptography",
            "OWASP MASVS: MSTG-CRYPTO-6"),
      results
    )
  }

  def name: String = "Weak Number Generator"
}
