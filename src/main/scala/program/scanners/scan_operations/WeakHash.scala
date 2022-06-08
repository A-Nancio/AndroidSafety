package program.scanners.scan_operations

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.br.instructions.LoadString

object WeakHash extends ScanOperation{
  private var foundHashUsage = false

  override def execute(instruction: MethodInvocationInstruction): Boolean = {
    if (Array(/*ADD FUNCTION PACKAGES*/).contains(instruction.declaringClass.toJava) && 
      Array("getInstance").contains(instruction.name))
      foundHashUsage = true
    
    return false
  }
  
  override def execute(instruction: LoadString): Boolean = {
    if (foundHashUsage) {
      foundHashUsage = false
      return instruction.value.contains("SHA1")
    }
    foundHashUsage = false
    return false
  }

  def json: SecurityWarning = SecurityWarning(
    "SHA-1 is a weak hash known to have hash collisions.",
    "warning",
    Array(
      "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
      "OWASP Top 10: M5: Insufficient Cryptography",
      "OWASP MASVS: MSTG-CRYPTO-4"
    ),
    results
  )
  
  def name: String = "Weak Hash Usage"

  
}
