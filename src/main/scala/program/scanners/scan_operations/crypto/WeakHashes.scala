package program.scanners.scan_operations

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.br.ObjectType
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL

object WeakHashes extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val messageDigestType = ObjectType("java/security/MessageDigest")
    if (methodCall.declaringClass == messageDigestType &&
    methodCall.name == "getInstance") {
      CodeTracker.processStringLoadOrigin(0, pc, Array("MD5"), interpretation)
    }

    val digestUtilsType = ObjectType("org/apache/commons/codec/digest/DigestUtils")
    if (methodCall.declaringClass == digestUtilsType && Array("md5", "md5Hex").contains(methodCall.name))
      return true
    
    // NOTE: Hashing.md5() not attended to
    
    return false
  }
  
  
  override def json = SecurityWarning(
    """Weak Hash algorithm used. The hash algorithm is known to have hash collisions.""",
    "ERROR",
    "cwe-327",
    "m5",
    "crypto-4",
    this.results,
    "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x04g-Testing-Cryptography.md#identifying-insecure-andor-deprecated-cryptographic-algorithms-mstg-crypto-4"
  )

  override def name = "Weak Chipers"
}

/*patterns:
      - pattern-either:
          - pattern: |
              $C.getInstance("=~/md5|md4/i", ...);
          - pattern: |
              $C.Files.hash(..., Hashing.md5());
          - pattern: |
              Files.hash(..., Hashing.md5());
          - pattern: |
              DigestUtils.md5Hex(...);
          - pattern: |
              DigestUtils.md5(...);
*/
