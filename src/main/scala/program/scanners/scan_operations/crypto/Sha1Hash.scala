package program.scanners.scan_operations.crypto

import program.scanners.scan_operations.ScanOperation
import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL
import program.scanners.scan_operations.SecurityWarning
import org.opalj.br.instructions.LoadString
import org.opalj.br.ObjectType
import program.scanners.scan_operations.CodeTracker

object Sha1Hash extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val digestUtilsType = ObjectType("org/apache/commons/codec/digest/DigestUtils")
    if (methodCall.declaringClass == digestUtilsType &&
      Array("sha1Hex", "sha", "sha1").contains(methodCall.name))
      return true
    
    val messageDigestType = ObjectType("java/security/MessageDigest")
    if (methodCall.declaringClass == messageDigestType &&
    methodCall.name == "getInstance") {
      CodeTracker.processStringLoadOrigin(0, pc, Array("SHA-1"), interpretation)
    }
    return false
  }
  
  override def json = SecurityWarning(
    "SHA1 Hash algorithm used. The SHA1 hash is known to have hash collisions.",
    "WARNING",
    "cwe-327",
    "m5",
    "crypto-4",
    this.results,
    "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x04g-Testing-Cryptography.md#identifying-insecure-andor-deprecated-cryptographic-algorithms-mstg-crypto-4"
  )

  override def name = "SHA-1 Hash"
}

/*
patterns:
      - pattern-either:
          - pattern: |
              $C.getInstance("=~/sha-1|sha1/i", ...);
          - pattern: |
              DigestUtils.sha1Hex(...);
          - pattern: |
              DigestUtils.sha1(...);
          - pattern: |
              DigestUtils.sha(...);
*/