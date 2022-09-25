package program.scanners.scan_operations.crypto

import program.scanners.scan_operations.ScanOperation
import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL
import program.scanners.scan_operations.SecurityWarning
import org.opalj.br.ObjectType
import org.opalj.br.instructions.LoadString

object WeakKeySize extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    return false
  }
  
  
  override def json = SecurityWarning(
    """Cryptographic implementations with insufficient key length is susceptible
      to bruteforce attacks.""",
    "ERROR",
    "cwe-326",
    "m5",
    "crypto-3",
    this.results,
    "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x04g-Testing-Cryptography.md#common-configuration-issues-mstg-crypto-1-mstg-crypto-2-and-mstg-crypto-3"
  )

  override def name = "WeakKeySize"
}

/*patterns:
      - pattern-either:
          - pattern: |
              $K = $G.getInstance("RSA");
              ...
              $K.initialize(1024);
          - pattern: |
              $K = $G.getInstance("RSA");
              ...
              $K.initialize(512);
          - pattern: |
              $K = $G.getInstance("EC");
              ...
              $K.initialize(new ECGenParameterSpec("secp112r1"));
          - pattern: |
              $K = $G.getInstance("EC");
              ...
              $S = new ECGenParameterSpec("secp112r1");
              ...
              $K.initialize($S);
          - pattern: |
              $K = $G.getInstance("EC");
              ...
              $K.initialize(new ECGenParameterSpec("secp224r1"));
          - pattern: |
              $K = $G.getInstance("EC");
              ...
              $S = new ECGenParameterSpec("secp224r1");
              ...
              $K.initialize($S);
          - pattern: |
              $K = $G.getInstance("Blowfish");
              ...
              $K.init(64);
          - pattern: |
              $K = $G.getInstance("AES");
              ...
              $K.init(64);
*/

