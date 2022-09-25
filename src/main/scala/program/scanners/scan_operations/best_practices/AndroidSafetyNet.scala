package program.scanners.scan_operations.best_practices

import program.scanners.scan_operations.ScanOperation
import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL
import program.scanners.scan_operations.SecurityWarning
import org.opalj.br.ObjectType
import org.opalj.br.instructions.LoadString
import program.scanners.scan_operations.CodeTracker

object AndroidSafetyNet extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    var safetyNetType = ObjectType("com/google/android/gms/safetynet/SafetyNetApi/SafetyNet")
    if (methodCall.declaringClass == safetyNetType && methodCall.name == "attest") {
      return CodeTracker.processMethodCallOrigin(interpretation.operandsArray.size - 1, pc,
        "com/google/android/gms/safetynet/SafetyNetApi/SafetyNet",
        "getClient",
        interpretation)
    }

    safetyNetType = ObjectType("com/google/android/gms/safetynet/SafetyNetApi/RNGoogleSafetyNetPackage")
    return methodCall.declaringClass == safetyNetType && methodCall.name == "init"
  }
  
  override def json = SecurityWarning(
    """This app does not uses SafetyNet Attestation API that provides
      cryptographically-signed attestation, assessing the device's integrity.
      This check helps to ensure that the servers are interacting with the
      genuine app running on a genuine Android device. """,
    "INFO",
    "cwe-353",
    "m8",
    "resilience-1",
    this.results,
    "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md#testing-root-detection-mstg-resilience-1"
  )

  override def name = "Android SafetyNet API"
}

/*
patterns:
      - pattern-either:
          - pattern: |
              import com.google.android.gms.safetynet.SafetyNetApi;
          - pattern: |
              $S = SafetyNet.getClient(...);
              ...
              $T = $S.attest(...);
          - pattern: |
              new RNGoogleSafetyNetPackage(...)
*/
