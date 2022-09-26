package program.scanners.scan_operations

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL
import org.opalj.br.ObjectType

object WeakIv extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    /*
    val ivParameterSpecType = ObjectType("javax/crypto/spec/IvParameterSpec")
    if (methodCall.declaringClass == ivParameterSpecType && methodCall.name == "init") {
      val reference = interpretation.operandsArray(pc)(0)

      if (reference.isPrimitiveValue) {
        reference.asPrimitiveValue match {
          case value: IsByteValue => {
            return value.asConstantByte == { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 } ||
                   value.asConstantByte == { 0x01,0x02,0x03,0x04,0x05,0x06,0x07 }  
          }
          case _ =>
        }
      }

    }
    val XMLDecoderType = ObjectType("java/beans/XMLDecoder")
    if (methodCall.declaringClass == XMLDecoderType && methodCall.name == "init") {
      !CodeTracker.processLoadConstantOrigin(0, pc, interpretation)
    }*/
    return false
  }
  
  override def json = SecurityWarning(
    """The App may use weak IVs like "0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00" or "0x01,0x02,0x03,0x04,0x05,0x06,0x07". Not using a random IV makes the resulting ciphertext much more predictable and susceptible to a dictionary attack.""",
    "WARNING",
    "cwe-1204",
    "m5",
    "crypto-5",
    this.results,
    "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x04g-Testing-Cryptography.md#mobile-app-cryptography"
  )

  override def name = "Weak IV"
}

/*
pattern: |
              byte[] $X = {
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
              };
              ...
              $Y =  new IvParameterSpec($X, ...);
          - pattern: |
              byte[] $X = {
                0x01,0x02,0x03,0x04,0x05,0x06,0x07
              };
              ...
              $Y =  new IvParameterSpec($X, ...);
*/