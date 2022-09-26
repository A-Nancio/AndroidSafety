package program.scanners.scan_operations

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL
import org.opalj.br.ObjectType

object AndroidCertificateTransparency extends BestPracticeScan {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val nameVerifierType = ObjectType("com/babylon/certificatetransparency/CTHostnameVerifierBuilder")
    val interceptorType = ObjectType("com/babylon/certificatetransparency/CTInterceptorBuilder")

    return (methodCall.declaringClass == nameVerifierType || methodCall.declaringClass == interceptorType) && methodCall.name == "init"
  }
  
  
  override def json = SecurityWarning(
    """This app does not enforce TLS Certificate Transparency that helps to detect SSL certificates that have been mistakenly issued by a certificate authority or maliciously acquired from an otherwise unimpeachable certificate authority.""",
    "INFO",
    "cwe-295",
    "m3",
    "network-4",
    this.results,
    "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#testing-custom-certificate-stores-and-certificate-pinning-mstg-network-4"
  )

  override def name = "Android Certificate Transparency"
}

/*
patterns:
      - pattern-either:
          - pattern: |
              import com.babylon.certificatetransparency;
          - pattern: |
              new CTInterceptorBuilder(...)
          - pattern: |
              new CTHostnameVerifierBuilder(...)
*/