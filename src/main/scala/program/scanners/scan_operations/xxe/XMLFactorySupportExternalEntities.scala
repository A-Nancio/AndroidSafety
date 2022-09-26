package program.scanners.scan_operations

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL
import org.opalj.br.ObjectType
import org.opalj.value.IsIntegerValue

object XMLFactorySupportExternalEntities extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val XMLInputFactoryType = ObjectType("javax/xml/stream/XMLInputFactory")
    if (methodCall.declaringClass == XMLInputFactoryType && methodCall.name == "setProperty") {
      val reference = interpretation.operandsArray(pc)(0)

      if (reference.isPrimitiveValue) {
        reference.asPrimitiveValue match {
          case value: IsIntegerValue => return value.asConstantInteger == 1
          case _ => return false
        }
      }
    }
    return false
  }
  
  override def json = SecurityWarning(
    """XML external entities are enabled for this XMLInputFactory. This is
      vulnerable to XML external entity attacks. Disable external entities by
      setting "javax.xml.stream.isSupportingExternalEntities" to false.""",
    "ERROR",
    "cwe-611",
    "m8",
    "platform-2",
    this.results,
    "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x04h-Testing-Code-Quality.md#injection-flaws-mstg-arch-2-and-mstg-platform-2"
  )

  override def name = "XML Input Factory XXE enabled"
}
/*
pattern: >-
      $XMLFACTORY.setProperty("javax.xml.stream.isSupportingExternalEntities",
      true);
*/