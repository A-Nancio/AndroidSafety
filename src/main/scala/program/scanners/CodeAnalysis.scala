package program.scanners

import io.circe.Json
import io.circe.Encoder
import io.circe.generic.auto._
import io.circe.parser._

import scala.collection.mutable.Set
import program.scanners.scan_operations._

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.br.PCAndInstruction
import org.opalj.br.Code


object CodeAnalysis {
  val methodScanOperations: Array[ScanOperation] = Array[ScanOperation](
    /*Base64,*/
    Log,
    WeakNumberGenerator,
    ReadWriteStorage,
    RawQuery
  )

  def scan(code: Code, classFile: String): Unit = {
    for (instruction <- code.collectInstructionsWithPC{case inst: PCAndInstruction => inst}) {
      instruction.value.instruction match {
        
        case methodCall: MethodInvocationInstruction => {
          methodScanOperations.foreach(operation => {
            if (operation.execute(methodCall, classFile))
              operation.register(classFile)
          })
        }
        case _ => {/*do nothing*/} 
      }
    }
    //println("\t\t[INSTRUCTION: " + instruction.pc + "] " + instruction.value.instruction + 
    //"--> Next is: " + instruction.value.instruction.nex)
  }

  def export(): Json = {
    val output = methodScanOperations.map(operation => operation.json)
    return Encoder[Array[SecurityWarning]].apply(output)
  }
}
