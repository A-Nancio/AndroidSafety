package program

import org.opalj.br.analyses.Project
import org.opalj.br.ClassFile
import org.opalj.br.instructions._

import io.circe.generic.auto._
import io.circe.parser._

import scala.io.Source
import java.net.URL
import program.scanners._
import org.opalj.br.PCAndInstruction

object Program {
  
  def analyse(project: Project[URL]): Unit = {
    val iterator = project.allProjectClassFiles.iterator
    while(iterator.hasNext) {
      val classFile = iterator.next
      //println("―" * 50)
      //println("[CLASSFILE]: " + classFile.thisType.toJava)

      //check fields
      
      for (method <- classFile.methods) {   //CHANGE FOR LOOP FOR FOR EACH
        //println("\t[METHOD] " + method.name)
        method.body match {
          case None => {}
          case Some(code) => {
            
            val pc_instruction_list = code.collectInstructionsWithPC{case inst: PCAndInstruction => inst} //remove all null cases
            //
            //val variable_instructions = instructions.collect{case inst: FieldAccess => inst}
            //val method_instructions = instructions.collect{case inst: MethodInvocationInstruction => inst}
            //val constant_instructions = instructions.collect{case inst: LoadString => inst}
            //val labeled_instructions = instructions.collect{case inst: LabeledInstruction => inst}
            for (pc_instruction <- pc_instruction_list) {
              pc_instruction.value.instruction match {
                case methodCall: MethodInvocationInstruction => {
                  for (operation <- CodeAnalysis.methodScanOperations) 
                    operation.execute(methodCall, classFile.thisType.toJava)
                }
                case access: FieldAccess => {
                  //do nothing, for now
                }
                case string: LoadString => {
                  //do nothing
                }
                case other:Any => {}
              }
              //println("\t\t[INSTRUCTION: " + instruction.pc + "] " + instruction.value.instruction + 
              //"--> Next is: " + instruction.value.instruction.nex)
            }
          } 
        }
        
      }
    }
    println(CodeAnalysis.export().toString())
  }

  def main(args: Array[String]): Unit = {
    println("―" * 50)
    
    //open project
    val jarPath = "mobsf-enjarify.jar"
    implicit val project = Project(
      new java.io.File(jarPath), // path to the JAR files/directories containing the project
      org.opalj.bytecode.RTJar // predefined path(s) to the used libraries
      ) 

    analyse(project)
  }
}