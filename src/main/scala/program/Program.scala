package program

import org.opalj.br.analyses.Project
import org.opalj.br.ClassFile

import io.circe.generic.auto._
import io.circe.parser._

import scala.io.Source
import java.net.URL
import program.scanners._
import java.io.File

object Program {
  
  def analyse(project: Project[URL]): Unit = {
    val code_analysis = new CodeAnalysis(project)

    val iterator = project.allProjectClassFiles.iterator
    while(iterator.hasNext) {
      val classFile = iterator.next

      //check fields
      classFile.fields.foreach(field => AndroidApiAnalysis.scan(field.fieldType.toJava, classFile.thisType.toJava))

      //check code
      classFile.methods.foreach(method => {
        code_analysis.scan(method, classFile.thisType.toJava)
      })
    }
  }
/*
println(AndroidApiAnalysis.export.toString())
AndroidApiAnalysis.scan(code, classFile.thisType.toJava)
println(CodeAnalysis.export.toString())
*/

  def main(args: Array[String]): Unit = {
    println("―" * 50)
    
    //open hel
    val jarPath = "basic.jar"
    implicit val project = Project(
      new java.io.File(jarPath), // path to the JAR files/directories containing the project
      org.opalj.bytecode.RTJar // predefined path(s) to the used libraries
      ) 

    analyse(project)
  }
}