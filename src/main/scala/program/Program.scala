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
    val api_analysis = AndroidApiAnalysis
    val iterator = project.allProjectClassFiles.iterator
    while(iterator.hasNext) {
      val classFile = iterator.next
      //check fields
      classFile.fields foreach(field => api_analysis.scan(field, classFile.thisType.toJava))

      //check code
      classFile.methods foreach(method => {
        code_analysis scan(method, classFile.thisType.toJava)
        api_analysis.scan(method, classFile.thisType.toJava)
      })
    }
    
    println("――――――――――――――――― API LIST RESULTS ―――――――――――――――――")
    val api_list_results = api_analysis.export
    println(api_list_results)

    println("――――――――――――――――― CODE ANALYSIS RESULTS ―――――――――――――――――")
    val code_analysis_results = code_analysis.export
    println(code_analysis_results + "\n")
  }

  def main(args: Array[String]): Unit = {
    
    //open hel
    val jarPath = "helloWorld.jar"
    implicit val project = Project(
      new java.io.File(jarPath), // path to the JAR files/directories containing the project
      org.opalj.bytecode.RTJar // predefined path(s) to the used libraries
      ) 
    analyse(project)
  }
}