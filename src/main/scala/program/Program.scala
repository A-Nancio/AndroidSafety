package program

import org.opalj.br.analyses.Project
import org.opalj.br.ClassFile

import io.circe.generic.auto._
import io.circe.parser._

import scala.io.Source
import java.net.URL
import program.scanners._
import java.io._  

object Program {
  
  def analyse(project: Project[URL], jarPath: String): Unit = {
    val code_analysis = new CodeAnalysis(project)
    val api_analysis = AndroidApiAnalysis
    val iterator = project.allProjectClassFiles.iterator
    while(iterator.hasNext) {
      val classFile = iterator.next
      println("scanning " + classFile.thisType.toJava)
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
    val api_list_writer = new PrintWriter(new File(jarPath + "_api_list.json"))
    println(api_list_results)
    api_list_writer.write(api_list_results.toString)
    api_list_writer.close

    println("――――――――――――――――― CODE ANALYSIS RESULTS ―――――――――――――――――")
    val code_analysis_results = code_analysis.export
    val code_analysis_writer = new PrintWriter(new File(jarPath + "_code_analysis.json"))
    println(code_analysis_results)
    code_analysis_writer.write(code_analysis_results.toString)
    code_analysis_writer.close
  }

  def main(args: Array[String]): Unit = {   
    val jarPath = args(0)
      implicit val project = Project(
      new java.io.File(jarPath), // path to the JAR files/directories containing the project
      org.opalj.bytecode.RTJar // predefined path(s) to the used libraries
      )
    analyse(project, jarPath)
  }
}