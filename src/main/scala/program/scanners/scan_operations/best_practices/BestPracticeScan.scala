package program.scanners.scan_operations

abstract class BestPracticeScan extends ScanOperation {
  var bestPracticeNotFound = true
  
  override def register(classFile: String): Unit = {
    bestPracticeNotFound = false
  }
}
