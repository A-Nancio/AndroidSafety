package program.scanners.scan_operations

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.br.instructions.FieldAccess

object RawQuery extends ScanOperation {
  override def execute(instruction: MethodInvocationInstruction, callerClass: String): Unit = {
    if (instruction.declaringClass.toJava == "android.database.sqlite.SQLiteDatabase" &&
        Array("rawQuery", "execSQL").contains(instruction.name)) {
          results += callerClass

    }
  }

  def json: SecurityWarning = {
    return SecurityWarning(
      "App uses SQLite Database and execute raw SQL query. Untrusted user input in raw SQL queries can cause SQL Injection. Also sensitive information should be encrypted and written to the database.",
      "warning",
      Array(
        "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "OWASP Top 10: M7: Client Code Quality",
      ),
      results
    )
  }

  def name: String = "Raw SQLite Query"
}
