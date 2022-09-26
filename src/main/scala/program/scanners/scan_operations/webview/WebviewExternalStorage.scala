package program.scanners.scan_operations

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL
import org.opalj.br.ObjectType

object WebviewExternalStorage extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    return false
  }
  
  
  override def json = SecurityWarning(
    """WebView load files from external storage. Files in external storage can be
      modified by any application.""",
    "ERROR",
    "cwe-749",
    "m1",
    "platform-6",
    this.results,
    "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md#testing-webview-protocol-handlers-mstg-platform-6"
  )

  override def name = "Webview External Storage"
}

/*
pattern-either:
          - pattern: |
              $X = <... $E.getExternalStorageDirectory() ...>;
              ...
              $WV.loadUrl(<... $X ...>);
          - pattern: |
              $WV.loadUrl(<... $E.getExternalStorageDirectory().$F() ...>);
          - pattern: |
              $X = <... Environment.getExternalStorageDirectory().$F() ...>;
              ...
              $WV.loadUrl(<... $X ...>);
          - pattern: |
              $X = <... $E.getExternalFilesDir(...) ...>;
              ...
              $WV.loadUrl(<... $X ...>);
*/