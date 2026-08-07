// VULN pack: jvm
import javax.crypto.Cipher;
import javax.xml.parsers.DocumentBuilderFactory;

public class App {
    void run(String name) throws Exception {
        // VULN: jvm.runtime-exec
        Runtime.getRuntime().exec("ls " + name);

        // VULN: jvm.jdbc-concat
        stmt.executeQuery("SELECT * FROM t WHERE n = '" + name + "'");

        // VULN: jvm.weak-cipher-getinstance
        Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");

        // VULN: jvm.xxe-factory
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
    }

    void config(HttpSecurity http) throws Exception {
        // VULN: jvm.csrf-disabled
        http.csrf().disable();
    }
}
