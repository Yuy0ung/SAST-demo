import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URL;
import java.sql.Connection;
import java.sql.Statement;
import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.hibernate.Session;

public class ComplexVulns {

    // 1. XSS (Reflected)
    public void xss(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String input = request.getParameter("input");
        response.getWriter().write(input);
    }

    // 2. SSRF
    public void ssrf(HttpServletRequest request) throws IOException {
        String urlStr = request.getParameter("url");
        // Intermediate variable to test propagation
        String target = urlStr;
        // Split for SAST analysis (simplified parser)
        URL u = new URL(target);
        u.openConnection();
    }

    // 3. Path Traversal
    public void pathTraversal(HttpServletRequest request) throws IOException {
        String filename = request.getParameter("file");
        // new File(filename) is a sink
        File f = new File(filename);
        new FileInputStream(f); // This is also a sink, but we catch it at new File usually
    }

    // 4. JDBC SQL Injection
    public void jdbcSql(HttpServletRequest request, Connection conn) throws Exception {
        String user = request.getParameter("user");
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement stmt = conn.createStatement();
        stmt.executeQuery(query);
    }

    // 5. JPA SQL Injection
    public void jpaSql(HttpServletRequest request, EntityManager entityManager) {
        String id = request.getParameter("id");
        // Vulnerable JPQL
        String jpql = "SELECT u FROM User u WHERE u.id = " + id;
        entityManager.createQuery(jpql);
    }

    // 6. Hibernate SQL Injection
    public void hibernateSql(HttpServletRequest request, Session session) {
        String name = request.getParameter("name");
        String hql = "FROM User WHERE name = '" + name + "'";
        session.createQuery(hql);
    }
}
