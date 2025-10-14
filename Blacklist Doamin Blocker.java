import java.util.HashSet;
import java.util.Set;

public class Firewall {
    private Set<String> blacklist = new HashSet<>();

    public Firewall() {
        // Add some blocked domains
        blacklist.add("malicious.com");
        blacklist.add("phishing.net");
    }

    public boolean allowRequest(String domain) {
        if (blacklist.contains(domain)) {
            System.out.println("❌ Blocked access to: " + domain);
            return false;
        } else {
            System.out.println("✅ Allowed access to: " + domain);
            return true;
        }
    }

    public static void main(String[] args) {
        Firewall fw = new Firewall();
        fw.allowRequest("example.com");
        fw.allowRequest("malicious.com");
    }
}
