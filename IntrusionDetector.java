import java.util.HashMap;
import java.util.Map;

public class IntrusionDetector {
    private Map<String, Integer> failedAttempts = new HashMap<>();
    private final int MAX_ATTEMPTS = 3;

    public void loginAttempt(String user, boolean success) {
        if (!success) {
            failedAttempts.put(user, failedAttempts.getOrDefault(user, 0) + 1);
            if (failedAttempts.get(user) >= MAX_ATTEMPTS) {
                System.out.println("🚨 Intrusion alert! User " + user + " locked out.");
            } else {
                System.out.println("❌ Failed login for " + user);
            }
        } else {
            System.out.println("✅ Successful login for " + user);
            failedAttempts.put(user, 0); // reset on success
        }
    }

    public static void main(String[] args) {
        IntrusionDetector detector = new IntrusionDetector();
        detector.loginAttempt("alice", false);
        detector.loginAttempt("alice", false);
        detector.loginAttempt("alice", false);
        detector.loginAttempt("alice", true);
    }
}
