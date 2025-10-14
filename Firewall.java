public class Firewall {
    private boolean enabled = true;
    private String uri = "http://example.com";

    public void net() {
        if (enabled) {
            blockUnauthTraffic(uri);
        }
    }

    private void blockUnauthTraffic(String uri) {
        System.out.println("Blocking unauthorized traffic to: " + uri);
    }

    // Entry point
    public static void main(String[] args) {
        Firewall fw = new Firewall();
        fw.net();
    }
}
